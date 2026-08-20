#!/usr/bin/env python3
"""
Safeye - a single-file HTTP endpoint monitor.

Reads endpoint definitions from a CSV file, checks them concurrently, and sends
email only when a check changes state (up -> down, down -> up). Keeps no
database and needs no container: a Python interpreter and a spreadsheet.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import smtplib
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()


def _env_int(name, default):
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _env_float(name, default):
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


def _env_bool(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


# --- Configuration -----------------------------------------------------------

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.example.com")
SMTP_PORT = _env_int("SMTP_PORT", 587)
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "safeye@example.com")
SMTP_STARTTLS = _env_bool("SMTP_STARTTLS", True)

LOGS_DIR = os.getenv("SAFEYE_LOGS_DIR", "logs")
RESUME_LOG_FILE = os.getenv("SAFEYE_RESUME_LOG", "resume.log")
STATE_FILE = os.getenv("SAFEYE_STATE_FILE", "state.json")
REQUESTS_CSV = os.getenv("SAFEYE_CONFIG", "requests.csv")

CHECK_INTERVAL = _env_int("SAFEYE_INTERVAL", 5 * 60)
REQUEST_TIMEOUT = _env_float("SAFEYE_TIMEOUT", 10)
RETRY_ATTEMPTS = max(1, _env_int("SAFEYE_RETRY_ATTEMPTS", 3))
RETRY_BACKOFF = _env_float("SAFEYE_RETRY_BACKOFF", 2)
MAX_WORKERS = max(1, _env_int("SAFEYE_MAX_WORKERS", 10))
VERIFY_TLS = _env_bool("SAFEYE_VERIFY_TLS", True)

# Warn when a certificate expires within this many days (0 disables the check).
TLS_WARN_DAYS = _env_int("SAFEYE_TLS_WARN_DAYS", 14)
# Re-send a reminder every N hours while an endpoint stays down (0 disables).
REALERT_HOURS = _env_float("SAFEYE_REALERT_HOURS", 0)
# Dead man's switch: pinged after every successful cycle so that a dead Safeye
# is distinguishable from healthy endpoints.
HEARTBEAT_URL = os.getenv("SAFEYE_HEARTBEAT_URL", "")

LOG_MAX_BYTES = _env_int("SAFEYE_LOG_MAX_BYTES", 1_000_000)
LOG_BACKUP_COUNT = _env_int("SAFEYE_LOG_BACKUP_COUNT", 5)

# TlsProbe.days carries this when a certificate has already expired.
EXPIRED = -1
# OpenSSL's X509_V_ERR_CERT_HAS_EXPIRED, the verification failure we can read.
X509_V_ERR_CERT_HAS_EXPIRED = 10

_logger_lock = threading.Lock()
_state_lock = threading.Lock()


# --- Logging -----------------------------------------------------------------


def ensure_log_dir(logs_dir=None):
    """Create the log directory if it does not exist and return its path."""
    logs_dir = logs_dir or LOGS_DIR
    os.makedirs(logs_dir, exist_ok=True)
    return logs_dir


def sanitize_filename(name):
    """Replace every non-alphanumeric character with an underscore."""
    return "".join(c if c.isalnum() else "_" for c in name)


def get_logger(project_name, logs_dir=None):
    """
    Return a logger that writes to logs/<project>.log.

    Handlers are attached once per project and rotate by size, so log files stay
    bounded without any external cleanup.
    """
    logs_dir = ensure_log_dir(logs_dir)
    logger = logging.getLogger(f"safeye.{project_name}")
    with _logger_lock:
        if not logger.handlers:
            path = os.path.join(logs_dir, f"{sanitize_filename(project_name)}.log")
            handler = RotatingFileHandler(
                path,
                maxBytes=LOG_MAX_BYTES,
                backupCount=LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False
    return logger


# --- Configuration file ------------------------------------------------------


def _parse_expected_status(raw):
    """Parse '200' or '200,204' into a set of ints. Defaults to {200}."""
    codes = set()
    for part in str(raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            codes.add(int(part))
        except ValueError:
            print(f"Ignoring invalid expected_http_status value: {part!r}")
    return codes or {200}


def read_requests_csv(file_path):
    """
    Read endpoint definitions from a semicolon-separated CSV file.

    Recognised columns: client, project_name, endpoint, expected_http_status
    (single code or comma-separated list), notify_emails, body_json,
    headers_json, http_method, max_response_ms (optional).
    """
    request_configs = []
    seen_keys = set()

    with open(file_path, "r", newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile, delimiter=";")
        for row in reader:
            endpoint = (row.get("endpoint") or "").strip()
            if not endpoint:
                print(f"Skipping row without an endpoint: {row}")
                continue

            try:
                headers = json.loads(row["headers_json"]) if row.get("headers_json") else {}
            except json.JSONDecodeError:
                print(f"Invalid headers_json for {endpoint}, ignoring headers")
                headers = {}

            try:
                body = json.loads(row["body_json"]) if row.get("body_json") else None
            except json.JSONDecodeError:
                print(f"Invalid body_json for {endpoint}, sending no body")
                body = None

            try:
                max_response_ms = (
                    float(row["max_response_ms"]) if row.get("max_response_ms") else None
                )
            except ValueError:
                print(f"Invalid max_response_ms for {endpoint}, ignoring threshold")
                max_response_ms = None

            config = {
                "client": (row.get("client") or "").strip(),
                "project_name": (row.get("project_name") or "default_project").strip(),
                "endpoint": endpoint,
                "expected_http_status": _parse_expected_status(row.get("expected_http_status")),
                "notify_emails": [
                    email.strip()
                    for email in (row.get("notify_emails") or "").split(",")
                    if email.strip()
                ],
                "body": body,
                "headers": headers,
                "http_method": (row.get("http_method") or "GET").strip().upper(),
                "max_response_ms": max_response_ms,
            }

            key = state_key(config)
            if key in seen_keys:
                print(f"Duplicate client/project_name {key!r}: logs and state will be shared")
            seen_keys.add(key)

            request_configs.append(config)
    return request_configs


# --- Persistent state --------------------------------------------------------


def state_key(config):
    """Stable identity for a check, used for state and de-duplication."""
    return f"{config['client']}::{config['project_name']}"


def load_state(path=None):
    """Load the persisted up/down state, returning an empty state on any error."""
    path = path or STATE_FILE
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(state, path=None):
    """Persist state atomically so a crash mid-write cannot corrupt the file."""
    path = path or STATE_FILE
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
    os.replace(tmp_path, path)


# --- Notifications -----------------------------------------------------------


def send_email(to_emails, subject, body):
    """Send one email. Returns True on success, False on failure."""
    if not to_emails:
        return False

    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(to_emails)
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=REQUEST_TIMEOUT) as server:
            if SMTP_STARTTLS:
                server.starttls(context=ssl.create_default_context())
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print(f"Email sent to {', '.join(to_emails)}: {subject}")
        return True
    except Exception as exc:
        print(f"Failed to send email ({subject}): {exc}")
        return False


def notify(config, subject, body, logger, dry_run=False):
    """
    Log an alert and email it to the configured recipients.

    Returns False only when delivery failed in a way a later attempt could fix,
    so callers know not to record the alert as sent. A dry run and a check with
    no recipients both report True: there is nothing left to retry.
    """
    logger.info(f"ALERT {subject}")
    if dry_run:
        print(f"[dry-run] would email {config['notify_emails']}: {subject}")
        return True
    if not config["notify_emails"]:
        logger.warning("No notify_emails configured; alert was logged only")
        return True
    return send_email(config["notify_emails"], subject, body)


# --- Checks ------------------------------------------------------------------


@dataclass
class CheckResult:
    ok: bool
    status_code: int | None = None
    elapsed_ms: float | None = None
    error: str | None = None
    attempts: int = 0


def perform_check(config):
    """
    Request an endpoint, retrying transient failures before declaring it down.

    A check fails if the request raises, if the status code is not expected, or
    if the response is slower than the configured max_response_ms.
    """
    error = None
    status_code = None
    elapsed_ms = None

    for attempt in range(1, RETRY_ATTEMPTS + 1):
        started = time.monotonic()
        try:
            response = requests.request(
                method=config["http_method"],
                url=config["endpoint"],
                headers=config["headers"],
                json=config["body"],
                timeout=REQUEST_TIMEOUT,
                verify=VERIFY_TLS,
            )
            elapsed_ms = (time.monotonic() - started) * 1000
            status_code = response.status_code

            expected = config["expected_http_status"]
            limit = config["max_response_ms"]
            if status_code not in expected:
                error = (
                    f"expected HTTP {'/'.join(str(c) for c in sorted(expected))}, "
                    f"got {status_code}"
                )
            elif limit is not None and elapsed_ms > limit:
                error = f"responded in {elapsed_ms:.0f} ms, above the {limit:.0f} ms limit"
            else:
                return CheckResult(
                    ok=True,
                    status_code=status_code,
                    elapsed_ms=elapsed_ms,
                    attempts=attempt,
                )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - started) * 1000
            error = f"{type(exc).__name__}: {exc}"

        if attempt < RETRY_ATTEMPTS:
            time.sleep(RETRY_BACKOFF * (2 ** (attempt - 1)))

    return CheckResult(
        ok=False,
        status_code=status_code,
        elapsed_ms=elapsed_ms,
        error=error,
        attempts=RETRY_ATTEMPTS,
    )


@dataclass
class TlsProbe:
    """
    What one probe learned about an endpoint's certificate.

    days is the margin before expiry, EXPIRED when the certificate has already
    expired, and None when the expiry could not be established at all.
    retryable splits that last case in two: we never got a look at the
    certificate, so a later cycle may do better, versus we did and it was
    unusable, which no later cycle today will change.
    """

    days: int | None
    retryable: bool = False

    @property
    def expired(self):
        return self.days is not None and self.days <= EXPIRED


def probe_tls_expiry(url, timeout=None):
    """
    Ask an endpoint how long its TLS certificate has left.

    A certificate we can reach but cannot use - self-signed, issued by a CA we
    do not trust, wrong hostname, or carrying an unparseable notAfter - is a
    standing configuration fact rather than a blip, so it comes back as not
    retryable. Only a failure to reach the certificate at all is retryable.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return TlsProbe(None)

    host = parsed.hostname
    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout or REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        # An expired certificate cannot be read, because verifying it is what
        # fails - and that is the certificate most worth alerting on. OpenSSL
        # tells us it was expiry rather than some other verification problem.
        if exc.verify_code == X509_V_ERR_CERT_HAS_EXPIRED:
            return TlsProbe(EXPIRED)
        return TlsProbe(None)
    except Exception:
        return TlsProbe(None, retryable=True)

    not_after = (cert or {}).get("notAfter")
    if not not_after:
        return TlsProbe(None)

    try:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return TlsProbe(None)
    return TlsProbe((expires - datetime.now(timezone.utc)).days)


def _check_tls(config, entry, logger, dry_run):
    """
    Warn at most once a day while a certificate is close to expiring.

    The daily marker gates the handshake, not just the email, so a healthy
    certificate costs one extra connection a day rather than one per cycle. A
    certificate we reached but could not use marks the day too - probing it
    again before tomorrow would only fail the same way - and is logged so the
    configuration problem is visible. Only an endpoint we could not reach is
    left unmarked to retry, along with a warning that failed to send: like
    DOWN and RECOVERED, the day counts as covered once the email leaves.
    """
    if TLS_WARN_DAYS <= 0 or urlparse(config["endpoint"]).scheme != "https":
        return
    today = datetime.now(timezone.utc).date().isoformat()
    if entry.get("tls_checked_on") == today:
        return

    probe = probe_tls_expiry(config["endpoint"])
    if probe.days is None:
        if not probe.retryable:
            logger.warning("TLS certificate could not be read; expiry unknown")
            entry["tls_checked_on"] = today
        return
    if probe.days > TLS_WARN_DAYS:
        entry["tls_checked_on"] = today
        return

    summary = "has expired" if probe.expired else f"expires in {probe.days} day(s)"
    logger.warning(f"TLS certificate {summary}")
    if notify(
        config,
        f"[Safeye] TLS certificate {summary}: {config['project_name']}",
        f"Client: {config['client']}\n"
        f"Endpoint: {config['endpoint']}\n"
        f"The TLS certificate {summary}.",
        logger,
        dry_run,
    ):
        entry["tls_checked_on"] = today


# --- Alert state machine -----------------------------------------------------


def _humanize(seconds):
    seconds = int(max(0, seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes = remainder // 60
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m"
    return f"{seconds}s"


def _downtime(since, until):
    """Human-readable gap between two ISO timestamps, or "" if unusable."""
    if not since or not until:
        return ""
    try:
        gap = datetime.fromisoformat(until) - datetime.fromisoformat(since)
    except ValueError:
        return ""
    return _humanize(gap.total_seconds())


def check_endpoint(config, state, dry_run=False):
    """
    Run one check and emit notifications only on a state change.

    Returns True if the endpoint is currently up.
    """
    logger = get_logger(config["project_name"])
    key = state_key(config)

    with _state_lock:
        entry = state.setdefault(key, {"status": "up", "consecutive_failures": 0})

    result = perform_check(config)
    now = datetime.now(timezone.utc)
    previous_status = entry.get("status", "up")

    # Independent of the check result: an endpoint failing because its
    # certificate expired is exactly the one that needs the warning.
    _check_tls(config, entry, logger, dry_run)

    if result.ok:
        logger.info(
            f"OK {config['http_method']} {config['endpoint']} "
            f"-> {result.status_code} in {result.elapsed_ms:.0f} ms"
        )
        # The outage facts are frozen on the transition, so a recovery alert
        # that has to be retried still reports the outage it belongs to.
        if previous_status == "down":
            recovery = {
                "since": entry.get("since"),
                "recovered_at": now.isoformat(),
                "last_error": entry.get("last_error") or "unknown",
            }
        else:
            recovery = entry.get("pending_recovery")

        if recovery:
            downtime = _downtime(recovery.get("since"), recovery.get("recovered_at"))
            delivered = notify(
                config,
                f"[Safeye] RECOVERED: {config['project_name']}",
                f"Client: {config['client']}\n"
                f"Endpoint: {config['endpoint']}\n"
                f"Status: HTTP {result.status_code} in {result.elapsed_ms:.0f} ms\n"
                + (f"Downtime: {downtime}\n" if downtime else "")
                + f"Previous error: {recovery.get('last_error', 'unknown')}\n",
                logger,
                dry_run,
            )
            if delivered:
                entry.pop("pending_recovery", None)
            else:
                entry["pending_recovery"] = recovery

        up_since = entry.get("since") if previous_status == "up" else None
        entry.update(
            {
                "status": "up",
                "consecutive_failures": 0,
                "since": up_since or now.isoformat(),
                "last_checked": now.isoformat(),
                "last_error": None,
            }
        )
        return True

    logger.error(
        f"FAIL {config['http_method']} {config['endpoint']} "
        f"after {result.attempts} attempt(s): {result.error}"
    )
    entry["consecutive_failures"] = entry.get("consecutive_failures", 0) + 1
    entry["last_checked"] = now.isoformat()
    entry["last_error"] = result.error

    body = (
        f"Client: {config['client']}\n"
        f"Endpoint: {config['http_method']} {config['endpoint']}\n"
        f"Error: {result.error}\n"
        f"Attempts: {result.attempts}\n"
        f"Consecutive failed checks: {entry['consecutive_failures']}\n"
    )

    def alert(kind):
        """Send one alert, recording it as notified only if it got out."""
        subject = f"[Safeye] {kind}: {config['project_name']}"
        if notify(config, subject, body, logger, dry_run):
            entry["last_notified"] = now.isoformat()

    if previous_status != "down":
        entry["status"] = "down"
        entry["since"] = now.isoformat()
        entry.pop("last_notified", None)
        entry.pop("pending_recovery", None)
        alert("DOWN")
        return False

    # Already down. An absent last_notified means the DOWN alert never reached
    # anyone, so retry it; otherwise stay quiet unless a reminder is due.
    last_notified = entry.get("last_notified")
    if not last_notified:
        alert("DOWN")
        return False

    if REALERT_HOURS > 0:
        try:
            due = now - datetime.fromisoformat(last_notified) >= timedelta(
                hours=REALERT_HOURS
            )
        except ValueError:
            due = True
        if due:
            alert("STILL DOWN")
    return False


# --- Cycle -------------------------------------------------------------------


def send_heartbeat():
    """Ping the dead man's switch so a dead Safeye is noticed."""
    if not HEARTBEAT_URL:
        return
    try:
        requests.get(HEARTBEAT_URL, timeout=REQUEST_TIMEOUT)
    except Exception as exc:
        print(f"Heartbeat ping failed: {exc}")


def execute_requests(config_path=None, state=None, dry_run=False):
    """Check every configured endpoint concurrently and write a cycle summary."""
    config_path = config_path or REQUESTS_CSV
    started = datetime.now()
    print(f"Executing requests at {started.isoformat()}")
    ensure_log_dir()

    request_configs = read_requests_csv(config_path)
    if state is None:
        state = load_state()

    if request_configs:
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(request_configs))) as pool:
            results = list(
                pool.map(lambda cfg: check_endpoint(cfg, state, dry_run), request_configs)
            )
    else:
        results = []

    down = [
        config["project_name"]
        for config, ok in zip(request_configs, results)
        if not ok
    ]
    if not dry_run:
        save_state(state)

    summary = (
        f"{started.isoformat()} | {len(request_configs)} analysed projects | "
        f"{len(down)} projects in alert"
        + (f" | down: {', '.join(down)}" if down else "")
        + "\n"
    )
    if not dry_run:
        with open(RESUME_LOG_FILE, "a", encoding="utf-8") as resume_log:
            resume_log.write(summary)
    print(summary, end="")

    if not dry_run:
        send_heartbeat()
    return {"total": len(request_configs), "down": down, "state": state}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Safeye - HTTP endpoint monitor")
    parser.add_argument("--config", default=REQUESTS_CSV, help="path to the CSV config")
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    parser.add_argument(
        "--interval",
        type=float,
        default=CHECK_INTERVAL,
        help="seconds between cycles (default: %(default)s)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="check endpoints but never send email"
    )
    args = parser.parse_args(argv)

    state = load_state()
    try:
        while True:
            started = time.monotonic()
            execute_requests(args.config, state, args.dry_run)
            if args.once:
                return 0
            time.sleep(max(0, args.interval - (time.monotonic() - started)))
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
