import json
import logging
import os
import ssl
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import safeye
from safeye import (
    CheckResult,
    EXPIRED,
    _downtime,
    _humanize,
    _parse_expected_status,
    check_endpoint,
    execute_requests,
    load_state,
    perform_check,
    read_requests_csv,
    sanitize_filename,
    save_state,
    send_email,
    state_key,
    TlsProbe,
    probe_tls_expiry,
)


def today():
    return datetime.now(timezone.utc).date().isoformat()


def make_config(**overrides):
    config = {
        "client": "Acme",
        "project_name": "Website",
        "endpoint": "https://example.com/health",
        "expected_http_status": {200},
        "notify_emails": ["ops@example.com"],
        "body": None,
        "headers": {},
        "http_method": "GET",
        "max_response_ms": None,
    }
    config.update(overrides)
    return config


class BaseTest(unittest.TestCase):
    """Isolates every test in its own temp dir with predictable settings."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.path = lambda name: os.path.join(self.tmpdir.name, name)

        self.set_module(
            LOGS_DIR=self.path("logs"),
            RESUME_LOG_FILE=self.path("resume.log"),
            STATE_FILE=self.path("state.json"),
            TLS_WARN_DAYS=0,
            REALERT_HOURS=0,
            HEARTBEAT_URL="",
            RETRY_ATTEMPTS=1,
            RETRY_BACKOFF=0,
        )
        self.addCleanup(self.reset_loggers)

    def set_module(self, **values):
        for name, value in values.items():
            patcher = patch.object(safeye, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def reset_loggers(self):
        """Drop cached per-project loggers so temp dirs can be removed."""
        manager = logging.Logger.manager
        for name in [n for n in manager.loggerDict if n.startswith("safeye.")]:
            logger = logging.getLogger(name)
            for handler in list(logger.handlers):
                handler.close()
                logger.removeHandler(handler)
            del manager.loggerDict[name]


class TestHelpers(BaseTest):
    def test_sanitize_filename(self):
        self.assertEqual(sanitize_filename("test file.log"), "test_file_log")
        self.assertEqual(sanitize_filename("test@file.log"), "test_file_log")
        self.assertEqual(sanitize_filename("test123"), "test123")

    def test_parse_expected_status(self):
        self.assertEqual(_parse_expected_status("200"), {200})
        self.assertEqual(_parse_expected_status("200, 204"), {200, 204})
        self.assertEqual(_parse_expected_status(""), {200})
        self.assertEqual(_parse_expected_status("abc"), {200})

    def test_humanize(self):
        self.assertEqual(_humanize(45), "45s")
        self.assertEqual(_humanize(120), "2m")
        self.assertEqual(_humanize(3900), "1h 5m")

    def test_downtime(self):
        until = datetime.now(timezone.utc)
        since = (until - timedelta(minutes=5)).isoformat()
        self.assertEqual(_downtime(since, until.isoformat()), "5m")
        self.assertEqual(_downtime(None, until.isoformat()), "")
        self.assertEqual(_downtime(since, None), "")
        self.assertEqual(_downtime("not a timestamp", until.isoformat()), "")

    def test_state_key_is_stable(self):
        self.assertEqual(state_key(make_config()), "Acme::Website")


class TestReadRequestsCsv(BaseTest):
    def write_csv(self, content):
        path = self.path("requests.csv")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def test_reads_all_fields(self):
        path = self.write_csv(
            "client;project_name;endpoint;expected_http_status;notify_emails;"
            "body_json;headers_json;http_method;max_response_ms\n"
            "TestClient;TestProject;http://example.com;200;a@example.com,b@example.com;"
            '{"key": "value"};{"Content-Type": "application/json"};post;1500\n'
        )
        (config,) = read_requests_csv(path)

        self.assertEqual(config["client"], "TestClient")
        self.assertEqual(config["project_name"], "TestProject")
        self.assertEqual(config["endpoint"], "http://example.com")
        self.assertEqual(config["expected_http_status"], {200})
        self.assertEqual(config["notify_emails"], ["a@example.com", "b@example.com"])
        self.assertEqual(config["body"], {"key": "value"})
        self.assertEqual(config["headers"], {"Content-Type": "application/json"})
        self.assertEqual(config["http_method"], "POST")
        self.assertEqual(config["max_response_ms"], 1500)

    def test_multiple_expected_statuses(self):
        path = self.write_csv(
            "project_name;endpoint;expected_http_status\n"
            "P;http://example.com;200,204\n"
        )
        (config,) = read_requests_csv(path)
        self.assertEqual(config["expected_http_status"], {200, 204})

    def test_malformed_rows_degrade_gracefully(self):
        path = self.write_csv(
            "project_name;endpoint;headers_json;body_json;max_response_ms\n"
            "P;http://example.com;{not json;{also not json;fast\n"
        )
        (config,) = read_requests_csv(path)
        self.assertEqual(config["headers"], {})
        self.assertIsNone(config["body"])
        self.assertIsNone(config["max_response_ms"])

    def test_rows_without_endpoint_are_skipped(self):
        path = self.write_csv(
            "project_name;endpoint\nGood;http://example.com\nBad;\n"
        )
        configs = read_requests_csv(path)
        self.assertEqual([c["project_name"] for c in configs], ["Good"])

    def test_defaults_when_columns_missing(self):
        path = self.write_csv("endpoint\nhttp://example.com\n")
        (config,) = read_requests_csv(path)
        self.assertEqual(config["project_name"], "default_project")
        self.assertEqual(config["http_method"], "GET")
        self.assertEqual(config["expected_http_status"], {200})
        self.assertEqual(config["notify_emails"], [])


class TestState(BaseTest):
    def test_roundtrip(self):
        path = self.path("state.json")
        save_state({"Acme::Website": {"status": "down"}}, path)
        self.assertEqual(load_state(path), {"Acme::Website": {"status": "down"}})

    def test_missing_file_returns_empty(self):
        self.assertEqual(load_state(self.path("nope.json")), {})

    def test_corrupt_file_returns_empty(self):
        path = self.path("state.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        self.assertEqual(load_state(path), {})


class TestPerformCheck(BaseTest):
    def response(self, status=200):
        response = MagicMock()
        response.status_code = status
        return response

    def test_success(self):
        with patch("safeye.requests.request", return_value=self.response(200)) as request:
            result = perform_check(make_config())

        self.assertTrue(result.ok)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.attempts, 1)
        request.assert_called_once()
        self.assertEqual(request.call_args.kwargs["method"], "GET")

    def test_unexpected_status_is_a_failure(self):
        with patch("safeye.requests.request", return_value=self.response(503)):
            result = perform_check(make_config())

        self.assertFalse(result.ok)
        self.assertIn("expected HTTP 200, got 503", result.error)

    def test_slow_response_is_a_failure(self):
        with patch("safeye.requests.request", return_value=self.response(200)), patch(
            "safeye.time.monotonic", side_effect=[0, 3.0]
        ):
            result = perform_check(make_config(max_response_ms=1000))

        self.assertFalse(result.ok)
        self.assertIn("above the 1000 ms limit", result.error)

    def test_transient_failure_is_retried_then_succeeds(self):
        self.set_module(RETRY_ATTEMPTS=3)
        responses = [ConnectionError("refused"), self.response(500), self.response(200)]
        with patch("safeye.requests.request", side_effect=responses), patch(
            "safeye.time.sleep"
        ) as sleep:
            result = perform_check(make_config())

        self.assertTrue(result.ok)
        self.assertEqual(result.attempts, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_exhausted_retries_report_last_error(self):
        self.set_module(RETRY_ATTEMPTS=2)
        with patch("safeye.requests.request", side_effect=TimeoutError("timed out")), patch(
            "safeye.time.sleep"
        ):
            result = perform_check(make_config())

        self.assertFalse(result.ok)
        self.assertEqual(result.attempts, 2)
        self.assertIn("TimeoutError: timed out", result.error)


class TestAlertStateMachine(BaseTest):
    """The alert path is the reason the tool exists; cover every transition."""

    def run_check(self, state, result, config=None, dry_run=False):
        config = config or make_config()
        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.send_email", return_value=True
        ) as email:
            up = check_endpoint(config, state, dry_run)
        return up, email

    def failure(self, error="ConnectionError: refused"):
        return CheckResult(ok=False, error=error, attempts=3)

    def success(self, status=200, elapsed_ms=120.0):
        return CheckResult(ok=True, status_code=status, elapsed_ms=elapsed_ms, attempts=1)

    def test_first_failure_alerts_and_records_down(self):
        state = {}
        up, email = self.run_check(state, self.failure())

        self.assertFalse(up)
        email.assert_called_once()
        recipients, subject, body = email.call_args[0]
        self.assertEqual(recipients, ["ops@example.com"])
        self.assertIn("DOWN: Website", subject)
        self.assertIn("ConnectionError: refused", body)

        entry = state["Acme::Website"]
        self.assertEqual(entry["status"], "down")
        self.assertEqual(entry["consecutive_failures"], 1)

    def test_sustained_outage_stays_quiet(self):
        state = {}
        self.run_check(state, self.failure())
        for _ in range(5):
            up, email = self.run_check(state, self.failure())
            self.assertFalse(up)
            email.assert_not_called()

        self.assertEqual(state["Acme::Website"]["consecutive_failures"], 6)

    def test_recovery_alerts_once_with_downtime(self):
        state = {}
        self.run_check(state, self.failure())
        state["Acme::Website"]["since"] = (
            datetime.now(timezone.utc) - timedelta(hours=2)
        ).isoformat()

        up, email = self.run_check(state, self.success())
        self.assertTrue(up)
        email.assert_called_once()
        _, subject, body = email.call_args[0]
        self.assertIn("RECOVERED: Website", subject)
        self.assertIn("2h 0m", body)
        self.assertEqual(state["Acme::Website"]["status"], "up")
        self.assertEqual(state["Acme::Website"]["consecutive_failures"], 0)
        self.assertIsNone(state["Acme::Website"]["last_error"])

        # A second healthy check is silent.
        up, email = self.run_check(state, self.success())
        self.assertTrue(up)
        email.assert_not_called()

    def test_failed_recovery_email_is_retried_with_the_same_downtime(self):
        state = {}
        self.run_check(state, self.failure())
        state["Acme::Website"]["since"] = (
            datetime.now(timezone.utc) - timedelta(hours=2)
        ).isoformat()

        with patch("safeye.perform_check", return_value=self.success()), patch(
            "safeye.send_email", return_value=False
        ) as email:
            up = check_endpoint(make_config(), state)

        self.assertTrue(up)
        email.assert_called_once()
        entry = state["Acme::Website"]
        self.assertEqual(entry["status"], "up")
        self.assertIn("pending_recovery", entry)

        # The retry reports the outage it belongs to, not the time since.
        _, email = self.run_check(state, self.success())
        email.assert_called_once()
        _, subject, body = email.call_args[0]
        self.assertIn("RECOVERED: Website", subject)
        self.assertIn("2h 0m", body)
        self.assertIn("ConnectionError: refused", body)
        self.assertNotIn("pending_recovery", state["Acme::Website"])

        # And once it lands, the endpoint is quiet again.
        _, email = self.run_check(state, self.success())
        email.assert_not_called()

    def test_a_new_outage_cancels_an_undelivered_recovery(self):
        state = {}
        self.run_check(state, self.failure())
        with patch("safeye.perform_check", return_value=self.success()), patch(
            "safeye.send_email", return_value=False
        ):
            check_endpoint(make_config(), state)
        self.assertIn("pending_recovery", state["Acme::Website"])

        _, email = self.run_check(state, self.failure())
        self.assertIn("DOWN: Website", email.call_args[0][1])
        self.assertNotIn("pending_recovery", state["Acme::Website"])

    def test_up_since_is_recorded_and_preserved(self):
        state = {}
        self.run_check(state, self.success())
        first_since = state["Acme::Website"]["since"]
        self.assertIsNotNone(first_since)

        self.run_check(state, self.success())
        self.assertEqual(state["Acme::Website"]["since"], first_since)

        self.run_check(state, self.failure())
        self.run_check(state, self.success())
        self.assertNotEqual(state["Acme::Website"]["since"], first_since)

    def test_healthy_endpoint_never_emails(self):
        state = {}
        for _ in range(3):
            up, email = self.run_check(state, self.success())
            self.assertTrue(up)
            email.assert_not_called()

    def test_realert_reminder_when_enabled(self):
        self.set_module(REALERT_HOURS=1)
        state = {}
        self.run_check(state, self.failure())

        # Not yet due.
        _, email = self.run_check(state, self.failure())
        email.assert_not_called()

        state["Acme::Website"]["last_notified"] = (
            datetime.now(timezone.utc) - timedelta(hours=3)
        ).isoformat()
        _, email = self.run_check(state, self.failure())
        email.assert_called_once()
        self.assertIn("STILL DOWN", email.call_args[0][1])

    def test_alert_without_recipients_is_logged_only(self):
        state = {}
        up, email = self.run_check(state, self.failure(), make_config(notify_emails=[]))
        self.assertFalse(up)
        email.assert_not_called()
        self.assertEqual(state["Acme::Website"]["status"], "down")

    def test_dry_run_never_emails(self):
        state = {}
        up, email = self.run_check(state, self.failure(), dry_run=True)
        self.assertFalse(up)
        email.assert_not_called()
        self.assertEqual(state["Acme::Website"]["status"], "down")

    def test_failed_down_email_is_retried_next_cycle(self):
        state = {}
        config = make_config()
        with patch("safeye.perform_check", return_value=self.failure()), patch(
            "safeye.send_email", return_value=False
        ) as email:
            check_endpoint(config, state)
        email.assert_called_once()

        entry = state["Acme::Website"]
        self.assertEqual(entry["status"], "down")
        self.assertNotIn("last_notified", entry)

        # The outage is still unannounced, so the next cycle tries again.
        _, email = self.run_check(state, self.failure())
        email.assert_called_once()
        self.assertIn("DOWN: Website", email.call_args[0][1])
        self.assertIn("last_notified", state["Acme::Website"])

        # And once it lands, the retry stops.
        _, email = self.run_check(state, self.failure())
        email.assert_not_called()

    def test_failed_realert_is_retried_next_cycle(self):
        self.set_module(REALERT_HOURS=1)
        state = {}
        self.run_check(state, self.failure())
        stale = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        state["Acme::Website"]["last_notified"] = stale

        with patch("safeye.perform_check", return_value=self.failure()), patch(
            "safeye.send_email", return_value=False
        ):
            check_endpoint(make_config(), state)
        # Delivery failed, so the reminder is still due rather than deferred.
        self.assertEqual(state["Acme::Website"]["last_notified"], stale)

        _, email = self.run_check(state, self.failure())
        email.assert_called_once()
        self.assertIn("STILL DOWN", email.call_args[0][1])

    def test_a_new_outage_does_not_inherit_the_previous_notification(self):
        state = {}
        self.run_check(state, self.failure())
        self.run_check(state, self.success())

        with patch("safeye.perform_check", return_value=self.failure()), patch(
            "safeye.send_email", return_value=False
        ):
            check_endpoint(make_config(), state)

        self.assertNotIn("last_notified", state["Acme::Website"])

    def test_state_survives_a_restart(self):
        state = {}
        self.run_check(state, self.failure())
        save_state(state, self.path("state.json"))

        reloaded = load_state(self.path("state.json"))
        _, email = self.run_check(reloaded, self.failure())
        email.assert_not_called()


class TestTlsWarning(BaseTest):
    def test_warns_once_per_day_when_expiring(self):
        self.set_module(TLS_WARN_DAYS=14)
        state = {}
        result = CheckResult(ok=True, status_code=200, elapsed_ms=10.0, attempts=1)

        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.probe_tls_expiry", return_value=TlsProbe(3)
        ), patch("safeye.send_email", return_value=True) as email:
            check_endpoint(make_config(), state)
            self.assertIn("TLS certificate expires in 3 day(s)", email.call_args[0][1])
            email.reset_mock()

            check_endpoint(make_config(), state)
            email.assert_not_called()

    def test_silent_when_certificate_is_fresh(self):
        self.set_module(TLS_WARN_DAYS=14)
        result = CheckResult(ok=True, status_code=200, elapsed_ms=10.0, attempts=1)
        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.probe_tls_expiry", return_value=TlsProbe(200)
        ), patch("safeye.send_email") as email:
            check_endpoint(make_config(), {})
        email.assert_not_called()

    def test_warns_while_the_endpoint_is_failing(self):
        self.set_module(TLS_WARN_DAYS=14)
        failure = CheckResult(ok=False, error="SSLError: expired", attempts=1)

        with patch("safeye.perform_check", return_value=failure), patch(
            "safeye.probe_tls_expiry", return_value=TlsProbe(EXPIRED)
        ), patch("safeye.send_email", return_value=True) as email:
            check_endpoint(make_config(), {})

        subjects = [call[0][1] for call in email.call_args_list]
        self.assertIn("[Safeye] TLS certificate has expired: Website", subjects)
        self.assertIn("[Safeye] DOWN: Website", subjects)

    def test_handshake_happens_once_a_day_not_once_a_cycle(self):
        self.set_module(TLS_WARN_DAYS=14)
        state = {}
        result = CheckResult(ok=True, status_code=200, elapsed_ms=10.0, attempts=1)

        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.probe_tls_expiry", return_value=TlsProbe(200)
        ) as probe, patch("safeye.send_email"):
            for _ in range(3):
                check_endpoint(make_config(), state)

        probe.assert_called_once()
        self.assertIn("tls_checked_on", state["Acme::Website"])

    def test_unreachable_certificate_is_retried_next_cycle(self):
        self.set_module(TLS_WARN_DAYS=14)
        state = {}
        result = CheckResult(ok=True, status_code=200, elapsed_ms=10.0, attempts=1)

        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.probe_tls_expiry", return_value=TlsProbe(None, retryable=True)
        ) as probe, patch("safeye.send_email"):
            check_endpoint(make_config(), state)
            check_endpoint(make_config(), state)

        self.assertEqual(probe.call_count, 2)

    def test_unusable_certificate_marks_the_day_instead_of_reprobing(self):
        self.set_module(TLS_WARN_DAYS=14)
        state = {}
        result = CheckResult(ok=True, status_code=200, elapsed_ms=10.0, attempts=1)

        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.probe_tls_expiry", return_value=TlsProbe(None)
        ) as probe, patch("safeye.send_email") as email:
            for _ in range(3):
                check_endpoint(make_config(), state)

        probe.assert_called_once()
        email.assert_not_called()
        self.assertEqual(state["Acme::Website"]["tls_checked_on"], today())

    def test_warning_that_fails_to_send_is_retried_next_cycle(self):
        self.set_module(TLS_WARN_DAYS=14)
        state = {}
        result = CheckResult(ok=True, status_code=200, elapsed_ms=10.0, attempts=1)

        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.probe_tls_expiry", return_value=TlsProbe(3)
        ), patch("safeye.send_email", return_value=False):
            check_endpoint(make_config(), state)

        self.assertNotIn("tls_checked_on", state["Acme::Website"])

        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.probe_tls_expiry", return_value=TlsProbe(3)
        ), patch("safeye.send_email", return_value=True) as email:
            check_endpoint(make_config(), state)

        subjects = [call[0][1] for call in email.call_args_list]
        self.assertIn("[Safeye] TLS certificate expires in 3 day(s): Website", subjects)
        self.assertEqual(state["Acme::Website"]["tls_checked_on"], today())

    def test_dry_run_warning_still_covers_the_day(self):
        self.set_module(TLS_WARN_DAYS=14)
        state = {}
        result = CheckResult(ok=True, status_code=200, elapsed_ms=10.0, attempts=1)

        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.probe_tls_expiry", return_value=TlsProbe(3)
        ), patch("safeye.send_email") as email:
            check_endpoint(make_config(), state, dry_run=True)

        email.assert_not_called()
        self.assertEqual(state["Acme::Website"]["tls_checked_on"], today())

    def test_plain_http_never_opens_a_handshake(self):
        self.set_module(TLS_WARN_DAYS=14)
        result = CheckResult(ok=True, status_code=200, elapsed_ms=10.0, attempts=1)
        config = make_config(endpoint="http://example.com/health")

        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.probe_tls_expiry"
        ) as probe, patch("safeye.send_email"):
            check_endpoint(config, {})

        probe.assert_not_called()

    def test_expired_certificate_is_read_from_the_verification_error(self):
        error = ssl.SSLCertVerificationError("certificate has expired")
        error.verify_code = 10

        with patch("safeye.socket.create_connection"), patch(
            "safeye.ssl.create_default_context"
        ) as context:
            context.return_value.wrap_socket.side_effect = error
            self.assertEqual(probe_tls_expiry("https://example.com").days, EXPIRED)

    def test_other_verification_errors_return_none(self):
        error = ssl.SSLCertVerificationError("self signed certificate")
        error.verify_code = 18

        with patch("safeye.socket.create_connection"), patch(
            "safeye.ssl.create_default_context"
        ) as context:
            context.return_value.wrap_socket.side_effect = error
            probe = probe_tls_expiry("https://example.com")

        self.assertIsNone(probe.days)
        self.assertFalse(probe.retryable)

    def test_reads_certificate_expiry_from_the_socket(self):
        expires = datetime.now(timezone.utc) + timedelta(days=30)
        cert = {"notAfter": expires.strftime("%b %d %H:%M:%S %Y GMT")}

        with patch("safeye.socket.create_connection"), patch(
            "safeye.ssl.create_default_context"
        ) as context:
            tls_sock = context.return_value.wrap_socket.return_value.__enter__.return_value
            tls_sock.getpeercert.return_value = cert
            days = probe_tls_expiry("https://example.com").days

        self.assertIn(days, (29, 30))

    def test_certificate_without_expiry_returns_none(self):
        with patch("safeye.socket.create_connection"), patch(
            "safeye.ssl.create_default_context"
        ) as context:
            tls_sock = context.return_value.wrap_socket.return_value.__enter__.return_value
            tls_sock.getpeercert.return_value = {}
            self.assertIsNone(probe_tls_expiry("https://example.com").days)

    def test_unparseable_expiry_returns_none(self):
        with patch("safeye.socket.create_connection"), patch(
            "safeye.ssl.create_default_context"
        ) as context:
            tls_sock = context.return_value.wrap_socket.return_value.__enter__.return_value
            tls_sock.getpeercert.return_value = {"notAfter": "whenever"}
            probe = probe_tls_expiry("https://example.com")

        self.assertIsNone(probe.days)
        self.assertFalse(probe.retryable)

    def test_plain_http_has_no_certificate(self):
        self.assertIsNone(probe_tls_expiry("http://example.com").days)

    def test_unreachable_host_is_the_only_retryable_failure(self):
        with patch("safeye.socket.create_connection", side_effect=OSError("no route")):
            probe = probe_tls_expiry("https://example.com")

        self.assertIsNone(probe.days)
        self.assertTrue(probe.retryable)


class TestSendEmail(BaseTest):
    def test_sends_over_starttls(self):
        with patch("safeye.SMTP_USER", "user@example.com"), patch("smtplib.SMTP") as smtp:
            self.assertTrue(send_email(["a@example.com"], "Subject", "Body"))

        server = smtp.return_value.__enter__.return_value
        server.starttls.assert_called_once()
        server.login.assert_called_once()
        server.send_message.assert_called_once()

    def test_smtp_failure_is_swallowed(self):
        with patch("smtplib.SMTP", side_effect=OSError("connection refused")):
            self.assertFalse(send_email(["a@example.com"], "Subject", "Body"))

    def test_no_recipients(self):
        with patch("smtplib.SMTP") as smtp:
            self.assertFalse(send_email([], "Subject", "Body"))
        smtp.assert_not_called()


class TestExecuteRequests(BaseTest):
    def write_csv(self, rows):
        path = self.path("requests.csv")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("client;project_name;endpoint;expected_http_status;notify_emails\n")
            handle.writelines(rows)
        return path

    def test_cycle_summarises_and_persists(self):
        path = self.write_csv(
            [
                "Acme;Up Site;http://up.example.com;200;ops@example.com\n",
                "Acme;Down Site;http://down.example.com;200;ops@example.com\n",
            ]
        )

        def fake_check(config):
            if "down" in config["endpoint"]:
                return CheckResult(ok=False, error="boom", attempts=3)
            return CheckResult(ok=True, status_code=200, elapsed_ms=15.0, attempts=1)

        with patch("safeye.perform_check", side_effect=fake_check), patch(
            "safeye.send_email", return_value=True
        ) as email:
            summary = execute_requests(path)

        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["down"], ["Down Site"])
        email.assert_called_once()
        self.assertIn("DOWN: Down Site", email.call_args[0][1])

        with open(self.path("resume.log"), encoding="utf-8") as handle:
            line = handle.read()
        self.assertIn("2 analysed projects | 1 projects in alert", line)
        self.assertIn("down: Down Site", line)

        persisted = load_state(self.path("state.json"))
        self.assertEqual(persisted["Acme::Down Site"]["status"], "down")
        self.assertEqual(persisted["Acme::Up Site"]["status"], "up")

    def test_empty_config_is_not_an_error(self):
        path = self.write_csv([])
        summary = execute_requests(path)
        self.assertEqual(summary["total"], 0)
        self.assertEqual(summary["down"], [])

    def test_heartbeat_pinged_after_cycle(self):
        self.set_module(HEARTBEAT_URL="https://hc.example.com/ping")
        path = self.write_csv(["Acme;Up;http://up.example.com;200;ops@example.com\n"])
        result = CheckResult(ok=True, status_code=200, elapsed_ms=5.0, attempts=1)

        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.requests.get"
        ) as get:
            execute_requests(path)

        get.assert_called_once()
        self.assertEqual(get.call_args[0][0], "https://hc.example.com/ping")

    def test_heartbeat_failure_does_not_break_the_cycle(self):
        self.set_module(HEARTBEAT_URL="https://hc.example.com/ping")
        path = self.write_csv(["Acme;Up;http://up.example.com;200;ops@example.com\n"])
        result = CheckResult(ok=True, status_code=200, elapsed_ms=5.0, attempts=1)

        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.requests.get", side_effect=OSError("unreachable")
        ):
            summary = execute_requests(path)

        self.assertEqual(summary["total"], 1)

    def test_dry_run_leaves_no_state_behind(self):
        path = self.write_csv(["Acme;Down;http://down.example.com;200;ops@example.com\n"])
        result = CheckResult(ok=False, error="boom", attempts=1)

        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.send_email", return_value=True
        ) as email:
            execute_requests(path, dry_run=True)

        email.assert_not_called()
        self.assertFalse(os.path.exists(self.path("state.json")))

        # A real run afterwards still sees the transition and alerts.
        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.send_email", return_value=True
        ) as email:
            execute_requests(path)

        email.assert_called_once()
        self.assertIn("DOWN: Down", email.call_args[0][1])

    def test_dry_run_does_not_write_the_resume_log(self):
        path = self.write_csv(["Acme;Up;http://up.example.com;200;ops@example.com\n"])
        result = CheckResult(ok=True, status_code=200, elapsed_ms=5.0, attempts=1)

        with patch("safeye.perform_check", return_value=result):
            execute_requests(path, dry_run=True)

        self.assertFalse(os.path.exists(safeye.RESUME_LOG_FILE))

        with patch("safeye.perform_check", return_value=result):
            execute_requests(path)

        with open(safeye.RESUME_LOG_FILE, encoding="utf-8") as resume_log:
            self.assertEqual(len(resume_log.read().splitlines()), 1)

    def test_dry_run_does_not_ping_the_heartbeat(self):
        self.set_module(HEARTBEAT_URL="https://hc.example.com/ping")
        path = self.write_csv(["Acme;Up;http://up.example.com;200;ops@example.com\n"])
        result = CheckResult(ok=True, status_code=200, elapsed_ms=5.0, attempts=1)

        with patch("safeye.perform_check", return_value=result), patch(
            "safeye.requests.get"
        ) as get:
            execute_requests(path, dry_run=True)

        get.assert_not_called()

    def test_project_log_file_is_written(self):
        path = self.write_csv(["Acme;My Site;http://up.example.com;200;ops@example.com\n"])
        result = CheckResult(ok=True, status_code=200, elapsed_ms=5.0, attempts=1)
        with patch("safeye.perform_check", return_value=result):
            execute_requests(path)

        log_path = os.path.join(self.path("logs"), "My_Site.log")
        self.assertTrue(os.path.exists(log_path))
        with open(log_path, encoding="utf-8") as handle:
            self.assertIn("OK GET http://up.example.com", handle.read())


class TestMain(BaseTest):
    def test_once_runs_a_single_cycle(self):
        with patch("safeye.execute_requests", return_value={}) as run, patch(
            "safeye.time.sleep"
        ) as sleep:
            exit_code = safeye.main(["--once", "--config", "requests.csv"])

        self.assertEqual(exit_code, 0)
        run.assert_called_once_with("requests.csv", {}, False)
        sleep.assert_not_called()

    def test_dry_run_flag_is_passed_through(self):
        with patch("safeye.execute_requests", return_value={}) as run, patch(
            "safeye.time.sleep"
        ):
            safeye.main(["--once", "--dry-run"])
        self.assertTrue(run.call_args[0][2])

    def test_loop_sleeps_between_cycles_until_interrupted(self):
        with patch(
            "safeye.execute_requests", side_effect=[{}, KeyboardInterrupt]
        ) as run, patch("safeye.time.sleep") as sleep:
            self.assertEqual(safeye.main(["--interval", "60"]), 0)

        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once()
        self.assertLessEqual(sleep.call_args[0][0], 60)

    def test_keyboard_interrupt_exits_cleanly(self):
        with patch("safeye.execute_requests", side_effect=KeyboardInterrupt):
            self.assertEqual(safeye.main([]), 0)


if __name__ == "__main__":
    unittest.main()
