# Safeye — HTTP endpoint monitoring in one file

Safeye checks a list of HTTP endpoints on a schedule and emails you **when something changes** — not every time it looks. No database, no container, no dashboard: one Python file and a spreadsheet.

```bash
pip install -r requirements.txt
cp .env.example .env && cp requests.example.csv requests.csv
python safeye.py --once --dry-run
```

## Is this the right tool for you?

**Use Safeye if** you look after a handful of sites or APIs, you want the config to be a spreadsheet a non-developer can edit, and you'd rather drop a file on a box you already have than run another service.

**Use something else if** you want dashboards, status pages, historical graphs, or 20 notification integrations. [Uptime Kuma](https://github.com/louislam/uptime-kuma) and [Gatus](https://github.com/TwiN/gatus) are excellent and Safeye is not trying to compete with them. Safeye's only real advantage is that it's ~600 lines you can read in a sitting.

## What it does

- Checks endpoints **concurrently** with any HTTP method, custom headers, and JSON bodies.
- **Retries** transient failures with exponential backoff before declaring anything down.
- **Alerts only on state changes**: one email when an endpoint goes down, one when it recovers, silence in between. Optional reminders while an outage continues.
- Remembers state in `state.json`, so a restart doesn't re-alert you about a known outage.
- Fails a check on a **slow response**, not just a bad status code.
- Warns before an **HTTPS certificate expires**, and when one already has — including while the endpoint itself is failing.
- Pings a **dead man's switch** each cycle, so a Safeye that has crashed doesn't look like healthy endpoints.
- Writes a rotating log per project plus a one-line summary per cycle.

## Install

```bash
git clone https://github.com/rcpassos/safeye-script.git
cd safeye-script
pip install -r requirements.txt
```

Python 3.10 or newer.

## Configuration

### Settings

Copy `.env.example` to `.env` and edit. Every setting has a working default except SMTP; see the file for the full annotated list. The ones that matter most:

| Variable | Default | Meaning |
| --- | --- | --- |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | — | Where alerts are sent from. `SMTP_USER` empty means no login. |
| `SAFEYE_INTERVAL` | `300` | Seconds between cycles. |
| `SAFEYE_RETRY_ATTEMPTS` | `3` | Total attempts before declaring an endpoint down. |
| `SAFEYE_REALERT_HOURS` | `0` | Remind every N hours during an outage. `0` = alert once, then stay quiet. |
| `SAFEYE_TLS_WARN_DAYS` | `14` | Warn when a certificate expires within N days. `0` disables. |
| `SAFEYE_HEARTBEAT_URL` | — | Pinged after every cycle. See [Watching the watcher](#watching-the-watcher). |
| `SAFEYE_MAX_WORKERS` | `10` | Endpoints checked in parallel. |

### Endpoints

Copy `requests.example.csv` to `requests.csv`. It is semicolon-separated, UTF-8, and **gitignored** — it will usually hold API tokens, so keep it out of version control.

| Column | Required | Description |
| --- | --- | --- |
| `client` | no | Grouping label, shown in alerts. |
| `project_name` | no | Names the log file and the alert. Must be unique per client. |
| `endpoint` | **yes** | URL to request. Rows without one are skipped. |
| `expected_http_status` | no | `200`, or a list like `200,204`. Defaults to `200`. |
| `notify_emails` | no | Comma-separated. Empty means log-only. |
| `body_json` | no | JSON request body. |
| `headers_json` | no | JSON headers, e.g. `{"Authorization": "Bearer …"}`. |
| `http_method` | no | Defaults to `GET`. |
| `max_response_ms` | no | Fail the check if the response is slower than this. |

```csv
client;project_name;endpoint;expected_http_status;notify_emails;body_json;headers_json;http_method;max_response_ms
Acme Corp;Website Uptime;https://example.com/health;200;admin@example.com;;;GET;2000
Beta Inc;API Status;https://api.example.com/v1/status;200,204;support@example.com;;{"Authorization": "Bearer TOKEN"};GET;
```

A malformed row degrades rather than crashes: bad JSON is logged and ignored, and the rest of the file still runs.

## Usage

```bash
python safeye.py                 # run forever, one cycle per SAFEYE_INTERVAL
python safeye.py --once          # single cycle, then exit — for cron or systemd timers
python safeye.py --dry-run       # check everything, print alerts instead of emailing
python safeye.py --config other.csv --interval 60
```

`--dry-run` is the right way to validate a new config: it exercises every check and shows exactly which alerts would have gone out. It leaves no trace — `state.json` is not written and the heartbeat is not pinged — so a dry run can't swallow the next real alert.

**As a cron job** (state persists between runs, so alerting still works correctly):

```bash
*/5 * * * * cd /opt/safeye && /usr/bin/python3 safeye.py --once >> cron.log 2>&1
```

## How alerting works

Safeye keeps an up/down state per check in `state.json`:

| Previous | Now | Result |
| --- | --- | --- |
| up | up | silence |
| up | down | **DOWN** email |
| down | down | silence (or a **STILL DOWN** reminder if `SAFEYE_REALERT_HOURS` > 0) |
| down | up | **RECOVERED** email, including how long it was down |

An endpoint is only "down" after `SAFEYE_RETRY_ATTEMPTS` consecutive failures *within a single cycle*, so a one-off blip doesn't page anyone. Deleting `state.json` resets everything to "up".

A transition is only recorded as announced once the email actually leaves. If your SMTP server is down when an endpoint goes down, Safeye retries the DOWN email every cycle until it gets through, rather than falling silent for the rest of the outage — and likewise for RECOVERED, which keeps reporting the downtime of the outage it belongs to.

### Watching the watcher

If Safeye dies, silence looks exactly like everything being fine. Set `SAFEYE_HEARTBEAT_URL` to a check-in URL from a dead man's switch service such as [healthchecks.io](https://healthchecks.io) (free tier is plenty). Safeye pings it after each cycle, and the service alerts you when the pings stop. Without this, Safeye can only tell you about failures it is still alive to notice.

## Logs

```
logs/
├── Website_Uptime.log     # rotates at 1 MB, 5 backups kept
└── API_Status.log
resume.log                 # one line per cycle
state.json                 # current up/down state
```

```
2026-08-20T10:24:24 | 12 analysed projects | 1 projects in alert | down: API Status
```

Rotation is handled by `RotatingFileHandler`, so disk usage is bounded without any cleanup job.

## Tests

```bash
python -m unittest test_safeye.py
```

59 tests, 97% statement coverage — including every branch of the alerting state machine, retry exhaustion, alerts that fail to send and are retried, TLS expiry warnings, SMTP failure, and heartbeat failure. The 9 uncovered statements are environment-variable parsing fallbacks, the duplicate-key warning, one corrupt-timestamp guard, and the `__main__` line.

```bash
pip install coverage
coverage run --source=safeye -m unittest test_safeye.py && coverage report -m
```

## Scope

Deliberately **not** planned: a web dashboard, a database, a plugin system, a REST API. Each of those turns Safeye into a worse version of Uptime Kuma. The single-file, single-spreadsheet constraint is the point.

Plausible additions that keep that constraint: response-body assertions, a Slack/webhook notifier alongside email, and per-endpoint check intervals. Contributions welcome — fork, branch, PR.

## License

[MIT](LICENSE).

---

**Disclaimer:** Ensure you have permission to send requests to the endpoints you configure.
