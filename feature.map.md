# WynDoze-Shield feature map

Reference for the working tree at version 1.0.0. Behavior below matches the code in this folder.
The installed package, console scripts, and import path are named
`WynDoze-InfoScanOverload` / `wyndoze_infoscanoverload`; environment variables use `RECON_*`.

## Programs

| Program | Entry | Role |
|---|---|---|
| `WynDoze-InfoScanOverload-agent` | `wyndoze_infoscanoverload.agent.cli:main` | Collect, upload, bundle, replay, evaluate |
| `WynDoze-InfoScanOverload-server` | `wyndoze_infoscanoverload.server.__main__:main` | Loopback dashboard and ingest |
| `WynDoze-InfoScanOverload-desktop` | `wyndoze_infoscanoverload.desktop:main` | Windows window for scan, dashboard, schedule, and opt-in SMTP alerts |

Agent commands are `scan`, `replay`, `bundle`, `evaluate-local`, `gen-key`, and `version`.
`scan` and `replay` accept `--insecure` to skip TLS verification for testing only.

| Exit code | Meaning |
|---|---|
| 0 | Success, or `RECON_AGENT_DISABLE` set |
| 1 | `scan` upload failed with `--no-defer`; `replay` had a failed upload or an acknowledged bundle it could not delete |
| 2 | Missing or non-loopback HTTP `--server-url`, missing token, missing key, or unreadable report |
| 3 | `scan` upload failed and the report was deferred to an encrypted bundle |

The source and installed Windows pack are identical v1.5.
Windows admin display names retain a bounded `local_admin_sids` mapping;
the admin policy recognizes account-domain RIDs 500/512, rather than trusting
an arbitrary qualified account's basename. Windows service posture rules are
platform-scoped and empty service inventories do not prove a missing service.
Windows components match exact case-insensitive names; explicit product/custom
substring matching remains available. Stopped/missing Defender is advisory and
does not establish protection policy, active/passive state or tampering.

Command-line `all_flags`/`any_flags` conditions run within one process row; legacy
`names` rules retain host-union behavior. Five contextual rules cover sensitive-target
dumping, PowerShell download/execution, recovery deletion, event-log clearing and
autorun writes. Matching covers direct supported syntax, not arbitrary shell/script
semantics. Command text stays opt-in and sealed; labels are bounded to 32 per row
alongside PID/create_time. Six benign Windows profiles test command calibration.

## Server routes

| Route | Auth | Result |
|---|---|---|
| `GET /api/health` | none | 200 and `{"status":"ok"}` |
| `POST /api/scans` | bearer `RECON_INGEST_TOKEN` | 201, or 401, or 413 over 8 MiB, or 422 when the JSON is not a report |
| `GET /`, `/triage`, `/timeline`, `/endpoints`, `/reports/summary` | basic auth | HTML |
| `GET /findings/{id}` | basic auth | Complete escaped evidence and matching-scan times, or 404 |
| `GET /findings/{id}/suppress/confirm` | basic auth | HTML confirm page. Cancel does not write. Confirm posts `suppress`. |
| `GET /scans/{id}` | basic auth | HTML scan facts, or 404 when the scan is missing or unreadable |
| `POST /findings/{id}/{action}` | basic auth, and a matching `Origin` when that header is present | 303, 403, or 404 |
| `GET /export/findings.{fmt}` | basic auth | `csv`, `md`, `json`, or `sentinel` |
| `/docs`, `/redoc`, `/openapi.json` | none | 404 |

Actions are `flag`, `archive`, `suppress`, and `triage`. Suppress asks for
confirmation. Cards group low/info findings unless filtered. Timeline combines
paginated findings with the 100 most recent public scan summaries; a scan page
shows at most 500 findings last touched by that scan, with a cap notice.

Finding lists use 50-row pages with stable severity/time/ID ordering. Optional
`hostname`, `rule_id`, `severity`, `status`, and `page` query parameters filter
`/triage` and `/timeline`; `host` is a compatible alias for `hostname`.
`status=active` includes triage and flagged. The inbox defaults to triage.
Actions retain the current filters and page. `/findings/{id}` requires
dashboard authentication and shows complete escaped evidence and matching-scan
times. Invalid filter/page values return 422; absent findings return 404.
Repeated evidence preserves operator status; changed evidence creates a new row. Authenticated CSV, Markdown, JSON, and
Sentinel exports include all stored findings and are rendered in memory.
Markdown cells encode markup and flatten line breaks. Its evidence preview is
limited to 160 characters; JSON and Sentinel preserve complete evidence.

## Agent environment

| Name | Effect |
|---|---|
| `RECON_AGENT_TOKEN` | Bearer token for upload and replay |
| `RECON_AGENT_ENCRYPTION_KEY` | Fernet key. Required before upload when `--defer` is on, and required by `bundle` and `replay` |
| `RECON_AGENT_DISABLE` | `1`, `true`, `yes`, or `on` exits 0 before collection |
| `RECON_AGENT_CMDLINE` | `1`, `true`, `yes`, or `on` collects command lines like `--cmdline`; requires the key |

`scan --server-url` is required unless `--no-upload` is set. The default cache directory on Windows is `%ProgramData%\WynDoze-InfoScanOverload\cache`.

## Server environment

| Name | Default | Effect |
|---|---|---|
| `RECON_INGEST_TOKEN` | unset | Unset or empty means every ingest is 401 |
| `RECON_DASHBOARD_USER` | `admin` | Basic auth user |
| `RECON_DASHBOARD_PASSWORD` | unset | Unset or empty means every dashboard route is 401 |
| `RECON_DB_PATH` | `%ProgramData%\WynDoze-InfoScanOverload\WynDoze-InfoScanOverload.sqlite3` on Windows | SQLite path. Journal mode is WAL. Connect timeout is 30 seconds |
| `RECON_RULES_PATH` | bundled pack | YAML rule pack |
| `RECON_HOST` | `127.0.0.1` | Only `127.0.0.1` or `::1` |
| `RECON_PORT` | `8000` | Listen port |
| `RECON_STALE_AFTER_HOURS` | `36` | Endpoint collection age (1–8760) after which it is overdue |
| `RECON_LOG_LEVEL` | `info` | Uvicorn log level |

Startup creates a missing database parent privately and preserves existing directory
permissions. Server/development FastAPI floors are 0.143.0.

FastAPI telemetry flags are forced off inside `create_app`. `OTEL_SDK_DISABLED` is set to `true`.

## Desktop and optional mail

`deploy/windows/Start-WynDoze.ps1` creates `.venv` with `py -3.12`, installs the
`server` extra, and starts the launcher. The Tk launcher generates per-window credentials and exposes the password as a
selectable read-only field, and opens `documentation.pdf` from the project root on request. Its current-user `WynDoze-InfoScanOverload-scan` task
collects locally without upload. The separate SYSTEM installer is
`deploy/windows/Install-ScanneragentTask.ps1`, default task `ScanzAgentDailyScan`.
It accepts Scanz credential aliases (preferred) or RECON inputs and writes
canonical `RECON_AGENT_*` keys. Its task action runs `powershell.exe` with
`-ExecutionPolicy RemoteSigned` (process scope; Group Policy still applies).
Systemd uses those same canonical keys.

`RECON_ALERTS=1` enables SMTP only with `RECON_SMTP_HOST`, `RECON_SMTP_USER`,
`RECON_SMTP_PASSWORD`, and `RECON_ALERT_TO`. `RECON_SMTP_PORT` defaults to 587
(STARTTLS); 465 uses TLS. Mail contains hostname and up to 40 finding summaries
per accepted scan, including repeats. Delivery runs in a worker after the 201
response and is best-effort, without durable retries. Header/SMTP failures are
logged without changing the persisted scan. No raw command lines are included.

## Limits

| Item | Limit |
|---|---|
| Ingest body | Authenticate first; count streamed bytes before retaining them; 413 at the first chunk crossing 8 MiB |
| `scan_time_utc` | 64 characters |
| Short strings such as `exe` and `display_name` | 512 characters, clipped before the model is built |
| Process list | 5000 on the model. The agent default `process_limit` is 1000 |
| Opt-in command line | Patterns: first 800 characters. Encrypted prefix: at most 3000 UTF-8 bytes, ending on a character boundary; Fernet token fits 4096 characters |
| Software list | The agent default `software_limit` is 2000. The second registry hive is not read after the limit is full |
| Unknown model keys on platform, service, and software | Dropped |
| Unknown rule severity | `RuleError` at pack load. Observations still coerce unknown values to `info` |

## Collection health

`collection_health` is optional on the wire (at most six collectors). New agents
report ok/partial/unavailable/failed, item count, duration_ms, truncated and up to
eight fixed issue categories. Legacy reports retain unknown coverage. Endpoints
show collection and receipt times separately; age defaults to 36 hours via
`RECON_STALE_AFTER_HOURS`. No finding is automatically resolved from missing data.
Missing-service checks skip explicitly incomplete service inventories.

## Collectors

Windows software comes from `reg.exe` with `/reg:64` and `/reg:32`, decoded as OEM text. Local administrators come from `Get-LocalGroupMember -SID S-1-5-32-544`. Service rows use the service name, display name, and status. Process command lines stay empty unless `--cmdline` or `RECON_AGENT_CMDLINE=1` is set. That mode requires `RECON_AGENT_ENCRYPTION_KEY`. The stored value is a Fernet token. Pattern names such as `encoded-powershell` are stored separately so the server can score them without the key.

Listener evidence retains address, scope, PID and observed process name. Loopback-only
severity is info; mixed bindings keep the higher assessment. RDP has one role-adjusted
rule. A local listener does not establish external reachability or protocol identity.
Changed PID/owner evidence can create a fresh triage row; identical evidence retains
the analyst decision.

## Not in this tree

There is no Docker deploy path in this tree. The Windows installer explicitly
registers a daily SYSTEM task with up to 30 minutes of trigger jitter when an
operator runs it. Its wrapper returns the agent exit code. Verification uses
synthetic state and mocked task registration; it does not install a task.
