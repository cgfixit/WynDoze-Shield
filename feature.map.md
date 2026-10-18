# WynDoze-InfoScanOverload feature map

Reference for the working tree at version 1.0.0. Behavior below matches the code in this folder.

## Programs

| Program | Entry | Role |
|---|---|---|
| `WynDoze-InfoScanOverload-agent` | `wyndoze_infoscanoverload.agent.cli:main` | Collect, upload, bundle, replay, evaluate |
| `WynDoze-InfoScanOverload-server` | `wyndoze_infoscanoverload.server.__main__:main` | Loopback dashboard and ingest |

Agent commands are `scan`, `replay`, `bundle`, `evaluate-local`, `gen-key`, and `version`.

The source and installed Windows pack are identical v1.2 with 28 rules.
Windows admin display names retain a bounded `local_admin_sids` mapping;
the admin policy recognizes account-domain RIDs 500/512, rather than trusting
an arbitrary qualified account's basename. Windows service posture rules are
platform-scoped and empty service inventories do not prove a missing service.

## Server routes

| Route | Auth | Result |
|---|---|---|
| `GET /api/health` | none | 200 and `{"status":"ok"}` |
| `POST /api/scans` | bearer `RECON_INGEST_TOKEN` | 201, or 401, or 413 over 8 MiB, or 422 when the JSON is not a report |
| `GET /`, `/triage`, `/timeline`, `/endpoints`, `/reports/summary` | basic auth | HTML |
| `POST /findings/{id}/{action}` | basic auth, and a matching `Origin` when that header is present | 303, 403, or 404 |
| `GET /export/findings.{fmt}` | basic auth | `csv`, `md`, `json`, or `sentinel` |
| `/docs`, `/redoc`, `/openapi.json` | none | 404 |

Actions are `flag`, `archive`, `suppress`, and `triage`.

Finding tables use 50-row pages with stable severity/time/ID ordering. Optional
`hostname`, `rule_id`, `severity`, `status`, and `page` query parameters filter
`/triage` and `/timeline`; the inbox defaults to triage. `/findings/{id}` requires
dashboard authentication and shows complete escaped evidence and matching-scan
times. Invalid filter/page values return 422; absent findings return 404.
Repeated evidence preserves operator status; changed evidence creates a new row. Authenticated CSV, Markdown, JSON, and
Sentinel exports include all stored findings and are rendered in memory.

## Agent environment

| Name | Effect |
|---|---|
| `RECON_AGENT_TOKEN` | Bearer token for upload and replay |
| `RECON_AGENT_ENCRYPTION_KEY` | Fernet key. Required before upload when `--defer` is on, and required by `bundle` and `replay` |
| `RECON_AGENT_DISABLE` | `1`, `true`, `yes`, or `on` exits 0 before collection |

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

FastAPI telemetry flags are forced off inside `create_app`. `OTEL_SDK_DISABLED` is set to `true`.

## Limits

| Item | Limit |
|---|---|
| Ingest body | 8 MiB, then 413 |
| `scan_time_utc` | 64 characters |
| Short strings such as `exe` and `display_name` | 512 characters, clipped before the model is built |
| Process list | 5000 on the model. The agent default `process_limit` is 1000 |
| Opt-in command line | Patterns: first 800 characters. Encrypted prefix: at most 3000 UTF-8 bytes, ending on a character boundary; Fernet token fits 4096 characters |
| Software list | The agent default `software_limit` is 2000. The second registry hive is not read after the limit is full |
| Unknown model keys on platform, service, and software | Dropped |
| Unknown rule severity | `RuleError` at pack load. Observations still coerce unknown values to `info` |

## Collectors

Windows software comes from `reg.exe` with `/reg:64` and `/reg:32`, decoded as OEM text. Local administrators come from `Get-LocalGroupMember -SID S-1-5-32-544`. Service rows use the service name, display name, and status. Process command lines stay empty unless `--cmdline` or `RECON_AGENT_CMDLINE=1` is set. That mode requires `RECON_AGENT_ENCRYPTION_KEY`. The stored value is a Fernet token. Pattern names such as `encoded-powershell` are stored separately so the server can score them without the key.

## Not in this tree

There is no Docker deploy path in this tree. The Windows installer explicitly
registers a daily SYSTEM task with up to 30 minutes of trigger jitter when an
operator runs it. Its wrapper returns the agent exit code. Verification uses
synthetic state and mocked task registration; it does not install a task.
