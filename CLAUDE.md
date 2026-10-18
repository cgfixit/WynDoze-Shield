# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

WynDoze-InfoScanOverload is a single-operator, loopback-only endpoint inventory scanner. Three console scripts ship from one package (`src/wyndoze_infoscanoverload`):

- `WynDoze-InfoScanOverload-agent` (`agent/cli.py`) collects read-only metadata (processes, listening ports, services, software, local admins) and uploads a JSON `ScanReport`, or writes a Fernet-encrypted bundle.
- `WynDoze-InfoScanOverload-server` (`server/__main__.py`) is a FastAPI app on `127.0.0.1:8000` that scores each report with a YAML rule pack, stores findings in SQLite, and serves a server-rendered triage dashboard.
- `WynDoze-InfoScanOverload-desktop` (`desktop.py`) is a Tkinter window for Windows that wraps the two above plus a current-user `schtasks` schedule and opt-in SMTP alerts.

Read `README.md`, `user-guide.md`, and `feature.map.md` before changing behavior. `feature.map.md` is the route/env/limit reference and also records what this tree deliberately does *not* ship (Docker, a git remote, an executed task script). Do not re-add those as features.

## Commands

Use the project venv at `.venv/` (Python 3.12). On Windows call `.venv\Scripts\python.exe`; the commands below assume the venv is active.

```bash
python -m pip install -e ".[server,dev]"   # pyproject.toml is the source of truth; requirements/constraints are floors, not a lock

pytest -q                                   # full suite (unit + integration, ~150 tests)
pytest tests/unit/test_rules.py -q          # one file
pytest tests/integration/test_server.py -q -k suppress   # one test by keyword

ruff check src tests                        # select = ALL, line-length 100; CI-equivalent lint
ruff format --check src tests
mypy src                                    # strict, pydantic plugin
```

Run the server locally (both secrets are required or every route returns 401):

```bash
export RECON_INGEST_TOKEN=devtoken RECON_DASHBOARD_PASSWORD=devpassword
WynDoze-InfoScanOverload-server
# second shell
export RECON_AGENT_TOKEN=devtoken
WynDoze-InfoScanOverload-agent scan --server-url http://127.0.0.1:8000/api/scans --role workstation
```

Agent subcommands: `scan`, `bundle`, `replay`, `evaluate-local`, `gen-key`, `version`. `scan --no-upload --output-json report.json` then `evaluate-local report.json` scores without a server. Delete that JSON afterwards; it is host inventory.

Test notes: `asyncio_mode = auto`, `--strict-markers`. The `integration` marker is declared in `pyproject.toml` but no test currently carries it; integration tests are selected by path (`tests/integration/`). Fixtures `backup_server_report`, `clean_report`, and `tmp_db` live in `tests/conftest.py`. Server tests build the app with `create_app(ServerConfig(...))` and `TestClient`; they never touch the ProgramData database.

## Architecture

### Data flow

```
agent/collectors.collect_report  -> ScanReport (core/models)
  -> agent/cmdline.seal_command_lines (only with --cmdline + Fernet key)
  -> agent/uploader.upload_report  (https anywhere; http only to 127.0.0.1/::1)
     or agent/cache.BundleCache     (encrypted .WynDoze-InfoScanOverload-bundle)
server/app POST /api/scans
  -> ScanReport.model_validate_json (8 MiB cap, 413 above)
  -> core/rules.evaluate(report, pack) -> list[Finding]
  -> server/storage.record_scan       (scans + endpoints upsert + findings upsert)
  -> alerts.notify_findings           (no-op unless RECON_ALERTS is on)
```

`core/` is the shared contract and has no agent or server imports. `agent/` and `server/` both depend on `core/` and never on each other.

### Rules engine (`core/rules.py`)

Rule packs are pure YAML data loaded with `yaml.safe_load`. Valid kinds are the `_VALID_KINDS` frozenset; each kind has one evaluator in `_EVALUATORS`. Unknown kind, unknown severity, duplicate id, or unknown role raises `RuleError` at load time. Rules may be scoped with `roles` and tagged with a MITRE `technique`, resolved against the tiny static catalog in `core/mitre.py`. `evaluate` returns findings sorted by severity rank then rule id.

The bundled pack exists in two identical copies and must be edited together in one commit: `src/wyndoze_infoscanoverload/core/rulepacks/windows_default.yaml` (shipped in the wheel, loaded by `default_rule_pack()`) and `rules/windows_default.yaml` (operator copy). `RECON_RULES_PATH` overrides the bundled pack.

### Finding lifecycle (`server/storage.py`, `server/desk.py`)

`findings.dedupe_key` is `hostname::rule_id::sorted(evidence)` (`core/models.dedupe_key`). A re-ingest of the same evidence does an `ON CONFLICT` upsert: `seen_count` increments, `last_seen_utc` and `scan_id` move forward, and status resets to `triage` **unless** it is `archived` or `suppressed`. That is why Flag does not stick across scans but Archive and Suppress do. Statuses are the `FindingStatus` enum; `active` is a desk query word only, never stored.

`desk.py` is the single parse point for `?status=&severity=&host=` and for the `next` return path. `safe_next` allowlists exact paths (`/`, `/triage`, `/timeline`, `/endpoints`, `/reports/summary`, `/scans/<digits>`) and rebuilds the query from allowlisted keys; anything else falls back to `/triage`. Keep new redirect targets inside that allowlist.

### Server security posture (`server/app.py`)

- Two fail-closed auth domains: bearer `RECON_INGEST_TOKEN` for ingest, HTTP Basic `RECON_DASHBOARD_USER`/`RECON_DASHBOARD_PASSWORD` for everything HTML. Unset or empty secret means 401 for that whole domain. Compares use `secrets.compare_digest` via `_const_eq`.
- `GET /api/health` is the only open route. `docs_url`, `redoc_url`, `openapi_url` are `None`; FastAPI telemetry is forced off and `OTEL_SDK_DISABLED=true` is set inside `create_app`. Keep it that way.
- `POST /findings/{id}/{action}` rejects a present `Origin` whose host is not this server (`_reject_foreign_origin`); a missing `Origin` passes because that is how the local form posts. Action body is capped at 2048 bytes.
- `server/__main__.py` exits 2 unless `RECON_HOST` is `127.0.0.1` or `::1`. `agent/uploader.assert_upload_url` is the mirror check on the client side.
- HTML is built in `server/templates.py` as pure functions with `html.escape` on every dynamic value, served with a strict CSP (`script-src 'none'`). There are no template files and no JavaScript. `tests/unit/test_templates_safe.py` guards this.
- `server/present.public_scan_facts` is the only path from stored raw scan JSON to a page. It emits counts and pack-allowed pattern names only; a command line never reaches HTML.

### Command lines and sealing (`agent/cmdline.py`)

Process command lines are off by default and `cmdline` is `None`. With `--cmdline` (or `RECON_AGENT_CMDLINE=1`) the agent also requires `RECON_AGENT_ENCRYPTION_KEY`; it regex-matches `_FLAG_PATTERNS` in memory, records only the pattern names in `report.cmdline_flags`, and replaces each line with a Fernet token before anything is written or uploaded. The server scores `cmdline_flag` rules from the names and never decrypts. `_PLAIN_MAX` (800) exists so the token fits the 4096-char model field.

### Agent exit codes and defer behavior (`agent/cli.py`)

`RECON_AGENT_DISABLE` set to `1/true/yes/on` exits 0 before collection. `--defer` is on by default for `scan`; the Fernet key must be set up front or the agent exits 2 before contacting the server. `bundle` and `replay` always need the key. Secrets are read from env only (`TOKEN_ENV`, `KEY_ENV`), never from CLI flags or files.

### Desktop launcher (`desktop.py`)

Builds argv lists for `subprocess` (`scan_argv`, `schtasks_create_argv`, `schtasks_delete_argv`) and keeps them as pure functions so tests cover them without Tkinter. It generates the dashboard password per process, registers only a current-user task named `WynDoze-InfoScanOverload-scan` that runs `scan --no-upload`, and never writes Machine env vars. The separate admin SYSTEM task path is `deploy/windows/Install-ReconAgentTask.ps1`, which this tree documents but does not run.

## Constraints to preserve

These come from `.agents/skills/wyndozescan-optimizer/SKILL.md` and the design above. They are invariants, not preferences.

- Loopback only: no listener and no `http` upload to any host other than `127.0.0.1` or `::1`.
- No telemetry export, no OpenAPI/docs routes, no dependency that sends data off the machine.
- Collectors stay metadata-only: never read file contents, collect credentials, scan the network, or store a raw command line.
- Do not raise `_MAX_INGEST_BYTES`, the model `max_length` caps, or the `AgentConfig` collector limits without a measurement.
- `yaml.safe_load` only; `subprocess` with argv lists only, never `shell=True`.
- Do not add a new rule kind or rename the `recon` substring. `RECON_*` env names, task `ReconAgentDailyScan`, `User=recon`, and the `/opt/recon`, `/etc/recon`, `/var/lib/recon` paths in `deploy/systemd/` are load-bearing.
- Never run `Install-ReconAgentTask.ps1`, scan a live workstation for a PR, or paste inventory, tokens, or bundle bytes into chat or a commit. `*.sqlite3*`, `*.WynDoze-InfoScanOverload-bundle`, `agent.env`, and `last-scan.json` are gitignored for that reason.

## Repo conventions

- Version is `__version__` in `src/wyndoze_infoscanoverload/_version.py` (hatch dynamic version).
- Pydantic v2 everywhere; nested telemetry models use `extra="ignore"` so a newer agent does not hard-fail an older server. Envelope fields on `ScanReport` stay strict.
- Imports used only in annotations stay out of `TYPE_CHECKING` blocks in model and route code (ruff `TC00x` are ignored for this reason).
- CI is `.github/workflows/ci.yml`: a lint job (`ruff check`, `ruff format --check`, `mypy src`) on Ubuntu and a pytest job on Ubuntu and Windows with `--cov-fail-under=80`. No PR template exists. Work on a prefixed branch (`grok/`, `claude/`, `codex/`, `kimi/`), never commit to `main`, open PRs as draft, one concern per PR. Before a PR run the same four commands locally and state what was not run.
- Line endings are normalized by `.gitattributes` (LF in the repo, `.ps1` as CRLF). Do not commit `documentation.pdf`, database files, or anything under `*.old`; the launcher opens the PDF from the project folder when the operator drops one there.
