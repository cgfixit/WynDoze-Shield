# WynDoze-Shield

A self-hosted agent and dashboard for endpoint inventory. Lightweight agents
collect local telemetry. A loopback server evaluates project-authored heuristics
mapped to MITRE ATT&CK® techniques. An analyst reviews the findings in a triage inbox.
 Designed for **Windows 10, Windows 11,
and Windows Server 2016, 2019, 2022, and 2025**, with **Python 3.12+**.
These are compatibility targets; native acceptance on each OS is still required.

---

## What it does

- **Agents** run on each endpoint (backup server, proxy, repository, DC,
  jumpbox, workstation), collect read-only telemetry, and upload it over HTTPS
  with a bearer token — or defer to an **encrypted local bundle** when the
  machine is isolated or the server is unreachable.
- **The server** (FastAPI + SQLite) ingests reports, runs a **declarative YAML
  rules engine** against each one, and records findings. A dark-themed dashboard
  gives you a **Triage Inbox**, a **Timeline**, an **Endpoints** registry, and a
  **Summary** report, plus exports to **CSV / Markdown / JSON / Microsoft
  Sentinel** (NDJSON).
- Findings carry a lifecycle: `triage → flagged / archived / suppressed`, and
  are deduplicated per (host, rule, evidence) so recurring conditions bump a
  `seen_count` instead of spamming the inbox.

Dashboard finding tables show 50 rows per page, with host, severity, status, and
rule filters. Finding titles open complete escaped evidence and matching-scan times. CSV, Markdown, JSON, and Sentinel
exports include every stored finding, including archived and suppressed rows.
Full exports are rendered in memory, so their memory use grows with the result set.
Exports include all stored findings regardless of the current dashboard filters.
Page numbers start at 1; invalid page or filter values return HTTP 422.
Recurring identical evidence preserves flagged, archived, and suppressed decisions;
changed evidence creates a separate finding for review.

### What it deliberately does **not** do

- No file *contents* are ever read — only metadata (names, ports, service
  states, package names, admin account names).
- No credential-store collection. Opt-in command lines can contain secrets;
  retained lines are encrypted, not redacted.
- No active network scanning — only local listening-socket state.
- No outbound cloud calls except the single HTTPS upload to *your* server.

---

## Security posture

| Concern | Design |
|---|---|
| Agent → server auth | Bearer token (`RECON_INGEST_TOKEN`), constant-time compared |
| Dashboard auth | HTTP Basic (`RECON_DASHBOARD_PASSWORD`); front with SSO/proxy in prod |
| Data at rest (deferred) | Fernet encrypted bundles. The Windows task stores the key in an ACL'd env file, not Machine environment. |
| Stored XSS | All telemetry HTML-escaped before rendering |
| Command execution | `subprocess` list-args only, never `shell=True`. Hard timeouts. |
| Rule packs | Pure data via `yaml.safe_load`. Unknown severity fails the pack load. |
| Transport | HTTPS, or HTTP only to `127.0.0.1` or `::1`. `httpx` ignores proxy env. |
| Ingest size | Bodies larger than 8 MiB are rejected with 413 before SQLite writes. |
| Process command lines | Off by default. Opt-in lines require a key and are sealed before storage/upload; patterns inspect at most 800 characters, and encrypted text is limited to 3000 UTF-8 bytes on a character boundary. |

If `RECON_INGEST_TOKEN` or `RECON_DASHBOARD_PASSWORD` is unset or empty, that
endpoint returns 401. The server logs a warning at startup. There is no
unauthenticated dev mode. Set `RECON_AGENT_DISABLE=1` to exit the agent before
collection or upload. `RECON_HOST` accepts only `127.0.0.1` and `::1`.

Use the scanner only on systems you own or are authorized to assess. Inventory
can identify people and machines through usernames, hostnames, addresses, and
executable paths. Command lines are off by default; enabling them can capture
embedded credentials in the encrypted text, which anyone holding the key can
recover. Encryption is not anonymization or redaction.

The SQLite database and plain JSON/CSV/Markdown exports are not encrypted by
the application. Restrict access to them, use appropriate disk protection, and
set your own retention/deletion policy. Do not attach real inventory, keys, or
credentials to public issues. See [SECURITY.md](SECURITY.md) for private reporting.

---

## Install

```bash
# From the project root, using uv (recommended):
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e ".[server,dev]"     # server + dev tooling
# Agents only need the base install:
uv pip install .
```

On the Windows targets above, `pyproject.toml` stays the source of truth.
The commands below use Python 3.12, the minimum supported version.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[server,dev]"
```

`requirements.txt` and `constraints.txt` repeat those floors. They are not a lock.

Two console scripts are installed:

- `WynDoze-InfoScanOverload-agent` — the endpoint agent CLI
- `WynDoze-InfoScanOverload-server` — the dashboard server (uvicorn wrapper)

---

## Quick start

**1. Start the server** on loopback. Both secrets are required:

```bash
export RECON_INGEST_TOKEN=devtoken
export RECON_DASHBOARD_PASSWORD=devpassword
WynDoze-InfoScanOverload-server                     # listens on 127.0.0.1:8000
# open http://127.0.0.1:8000/ and sign in as admin
```

**2. Run an agent scan** against it:

```bash
export RECON_AGENT_TOKEN=devtoken           # must match RECON_INGEST_TOKEN
export RECON_AGENT_ENCRYPTION_KEY=$(WynDoze-InfoScanOverload-agent gen-key)
WynDoze-InfoScanOverload-agent scan --server-url http://127.0.0.1:8000/api/scans --role backup_server
```

**3. Work findings** in the Triage Inbox at `/triage`.

### Isolated / air-gapped machines

```bash
# On the isolated host — write an encrypted bundle, no network:
export RECON_AGENT_ENCRYPTION_KEY=$(WynDoze-InfoScanOverload-agent gen-key)   # store this key safely
WynDoze-InfoScanOverload-agent bundle --role repository --cache-dir ./out

# Move ./out/*.WynDoze-InfoScanOverload-bundle to a jumpbox with the same key, then:
export RECON_AGENT_ENCRYPTION_KEY=<same key>
export RECON_AGENT_TOKEN=<server token>
WynDoze-InfoScanOverload-agent replay --server-url https://recon.internal/api/scans --cache-dir ./out
```

Replay deletes a bundle only after HTTP 201 with an `accepted` acknowledgement,
a positive scan ID, and the matching hostname. Redirects and malformed responses
retain the bundle. Corrupt or unreadable bundles are reported individually while
later valid bundles continue; any failure makes replay exit 1. Each save uses an
exclusive filename so rapid scans cannot overwrite one another. `replay --keep`
retains acknowledged bundles too.

### Evaluate a report locally (no server)

```bash
WynDoze-InfoScanOverload-agent scan --no-upload --output-json report.json --role backup_server
WynDoze-InfoScanOverload-agent evaluate-local report.json          # prints findings as JSON
```

---

## Configuration

All configuration is environment-driven (Pydantic Settings).

### Agent (`RECON_AGENT_*`)

| Variable | Purpose |
|---|---|
| `RECON_AGENT_TOKEN` | Bearer token presented to the server |
| `RECON_AGENT_ENCRYPTION_KEY` | Fernet key for deferred/isolated bundles |
| `RECON_AGENT_DISABLE` | Set to `1` to exit before collection or upload |

### Server (`RECON_*`)

| Variable | Default | Purpose |
|---|---|---|
| `RECON_DB_PATH` | `WynDoze-InfoScanOverload.sqlite3` | SQLite database path |
| `RECON_INGEST_TOKEN` | *(unset)* | Required bearer token for `/api/scans` |
| `RECON_DASHBOARD_USER` | `admin` | Basic-auth username |
| `RECON_DASHBOARD_PASSWORD` | *(unset)* | Required basic-auth password. Unset returns 401. |
| `RECON_RULES_PATH` | *(bundled)* | Override rule pack YAML |
| `RECON_HOST` / `RECON_PORT` | `127.0.0.1` / `8000` | Bind address. Only `127.0.0.1` and `::1` are accepted. |

---

## Rules engine

Rules are declarative YAML. The source and bundled pack (`windows-default`, v1.2)
ship the same **28 rules** (CI checks the two copies byte-for-byte) across **7 rule kinds**. Command lines stay empty unless
`--cmdline` is set, and then they are stored as Fernet tokens.

Supported rule kinds:

| Kind | Fires when |
|---|---|
| `listening_port` | A listed port is listening locally |
| `process_name` | A process matching a listed name is running |
| `service_present` | A service matching a substring exists (optional state filter) |
| `software_present` | Installed software matches a substring |
| `local_admin_unexpected` | A local admin not on the allow-list is present |
| `missing_expected_service` | An expected service is absent |
| `cmdline_flag` | An opted-in command line produced a matching pattern label; the server uses the label rather than decrypting text |

Every rule may declare `roles:` (scope to endpoint roles) and `technique:`
(a MITRE ATT&CK id).

Rules can also declare `platforms:`; the Windows service posture rules apply
only to Windows and those missing-service checks require a nonempty service inventory.
Process/service presence is a review hint, not proof of malicious behavior.
Recovery utilities and an idle Windows Update service are low-severity hints;
short tunnel software names use whole-name matching to reduce incidental hits.

Windows reports retain administrator display names and add a bounded
`local_admin_sids` mapping. The bundled admin rule accepts account-domain RIDs
500 (built-in Administrator, including renamed/localized accounts) and 512
(Domain Admins), plus its explicit name allowlist. A qualified name alone is
never stripped to a trusted basename. Older reports without SIDs still use
explicit name matches; tune qualified allowlist entries for other approved accounts.

Example:

```yaml
name: windows-default
version: "1.0"
rules:
  - id: proc-credential-dumping
    kind: process_name
    title: Credential-dumping tool detected
    severity: critical
    technique: T1003
    names: [mimikatz.exe, procdump.exe, secretsdump.py]
```

Point the server at a custom pack with `RECON_RULES_PATH=/path/to/pack.yaml`,
or evaluate with `WynDoze-InfoScanOverload-agent evaluate-local report.json --rules pack.yaml`.

---

## Deployment

See [`deploy/`](deploy/):

- **Linux (systemd):** `deploy/systemd/WynDoze-InfoScanOverload-agent.{service,timer}` — a hardened
  daily one-shot timer. Copy secrets to `/etc/recon/agent.env` (see
  `deploy/agent.env.example`).
- **Windows:** `deploy/windows/Install-ReconAgentTask.ps1` registers a daily
  SYSTEM task when you run it. It copies the session token and key into
  `C:\ProgramData\WynDoze-InfoScanOverload\agent.env` and locks that file to SYSTEM and
  Administrators. This tree does not register the task for you.
  The dashboard database defaults to `C:\ProgramData\WynDoze-InfoScanOverload\WynDoze-InfoScanOverload.sqlite3`.
  Use the installed agent `.exe` shim for `-PythonExe`. The daily trigger adds
  up to 30 minutes of random delay. The UTF-8 wrapper quotes paths and passes
  the agent exit code to Task Scheduler; ACL failures stop installation.

Operator guides: [user-guide.md](user-guide.md) and [feature.map.md](feature.map.md).

Put the server behind a TLS-terminating reverse proxy in production.

---

## Development

```bash
ruff check src tests        # lint (ruff "ALL" ruleset)
ruff format src tests       # format
mypy src                    # strict type check
pytest -q                   # unit + integration tests
```

Project layout:

```
src/wyndoze_infoscanoverload/
├── core/         # domain: models, severity, MITRE catalog, rules engine
│   └── rulepacks/  # bundled YAML rule packs
├── agent/        # collectors, encrypted cache, uploader, Typer CLI
└── server/       # FastAPI app, SQLite storage, HTML templates, exports
```

---

## License / status

The project's code is available under the [MIT license](LICENSE), without
warranty. The static ATT&CK catalog includes third-party material covered by
[MITRE's notice and license](NOTICE.md), which also ships in built packages.
Dependencies retain their own licenses.

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.
This independently maintained project is not affiliated with or endorsed by
MITRE or any security/backup vendor. Its heuristic findings are leads for human
review, not MITRE-certified detections or proof of compromise.
