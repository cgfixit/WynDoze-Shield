# WynDoze-InfoScanOverload

WynDoze-InfoScanOverload is a local inventory scanner for one operator. An agent reads names, ports, and account names on an endpoint. A loopback server scores that report with a YAML rule pack and stores the findings in SQLite. You work the results in a browser on the same machine. The agent does not call a vendor. The YAML rules are project-authored heuristics mapped to MITRE ATT&CK® techniques.

The desk is for judgment. Summary counts open the same triage and flagged set they display. The inbox is one card per finding. Flag returns to triage on the next matching scan. Archive and Suppress stay. Timeline lists scans. A scan page shows pattern names and a sealed-token count, and it does not print a command line. Exports are CSV, Markdown, JSON, and Sentinel NDJSON.

CGFixIT maintains this tree. It needs Python 3.12 or newer. The Windows operator guide is [user-guide.md](user-guide.md). The route list is [feature.map.md](feature.map.md).

## What the agent collects

The agent is read-only. It does not read file contents, and it does not scan the network. On Windows it collects processes, listening ports, services, installed software, and local administrator names. On macOS it collects processes and listening ports. Services, software, and local admin names stay empty on macOS. Those collectors run on Windows and on Linux.

Command lines are off. Pass `--cmdline` and set `RECON_AGENT_ENCRYPTION_KEY` when you want pattern names such as `encoded-powershell`. The agent replaces the line with a Fernet token before it writes or uploads the report. The dashboard does not decrypt that token.

Upload uses HTTPS, or HTTP only to `127.0.0.1` or `::1`. The agent ignores proxy environment variables. If `RECON_INGEST_TOKEN` or `RECON_DASHBOARD_PASSWORD` is unset or empty, that side returns 401. `RECON_HOST` accepts only `127.0.0.1` and `::1`. Set `RECON_AGENT_DISABLE=1` to exit before collection. Bodies over 8 MiB are rejected with 413.

Use the scanner only on systems you own or are authorized to assess. Inventory
can identify people and machines through usernames, hostnames, addresses, and
executable paths. Command lines are off by default; enabling them can capture
embedded credentials in the encrypted text, which anyone holding the key can
recover. Encryption is not anonymization or redaction.

The SQLite database and plain JSON/CSV/Markdown exports are not encrypted by
the application. Restrict access to them, use appropriate disk protection, and
set your own retention/deletion policy. Do not attach real inventory, keys, or
credentials to public issues. See [SECURITY.md](SECURITY.md) for private reporting.

## Install and start on Windows

`pyproject.toml` is the source of truth. `requirements.txt` and `constraints.txt` repeat the same floors. They are not a lock.

From the project root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[server,dev]"
$env:RECON_INGEST_TOKEN = "devtoken"
$env:RECON_DASHBOARD_PASSWORD = "devpassword"
.\.venv\Scripts\WynDoze-InfoScanOverload-server.exe
```

Or run `deploy\windows\Start-WynDoze.ps1`. That script installs the venv and opens a window with the same scan, start, and stop actions. Email alerts stay off until you check the box. A scheduled task from that window collects locally for the current user. It does not upload.

Open http://127.0.0.1:8000/ and sign in as `admin`. In a second shell, with the same venv:

```powershell
$env:RECON_AGENT_TOKEN = "devtoken"
.\.venv\Scripts\WynDoze-InfoScanOverload-agent.exe scan --server-url http://127.0.0.1:8000/api/scans --role workstation
```

Roles are `backup_server`, `proxy`, `repository`, `domain_controller`, `jumpbox`, `workstation`, and `other`. A successful upload prints `Upload OK`. The inbox is `/triage`. The database defaults to `%ProgramData%\WynDoze-InfoScanOverload\WynDoze-InfoScanOverload.sqlite3`.

[user-guide.md](user-guide.md) covers collect-only scans, the kill switch, cards, Suppress, bundles, and the optional daily task. `deploy/windows/Install-ReconAgentTask.ps1` registers that SYSTEM task only when you run the script. This tree does not register it for you.

## Install and start on macOS

From the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[server,dev]"
export RECON_INGEST_TOKEN=devtoken
export RECON_DASHBOARD_PASSWORD=devpassword
WynDoze-InfoScanOverload-server
```

In a second shell:

```bash
source .venv/bin/activate
export RECON_AGENT_TOKEN=devtoken
WynDoze-InfoScanOverload-agent scan --server-url http://127.0.0.1:8000/api/scans --role workstation
```

On macOS the database file is `WynDoze-InfoScanOverload.sqlite3` in the working directory. There is no Mac scheduled-task script in this tree. Linux unit files are in [deploy/systemd/](deploy/systemd/). Edit the paths inside those files before you install them.

## Keep a bundle

`--defer` is the default when a scan uploads. The Fernet key must already be set, or the agent exits 2 before it calls the server and writes no bundle. `--no-upload` does not require that key.

On Windows, generate a key and write a bundle:

```powershell
$env:RECON_AGENT_ENCRYPTION_KEY = .\.venv\Scripts\WynDoze-InfoScanOverload-agent.exe gen-key
.\.venv\Scripts\WynDoze-InfoScanOverload-agent.exe bundle --role workstation --cache-dir .\out
```

On macOS:

```bash
export RECON_AGENT_ENCRYPTION_KEY="$(WynDoze-InfoScanOverload-agent gen-key)"
WynDoze-InfoScanOverload-agent bundle --role workstation --cache-dir ./out
```

Move the `.WynDoze-InfoScanOverload-bundle` file to a machine that can reach the server. Replay it with the same key and `RECON_AGENT_TOKEN`. Store the key outside the repo. On Windows the cache directory defaults to `%ProgramData%\WynDoze-InfoScanOverload\cache`, and the bundle ACL keeps SYSTEM, Administrators, and the current user.

To score a saved report without the server:

```bash
WynDoze-InfoScanOverload-agent scan --no-upload --output-json report.json --role workstation
WynDoze-InfoScanOverload-agent evaluate-local report.json
```

Delete `report.json` when you are done. It contains host inventory.

## Configuration

Agent variables use the prefix `RECON_AGENT_`. Server variables use the prefix `RECON_`.

| Variable | Purpose |
|---|---|
| `RECON_AGENT_TOKEN` | Bearer token the agent sends |
| `RECON_AGENT_ENCRYPTION_KEY` | Fernet key for bundles and for `--cmdline` |
| `RECON_AGENT_DISABLE` | `1`, `true`, `yes`, or `on` exits before collection |
| `RECON_INGEST_TOKEN` | Required bearer token for `POST /api/scans` |
| `RECON_DASHBOARD_USER` | Basic-auth user. Default `admin` |
| `RECON_DASHBOARD_PASSWORD` | Required basic-auth password. Unset returns 401 |
| `RECON_DB_PATH` | SQLite path. Windows default is under ProgramData. Other systems default to `WynDoze-InfoScanOverload.sqlite3` in the working directory |
| `RECON_RULES_PATH` | Optional pack YAML. Unset uses the bundled pack |
| `RECON_HOST` | `127.0.0.1` or `::1`. Any other value exits 2 |
| `RECON_PORT` | Default `8000` |

## Rules and checks

The bundled pack is `windows-default`. It has 17 rules. The engine accepts 7 kinds. They are `listening_port`, `process_name`, `service_present`, `software_present`, `local_admin_unexpected`, `missing_expected_service`, and `cmdline_flag`. The bundled pack does not ship a `missing_expected_service` rule. A rule may set `roles` and `technique`. An unknown severity fails the pack load. The same host, rule, and evidence bump `seen_count` instead of opening a second card. The pack file is [windows_default.yaml](src/wyndoze_infoscanoverload/core/rulepacks/windows_default.yaml). Set `RECON_RULES_PATH` to use another file.

`GET /api/health` stays open and returns `{"status":"ok"}`. A finding post rejects a foreign `Origin`. The pages escape hostnames, titles, and evidence. The two commands are `WynDoze-InfoScanOverload-agent` and `WynDoze-InfoScanOverload-server`.

```bash
ruff check src tests
mypy src
pytest -q
```

The layout is `src/wyndoze_infoscanoverload/core` for rules, `agent` for collection, and `server` for the dashboard.

The project's code is available under the [MIT license](LICENSE), without
warranty. The static ATT&CK catalog includes third-party material covered by
[MITRE's notice and license](NOTICE.md), which also ships in built packages.
Dependencies retain their own licenses.

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.
This independently maintained project is not affiliated with or endorsed by
MITRE or any security/backup vendor. Its heuristic findings are leads for human
review, not MITRE-certified detections or proof of compromise.
