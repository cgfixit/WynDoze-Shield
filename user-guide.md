# Use WynDoze-InfoScanOverload on Windows

This guide is for an operator on Windows 10 or Windows 11 with Python 3.12. It gets a loopback dashboard and one agent scan running. It does not register a scheduled task unless you run that script yourself.

The product is an internal scanner.

## Install

From the project root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[server,dev]"
```

`pyproject.toml` is the source of truth. `requirements.txt` and `constraints.txt` repeat the same floors. They are not a lock.

You should see `WynDoze-InfoScanOverload-agent.exe` and `WynDoze-InfoScanOverload-server.exe` under `.venv\Scripts`.

## Start the dashboard

Set both secrets. An unset or empty value returns 401.

```powershell
$env:RECON_INGEST_TOKEN = "devtoken"
$env:RECON_DASHBOARD_PASSWORD = "devpassword"
.\.venv\Scripts\WynDoze-InfoScanOverload-server.exe
```

The process listens on `127.0.0.1:8000`. Open `http://127.0.0.1:8000/` and sign in as `admin` with the dashboard password. `GET /api/health` stays open and returns `{"status":"ok"}`.

`RECON_HOST` accepts only `127.0.0.1` and `::1`. Any other host exits 2.

## Scan an endpoint

In a second shell, with the venv active:

```powershell
$env:RECON_AGENT_TOKEN = "devtoken"
.\.venv\Scripts\WynDoze-InfoScanOverload-agent.exe scan --server-url http://127.0.0.1:8000/api/scans --role workstation
```

HTTP is allowed only for `127.0.0.1` and `::1`. Every other host needs `https`. The agent ignores proxy environment variables.

A successful upload prints `Upload OK`. The Triage Inbox at `/triage` lists the findings.

To collect without uploading:

```powershell
.\.venv\Scripts\WynDoze-InfoScanOverload-agent.exe scan --no-upload --output-json .\report.json --role workstation
```

Delete `report.json` when you are done. It contains host inventory. Every process row has `cmdline` set to null unless you pass `--cmdline`.

`--cmdline` also needs `RECON_AGENT_ENCRYPTION_KEY`. The agent checks the line in memory, keeps a short pattern name such as `encoded-powershell`, and replaces the line with a Fernet token before the report is written or uploaded. The dashboard does not need the key to score that pattern name. Anyone who has the key can decrypt the token. Keep the key off the server if you do not want the server to be able to read those lines.

## Stop a scan

Set the kill switch before you start the agent. The process exits 0 and writes nothing.

```powershell
$env:RECON_AGENT_DISABLE = "1"
.\.venv\Scripts\WynDoze-InfoScanOverload-agent.exe scan --no-upload --output-json .\report.json --role workstation
```

## Work the inbox

Sign in, then open **Triage Inbox**. Flag, archive, suppress, or send a finding back to triage from that page. A browser on another origin receives 403. A request with no `Origin` header still works, which is how the local page posts.

Exports are CSV, Markdown, JSON, and Sentinel NDJSON. A CSV cell that starts with `=`, `+`, `-`, `@`, a tab, or a carriage return is prefixed with a single quote.

## Keep a bundle when upload fails

`--defer` is the default on `scan`. The Fernet key must already be set, or the agent exits 2 before it calls the server and writes no bundle.

```powershell
$env:RECON_AGENT_ENCRYPTION_KEY = .\.venv\Scripts\WynDoze-InfoScanOverload-agent.exe gen-key
```

Store that key outside the repo. On Windows the default cache directory is `%ProgramData%\WynDoze-InfoScanOverload\cache`. The dashboard database defaults to `%ProgramData%\WynDoze-InfoScanOverload\WynDoze-InfoScanOverload.sqlite3`. Encrypted bundles drop inherited Users access and grant SYSTEM, Administrators, and the current user.

For a machine with no route to the server, use `bundle`, move the `.WynDoze-InfoScanOverload-bundle` file, then `replay` with the same key and `RECON_AGENT_TOKEN`.

Replay requires a matching HTTP 201 ingest acknowledgement before deleting a
bundle. A redirect or invalid acknowledgement leaves it on disk. Corrupt or
unreadable files stay in the cache and are reported without preventing later
valid bundles from uploading; replay exits 1 if any file fails. Use `--keep` to
retain successful uploads. Every save gets an exclusive filename, including
multiple scans from the same host within one second.

## Schedule a daily scan

Run `deploy\windows\Install-ReconAgentTask.ps1` only when you want a SYSTEM task. Set `RECON_AGENT_TOKEN` and `RECON_AGENT_ENCRYPTION_KEY` in that admin session first. The script writes `C:\ProgramData\WynDoze-InfoScanOverload\agent.env`, locks the file to SYSTEM and Administrators, and registers `ReconAgentDailyScan`. It does not write Machine environment variables.

Quote is already applied to the server URL and the cache directory inside the script. The task is allowed to start on battery.
