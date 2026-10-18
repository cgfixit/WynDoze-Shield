# Use WynDoze-InfoScanOverload on Windows

This guide targets Windows 10, Windows 11, and Windows Server 2016, 2019, 2022,
and 2025 with Python 3.12 or newer. Examples use the minimum version, 3.12.
Native acceptance is still required on each OS; this target list is not a
certification. The guide gets a loopback dashboard and one agent scan running.
It does not register a scheduled task unless you run that script yourself.

Use this scanner only on systems you own or are authorized to assess.

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
$env:RECON_AGENT_ENCRYPTION_KEY = .\.venv\Scripts\WynDoze-InfoScanOverload-agent.exe gen-key
.\.venv\Scripts\WynDoze-InfoScanOverload-agent.exe scan --server-url http://127.0.0.1:8000/api/scans --role workstation
```

HTTP is allowed only for `127.0.0.1` and `::1`. Every other host needs `https`. The agent ignores proxy environment variables.

A successful upload prints `Upload OK`. The Triage Inbox at `/triage` lists the findings.

To collect without uploading:

```powershell
.\.venv\Scripts\WynDoze-InfoScanOverload-agent.exe scan --no-upload --output-json .\report.json --role workstation
```

Delete `report.json` when you are done. It contains host inventory. Every process row has `cmdline` set to null unless you pass `--cmdline`.

Inventory can contain usernames, hostnames, addresses, and executable paths.
The application does not encrypt its SQLite database or plain exports. Protect
those files and backups, decide how long to keep them, and do not post real
inventory or credentials in public issues. Use [private security reporting](SECURITY.md)
for suspected vulnerabilities.

`--cmdline` also needs `RECON_AGENT_ENCRYPTION_KEY`. The agent checks the line in memory, keeps a short pattern name such as `encoded-powershell`, and replaces the line with a Fernet token before the report is written or uploaded. The dashboard does not need the key to score that pattern name. Anyone who has the key can decrypt the token. Keep the key off the server if you do not want the server to be able to read those lines.

Command lines may include passwords or tokens supplied to other programs.
Sealing encrypts the retained text; it does not redact embedded secrets. Leave
command-line collection off unless you need it and have authorized its use.

Pattern matching examines at most 800 characters. Before encryption, the stored
prefix is also limited to 3000 UTF-8 bytes without splitting a character. This
keeps non-ASCII command lines within the 4096-character token field so reports
can be uploaded and replayed. A pattern label can describe text beyond the
shorter stored prefix.

## Stop a scan

Set the kill switch before you start the agent. The process exits 0 and writes nothing.

```powershell
$env:RECON_AGENT_DISABLE = "1"
.\.venv\Scripts\WynDoze-InfoScanOverload-agent.exe scan --no-upload --output-json .\report.json --role workstation
```

## Work the inbox

The installed v1.2 rule pack matches the source copy and contains 28 rules.
Both files must be updated together; a regression check rejects policy drift.
Treat tool and service presence as context for review, not a malware verdict.
Windows-only missing-service hints require a nonempty service inventory.

Local administrator names are accompanied by SIDs. Built-in Administrator
(RID 500) and Domain Admins (RID 512) are recognized by account-domain SID,
including renamed/localized principals. A different `DOMAIN\Administrator`
is not trusted just because its last component matches. Older reports without
SIDs need explicit qualified-name entries in a custom rule pack to allow such
principals. Tune the supplied policy to your estate.

Sign in, then open **Triage Inbox**. Flag, archive, suppress, or send a finding back to triage from that page. A browser on another origin receives 403. A request with no `Origin` header still works, which is how the local page posts.

Exports are CSV, Markdown, JSON, and Sentinel NDJSON. A CSV cell that starts with `=`, `+`, `-`, `@`, a tab, or a carriage return is prefixed with a single quote.

Finding tables show at most 500 rows; the page states that limit. All four export
formats include the complete stored finding set, including archived and suppressed
rows. Full exports are rendered in memory and can be large on a busy dashboard.

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

Pass the installed `WynDoze-InfoScanOverload-agent.exe` shim to `-PythonExe`,
rather than `python.exe`. The daily trigger adds up to 30 minutes of random
delay. Native `-File` arguments use double quotes, while values inside the
UTF-8 wrapper use PowerShell quoting. The wrapper returns the agent exit code,
and installation stops if a task-state ACL cannot be applied. The task is
allowed to start on battery.
