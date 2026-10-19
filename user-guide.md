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

You should see `WynDoze-InfoScanOverload-agent.exe`, `WynDoze-InfoScanOverload-server.exe`, and `WynDoze-InfoScanOverload-desktop.exe` under `.venv\Scripts`.

## Desktop launcher

On a Windows desktop with Tk installed, run:

```powershell
.\.venv\Scripts\WynDoze-InfoScanOverload-desktop.exe
```

Choose the scan role, click **Start dashboard**, then **Run scan** to
collect a local JSON report. This button does not upload; use the CLI upload
command below to populate the dashboard. Open
`http://127.0.0.1:8000/` in your browser. Sign in as `admin`; select the password
in the read-only field and press Ctrl+C, then paste it into the browser. Each
window generates new credentials. **Stop dashboard** stops its server process.
The launcher sets its child dashboard username to `admin`, matching the window,
even when the shell has `RECON_DASHBOARD_USER` set to another name. A server
started directly from the CLI still honors that environment setting.

**Create scheduled task** registers `WynDoze-InfoScanOverload-scan` for the current
user at 02:30 with the selected cadence. It collects to
`%LOCALAPPDATA%\WynDoze-InfoScanOverload\scheduled-scan.json` without uploading or
sending mail. That file contains unencrypted inventory. Restrict and remove it
according to your retention policy. The SYSTEM task described below is separate.
Registration runs in the background with a 30-second timeout. The button stays
disabled while it runs; timeout or launch failures appear in the window. After
a timeout, check Task Scheduler before retrying because the task may have been
created. Task creation is disabled on macOS and other non-Windows systems.

Email alerts are off by default. Before starting the dashboard, enable the mail
checkbox and supply host, port, username, password, and recipient. SMTP uses
STARTTLS (default port 587), or TLS on port 465. Each accepted scan sends a
hostname and up to 40 finding summaries, including repeated findings, to that
recipient. Credentials stay in the window/server process environment. Restart
the dashboard to apply changed mail settings. Mail failures are logged without
rejecting an accepted scan. Delivery runs in a worker after the ingest response;
it is best-effort, without a durable queue or retry guarantee. No live mail service is required to use the app.

Use the CLI below on Server Core or installations without Tk.

## Start the dashboard

The server requires FastAPI 0.143.0+. A missing database parent is created with
access for its owner, SYSTEM, and Administrators. Existing directory permissions
are preserved. ACL setup failures prevent database creation.

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

## Ingest limits

The server authenticates before reading a report and returns 413 as soon as
received body bytes exceed 8 MiB. Rejected reports are not evaluated or stored.
This bounds accumulated application body bytes; transport buffers, the current
ASGI chunk, concurrent requests, and valid JSON parsing also consume memory.

## Work the inbox

The installed v1.3 rule pack matches the source copy.
Both files must be updated together; a regression check rejects policy drift.
Treat tool and service presence as context for review, not a malware verdict.
Windows-only missing-service hints require a nonempty service inventory.
Windows component services match exact names, case-insensitively. Product/custom
rules may still declare explicit substrings. Stopped/missing WinDefend or Sense is
advisory: check protection policy and active/passive/third-party state rather than
inferring tampering. Legacy empty/incomplete-inventory behavior remains unchanged.

Local administrator names are accompanied by SIDs. Built-in Administrator
(RID 500) and Domain Admins (RID 512) are recognized by account-domain SID,
including renamed/localized principals. A different `DOMAIN\Administrator`
is not trusted just because its last component matches. Older reports without
SIDs need explicit qualified-name entries in a custom rule pack to allow such
principals. Tune the supplied policy to your estate.

Sign in, then open **Triage Inbox**. Each finding is a decision card; low/info
cards are grouped unless that severity is selected. Suppress has a confirmation
page. Timeline also shows recent scans with redacted facts and counts. Flag, archive, suppress, or send a finding back to triage from that page. A browser on another origin receives 403. The dashboard uses `Referrer-Policy:
same-origin` so its own browser forms retain the origin needed by this check,
while links to other sites receive no referrer. A request with no `Origin` header still works, which is how the local page posts.

Exports are CSV, Markdown, JSON, and Sentinel NDJSON. A CSV cell that starts with `=`, `+`, `-`, `@`, a tab, or a carriage return is prefixed with a single quote.

Finding lists show 50 rows per page. Filter by exact hostname/rule ID, severity,
or status; Next and Previous retain the selected filters. Page numbers start at 1;
invalid page or filter values return HTTP 422. Click a finding title
to see complete escaped evidence, first/last seen, occurrence count and the latest
matching scan with separate collection/receipt times. Repeated identical evidence
preserves review decisions, including Flagged. Changed evidence gets a separate
finding. Empty results retain filter controls. All four export
formats include the complete stored finding set, including archived and suppressed
rows, regardless of the current filters. Full exports are rendered in memory and can be large on a busy dashboard.

## Check collection health

Open **Endpoints** to compare **Collected** with **Received**. An upload can
succeed while a collector is partial, unavailable, or failed. Coverage reports
counts, milliseconds, truncation and bounded issue categories, never command
text or stderr. Older agents show unknown coverage. No findings does not mean
a complete or clean scan. Reports older than `RECON_STALE_AFTER_HOURS` (36 by
default) are overdue; future or timezone-less timestamps have unknown age.
An air-gapped replay changes receipt time, not collection time. Missing-service
rules are skipped when reported service coverage is incomplete.

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

If an acknowledged bundle cannot be deleted (for example, a Windows file lock
or read-only cache), replay reports the cleanup failure, continues with later
bundles, and exits 1. The uploaded count still includes that accepted report.
The retained bundle may upload again on the next replay; resolve the permission
or lock problem before retrying.

## Schedule a daily scan

Run `deploy\windows\Install-ScanneragentTask.ps1` only when you want a SYSTEM task. Set `Scanz_AGENT_TOKEN` and `Scanz_AGENT_ENCRYPTION_KEY` in that admin session first, or use the existing `RECON_AGENT_TOKEN` and `RECON_AGENT_ENCRYPTION_KEY` inputs. The Scanz aliases take precedence; the generated env file always uses the `RECON_AGENT_*` keys read by the agent. The script writes `C:\ProgramData\WynDoze-InfoScanOverload\agent.env`, locks the file to SYSTEM and Administrators, and registers `ScanzAgentDailyScan`. It does not write Machine environment variables.

Pass the installed `WynDoze-InfoScanOverload-agent.exe` shim to `-PythonExe`,
rather than `python.exe`. The daily trigger adds up to 30 minutes of random
delay. Native `-File` arguments use double quotes, while values inside the
UTF-8 wrapper use PowerShell quoting. The wrapper returns the agent exit code,
and installation stops if a task-state ACL cannot be applied. The task is
allowed to start on battery.

The synthetic installer check resets its exit status only after all assertions
pass, including the expected child exit and ACL failure probes. A failed assertion
still fails the PowerShell workflow. It does not register a real task or change ACLs.
