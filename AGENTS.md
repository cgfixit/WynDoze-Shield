# WynDoze-Shield contributor guidance

## Platform contract

- Design the agent and dashboard for Windows 10, Windows 11, and Windows
  Server 2016, 2019, 2022, and 2025, including Server Core where applicable.
  These are compatibility targets, not a claim that every combination has
  passed native acceptance. Preserve the existing Linux paths.
- Python 3.12 is the minimum. Keep syntax compatible with 3.12 and verify
  released CPython versions from 3.12 onward as CI availability permits.
  `pyproject.toml` owns dependencies; keep the repeated floors in
  `requirements.txt` and `constraints.txt` aligned when changing them.
- Use Windows PowerShell 5.1-compatible syntax in deployment scripts. Do not
  require PowerShell 7, a desktop session, a particular display language, or
  an interactive user profile for a SYSTEM task. Check 32/64-bit registry
  views and LocalAccounts availability before claiming architecture support.
- Windows runtime state belongs under `%ProgramData%\WynDoze-InfoScanOverload`
  unless the operator overrides the path. Account for fresh directories,
  spaces, Unicode, NTFS ACLs, and localized Windows installations. Use stable
  SIDs for built-in security principals.

## Read before changing behavior

- Trace the affected entrypoint and callers under
  `src/wyndoze_infoscanoverload/{agent,core,server}`. Read `README.md`,
  `user-guide.md`, and `feature.map.md` for operator contracts, then check
  their claims against current source. The CLI and package still use the
  `WynDoze-InfoScanOverload` name; preserve `RECON_*` environment variables
  and systemd `recon` paths. The Windows installer now uses
  `ScanzAgentDailyScan`; retain its credential aliases and canonical agent env keys.
- For rule changes, inspect both `rules/windows_default.yaml` and the
  packaged `core/rulepacks/windows_default.yaml`. Keep both copies in the
  same commit and verify the installed wheel loads the intended pack. If
  they differ, establish the intended behavior before reconciling detections.
- Three entrypoints ship: `agent/cli.py` collects/seals/uploads or bundles;
  `server/__main__.py` starts the loopback dashboard; `desktop.py` launches Tk,
  starts the server, scans, and optionally registers a current-user collect task.
  `alerts.py` sends SMTP only when explicitly configured. `core/` imports none
  of agent/server/desktop/alerts; agent and server never import each other.
- Version comes from `_version.py`. Pydantic v2 route/model annotations remain
  runtime imports. Preserve `.gitattributes` line endings, including CRLF scripts.
- For optimizer work, read `.agents/skills/wynshield-optimizer/SKILL.md`.
  This is the single manual optimizer workflow for every agent.

## Boundaries to preserve

- Collect local metadata only. Preserve read-only collection, per-item
  permission handling, timeouts, and payload limits. Keep file contents,
  credentials, active network scans, and cloud telemetry out of collection.
- Command lines are opt-in and require a Fernet key. Match patterns in
  memory and seal lines before writing, caching, or uploading a report.
- Keep server binding on `127.0.0.1` or `::1`; HTTP uploads are allowed only
  to those literal loopback addresses. Retain TLS verification by default
  and the uploader's `trust_env=False` behavior.
- Keep ingest bearer authentication and dashboard Basic authentication
  closed when their secrets are absent. Keep API docs and OpenTelemetry
  export disabled, dynamic HTML escaped, and CSV formula cells protected.
  Retain the no-script CSP, bounded action bodies, and same-origin form check.
- `server/app.py` validates finding filters; `server/desk.py` rebuilds only
  allowlisted local return paths. Preserve page/host/rule filters after actions.
  `active` means triage or flagged and is never a stored status. Identical
  evidence increments occurrences without resetting any analyst decision.
- `server/present.py` converts raw scans to display facts. Render counts and
  allowed pattern names, never raw scan JSON or encrypted command-line tokens.
  Endpoints show collection age separately from receipt age and retain unknown
  coverage for older agents. Missing data cannot automatically resolve findings.
- Command-line pattern matching reads at most 800 characters; sealing retains
  at most 3000 UTF-8 bytes on a character boundary within the 4096-character
  model field. Keep the 8 MiB streamed ingest cap and 2048-byte action cap.
- Load YAML with `safe_load`, reject invalid rule severity, use SQL
  parameters, and invoke subprocesses with argument lists and bounded waits.
- Preserve encryption and restrictive Windows ACLs for deferred bundles
  and task secrets. Use synthetic inventory and disposable secrets for
  verification; do not publish real inventory or keys. The desktop password is
  generated per window and remains selectable in a read-only entry. Its schedule
  collects locally under the current user; the separate SYSTEM installer is
  `deploy/windows/Install-ScanneragentTask.ps1`. Never run the real installer or
  scan a live workstation as routine PR verification. Opt-in SMTP sends hostname
  and finding summaries to the configured recipient; it is not telemetry.
- Keep Windows-only OEM decoding and `os.startfile` handling portable. Tests can
  use `cp437` off Windows; type-check both default and `--platform win32` paths.

## Verification and delivery

- Exercise the affected command, API, library, or UI behavior using isolated
  state. Run focused checks tied to the change; leave broad regression and
  platform matrices to hosted CI. Lint changed workflows with `actionlint`
  and inspect the commands they invoke instead of running a full local suite.
- CI workflows belong in `.github/workflows/`. Use minimal token permissions,
  pin third-party actions to full commit SHAs, and keep secret scanning
  redacted without posting PR comments or uploading sensitive reports.
- Hosted Windows Server 2022/2025 runners do not establish Windows 10/11 or
  Server 2016/2019 acceptance. Report native, fixture, build, lint, and hosted
  evidence separately. Parse deployment scripts without registering tasks
  or changing a workstation's ACLs during routine checks. The synthetic fixture
  `tests/windows/Test-TaskInstaller.ps1` mocks both operations; native module
  metadata is checked only when the fixture runs on Windows.
- For source/rules/deploy/packaging changes, run
  `python .agents/skills/invariant-guard/check_invariants.py`. After changing the
  guard, run `bash .agents/skills/invariant-guard/verify.sh` to prove planted
  violations fail. Update pins only for intentional contract changes.
- CI keeps Ruff, strict default/Windows mypy, the guard, wheel building, Linux
  coverage (80% floor), and Server 2022/2025 with Python 3.12–3.15 regressions.
  Check workflow enablement separately from YAML; a disabled gate is not passed.
- Publish requested drafts from `codex/<short-kebab-case-topic>` branches
  based on the refreshed default branch. Use the repository PR template's
  applicable sections and name stale checks or paths explicitly. Read back
  the PR head and check status; leave drafts unmerged unless the user authorizes merging.
