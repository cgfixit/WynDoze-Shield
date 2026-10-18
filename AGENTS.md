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
  and `ReconAgentDailyScan` unless a migration is explicitly requested.
- For rule changes, inspect both `rules/windows_default.yaml` and the
  packaged `core/rulepacks/windows_default.yaml`. Keep both copies in the
  same commit and verify the installed wheel loads the intended pack. If
  they differ, establish the intended behavior before reconciling detections.
- For optimizer work, read `.agents/skills/wyndozescan-optimizer/SKILL.md`.
  Recheck its historical repository and tool claims against the current tree.

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
- Load YAML with `safe_load`, reject invalid rule severity, use SQL
  parameters, and invoke subprocesses with argument lists and bounded waits.
- Preserve encryption and restrictive Windows ACLs for deferred bundles
  and task secrets. Use synthetic inventory and disposable secrets for
  verification; do not publish real inventory or keys.

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
  or changing a workstation's ACLs during routine checks.
- Publish requested drafts from `codex/<short-kebab-case-topic>` branches
  based on the refreshed default branch. Use the repository PR template's
  applicable sections and name stale checks or paths explicitly. Read back
  the PR head and check status; leave drafts unmerged.
