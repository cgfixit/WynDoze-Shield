---
name: wyndozescan-optimizer
description: >
  Time-boxed read-only scan of WynDoze-InfoScanOverload, then a few draft
  PRs only when each chunk earns it. Use when asked to optimize
  WynDoze-InfoScanOverload, audit this scanner, or run /wyndozescan-optimizer.
---

# WynDoze-InfoScanOverload optimizer

You scan this Python package for small, reviewable fixes. The agent collects local metadata. The loopback server scores that metadata with a YAML rule pack and shows a triage inbox.

Read `README.md`, `user-guide.md`, and `feature.map.md` before the first edit. The package version is `__version__` in `src/wyndoze_infoscanoverload/_version.py`.

## Scan

Stay read-only until the user picks chunks. About four minutes.

1. Read the three docs above and `_version.py`.
2. If `git remote -v` prints a URL, fetch that remote and read the last 20 commits on its default branch. If `git remote -v` is empty, scan this checkout. Do not invent a remote or a GitHub owner.
3. When a remote exists, list open pull requests with `"C:\Program Files\GitHub CLI\gh.exe" pr list --repo <owner>/<name> --state open --limit 20`. Drop anything an open pull request already covers. On Windows, `gh` on PATH may be the wrong binary.
4. Sweep `src/wyndoze_infoscanoverload/agent`, `src/wyndoze_infoscanoverload/core`, `src/wyndoze_infoscanoverload/server`, both copies of `windows_default.yaml`, `deploy`, and `tests`.

Return only findings you can point at in the tree. Each one names the file, the evidence, the lens, and small or medium effort. Zero findings is a valid result.

Lenses are collector correctness, sealed command lines, ingest and list caps, loopback and auth, rule-pack scoring, telemetry, tests, and the deploy scripts. Do not propose file-content scanning, credential collection, or a new rule kind. `feature.map.md` records what this tree does not ship. Do not re-add those items as features.

## Chunks

Keep one to four chunks. One solid chunk beats four thin ones. A chunk is one concern.

If two chunks edit the same file, put those edits in one pull request, or cut the later branch from the earlier branch and set the pull request base to that branch. Trial-merge before opening. Merge the parent first.

Branch prefix is `grok/<slug>` in a Grok session. Cut the first branch from the default branch. This tree has no `.github/PULL_REQUEST_TEMPLATE.md`. Do not invent one during the scan.

## Pull requests

Open a draft only after the user asks for that chunk. Never push `main`. Never force-push.

Title shape is `[prefix] - sentence`. Body headings are Summary, Test evidence, Merge order, and Base. Fill Test evidence with commands you actually ran.

Before that pull request, run the focused pytest for the modules you touched. For a code change, also run `ruff check src tests` and `mypy src`. A docs-only chunk does not need mypy. Say what you did not run. `README.md` lists the full local commands. This tree has no GitHub Actions workflow.

When a remote exists, create the draft with `"C:\Program Files\GitHub CLI\gh.exe" pr create --draft`. On PowerShell, do not pass an unquoted `#`. When no remote exists, commit on the branch and stop. Do not invent `cgfixit/WynDoze-InfoScanOverload`.

## Do not

- Bind a listener on any host other than `127.0.0.1` or `::1`, or allow an `http` upload to any other host. `server/__main__.py` and `agent/uploader.py` own those checks.
- Turn on OpenTelemetry or FastAPI telemetry export, or set `docs_url` or `openapi_url` in `create_app`.
- Read file contents, collect credentials, or store a raw process command line. `--cmdline` stays off unless the Fernet key is set, and `seal_command_lines` runs before the report is written.
- Raise `_MAX_INGEST_BYTES` or the collector limits to go faster without a measurement.
- Load a rule pack with `yaml.load`, or call `subprocess` with `shell=True`. Kinds live in `_VALID_KINDS` in `core/rules.py`. Unknown severity stays a `RuleError`.
- Replace the substring `recon` blindly. Keep `RECON_*` names, the task `ReconAgentDailyScan`, `User=recon`, and the paths `/opt/recon`, `/etc/recon`, and `/var/lib/recon`.
- Edit `rules/windows_default.yaml` or `src/wyndoze_infoscanoverload/core/rulepacks/windows_default.yaml` alone. Treat the two copies as one pack and update both in the same commit.
- Run `deploy/windows/Install-ReconAgentTask.ps1`, scan a live workstation for a pull request, or paste inventory, tokens, or bundle bytes into chat or a commit.
- Add a workflow secret, a new license, or a dependency that sends data off the machine.
- Add a scan that reads file bytes. Collectors stay metadata only.
