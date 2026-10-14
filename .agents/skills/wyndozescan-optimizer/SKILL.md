---
name: lan-optimizer
description: >
  Time-boxed read-only scan of cgfixit/LanCartographer, then a few draft
  PRs only when each chunk earns it. Use when asked to optimize
  LanCartographer, audit this scanner, or run /lan-optimizer.
---

# LanCartographer optimizer

You scan this Go LAN inventory app for small, reviewable fixes. Windows and macOS share one scan engine. The GUI is Fyne and needs CGO. The CLI is the same engine behind flags.

Read `AGENTS.md` before the first edit. The short sibling scan is `.agents/skills/optimize/SKILL.md`. This file is the one that plans branches and PRs.

## Scan

Stay read-only until the user picks chunks. About four minutes.

1. Read `AGENTS.md` and the `README.md` headings.
2. `git fetch origin` and `git log --oneline -20 origin/main`.
3. List open PRs with `"C:\Program Files\GitHub CLI\gh.exe" pr list --repo cgfixit/LanCartographer --state open --limit 20`. Drop anything an open PR already covers. On Windows, `gh` on PATH may be the wrong binary.
4. Sweep `internal/scan`, `internal/probe`, `internal/discover`, `internal/gui`, `internal/cli`, `internal/authz`, `.github/workflows`, and `tests/`.

Return only findings you can point at in the tree. Each one names the file, the evidence, the lens, and small or medium effort. Zero findings is a valid result.

Lenses are scan correctness, dial budget, cancellation, authorization, telemetry, Windows and macOS parity, tests, and CI. Do not propose a new discovery protocol, a 3D view, or the v1.1 map. `todo.txt` is the deletion list. Do not re-add those items as features.

## Chunks

Keep one to four chunks. One solid chunk beats four thin ones. A chunk is one concern.

If two chunks edit the same file, put those edits in one PR, or cut the later branch from the earlier branch and set the PR base to that branch. Trial-merge before opening. Merge the parent first.

Branch prefix is `grok/<slug>` in a Grok session. Other tools use the prefix in `.github/PULL_REQUEST_TEMPLATE.md`. Cut the first branch from `origin/main`.

## Pull requests

Open a draft only after the user asks for that chunk. Never push `main`. Never force-push.

Title and body follow `.github/PULL_REQUEST_TEMPLATE.md`. Fill Test evidence with commands you actually ran.

Before that PR, run the focused test for the packages you touched. Run `bash tests/ci-gate.sh` when the change is on the Windows gate path and the user asked for the PR. A docs-only chunk does not need the race suite. Say what you did not run.

Use `"C:\Program Files\GitHub CLI\gh.exe" pr create --draft`. On PowerShell, do not pass an unquoted `#`.

## Do not

- Bind a listener on `0.0.0.0` or add telemetry, a crash reporter, or a runtime download.
- Change the Windows manifest away from `asInvoker`.
- Weaken `authz.NeedsConfirmation` or rewrite the CFAA sentence.
- Delete or gitignore `cmd/lancartographer/resource.syso` or `internal/oui/oui_data.go`.
- Raise the dial cap, the 64 host workers, or the HTTP one-second and 32 KiB limits to "go faster" without a measurement.
- Scan a real LAN from CI. Use loopback fixtures and a disposable data directory.
- Log raw inventory, prompts, or secrets.
- Add a workflow secret or a new license.
