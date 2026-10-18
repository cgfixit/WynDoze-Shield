---
name: wyndoze-optimize
description: Time-boxed read-only scan of WynDoze-InfoScanOverload for code, CI, security, and maintainability fixes, then a small set of focused draft PRs only when each chunk earns it (not a quota). Use when asked to optimize this scanner, audit it, harden its CI, or open optimization PRs. Not auto-invoked, because it opens PRs.
disable-model-invocation: true
---

# WynDoze-Optimize

**Persona:** you are a Python engineer who knows this tree. The agent (`agent/`) collects read-only host metadata into a pydantic `ScanReport`, seals opt-in command lines with Fernet, and uploads over https, or over http to loopback only. The server (`server/`) is a loopback-only FastAPI app. It scores reports with a YAML rule pack (`core/rules.py`), upserts findings into SQLite, and renders a no-JavaScript triage desk. `desktop.py` is the Windows Tk launcher. Windows is the primary target and Linux is the CI and systemd secondary. You read for leverage: collector correctness, the security posture, CI health, test gaps, and maintainability.

**What it does:** time-box a scan of the default branch, group real findings into about 1 to 4 PR-sized chunks (a guideline, not a quota), and open one draft PR per kept chunk. Zero PRs is a valid result. Never commit to `main`. A human merges.

**How it runs:** `bootstrap.sh` does the setup and prints a scan seed. A read-only `Explore` subagent scans. PR dedup and PR creation are GitHub MCP calls. `.agents/skills/wyndozescan-optimizer/SKILL.md` is the same workflow for non-Claude agents. If the two disagree, this file and `CLAUDE.md` win for Claude Code.

---

## Step 0: bootstrap

```bash
bash .claude/skills/wyndoze-optimize/bootstrap.sh "claude/wyndoze-optimize-<topic>"            # cut from origin/main
bash .claude/skills/wyndoze-optimize/bootstrap.sh "claude/wyndoze-optimize-<topic>" origin/<parent>  # stacked child
```

Use the driver prefix (`claude/` for Claude Code; `grok/`, `codex/`, `kimi/` for others). With no argument it runs read-only on the current branch. It never resets a branch that already exists.

Read the **remote branches with commits not on main** section first. This repo has carried large unmerged branches with no PR (for example `grok/desktop-launcher`, which added CI, `CLAUDE.md`, and the desktop launcher). A finding that branch already fixes is not a new finding. If your chunk touches a file that branch rewrote, stack on it (Step 3.5) instead of forking a parallel copy.

## Step 1: dedup against open PRs (before you pick anything)

```text
mcp__github__list_pull_requests(owner="cgfixit", repo="WynDoze-InfoScanOverload", state="open",
                                fields=["number", "title", "head", "base", "draft"])
```

Pass `fields` so the payload stays small. Drop any candidate an open PR or an unmerged branch from Step 0 already covers. Off GitHub MCP (local Windows), use `"C:\Program Files\GitHub CLI\gh.exe" pr list --state open --limit 20`, because `gh` on PATH may be the wrong binary.

## Step 2: time-boxed scan (read-only subagent, about 4 minutes)

Dispatch one `Explore` subagent. It must not edit. Adapt this prompt and keep its structure:

> You know the WynDoze-InfoScanOverload architecture (see CLAUDE.md). Repo root is the CWD. Spend about 4 minutes on a READ-ONLY scan for concrete fixes that fit small or medium PRs. Sweep: `.github/workflows/*.yml` (SHA pins, caching keyed on `pyproject.toml`, timeouts, matrix gaps, Windows-only code that breaks the Ubuntu leg; nothing that needs a secret or a license); `src/wyndoze_infoscanoverload/agent/` (collector correctness on Windows and Linux, OEM code-page decoding, `_run_command` timeouts, collector limits, the sealing order in `cmdline.py`, uploader retry policy); `core/` (rule-pack validation, severity ranking, MITRE lookup, model `max_length` caps); `server/` (auth fail-closed, Origin check, `safe_next` allowlist, ingest cap, the storage upsert status rule, `html.escape` coverage in `templates.py`, export formats); `desktop.py` and `alerts.py` (argv builders, schtasks, SMTP opt-in); `deploy/` (systemd hardening, the PowerShell task script, without running it); `tests/` (logic gaps, missing assertions, platform-dependent tests). Return 4 to 8 DISTINCT findings, each with: title, file:line, one-line description, lens, effort (small or medium). End with a suggested grouping into PR-sized chunks, only as many as earn a PR. Cite real code. Do not invent.

The 4 minutes bounds the first sweep only. Keep reading code afterwards to confirm each finding before it becomes a PR.

**Out of scope, always:** file-content scanning, credential collection, network scanning, a new rule kind, telemetry export, docs/OpenAPI routes, a non-loopback listener, Docker, or anything `feature.map.md` lists as not shipped.

## Step 3: select chunks and announce them

Keep only chunks that clearly earn a PR. One solid chunk beats four thin ones. A chunk is one concern: one or two major ideas, or three to five minor ones. Give each kept chunk one line saying which code it touches and why (correctness, security, CI health, auditability, maintainability).

## Step 3.5: branch topology for shared files

Build a file-to-chunks map before cutting branches. The usual shared files here are `.github/workflows/ci.yml`, `pyproject.toml`, `CLAUDE.md`, both `windows_default.yaml` copies (always one chunk, same commit), and `tests/conftest.py`. For each shared file, pick one strategy:

- **Consolidate:** put every edit to that file in one chunk.
- **Stack:** cut the later branch from the earlier branch (`bootstrap.sh <branch> origin/<parent>`) and set its PR base to that parent, not `main`. Merge the parent first.

Trial-merge every pair that shares a file before opening either PR:

```bash
git checkout -B _trial origin/main
git merge --no-ff --no-edit "origin/<branch-A>" && git merge --no-ff --no-edit "origin/<branch-B>"
grep -rc '<<<<<<<' <shared-file>                       # must be 0
python3 -c "import tomllib; tomllib.load(open('pyproject.toml','rb'))"
git checkout - && git branch -D _trial
```

| Topology | Cut from | PR `base` |
|---|---|---|
| Independent | `origin/main` | `main` |
| Stacked | the parent chunk's branch | that parent branch until it merges |
| Consolidated | whichever branch owns the shared edits | same as that branch |

## Step 4: one draft PR per chunk

Work in planned merge order, parents first.

1. Make the minimal, on-topic change. Do not touch unrelated files.
2. Verify (below).
3. Commit and push:

   ```bash
   git add <this chunk's files>
   git commit -m "[fix] - <what changed and why>"
   git push -u origin "<branch>"          # on network failure only: retry 4x at 2s, 4s, 8s, 16s
   ```

4. Open a **draft** with title `[prefix] - sentence` (prefix: `fix`, `ci`, `docs`, `test`, `refactor`, `security`). The repo has no PR template. Use the body headings **Summary**, **Test evidence** (commands you actually ran, plus what you did not run), **Merge order** (independent, or stacked on `<parent>`, plus the trial-merge result), and **Base**.

   ```text
   mcp__github__create_pull_request(owner="cgfixit", repo="WynDoze-InfoScanOverload",
     base="main",                       # stacked child: base="<parent-branch>"
     head="<branch>", draft=true, title="[fix] - <sentence>", body="<four headings>")
   ```

   Then `subscribe_pr_activity` and drive the PR to green.

Merge order for a run: lowest PR number to highest, parents before children. Re-run the trial merge whenever `main` moves.

## Verify (per chunk, before pushing)

Run the changed code first, then the cheap static gates, then let CI run the suites. Use one focused pytest file only when nothing else exercises the path.

```bash
python -c "from wyndoze_infoscanoverload.<module> import <fn>; print(<fn>(<real input>))"   # run it
ruff check src tests && ruff format --check src tests
mypy src && mypy --platform win32 src        # both CI legs; Windows-only APIs break one of them
python3 .claude/skills/invariant-guard/check_invariants.py   # any change to src/, rules/, deploy/, pyproject.toml
pytest tests/unit/test_<area>.py -q          # at most one file, only if the path is otherwise unexercised
```

A workflow-only or docs-only chunk needs no pytest. Validate YAML with `python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" .github/workflows/ci.yml`. Run `/code-review` on the diff if it touches `server/app.py`, `agent/uploader.py`, or `agent/cmdline.py`.

**Cloud container setup:** the system Python 3.13 here has no `tkinter`, so `tests/unit/test_desktop.py` fails to collect. Build the venv on a managed 3.12 instead:

```bash
uv venv --python 3.12 --managed-python .venv && uv pip install --python .venv/bin/python -e ".[server,dev]"
```

---

## Branch permissions (pre-granted when this skill runs)

Invoking this skill authorizes creating and pushing per-chunk branches named `<driver-prefix>/wyndoze-optimize-<topic>` cut from the topology base, plus opening them as draft PRs. Do not stop to ask before pushing those branches. When the session has a designated branch, use it for the first chunk instead of a new name, and never push to a branch you were not given or that this skill did not create.

## Guardrails (the invariants; never an optimization target)

- Branch, then draft PR, then a human merges. Never push `main`. Never force-push without the owner's OK.
- Every item in CLAUDE.md "Constraints to preserve" stands, and `invariant-guard` checks most of them. Do not loosen a pinned value to make a chunk fit.
- Workflow changes need no secret, license, or paid service.
- Never run `deploy/windows/Install-ReconAgentTask.ps1`, scan a live workstation for a PR, or paste inventory, tokens, or bundle bytes into chat, a commit, or a PR body.

## Gotchas (each one hit in this repo)

- **Windows-only stdlib breaks the Ubuntu leg.** The `"oem"` codec and `os.startfile` exist only on Windows. A test that calls `.encode("oem")` fails on Linux, so use `cp437` there. An `os.name == "nt"` guard does not narrow for mypy, and a `sys.platform` guard trips `warn_unreachable` on the other leg. Probe with `getattr(os, "startfile", None)` and run `mypy --platform win32 src` as well.
- **Two rule-pack copies.** `rules/windows_default.yaml` and `core/rulepacks/windows_default.yaml` change in the same commit, or `invariant-guard` R1 fails.
- **Do not rename `recon`.** `RECON_*`, `ReconAgentDailyScan`, `User=recon`, and `/opt/recon` are load-bearing.
- **Line endings.** `.gitattributes` stores LF with `.ps1` as CRLF. If `git diff --numstat` is far larger than the change, compare with `--ignore-cr-at-eol` and restore the original endings.
- **`documentation.pdf` is gitignored but tracked** (force-added on `grok/desktop-launcher`). Do not regenerate or re-commit it in an unrelated chunk.
- **Stacked PRs and squash merges.** If a parent is squash-merged, the child still carries the parent's commits. Rebase the child with `git rebase --onto origin/main <parent-tip> <child>` (your own branch only), or merge the parent with a merge commit.
- **Size is a lead, not a defect.** `templates.py` and `test_server.py` are the largest files on purpose (pure HTML builders and wide integration coverage). Confirm a real defect before proposing a split.
- **Coverage floor is 80%.** A chunk that adds code without tests can turn the Windows or Ubuntu test leg red on coverage alone.

If nothing survives dedup and verification, say so in one line and stop.
