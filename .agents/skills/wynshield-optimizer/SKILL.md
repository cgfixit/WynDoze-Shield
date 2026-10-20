---
name: wynshield-optimizer
description: Inspect WynDoze-Shield for evidence-backed correctness, security, CI, and maintainability fixes, then deliver focused draft PRs when authorized. Use when explicitly asked for /wynshield-optimizer, the legacy wyndozescan-optimizer, or a scanner improvement audit.
---

# WynShield optimizer

Read `AGENTS.md`, `README.md`, `user-guide.md`, and `feature.map.md` first.
`AGENTS.md` owns the platform and security boundaries. This skill is manual-only.

## Establish scope

1. Inspect the repository root, remotes, default branch, dirty state, and local-only
   commits. Fetch the remote and compare open PR heads/files and unmerged branches.
   Derive the repository owner/name from the remote; use the available `gh` or
   GitHub connector. Do not invent a remote or hard-code a machine's CLI path.
2. Preserve dirty checkouts and local-only commits. Compare local work with the
   refreshed default branch and open PRs; report which changes are landed, pending,
   or unique. When optimization is authorized, continue from a clean worktree based
   on the refreshed default branch and exclude pending PR work. Unmerged local work
   is not a prerequisite for unrelated optimization. Honor an explicit user condition
   such as "only if already merged"; a later instruction to use clean main resolves it.
   Do not merge pending PRs or discard local files to prepare the baseline. Optional
   `bash .agents/skills/wynshield-optimizer/bootstrap.sh` fetches origin and prints
   a scan seed. With a branch and optional base argument it checks out an existing
   branch without resetting it, or creates a new branch from that base. Inspect
   its output before editing; a failed fetch means remote evidence is stale.
3. Spend about four minutes on an initial read-only sweep, then verify each lead
   against the actual callers and input-to-effect path. Inspect collectors,
   command-line sealing, upload/replay, rule validation and both rule packs,
   ingest limits, authentication, redirects, HTML escaping, finding status,
   exports, desktop argv/scheduling, opt-in alerts, deployment, and CI.
4. Drop work already covered upstream. Report only concrete findings, each with
   a file/line, observed behavior, impact, and focused verification. Zero findings
   is valid; neither file size nor a target PR count establishes a defect.

## Implement and deliver

Proceed within the user's authorized scope. A review-only request ends with
findings; an implementation request continues through verification and requested
publication without another approval ritual.

Keep one concern per draft, based on the refreshed default branch. Consolidate
overlapping edits; this repository does not stack PRs. Trial-merge overlapping
work in a separate worktree. Never reset a shared checkout or force-push shared history.
Use the session's driver prefix for new branches; preserve the head of an existing
PR when updating it. The repository has `.github/PULL_REQUEST_TEMPLATE.md`;
apply its relevant sections and identify stale references rather than inventing
checks for another project.

Run the changed code with isolated state and synthetic inputs. Use focused tests
when needed to cover a real boundary; leave full suites and platform matrices to
hosted CI. Relevant static checks are:

```bash
ruff check src tests
ruff format --check src tests
mypy src
mypy --platform win32 src
python .agents/skills/invariant-guard/check_invariants.py
bash .agents/skills/invariant-guard/verify.sh  # when the checker changes
```

Lint changed workflows with `actionlint` and inspect their invoked scripts.
Validate an installed wheel for packaging/rule-pack changes. Windows-only `oem`
and `os.startfile` need platform-aware handling; macOS/Linux fixtures do not prove
native Windows behavior. A Python without Tk cannot exercise the launcher.

Inspect the final diff, stage only intended files, commit, push, and create the
requested draft using `--body-file` or a structured body. State actual commands,
revision, evidence class, skipped checks, and residual risks. Read back the PR
body, remote head, base, reviews, and all checks. Follow the exact pushed head
through CI. Leave drafts unmerged unless the user explicitly authorizes merging.

Never scan a live workstation or run the real SYSTEM-task installer for a PR.
Use `tests/windows/Test-TaskInstaller.ps1` for synthetic task/ACL contracts. Keep
both rule packs together, preserve `RECON_*` and systemd paths, and preserve the
installer's documented credential aliases. Do not regenerate `documentation.pdf`
unless the user requests it. Bounds and security invariants are not optimization
parameters; update the guard only for an intentional, justified contract change.
