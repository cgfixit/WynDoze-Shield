## Branch naming (required for agent-opened PRs)

Before opening a PR, create the head branch with the **driver-matched** prefix.
This is a convention, not an automated check; casual / generic names are not a substitute.

| Driver | Branch pattern | Example |
|--------|----------------|---------|
| Claude Code | `claude/<feature>` | `claude/loopback-host-check` |
| Codex | `codex/<feature>` | `codex/verify-dep-guard` |
| Grok Bot / Build / Cursor| `grok/<feature>` | `grok/pr-template-branch-rules` |
| Kimi / Kimi Code | `kimi/<feature>` | `kimi/docs-sync` |
|  CyClaw | `CyClaw/<feature>-<YYYYMMDD>` or `cyclaw/<feature>` | `cyclaw/harness-timeout` |
| Unknown / harness default | `agent/<feature>` | `agent/rulepack-sync` |

Rules for agents:
1. Pick the prefix that matches **the tool that is creating the branch**, not a generic label.
2. Do **not** default to `agent/` when the driver is known (Claude → `claude/`, Grok → `grok/`, etc.).
3. `<feature>` must be short, kebab-case, and describe the change (no spaces, no leading `-`).
4. If the branch name is wrong, rename **before** push: `git branch -m <prefix>/<feature>`.

Also allowed (non-feature): `main`, `dependabot/*`, `renovate/*`, `release/*`, `hotfix/*`.

**Base branch: `main`.** Never open a PR against another feature branch (no stacking).
A stacked PR is not reviewed; fix with `gh pr edit <n> --base main` after rebasing onto `origin/main`.

Record the head SHA in Further comments after the branch exists. Do not force-push, except `--force-with-lease` after rebasing your own unshared branch (see merge order). If you skipped a fetch of `origin/main`, say so under Risks and why.

## Title
**Use this format:**  
`[prefix] - Short descriptive sentence of the change`

**Recommended prefixes (pick the most relevant):**  
`[invariant]` • `[security]` • `[infra]` • `[fix]` • `[docs]` • `[rules]` • `[deploy]` • `[agentic]` • `[test]` • `[feat]`

Example: `[docs] - Restructure README around verified claims`

The prefix classifies the diff. It is not a feature claim. Put commands, exit codes, and the head SHA in Further comments, not in the title.

---

## Proposed changes
Describe the big picture of your changes here. Explain **why** maintainers should accept this PR.  
If it fixes a bug or resolves a feature request, link the issue.

**Invariant / Governance Impact** (required for any change touching core paths):
- Which guarantee in the invariant guard table (`.agents/skills/invariant-guard/SKILL.md`, L1–P1) or the boundaries in `AGENTS.md` does this change affect (or confirm none)? Call out L1/L2 (loopback bind and upload), closed auth (401 when `RECON_INGEST_TOKEN` / `RECON_DASHBOARD_PASSWORD` are absent), T1 (no API docs, no OpenTelemetry), C1 (metadata only), C2 (pinned caps), and R1 (twin rule pack) when relevant.
- Provide evidence it is preserved (e.g., `check_invariants.py` exits 0 on the head, `core/` still imports none of agent/server/desktop/alerts, both rule pack copies changed in the same commit, command lines are still sealed before any write or upload).
- If you are intentionally relaxing or evolving an invariant (a measured cap raise, a reviewed new dependency, a renamed pinned name), explain the justification and compensating controls, and update `check_invariants.py` in the same commit, then run `verify.sh` to prove it still bites.

Truth order for every claim is the code, then `rules/windows_default.yaml` and `core/rulepacks/windows_default.yaml`, then the guard table and `AGENTS.md`, then `README.md`, `user-guide.md`, and `feature.map.md`. When prose and code disagree, the code wins. Do not describe a gate as weaker, optional, or off when the code keeps it closed.

Name each invariant this diff touches, or say it touches none. For each command, give the command, its exit code, and the head SHA it ran on. Name each skipped check and why. State residual risk. Rollback is reverting the squash commit on `main`. Do not widen a cap, open a bind, or relax auth to undo a failure.

---

## Types of changes
What types of changes does your code introduce to WynDoze-Shield (`wyndoze_infoscanoverload`)?  
_Put an `x` in the boxes that apply_

- [ ] Bugfix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Security (auth, encryption, certs, rbac, privacy, injection, egress, redaction, or secrets)
- [ ] Invariant / Governance refinement (use this for changes that strengthen or evolve the guard, the loopback contract, collection boundaries, or sealing)
- [ ] Rule pack (both `rules/` and `core/rulepacks/` copies in the same commit)
- [ ] Deployment scripts (`deploy/windows/*.ps1`, `deploy/systemd/*`; PowerShell 5.1-compatible)
- [ ] Dependencies (updated, aligned between `pyproject.toml`, `requirements.txt`, and `constraints.txt`, new deps added, removed, or bumped)
- [ ] CI / Skills / AI infrastructure (skills, workflows, hooks, lint tools, ci/cd and tests/ additions or updates/trims, templates, checkers, etc)
- [ ] Refactor or clean-up (behavior-preserving, no new capability)
- [ ] Documentation Update 
- [ ] Other (none of the boxes above fit)


**Optional free-text scope note** (recommended):  
Core domain (`core/`, rule packs, guard) | Agent (collectors, cache, cmdline sealing, uploader, CLI) | Server / dashboard | Desktop / alerts | Deploy scripts | Docs | Infrastructure / CI only

Check a box only when the diff matches it. A docs or template edit is not a new feature. If a quality-bar command was skipped, leave the checklist row open and explain it under Risks, with the head SHA those boxes describe.

---

## Benefits / why
- Why make this change? What is the concrete upside for WynDoze-Shield operators, contributors, or long-term maintainability?
- How does this improve (or at least not degrade) loopback-only posture, closed-by-default auth, metadata-only collection, command-line sealing, or security posture?
- For agent or server changes: how does this increase capability without widening what is collected, where it is sent, or who can read it?

State the maintainer outcome in concrete terms. Do not market a capability or claim a gate is easier. Loopback bind, closed auth, the ingest and command-line caps, and the twin rule pack stay as the code ships them. If a benefit depends on a skipped check, name that check and why the benefit still holds.

---

## Risks to monitor
- What are the potential regressions, negative side-effects, or things that need extra attention after merge?
- Could this introduce a non-loopback bind or upload, open an endpoint when its secret is absent, read file contents in a collector, write or upload an unsealed command line, raise a pinned cap, or add a network assumption?
- For rule pack or deploy changes: what happens on an older agent report, a localized Windows install, Server Core, or a 32-bit registry view?
- How will you (or future maintainers) detect drift from the intended behavior?

Name residual risk after the checks you actually ran. Include failed or skipped commands, their exit codes, and why you skipped them. Say which invariants the diff touches. Detect drift by re-running the quality bar and `check_invariants.py` on the same head SHA.

---

## Checklist
_Put an `x` in the boxes that apply. You can fill these out after creating the PR. If you're unsure about any item, ask before opening the PR._

- [ ] I have read `AGENTS.md` and `.agents/skills/invariant-guard/SKILL.md`
- [ ] This change preserves the guarded invariants and the `AGENTS.md` boundaries (explicit evidence for core-path changes)
- [ ] Quality bar has been run (`ruff check src tests`, `ruff format --check src tests`, `mypy src`, `mypy --platform win32 src`, `python .agents/skills/invariant-guard/check_invariants.py`, and the focused `pytest` paths for the change) and passes with no regressions
- [ ] No new external network dependencies or outbound destinations were introduced without explicit justification (uploads stay to the configured server; SMTP stays opt-in)
- [ ] For any collector, sealing, upload, or server change: collection stays read-only metadata, command lines stay opt-in and sealed before any write or upload, auth stays closed when secrets are absent, and the bind stays loopback
- [ ] Relevant docs (`README.md`, `user-guide.md`, `feature.map.md`, `AGENTS.md`) have been updated if operator-visible behavior or topology changed
- [ ] No new Markdown file: doc changes edit the section that owns the topic, and evidence is in this PR body
- [ ] Commit messages follow the title prefix convention above
- [ ] For large or complex changes: before/after invariant notes + `pytest` evidence is included in "Further comments" or linked
- [ ] If `check_invariants.py` changed: `bash .agents/skills/invariant-guard/verify.sh` was run and the planted violations still fail
- [ ] If a workflow changed: `actionlint` was run and the invoked commands were inspected

Mark a box only after that command exits 0 on the head SHA you will push. A skipped row stays unchecked. The quality-bar row is not met by a green subset. Invariants touched, residual risk, and rollback belong in Proposed changes, Risks, and Further comments.

---

## Further comments
If this is a relatively large, complex, or core-path change, kick off the discussion here.

**For changes touching `server/__main__.py`, `server/app.py`, `server/desk.py`, `server/templates.py`, `agent/uploader.py`, `agent/cmdline.py`, `agent/collectors.py`, `core/rules.py`, either `windows_default.yaml`, `deploy/`, or `check_invariants.py`, include:**
- Explicit before/after invariant statement (which guard row or `AGENTS.md` boundary holds and why)
- Test, `check_invariants.py`, or `verify.sh` evidence
- Any compensating controls or observability added
- A technical summary plus a plain-language (ELI5) summary of what changed, what is at risk, and where to monitor

**Examples of what good "Further comments" look like for core changes:**
- "No change to the loopback boundary. `_LOOPBACK_HOSTS` and `_LOOPBACK_HTTP` are still `{127.0.0.1, ::1}`; the guard passed L1 and L2 on the head."
- "Auth still ships closed. An absent `RECON_INGEST_TOKEN` still returns 401; `compare_digest` is still the only comparison. `test_server.py` covers both."
- "Docs-only: no code, no rules, no deploy, no CI. Invariants untouched."

Paste the head SHA and each command with its exit code. List skipped checks and why. Restate invariants touched, residual risk, and rollback. A docs-only diff names the guarantee it leaves untouched.

---

**Notes for contributors (including solo maintainer / multi-agent PRs):**
- `desktop.py`, `alerts.py`, and dashboard-template-only changes may use a lighter checklist, but still need Benefits + Risks + the relevant items.
- Hosted Windows Server 2022/2025 runners do not establish Windows 10/11 or Server 2016/2019 acceptance. Report native, fixture (`tests/windows/Test-TaskInstaller.ps1`), build, lint, and hosted evidence separately. Never run the real installer or scan a live workstation as PR verification.
- Prefer squash-and-merge. The final squashed commit message is the permanent record; keep intermediate agent WIP out of `main`.
- PRs are draft by default until a human marks them ready.

## Suggested merge order of open PRs
_Required on every PR, including a lone one (write "independent, only open PR"). Keep every entry to 3 short lines so it reads on a phone: the PR, its impact, the action._

- **Order:** chronological (lowest PR number first) unless a real dependency exists. Name the dependency in that PR's `Impact:` line.
- **Status:** `Safe ✅` (trial merge clean against current `main`), `Dirty ⚠️` (conflicts, or stacked on something unmerged), `Blocked ⛔` (red CI, unresolved blocking review, or still a draft that is not ready).
- **Trial merge note (required):** say you verified it, with the date and the `main` SHA. Locally: `git fetch origin && git switch --detach origin/main && git merge --no-commit --no-ff origin/<branch>`, then `git merge --abort`. A "Safe" is only true until the next merge into `main`; re-run it right before merging.
- **If a PR is Dirty:** prefer a local rebase (or `git rebase --onto origin/main <old-parent-tip> <branch>` for a stacked child whose parent was squash-merged) over GitHub's "Update branch" button. Force-pushing a rebased branch is fine only on a branch that is yours alone, with `--force-with-lease`, and with the owner's OK.

```markdown
**#45** · Safe 
Impact: Rule pack v1.3, both copies. No dependency.  
Action: Merge first. Trial merge clean vs main.

**#47** · Dirty 
Impact: Guard pins the new rule count; depends on #45.  
Action: After #45 → rebase onto `origin/main` → `--force-with-lease` → re-verify.

## ELI5: Merge Order
Merge the foundation first. If a later PR was written against an older base, rebase it onto the new one so it drops in clean instead of creating a merge commit. We already tested the fit with a trial merge.
```

## ELI5
_Required on every PR, and it must stay the **last heading** in the body. The body's last non-blank line is the stamp below, starting with 🤖 (e.g. `🤖 Last updated: 2026-10-14 15:05 ET`); an automated tool attribution footer may follow it, nothing else. Refresh the stamp whenever you edit the body._

Explain the **whole** diff against `main`, not just the first commit. Re-read it whenever a later commit changes what the PR does. Plain words, no jargon you would not say out loud, but keep the specifics:
Write for the operator: plain but technical, nothing glossed. Cover the whole branch diff against main, later commits included. Say what changed and why, naming files and functions; what could break and where to look; what was run versus only reasoned. Mark guesses. Do not market a feature or soften a gate. No heading after this one. Plain words, no jargon you would not say out loud, but keep the specifics on what is changing, what it touches, what it adds, potential or expected risk, etc .. (Think: McLuhan's tetrad: "What does this Pr's changes enhance? What does this Pr's changes make obsolete? What does this Pr's changes retrieve that had been obsolesced earlier? What does this Pr's changes reverse or flip into when pushed to extremes?"):

- **What was broken or missing**, in one picture or analogy, then the real names (file, function, setting) so you can still find it.
- **What changed**, including every later commit. Say what the new behavior is and what it deliberately does not do.
- **What could still go wrong**, and the exact signal that would show it (a log line, a test, a guard `FAIL` line).
- Be blunt about anything you did not run or could not check.

🤖 Last updated: YYYY-MM-DD HH:MM ET
