# Skills

| Skill | Purpose | Entry |
|---|---|---|
| [`invariant-guard`](invariant-guard/SKILL.md) | Deterministic check that the design invariants (loopback bind and upload, closed auth, pinned caps, twin rule pack, dependency fence) still hold | `python .agents/skills/invariant-guard/check_invariants.py`; `bash .agents/skills/invariant-guard/verify.sh` after editing the checker |
| [`wynshield-optimizer`](wynshield-optimizer/SKILL.md) | Manual, evidence-backed audit that delivers focused draft PRs when authorized | `bash .agents/skills/wynshield-optimizer/bootstrap.sh [branch [base]]` |

CI runs the invariant guard and its self-test on every push and pull request.
