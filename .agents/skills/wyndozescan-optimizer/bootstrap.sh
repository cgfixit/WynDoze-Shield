#!/usr/bin/env bash
# bootstrap.sh: WynDoze-Optimize harness.
#
# The scriptable half of the WynDoze-Optimize workflow, so the agent spends its
# budget reading code and writing PRs.
#
#   1. Reports the git identity commits will carry.
#   2. Fetches origin and, when given a branch name, positions on it: an existing
#      branch is checked out without a reset; a new one is cut from BASE
#      (default origin/main; pass a parent branch to stack).
#   3. Prints a scan seed: unmerged remote branches, file counts, largest
#      modules, CI workflows, manifests, the invariant checker summary, and
#      recent commits on main.
#
# It does not call the GitHub API (PR dedup is an MCP step), edit code, or
# commit.
#
# Usage:
#   bash .agents/skills/wyndozescan-optimizer/bootstrap.sh [work-branch [base-ref]]

set -euo pipefail

WORK_BRANCH="${1:-}"
BASE_REF="${2:-origin/main}"
PKG="src/wyndoze_infoscanoverload"

hr() { printf '%s\n' "------------------------------------------------------------"; }

hr
# git var honours GIT_AUTHOR_*/GIT_COMMITTER_* env, which outrank user.name.
author=$(git var GIT_AUTHOR_IDENT 2>/dev/null | sed -E 's/ [0-9]+ [-+][0-9]{4}$//') || true
committer=$(git var GIT_COMMITTER_IDENT 2>/dev/null | sed -E 's/ [0-9]+ [-+][0-9]{4}$//') || true
if [ -z "$author" ] || [ -z "$committer" ]; then
  echo "git identity: incomplete (author: ${author:-none}, committer: ${committer:-none})"
elif [ "$author" = "$committer" ]; then
  echo "git identity: $committer"
else
  echo "git identity: author $author, committer $committer"
fi

echo "fetching origin ..."
git fetch origin --prune --quiet || echo "WARN: fetch failed (offline?), using local refs"

if [ -n "$WORK_BRANCH" ]; then
  if git show-ref --verify --quiet "refs/heads/${WORK_BRANCH}"; then
    echo "branch '${WORK_BRANCH}' exists, checking it out (no reset)"
    git checkout --quiet "$WORK_BRANCH"
  else
    echo "creating '${WORK_BRANCH}' from ${BASE_REF}"
    git checkout --quiet -b "$WORK_BRANCH" "$BASE_REF"
  fi
fi
hr
echo "current branch: $(git rev-parse --abbrev-ref HEAD)"
echo "commits ahead of origin/main: $(git rev-list --count origin/main..HEAD 2>/dev/null || echo '?')"
echo "commits behind origin/main:   $(git rev-list --count HEAD..origin/main 2>/dev/null || echo '?')"

hr
echo "SCAN SEED"
hr

echo "## Remote branches with commits not on main (open-PR or abandoned work; dedup against these too)"
found=0
while read -r ref; do
  [ "$ref" = "origin/main" ] || [ "$ref" = "origin/HEAD" ] && continue
  ahead=$(git rev-list --count "origin/main..$ref" 2>/dev/null || echo 0)
  if [ "$ahead" -gt 0 ]; then
    found=1
    printf '  %-48s +%s  %s\n' "$ref" "$ahead" "$(git log -1 --format='%cs %s' "$ref" | cut -c1-70)"
  fi
done < <(git for-each-ref --format='%(refname:short)' refs/remotes/origin)
[ "$found" -eq 1 ] || echo "  (none)"

echo
echo "## File counts by area"
for d in "$PKG/agent" "$PKG/core" "$PKG/server" "$PKG/desktop.py" "$PKG/alerts.py" \
         rules deploy tests/unit tests/integration .github .agents; do
  if [ -d "$d" ]; then
    printf '  %-40s %s files\n' "$d/" "$(find "$d" -type f -not -path '*/__pycache__/*' | wc -l | tr -d ' ')"
  elif [ -f "$d" ]; then
    printf '  %-40s %s lines\n' "$d" "$(wc -l < "$d" | tr -d ' ')"
  fi
done

echo
echo "## Largest Python modules (size is a lead, not a defect)"
find src tests -name '*.py' -not -path '*/__pycache__/*' -exec wc -l {} + 2>/dev/null \
  | sort -rn | sed -n '2,11p'

echo
echo "## CI workflows"
ls -1 .github/workflows/ 2>/dev/null | sed 's/^/  /' || echo "  (none)"

echo
echo "## Manifests (pyproject.toml is the source of truth)"
for f in pyproject.toml requirements.txt constraints.txt .python-version; do
  [ -f "$f" ] && printf '  %-20s %s lines\n' "$f" "$(wc -l < "$f" | tr -d ' ')"
done

echo
echo "## Invariant checker (stdlib, no install)"
if [ -f .agents/skills/invariant-guard/check_invariants.py ]; then
  python3 .agents/skills/invariant-guard/check_invariants.py | grep -E 'FAIL|passed' | sed 's/^/  /' || true
else
  echo "  (invariant-guard not on this branch)"
fi

echo
echo "## Recent commits on main (do not redo landed work)"
git log origin/main --oneline -n 12 2>/dev/null | sed 's/^/  /'

hr
echo "Next: compare open PRs and remote branches, then read the affected code (SKILL.md)."
