#!/usr/bin/env bash
# invariant-guard verify: clean-tree pass, then a mutation self-test.
# Stdlib only; safe before any pip install. Exit 0 = the checker is healthy.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../../.." && pwd)"
checker="$here/check_invariants.py"
pkg="src/wyndoze_infoscanoverload"

echo "== invariant-guard verify =="

# 1. The real tree must pass.
if python3 "$checker" --repo-root "$repo_root" > /dev/null; then
  echo "clean tree: PASS"
else
  python3 "$checker" --repo-root "$repo_root" | grep FAIL >&2
  echo "clean tree: FAIL (an invariant is violated on the current tree)" >&2
  exit 1
fi

# 2. A copy with planted violations must fail with exit 2, one FAIL per plant.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp -r "$repo_root/src" "$repo_root/rules" "$repo_root/deploy" "$repo_root/pyproject.toml" "$tmp"/

plant() {  # plant <file> <sed-script> <grep-proof-that-it-applied>
  local file="$1" edit="$2" proof="$3"
  sed -i.bak "$edit" "$tmp/$file" && rm -f "$tmp/$file.bak"
  grep -q -- "$proof" "$tmp/$file" || { echo "mutation did not apply to $file" >&2; exit 1; }
}

# A. Widen the bind allowlist (L1).
plant "$pkg/server/__main__.py" 's/frozenset({"127.0.0.1", "::1"})/frozenset({"127.0.0.1", "::1", "0.0.0.0"})/' '0.0.0.0'
# B. Re-open the docs route (T1).
plant "$pkg/server/app.py" 's/docs_url=None,/docs_url="\/docs",/' 'docs_url="/docs"'
# C. Unsafe YAML in the rules engine (S1).
printf '\n_PLANT = yaml.load("a: 1", Loader=yaml.Loader)\n' >> "$tmp/$pkg/core/rules.py"
# D. shell=True and a file read in the collectors (S2, C1).
printf '\n_PLANT = subprocess.run(["x"], shell=True, check=False)\n_PLANT2 = open("x")\n' >> "$tmp/$pkg/agent/collectors.py"
# E. The agent reaching into the server (M1).
printf '\nfrom wyndoze_infoscanoverload.server import app as _plant\n' >> "$tmp/$pkg/agent/uploader.py"
# F. Edit one rule-pack copy only (R1).
printf '\n# planted drift\n' >> "$tmp/rules/windows_default.yaml"
# G. A new rule kind (R2).
plant "$pkg/core/rules.py" 's/"cmdline_flag",/"cmdline_flag",\n        "file_hash",/' 'file_hash'
# H. Raise the ingest cap (C2).
plant "$pkg/server/app.py" 's/_MAX_INGEST_BYTES = 8 \* 1024 \* 1024/_MAX_INGEST_BYTES = 64 * 1024 * 1024/' '64 \* 1024'

out="$(python3 "$checker" --repo-root "$tmp" 2>&1)"
rc=$?
if [ "$rc" -ne 2 ]; then
  echo "mutation test: FAIL (expected exit 2 on the planted tree, got $rc)" >&2
  echo "$out" >&2
  exit 1
fi

expect=(
  "FAIL L1 server _LOOPBACK_HOSTS"
  "FAIL T1 FastAPI(docs_url=None)"
  "FAIL S1 no unsafe yaml"
  "FAIL S2 no shell=True"
  "FAIL C1 agent/collectors.py opens"
  "FAIL M1 agent/ imports none"
  "FAIL R1 rules/ and core/rulepacks/"
  "FAIL R2 _VALID_KINDS"
  "FAIL C2 server/app.py _MAX_INGEST_BYTES"
)
for line in "${expect[@]}"; do
  echo "$out" | grep -qF -- "$line" || { echo "mutation test: not detected: $line" >&2; echo "$out" >&2; exit 1; }
done
echo "mutation test: PASS (${#expect[@]} planted violations detected, exit 2)"

# 3. A wrong root is an environment error, not a pass.
python3 "$checker" --repo-root "$tmp/deploy" > /dev/null 2>&1
rc=$?
[ "$rc" -eq 3 ] || { echo "env test: FAIL (expected exit 3 for a wrong root, got $rc)" >&2; exit 1; }
echo "env test: PASS (wrong root exits 3)"

echo "== invariant-guard verify: OK =="
