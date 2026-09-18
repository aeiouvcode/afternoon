#!/usr/bin/env bash
# Afternoon pre-push secret scan.
# Refuses the push when anything shaped like a real credential appears in
# tracked files. Placeholders in the UI use an ellipsis (thk_live_…, sk-or-v1-…)
# and never match. Prints file:line only, never the matched text.
set -euo pipefail
cd "$(dirname "$0")"
fail=0
labels=(
  'Token Harbor key'
  'API key (sk-...)'
  'GitHub fine-grained PAT'
  'GitHub token'
  'bearer token'
  'hardcoded credential'
)
pats=(
  'thk_live_[A-Za-z0-9]{8,}'
  'sk-[A-Za-z0-9_-]{20,}'
  'github_pat_[A-Za-z0-9_]{20,}'
  'ghp_[A-Za-z0-9]{30,}'
  'Bearer[[:space:]]+[A-Za-z0-9._~+/-]{16,}'
  "(password|passwd|passphrase|secret|api[_-]?key)[\"'[:space:]]*[:=][\"'[:space:]]*[\"'][^\"']{8,}"
)
for i in "${!pats[@]}"; do
  out=$(grep -REn --exclude=scan.sh --exclude-dir=.git -- "${pats[$i]}" . 2>/dev/null | cut -d: -f1,2 || true)
  if [ -n "$out" ]; then
    echo "REFUSED: possible ${labels[$i]} at:" >&2
    echo "$out" >&2
    fail=1
  fi
done
if [ "$fail" -ne 0 ]; then
  echo "Push refused: secret scan found matches." >&2
  exit 1
fi
echo "Secret scan: clean."
