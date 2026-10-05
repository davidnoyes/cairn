#!/usr/bin/env bash
# Runs every Go fuzz test in the repository for FUZZTIME each (default 60s).
# Go fuzzes one target per invocation, so this finds them and loops.
#
# Usage: scripts/fuzz.sh            FUZZTIME=10s scripts/fuzz.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FUZZTIME="${FUZZTIME:-60s}"
unset CAIRN_HOST CAIRN_API_KEY

cd "$ROOT"
out="$(mktemp)"
trap 'rm -f "$out"' EXIT
found=0
while IFS=: read -r file name; do
  found=$((found + 1))
  pkg="./$(dirname "$file")"
  echo "== $pkg $name ($FUZZTIME)"
  # Go sometimes fails a clean run at the -fuzztime boundary with "context
  # deadline exceeded" (golang/go#75804). A real failure writes its input to
  # testdata, so retry once only when none was written.
  for attempt in 1 2; do
    if go test "$pkg" -run '^$' -fuzz "^${name}\$" -fuzztime "$FUZZTIME" 2>&1 | tee "$out"; then
      break
    fi
    if [[ "$attempt" -eq 2 ]] || grep -q 'Failing input written' "$out" || ! grep -q 'context deadline exceeded' "$out"; then
      exit 1
    fi
    echo "== $name: deadline flake with no failing input; retrying once"
  done
done < <(git grep -o -E '^func Fuzz[A-Za-z0-9_]+' -- '*_test.go' | sed -E 's/:func /:/')

if [[ "$found" -eq 0 ]]; then
  echo "no fuzz tests found" >&2
  exit 1
fi
echo "fuzzed $found targets"
