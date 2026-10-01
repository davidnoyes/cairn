#!/usr/bin/env bash
# Mutation checks: proves the tests notice when a critical check breaks.
# Applies each mutation in scripts/mutations.txt to a scratch copy of the
# tree, runs its command, and fails if any mutation survives (the command
# passes) or no longer applies (the search text is gone).
#
# Usage: scripts/mutate.sh [filter]   # filter: only lines containing it
# MUTATIONS=path overrides the list, to try a new entry on its own.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIST="${MUTATIONS:-$ROOT/scripts/mutations.txt}"
FILTER="${1:-}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
unset CAIRN_HOST CAIRN_API_KEY
export CAIRN_CONFIG="$WORK/config.json"

survived=0
total=0
while IFS=$'\t' read -r file search replace cmd; do
  [[ -z "$file" || "$file" == \#* ]] && continue
  if [[ -n "$FILTER" && "$file$search$cmd" != *"$FILTER"* ]]; then
    continue
  fi
  total=$((total + 1))
  tree="$WORK/tree"
  rm -rf "$tree"
  mkdir -p "$tree"
  (cd "$ROOT" && git ls-files -z --cached --others --exclude-standard | xargs -0 -I{} rsync -R "{}" "$tree/") 2>/dev/null
  if [[ -d "$ROOT/node_modules" ]]; then
    ln -s "$ROOT/node_modules" "$tree/node_modules"
  fi
  if ! python3 - "$tree/$file" "$search" "$replace" <<'PY'
import sys
path, search, replace = sys.argv[1:4]
text = open(path, encoding="utf-8").read()
n = text.count(search)
if n != 1:
    sys.exit(f"search text occurs {n} times, want exactly 1")
open(path, "w", encoding="utf-8").write(text.replace(search, replace, 1))
PY
  then
    printf '  \033[31m✗ does not apply:\033[0m %s: %s\n' "$file" "$search"
    survived=$((survived + 1))
    continue
  fi
  if (cd "$tree" && bash -c "$cmd") >"$WORK/out" 2>&1; then
    printf '  \033[31m✗ survived:\033[0m %s: %s\n' "$file" "$search"
    survived=$((survived + 1))
  elif grep -qE '\[(build|setup) failed\]|SyntaxError' "$WORK/out"; then
    printf '  \033[31m✗ does not compile:\033[0m %s: %s\n' "$file" "$search"
    survived=$((survived + 1))
  else
    printf '  \033[32m✓ killed:\033[0m %s: %s\n' "$file" "$search"
  fi
done <"$LIST"

echo "$((total - survived))/$total mutations killed"
[[ $survived -eq 0 ]]
