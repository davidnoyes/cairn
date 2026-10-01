#!/usr/bin/env bash
# Rebuilds the vendored Argon2id WebAssembly module and copies the matching
# wasm_exec.js glue from the Go toolchain. Run after any change to
# cmd/argon2wasm or after a Go version bump, then commit the result — see
# internal/server/web/vendor/README.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/internal/server/web/vendor"

# The output bytes depend on the Go version, so the build pins one. CI checks
# that a rebuild matches the committed files; bump this with the rebuild.
export GOTOOLCHAIN=go1.27.1

GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
  -o "$OUT/argon2.wasm" "$ROOT/cmd/argon2wasm"

cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$OUT/wasm_exec.js"
