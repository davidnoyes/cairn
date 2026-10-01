package web

// Rebuilds the vendored Argon2id WebAssembly module and its wasm_exec.js
// glue; see vendor/README.md.
//go:generate ../../../scripts/build-argon2-wasm.sh
