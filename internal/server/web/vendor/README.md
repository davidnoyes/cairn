# Vendored third-party files

Each file here is copied unmodified from its upstream package, so the server
works offline and loads nothing from a CDN.

## Mermaid

`mermaid.min.js` is the official single-file browser bundle from the
`mermaid` npm package.

- **Version:** 11.17.2.
- **Source:** `npm pack mermaid@11` → `package/dist/mermaid.min.js`, from
  [Mermaid on npm](https://www.npmjs.com/package/mermaid).
- **License:** the MIT License, copyright Knut Sveidqvist. The full text is in
  `LICENSE.mermaid`. The bundle also carries third-party notices for
  DOMPurify, lodash-es, and cytoscape, under the MIT, Apache-2.0, and MPL-2.0
  licenses, in a trailing comment block.

Loading it sets `window.mermaid`. The server appends
`internal/server/web/mermaid-boot.js` at serve time to normalize markup and
call `mermaid.run()`. See `serveMermaidJS` in `internal/server/serving.go`.

## SQLite in WebAssembly

`sql-wasm.js` and `sql-wasm.wasm` are the SQLite-in-WebAssembly build from the
`sql.js` npm package. `cairn.js` loads them from the server.

- **Version:** 1.14.2.
- **Source:** `npm pack sql.js@1.14.2` → `package/dist/sql-wasm.js` and
  `package/dist/sql-wasm.wasm`, from
  [sql.js on npm](https://www.npmjs.com/package/sql.js).
- **License:** the MIT License, copyright the sql.js authors. The full text is
  in `LICENSE.sqljs`.

The server serves both at `/sql-wasm.js` and `/sql-wasm.wasm`, and inside every
version's URL space next to `cairn.js`.

## Argon2id

`argon2.wasm` and `wasm_exec.js` let the browser stretch a password with
Argon2id, matching the parameters the server returns from prelogin (see
"Password stretching" in `design/e2e-wire-formats.md`).

- **Source:** `argon2.wasm` is built from `cmd/argon2wasm`, which calls
  `golang.org/x/crypto/argon2` at the version pinned in `go.mod`
  (currently v0.54.0). `wasm_exec.js` is the Go runtime's own WebAssembly
  glue, copied from `$(go env GOROOT)/lib/wasm/wasm_exec.js`.
- **License:** the BSD-3-Clause License, copyright the Go Authors. The full
  text is in `LICENSE.golang` (not `LICENSE.go`: that extension would make
  the Go toolchain try to compile it as source).
- **Rebuilding:** run `scripts/build-argon2-wasm.sh` (or
  `go generate ./internal/server/web`) and commit the result. The build is
  reproducible: `GOOS=js GOARCH=wasm go build -trimpath` with a stripped,
  empty build ID, and the script pins the Go toolchain with `GOTOOLCHAIN`,
  so every rebuild produces the same bytes. CI checks that it does.

The server serves both at `/argon2.wasm` and `/wasm_exec.js`.
`internal/server/web/argon2.mjs` loads them to derive a key in the main
thread; `argon2-worker.js` does the same off the UI thread.

## Password strength (zxcvbn)

`zxcvbn.js` is the password strength estimator the sign-up and reset pages
load. The browser scores a new password with it, and refuses one below 3.

- **Version:** 4.4.2.
- **Source:** `npm pack zxcvbn@4.4.2` → `package/dist/zxcvbn.js`, from
  [zxcvbn on npm](https://www.npmjs.com/package/zxcvbn). The tarball's
  integrity matched the registry's sha512 value.
- **License:** the MIT License. Dan Wheeler and Dropbox hold the copyright.
  The full text is in `LICENSE.zxcvbn`.

Loading it sets `window.zxcvbn`. The server serves it at `/zxcvbn.js`, and
only the sign-up and reset pages load it.

## Checksums

`SHA256SUMS` pins every vendored file. `vendor_test.go` fails when a file
changes, or when a file is missing from the list.

## Upgrading

1. In a scratch directory, run `npm pack <package>@<version>` and unpack it.
2. Replace the files here, and update the version in this README.
3. Regenerate the checksums in this directory:

   ```sh
   shasum -a 256 argon2.wasm mermaid.min.js sql-wasm.js sql-wasm.wasm \
     wasm_exec.js zxcvbn.js > SHA256SUMS
   ```
