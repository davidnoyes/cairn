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

## Checksums

`SHA256SUMS` pins every vendored file. `vendor_test.go` fails when a file
changes, or when a file is missing from the list.

## Upgrading

1. In a scratch directory, run `npm pack <package>@<version>` and unpack it.
2. Replace the files here, and update the version in this README.
3. Regenerate the checksums in this directory:

   ```sh
   shasum -a 256 mermaid.min.js sql-wasm.js sql-wasm.wasm > SHA256SUMS
   ```
