# Vendored: Mermaid

`mermaid.min.js` is the official single-file browser bundle from the
`mermaid` npm package, vendored so diagram rendering works offline (no CDN).

- **Version:** 11.17.2
- **Source:** `npm pack mermaid@11` → `package/dist/mermaid.min.js`
  (https://www.npmjs.com/package/mermaid)
- **License:** MIT (Copyright Knut Sveidqvist) — full text in
  `LICENSE.mermaid`. The bundle itself also carries third-party notices
  (DOMPurify, lodash-es, cytoscape, all MIT/Apache-2.0/MPL-2.0) in a trailing
  comment block; nothing here is modified from upstream.

Loading it sets `window.mermaid`. `internal/server/web/mermaid-boot.js` is
appended at serve time to normalize markup and call `mermaid.run()` — see
`internal/server/serving.go` (`serveMermaidJS`).

To upgrade: `npm pack mermaid@<version>` in a scratch directory, replace both
files here, and bump the version noted above.
