// Package web holds the embedded browser-facing assets: HTML templates for
// the account pages, shared shell and admin UI, the cairn.js client library,
// the account pages' scripts, and a vendored Mermaid bundle for diagram
// rendering. Everything is
// self-contained — no CDNs, no build step.
package web

import "embed"

//go:embed *.html
var Templates embed.FS

//go:embed cairn.js
var CairnJS []byte

//go:embed vendor/mermaid.min.js
var mermaidLib []byte

//go:embed mermaid-boot.js
var mermaidBoot []byte

// MermaidJS is served at /mermaid.js: the vendored Mermaid bundle (see
// vendor/README.md) followed by the auto-render bootstrap.
var MermaidJS = buildMermaidJS()

func buildMermaidJS() []byte {
	out := make([]byte, 0, len(mermaidLib)+1+len(mermaidBoot))
	out = append(out, mermaidLib...)
	out = append(out, '\n')
	out = append(out, mermaidBoot...)
	return out
}

//go:embed shell.js
var ShellJS []byte

// Assets holds the files the account pages load: styles, the page scripts
// and the modules they import, the argon2 worker, and the vendored strength
// estimator. The server serves each at the path listed in appAssets.
//
//go:embed app.css admin.css icon.svg
//go:embed e2e.mjs account.mjs keystore.mjs argon2-client.mjs ui.mjs content.mjs sw.js
//go:embed signup.js verify.js login.js forgot.js reset.js admin.js admin-init.mjs argon2-worker.js
//go:embed vendor/zxcvbn.js
var Assets embed.FS

// SqlJS and SqlWasm are the vendored sql.js loader and its WebAssembly
// module (see vendor/README.md).
//
//go:embed vendor/sql-wasm.js
var SqlJS []byte

//go:embed vendor/sql-wasm.wasm
var SqlWasm []byte

// Argon2Wasm and WasmExecJS are the vendored Argon2id WebAssembly module and
// the Go runtime glue needed to run it (see vendor/README.md).
//
//go:embed vendor/argon2.wasm
var Argon2Wasm []byte

//go:embed vendor/wasm_exec.js
var WasmExecJS []byte

// ContentAssets holds the files an artifact's content origin serves under
// /_cairn/, besides cairn.js, Mermaid, and sql.js, which are served from the
// variables above. Its pages load them and the service worker never
// intercepts them.
//
//go:embed boot.js sw.js frame.js content.mjs e2e.mjs
var ContentAssets embed.FS
