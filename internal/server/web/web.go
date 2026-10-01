// Package web holds the embedded browser-facing assets: HTML templates for
// the login page, shared shell and admin UI, the cairn.js client library, and
// a vendored Mermaid bundle for diagram rendering. Everything is
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
