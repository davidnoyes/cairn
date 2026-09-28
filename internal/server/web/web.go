// Package web holds the embedded browser-facing assets: HTML templates for
// the login page, shared shell and admin UI, plus the cairn.js client
// library. Everything is self-contained — no CDNs, no build step.
package web

import "embed"

//go:embed *.html
var Templates embed.FS

//go:embed cairn.js
var CairnJS []byte

//go:embed shell.js
var ShellJS []byte
