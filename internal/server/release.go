package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"sort"

	"github.com/aloisdeniel/cairn/internal/release"
	"github.com/aloisdeniel/cairn/internal/server/web"
)

// ReleaseManifest lists what this binary sends a browser: every embedded
// file, by origin and path, with its SHA-256, and the source of every HTML
// template. It reads the same tables the routes serve from, so the release
// tool signs exactly what the server delivers.
func ReleaseManifest(version string) (release.Manifest, error) {
	m := release.Manifest{V: 1, Version: version}
	add := func(origin, path string, data []byte) {
		sum := sha256.Sum256(data)
		m.Assets = append(m.Assets, release.Asset{Origin: origin, Path: path, SHA256: hex.EncodeToString(sum[:])})
	}
	for path, file := range appAssets {
		data, err := web.Assets.ReadFile(file)
		if err != nil {
			return m, err
		}
		add(release.OriginApp, path, data)
	}
	for path, data := range map[string][]byte{
		"/cairn.js":      web.CairnJS,
		"/mermaid.js":    web.MermaidJS,
		"/sql-wasm.js":   web.SqlJS,
		"/sql-wasm.wasm": web.SqlWasm,
		"/argon2.wasm":   web.Argon2Wasm,
		"/wasm_exec.js":  web.WasmExecJS,
	} {
		add(release.OriginApp, path, data)
	}
	for path, a := range contentAssets {
		add(release.OriginContent, path, a.data)
	}
	sort.Slice(m.Assets, func(i, j int) bool {
		if m.Assets[i].Origin != m.Assets[j].Origin {
			return m.Assets[i].Origin < m.Assets[j].Origin
		}
		return m.Assets[i].Path < m.Assets[j].Path
	})
	names, err := fs.Glob(web.Templates, "*.html")
	if err != nil {
		return m, err
	}
	for _, name := range names {
		src, err := fs.ReadFile(web.Templates, name)
		if err != nil {
			return m, err
		}
		m.Templates = append(m.Templates, release.Template{Name: name, Source: string(src)})
	}
	return m, nil
}

// handleWellKnownRelease serves the signed release manifest the binary
// embeds, or null when it has none, with the origins cairn verify needs:
// the app origin, and the content origin with * for the artifact ID. Only
// the manifest is signed; a verifier that trusts the origins checks them
// against the pages it renders.
func (s *Server) handleWellKnownRelease(w http.ResponseWriter, r *http.Request) {
	var manifest json.RawMessage
	if len(release.Signed) > 0 {
		manifest = release.Signed
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"manifest":      manifest,
		"appOrigin":     s.appOrigin,
		"contentOrigin": s.contentOrigin("*"),
	})
}
