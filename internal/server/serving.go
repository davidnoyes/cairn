package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/aloisdeniel/cairn/internal/server/web"
	"github.com/aloisdeniel/cairn/internal/store"
)

// handleArtifactRedirect sends /artifacts/{id} and every path under it to the
// same path under /shared/, so links from before milestone 4 keep working. The
// app origin no longer serves an artifact's files: they render on the
// artifact's content origin, inside the shell. The redirect names no artifact
// data and checks no access; the shell page does.
func (s *Server) handleArtifactRedirect(w http.ResponseWriter, r *http.Request) {
	target := "/shared" + strings.TrimPrefix(r.URL.EscapedPath(), "/artifacts")
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// Shared shell: /shared/{id}[/{vid}] wraps the fullscreen page in a frame
// with artifact metadata and a version picker.

type shellVersion struct {
	*store.Version
	Current bool
}

type shellData struct {
	Artifact *store.Artifact
	Version  *store.Version
	Versions []shellVersion
	User     *store.User
}

func (s *Server) handleShared(w http.ResponseWriter, r *http.Request) {
	a := s.pageArtifact(w, r)
	if a == nil {
		return
	}
	versions, err := s.store.ListVersions(a.ID)
	if err != nil || len(versions) == 0 {
		http.Error(w, "this artifact has no versions yet", http.StatusNotFound)
		return
	}
	current := versions[0]
	if vid := r.PathValue("vid"); vid != "" {
		found := false
		for _, v := range versions {
			if v.ID == vid {
				current, found = v, true
				break
			}
		}
		if !found {
			http.NotFound(w, r)
			return
		}
	}
	if rs, err := s.store.ListResources(a.ID); err == nil {
		a.Resources = rs
	}
	data := shellData{Artifact: a, Version: current}
	for _, v := range versions {
		data.Versions = append(data.Versions, shellVersion{Version: v, Current: v.ID == current.ID})
	}
	if u, err := s.currentUser(r); err == nil {
		data.User = u
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := s.templates().ExecuteTemplate(w, "shell.html", data); err != nil {
		s.log.Error("render shell", "err", err)
	}
}

// Login / logout pages

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// Already logged in? Straight through.
	if u, err := s.currentUser(r); err == nil && u != nil {
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusFound)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := s.templates().ExecuteTemplate(w, "login.html", map[string]any{
		"Next": safeNext(r.URL.Query().Get("next")),
	}); err != nil {
		s.log.Error("render login", "err", err)
	}
}

// handleStaticPage serves a signed-out account page whose template takes no
// data: its script reads everything it needs from the URL.
func (s *Server) handleStaticPage(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if err := s.templates().ExecuteTemplate(w, name, nil); err != nil {
			s.log.Error("render page", "page", name, "err", err)
		}
	}
}

func (s *Server) handleLogoutPage(w http.ResponseWriter, r *http.Request) {
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if u, err := s.currentUser(r); err == nil && u != nil {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// handleAdminPage serves the admin UI; the page itself talks to the JSON
// APIs. Anonymous visitors are sent to login, non-admins get a 403.
func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	u, err := s.currentUser(r)
	if err != nil || u == nil {
		http.Redirect(w, r, "/login?next=/admin", http.StatusFound)
		return
	}
	if !u.IsAdmin {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := s.templates().ExecuteTemplate(w, "admin.html", nil); err != nil {
		s.log.Error("render admin", "err", err)
	}
}

func (s *Server) serveCairnJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(web.CairnJS)
}

// serveMermaidJS serves the vendored Mermaid bundle + auto-render bootstrap
// (see web.MermaidJS). Unlike cairn.js it's versioned with the binary rather
// than the session, so it can be cached.
func (s *Server) serveMermaidJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(web.MermaidJS)
}

// serveShellJS serves the shared shell's link-handling and Mermaid-loading script.
func (s *Server) serveShellJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(web.ShellJS)
}

// serveSqlJS serves the vendored sql.js loader or its WebAssembly module,
// chosen by the last path segment. Like mermaid.js it ships with the binary.
func (s *Server) serveSqlJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=86400")
	if strings.HasSuffix(r.URL.Path, ".wasm") {
		w.Header().Set("Content-Type", "application/wasm")
		w.Write(web.SqlWasm)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Write(web.SqlJS)
}

// appAssets maps a URL path to its file in web.Assets: what the account pages
// load. Modules import each other with relative URLs, so they share one
// directory. The worker's own files are served by the handlers below.
var appAssets = map[string]string{
	"/app.css":           "app.css",
	"/admin.css":         "admin.css",
	"/icon.svg":          "icon.svg",
	"/e2e.mjs":           "e2e.mjs",
	"/account.mjs":       "account.mjs",
	"/keystore.mjs":      "keystore.mjs",
	"/argon2-client.mjs": "argon2-client.mjs",
	"/ui.mjs":            "ui.mjs",
	"/signup.js":         "signup.js",
	"/verify.js":         "verify.js",
	"/login.js":          "login.js",
	"/forgot.js":         "forgot.js",
	"/reset.js":          "reset.js",
	"/admin.js":          "admin.js",
	"/admin-init.mjs":    "admin-init.mjs",
	"/argon2-worker.js":  "argon2-worker.js",
	"/zxcvbn.js":         "vendor/zxcvbn.js",
}

// serveAppAsset serves one embedded file, with a content type from its
// extension. It sets no Content-Security-Policy: the argon2 worker runs
// without Trusted Types enforcement, and the other files are not documents.
// The ETag is a hash of the embedded bytes, computed once, and no-cache makes
// the browser revalidate with it, so an unchanged file costs a 304 rather
// than a download (zxcvbn.js is 822 KB).
func serveAppAsset(file string) http.HandlerFunc {
	contentType := "text/javascript; charset=utf-8"
	switch path.Ext(file) {
	case ".css":
		contentType = "text/css; charset=utf-8"
	case ".svg":
		contentType = "image/svg+xml"
	}
	data, err := web.Assets.ReadFile(file)
	if err != nil {
		panic("app asset " + file + " is not embedded: " + err.Error())
	}
	sum := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("ETag", etag)
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
	}
}

// serveArgon2Wasm serves the vendored Argon2id WebAssembly module. Like
// sql.js it ships with the binary, but it is an app-origin asset only: it is
// not available inside a version's URL space.
func (s *Server) serveArgon2Wasm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Type", "application/wasm")
	w.Write(web.Argon2Wasm)
}

// serveWasmExecJS serves the Go runtime glue that runs argon2.wasm.
func (s *Server) serveWasmExecJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Write(web.WasmExecJS)
}

// templates parses the embedded HTML templates once.
func (s *Server) templates() *template.Template {
	s.tmplOnce.Do(func() {
		s.tmpl = template.Must(template.ParseFS(web.Templates, "*.html"))
	})
	return s.tmpl
}
