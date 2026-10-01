package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/aloisdeniel/cairn/internal/server/web"
	"github.com/aloisdeniel/cairn/internal/store"
)

func artifactPageHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Allow embedding only by our own shell frame.
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
}

// handleArtifactRedirect sends /artifacts/{id} to the latest version's
// canonical URL so every relative asset resolves inside one version. The {id}
// may be a resource reference (e.g. a Claude session id); the redirect
// canonicalizes it to the artifact id.
func (s *Server) handleArtifactRedirect(w http.ResponseWriter, r *http.Request) {
	a := s.pageArtifact(w, r)
	if a == nil {
		return
	}
	v, err := s.store.LatestVersion(a.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "this artifact has no versions yet", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/artifacts/"+a.ID+"/"+v.ID+"/", http.StatusFound)
}

// handleVersionPage serves the files of one version. The path shape is
// /artifacts/{id}/{vid}/{path...} — a trailing-slash canonical base URL, so
// relative routing inside the SPA needs no rewriting at all.
func (s *Server) handleVersionPage(w http.ResponseWriter, r *http.Request) {
	a := s.pageArtifact(w, r)
	if a == nil {
		return
	}
	v, err := s.store.VersionByID(a.ID, r.PathValue("vid"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rel := r.PathValue("path")
	artifactPageHeaders(w)
	s.serveVersionFile(w, r, a, v, rel)
}

// handleVersionNoSlash canonicalizes /artifacts/{id}/{vid} (no trailing
// slash) so relative asset paths resolve inside the version.
func (s *Server) handleVersionNoSlash(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
}

func (s *Server) serveVersionFile(w http.ResponseWriter, r *http.Request, a *store.Artifact, v *store.Version, rel string) {
	root := s.layout.ContentDir(a.ID, v.ContentDir)
	clean, ok := cleanRequestPath(rel)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if clean == "" {
		clean = "index.html"
	}
	// cairn.js is always available inside a version's URL space so artifacts
	// can load it with a relative <script src="./cairn.js"> that also works
	// when the directory is opened locally (drop the file next to index.html).
	if clean == "cairn.js" {
		if _, err := os.Stat(filepath.Join(root, "cairn.js")); err != nil {
			s.serveCairnJS(w, r)
			return
		}
	}
	// mermaid.js is likewise always available so artifacts can render
	// ```mermaid fences with a relative <script src="./mermaid.js">.
	if clean == "mermaid.js" {
		if _, err := os.Stat(filepath.Join(root, "mermaid.js")); err != nil {
			s.serveMermaidJS(w, r)
			return
		}
	}
	// The vendored sql.js is likewise available next to cairn.js, which
	// looks for it there before anywhere else.
	if clean == "sql-wasm.js" || clean == "sql-wasm.wasm" {
		if _, err := os.Stat(filepath.Join(root, clean)); err != nil {
			s.serveSqlJS(w, r)
			return
		}
	}
	target := filepath.Join(root, filepath.FromSlash(clean))
	st, err := os.Stat(target)
	if err == nil && st.IsDir() {
		idx := filepath.Join(target, "index.html")
		if _, ierr := os.Stat(idx); ierr == nil {
			// Directories need a trailing slash for relative resolution.
			if !strings.HasSuffix(r.URL.Path, "/") {
				http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
				return
			}
			target, st, err = idx, nil, nil
			if st, err = os.Stat(idx); err != nil {
				http.NotFound(w, r)
				return
			}
		} else {
			http.NotFound(w, r)
			return
		}
	}
	if err != nil {
		// SPA fallback: extension-less paths negotiated as HTML get
		// index.html; real assets 404 so missing files fail loudly.
		if path.Ext(clean) == "" && acceptsHTML(r) {
			http.ServeFile(w, r, filepath.Join(root, "index.html"))
			return
		}
		http.NotFound(w, r)
		return
	}
	if !st.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	// Defense in depth: never follow a path that escapes the version dir.
	if resolved, err := filepath.EvalSymlinks(target); err != nil || !strings.HasPrefix(resolved+string(filepath.Separator), mustEval(root)+string(filepath.Separator)) {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, target)
}

func mustEval(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
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
		return http.NotFound
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
