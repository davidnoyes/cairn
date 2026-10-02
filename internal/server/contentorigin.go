package server

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/server/web"
	"github.com/google/uuid"
)

// The content origin: each artifact renders on its own host,
// <artifact ID>.<content domain>, which serves only the boot page, the worker
// and its scripts, and the content-token API for that one artifact. See
// design/e2e-api.md (Encrypted content and serving).

// initContent derives what content-host routing and content URLs need from the
// public URL, the listen address, and the resolved content domain.
func (s *Server) initContent() {
	s.contentDomain = s.cfg.ContentDomain
	s.appOrigin = originOf(s.cfg.PublicURL)
	port := ""
	if s.cfg.PublicURL != "" {
		if u, err := url.Parse(s.cfg.PublicURL); err == nil {
			s.appHost = normalizeHost(u.Hostname())
			port = u.Port()
			if u.Scheme == "https" && port == "443" || u.Scheme == "http" && port == "80" {
				port = ""
			}
		}
	} else if _, p, err := net.SplitHostPort(s.cfg.Addr); err == nil && p != "80" {
		port = p
	}
	if port != "" {
		s.contentPort = ":" + port
	}
}

// hostName returns the lowercase host name of a Host header: no port, and no
// brackets around an IPv6 literal.
func hostName(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

// contentArtifactOf returns the artifact a Host header names: a single
// lowercase canonical UUID label followed by the content domain. Only the host
// name counts; the port is ignored, as a browser omits a default one.
func (s *Server) contentArtifactOf(host string) (string, bool) {
	label, ok := strings.CutSuffix(hostName(host), "."+s.contentDomain)
	if !ok || len(label) != 36 {
		return "", false
	}
	if _, err := uuid.Parse(label); err != nil {
		return "", false
	}
	return label, true
}

// inContentDomain reports whether a Host header names the content domain or
// anything under it, with or without a trailing dot. The content domain itself
// is not, when it is also the app's host (a localhost content domain beside a
// localhost public URL, or none).
func (s *Server) inContentDomain(host string) bool {
	name := strings.TrimSuffix(hostName(host), ".")
	if name == s.contentDomain {
		return name != s.appHost && !(s.appHost == "" && isLocalHost(name))
	}
	return strings.HasSuffix(name, "."+s.contentDomain)
}

// routeByHost sends a request for a content host to the content origin's
// routes and every other request to app. A host under the content domain that
// is no artifact's content host is a 404. It sits at the top of the handler
// chain, so nothing under the content domain reaches an app route.
func (s *Server) routeByHost(app http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := s.contentArtifactOf(r.Host); ok {
			s.serveContentOrigin(w, r, id)
			return
		}
		if s.inContentDomain(r.Host) {
			w.Header().Set("Cache-Control", "no-store")
			http.NotFound(w, r)
			return
		}
		app.ServeHTTP(w, r)
	})
}

// contentAsset is one file served under /_cairn/.
type contentAsset struct {
	data        []byte
	contentType string
	headers     map[string]string
}

// contentAssets is the allowlist of /_cairn/ files, by request path.
var contentAssets = buildContentAssets()

func buildContentAssets() map[string]contentAsset {
	const js = "text/javascript; charset=utf-8"
	assets := map[string]contentAsset{
		"/_cairn/cairn.js":      {data: web.CairnJS, contentType: js},
		"/_cairn/mermaid.js":    {data: web.MermaidJS, contentType: js},
		"/_cairn/sql-wasm.js":   {data: web.SqlJS, contentType: js},
		"/_cairn/sql-wasm.wasm": {data: web.SqlWasm, contentType: "application/wasm"},
	}
	for _, name := range []string{"boot.js", "sw.js", "frame.js", "content.mjs", "e2e.mjs"} {
		data, err := web.ContentAssets.ReadFile(name)
		if err != nil {
			panic("content asset " + name + " is not embedded: " + err.Error())
		}
		assets["/_cairn/"+name] = contentAsset{data: data, contentType: js}
	}
	sw := assets["/_cairn/sw.js"]
	sw.headers = map[string]string{"Service-Worker-Allowed": "/"}
	assets["/_cairn/sw.js"] = sw
	return assets
}

// contentHTMLHeaders sets the headers every HTML response on a content host
// carries: only the app origin may frame it.
func (s *Server) contentHTMLHeaders(w http.ResponseWriter) {
	ancestors := "'none'"
	if s.appOrigin != "" {
		ancestors = s.appOrigin
	}
	w.Header().Set("Content-Security-Policy", "frame-ancestors "+ancestors)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
}

// serveContentOrigin answers a request whose Host names artifactID's content
// host. It ignores cookies, serves only the routes of the content origin, and
// answers anything else 404.
func (s *Server) serveContentOrigin(w http.ResponseWriter, r *http.Request, artifactID string) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	r.Header.Del("Cookie")
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/"):
		s.serveContentAPI(w, r, artifactID)
	case read && contentAssets[r.URL.Path].data != nil:
		a := contentAssets[r.URL.Path]
		w.Header().Set("Content-Type", a.contentType)
		w.Header().Set("Cache-Control", "no-cache")
		for k, v := range a.headers {
			w.Header().Set(k, v)
		}
		w.Write(a.data)
	case read && (r.URL.Path == "/_cairn/boot" || acceptsHTML(r)):
		s.contentHTMLHeaders(w)
		if err := s.templates().ExecuteTemplate(w, "boot.html", map[string]string{"AppOrigin": s.appOrigin}); err != nil {
			s.log.Error("render boot page", "err", err)
		}
	default:
		http.NotFound(w, r)
	}
}

// serveContentAPI dispatches an /api/ request on a content host to the app's
// handlers, but only for the routes in contentTokenRoutes. The request carries
// no cookie. An Authorization header must be a content-origin token for this
// host's artifact. Artifact routes then resolve their {id} to that artifact
// alone (see artifactRoute).
func (s *Server) serveContentAPI(w http.ResponseWriter, r *http.Request, artifactID string) {
	if _, pattern := s.mux.Handler(r); !contentTokenRoutes[pattern] {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if h := r.Header.Get("Authorization"); h != "" && !s.isContentTokenFor(h, artifactID) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contentHostCtxKey, artifactID)))
}

// isContentTokenFor reports whether an Authorization header value is a
// validly signed content-origin token whose art claim names artifactID. An API
// key and an ordinary sign-in token are not.
func (s *Server) isContentTokenFor(header, artifactID string) bool {
	tok, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || isAPIKeyBearer(tok) {
		return false
	}
	claims, err := auth.VerifyJWT(s.secret, tok)
	return err == nil && claims.Artifact == artifactID
}
