package server

import "net/http"

// appCSP is the Content Security Policy for the account pages (signup,
// verify, login, forgot, reset, admin): scripts load only from files, never
// inline or from a CDN.
const appCSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; require-trusted-types-for 'script'"

// shellCSP is the Content Security Policy of a page that frames artifacts: the
// app policy plus frame-src for the artifacts' content hosts, which are
// subdomains of the content domain on the public URL's scheme and port (the
// port omitted when it is the default). The full-screen page reuses it.
func (s *Server) shellCSP() string {
	return appCSP + "; frame-src " + s.contentScheme() + "://*." + s.contentDomain + s.contentPort
}

func (s *Server) contentScheme() string {
	if s.secure {
		return "https"
	}
	return "http"
}

// contentOrigin is the origin of an artifact's content host, which the
// shell page names so its script can frame it.
func (s *Server) contentOrigin(artifactID string) string {
	return s.contentScheme() + "://" + artifactID + "." + s.contentDomain + s.contentPort
}

// withShellCSP sets the shell Content Security Policy on h's response.
func (s *Server) withShellCSP(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", s.shellCSP())
		h(w, r)
	}
}

// withAppCSP sets the account-pages Content Security Policy on h's response.
func withAppCSP(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", appCSP)
		h(w, r)
	}
}
