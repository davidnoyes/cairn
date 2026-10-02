package server

import (
	"net/http"

	"github.com/aloisdeniel/cairn/internal/access"
	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/store"
)

// contentTokenRoutes is the allowlist of a content-origin token, as exact
// registered patterns. A request carrying one that matches any other pattern,
// or none, answers 404. See design/e2e-api.md (Access).
var contentTokenRoutes = map[string]bool{
	"GET /api/me":                                               true,
	"GET /api/users/{id}":                                       true,
	"GET /api/artifacts/{id}/membership":                        true,
	"GET /api/artifacts/{id}/versions":                          true,
	"GET /api/artifacts/{id}/versions/{vid}":                    true,
	"POST /api/artifacts/{id}/versions/{vid}/db/query":          true,
	"POST /api/artifacts/{id}/versions/{vid}/db/batch":          true,
	"GET /api/artifacts/{id}/versions/{vid}/db/download":        true,
	"GET /api/artifacts/{id}/versions/{vid}/files":              true,
	"GET /api/artifacts/{id}/versions/{vid}/files/{path...}":    true,
	"PUT /api/artifacts/{id}/versions/{vid}/files/{path...}":    true,
	"DELETE /api/artifacts/{id}/versions/{vid}/files/{path...}": true,
}

// carriesContentToken reports whether r presents a validly signed sign-in JWT
// with an art claim. Whether its user is still valid is for the handler.
func (s *Server) carriesContentToken(r *http.Request) bool {
	cred, isKey, err := extractCredential(r, s.sessionCookieName())
	if err != nil || cred == "" || isKey {
		return false
	}
	claims, err := auth.VerifyJWT(s.secret, cred)
	return err == nil && claims.Artifact != ""
}

// contentTokenGate answers 404 to a request carrying a content-origin token
// unless it matches a pattern in contentTokenRoutes. Other requests pass. The
// gate is the allowlist; the checks behind it that refuse a token on their
// own (requireSession, currentUser, the artifact list) are defence in depth,
// so a route registered past the gate still cannot serve one.
func (s *Server) contentTokenGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.carriesContentToken(r) {
			if _, pattern := s.mux.Handler(r); !contentTokenRoutes[pattern] {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// tokenMayReadUser returns nil if the content-origin token on r, scoped to
// artifactID, may read userID: its holder may read the artifact's membership,
// and userID is the owner or a member of the latest record. Otherwise it
// returns store.ErrNotFound, or the error that stopped the check.
func (s *Server) tokenMayReadUser(r *http.Request, artifactID, userID string) error {
	c, err := s.callerFor(requestUser(r), requestAPIKey(r), artifactID)
	if err != nil {
		return err
	}
	_, req, err := s.accessRequest(c, artifactID, nil)
	if err != nil {
		return err
	}
	if access.Check(req, access.ReadMembership) != access.Allow {
		return store.ErrNotFound
	}
	st, err := s.store.AccessState(artifactID, userID)
	if err != nil {
		return err
	}
	if st.Artifact.OwnerID != userID && st.Member == nil {
		return store.ErrNotFound
	}
	return nil
}
