package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/store"
)

// Session cookie names. The __Host- prefix (used whenever the server is
// served over https) is enforced by browsers: it requires Secure, Path=/,
// and no Domain attribute, which together rule out a subdomain planting a
// cookie that this server would also accept.
const (
	secureSessionCookie   = "__Host-cairn_session"
	insecureSessionCookie = "cairn_session"
)

// sessionCookieName returns the cookie name to set and to read, which
// depends on whether the server is serving behind https.
func (s *Server) sessionCookieName() string {
	if s.secure {
		return secureSessionCookie
	}
	return insecureSessionCookie
}

type ctxKey int

const (
	userCtxKey ctxKey = iota
	apiKeyCtxKey
	tokenScopeCtxKey
	artifactCtxKey
	accessCtxKey
	contentHostCtxKey
)

// tokenScope is what a content-origin token is limited to: its artifact, and
// whether it carries link access only. The zero value is no content-origin
// token.
type tokenScope struct {
	Artifact string
	LinkOnly bool
}

// apiKeyBearerPrefix starts every API key bearer credential:
// cairn_<keyid 16 hex>_<authSecret 32 hex>.
const apiKeyBearerPrefix = "cairn_"

// isAPIKeyBearer reports whether a presented Authorization bearer credential
// looks like an API key rather than a sign-in JWT.
func isAPIKeyBearer(token string) bool {
	return strings.HasPrefix(token, apiKeyBearerPrefix)
}

// isLowerHex reports whether s is non-empty and every character is a lowercase
// hex digit; the wire format refuses uppercase hexadecimal.
func isLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// parseAPIKeyBearer splits a presented bearer credential into its key id and
// auth secret, refusing anything but cairn_<16 lowercase hex>_<32 lowercase
// hex>.
func parseAPIKeyBearer(token string) (keyID, authSecret string, ok bool) {
	rest, found := strings.CutPrefix(token, apiKeyBearerPrefix)
	if !found {
		return "", "", false
	}
	keyID, authSecret, found = strings.Cut(rest, "_")
	if !found || len(keyID) != 16 || len(authSecret) != 32 || !isLowerHex(keyID) || !isLowerHex(authSecret) {
		return "", "", false
	}
	return keyID, authSecret, true
}

// extractCredential reads the bearer credential from the Authorization
// header, or failing that the session cookie, reporting whether it looks like
// an API key. An absent credential is ("", false, nil); a header present but
// not a Bearer scheme is an error.
func extractCredential(r *http.Request, cookieName string) (cred string, isAPIKey bool, err error) {
	if h := r.Header.Get("Authorization"); h != "" {
		c, ok := strings.CutPrefix(h, "Bearer ")
		if !ok {
			return "", false, errors.New("unsupported Authorization scheme")
		}
		return c, isAPIKeyBearer(c), nil
	}
	if c, err := r.Cookie(cookieName); err == nil {
		return c.Value, false, nil
	}
	return "", false, nil
}

// currentUser resolves the request identity under the "Any" rule: the
// Authorization bearer credential (sign-in JWT or API key), or the session
// cookie. It returns (nil, nil) for anonymous requests and an error only for
// credentials that are present but invalid. A content-origin token is not a
// page credential, so it is invalid here.
func (s *Server) currentUser(r *http.Request) (*store.User, error) {
	if u, ok := r.Context().Value(userCtxKey).(*store.User); ok {
		return u, nil
	}
	u, _, scope, err := s.resolveAny(r)
	if err == nil && scope.Artifact != "" {
		return nil, errBadCredentials
	}
	return u, err
}

// resolveAny is currentUser's underlying resolution, also returning the
// matched API key (nil for a cookie or JWT credential) so callers that need
// it, such as GET /api/me/bundle, can tell the two apart. scope is what a
// content-origin token is limited to, zero for any other credential.
func (s *Server) resolveAny(r *http.Request) (u *store.User, key *store.APIKey, scope tokenScope, err error) {
	cred, isKey, err := extractCredential(r, s.sessionCookieName())
	if err != nil {
		return nil, nil, tokenScope{}, err
	}
	if cred == "" {
		return nil, nil, tokenScope{}, nil
	}
	if isKey {
		u, key, err = s.userFromAPIKey(cred)
		return u, key, tokenScope{}, err
	}
	u, scope, err = s.userFromJWT(cred)
	return u, nil, scope, err
}

// userFromJWT verifies a sign-in JWT and returns its user, with the scope of
// a content-origin token (zero for a sign-in token).
func (s *Server) userFromJWT(token string) (*store.User, tokenScope, error) {
	claims, err := auth.VerifyJWT(s.secret, token)
	if err != nil {
		return nil, tokenScope{}, err
	}
	u, err := s.store.UserByID(claims.UserID)
	if err != nil {
		return nil, tokenScope{}, auth.ErrInvalidToken
	}
	if u.Disabled || u.TokenVersion != claims.TokenVersion {
		return nil, tokenScope{}, auth.ErrInvalidToken
	}
	return u, tokenScope{Artifact: claims.Artifact, LinkOnly: claims.Artifact != "" && claims.Link}, nil
}

// userFromAPIKey looks the key up by id and compares the SHA-256 of the
// presented auth secret (the hex string, not the bytes it decodes to) in
// constant time, refusing a revoked key or a disabled or unverified user. On
// success it touches the key's last-used time.
func (s *Server) userFromAPIKey(token string) (*store.User, *store.APIKey, error) {
	keyID, authSecret, ok := parseAPIKeyBearer(token)
	if !ok {
		return nil, nil, errors.New("malformed API key")
	}
	key, err := s.store.APIKeyByID(keyID)
	if err != nil {
		return nil, nil, errors.New("invalid API key")
	}
	sum := sha256.Sum256([]byte(authSecret))
	hash := hex.EncodeToString(sum[:])
	if key.RevokedAt != "" || subtle.ConstantTimeCompare([]byte(hash), []byte(key.SecretHash)) != 1 {
		return nil, nil, errors.New("invalid API key")
	}
	u, err := s.store.UserByID(key.UserID)
	// No path today leaves a live key on an unverified account (creating one
	// needs a session, and re-signup deletes the unverified account and its
	// keys); the check keeps that true if either changes.
	if err != nil || u.Disabled || u.VerifiedAt == "" {
		return nil, nil, errors.New("invalid API key")
	}
	s.store.TouchAPIKey(key.ID, s.clk.Now())
	return u, key, nil
}

// withUser stores the resolved user in the request context so handlers can
// read it back cheaply via requestUser.
func withUser(r *http.Request, u *store.User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userCtxKey, u))
}

// requestUser returns the user attached by requireAuth/requireSession/
// requireAdmin (never nil inside those handlers).
func requestUser(r *http.Request) *store.User {
	u, _ := r.Context().Value(userCtxKey).(*store.User)
	return u
}

// withAPIKey stores the API key that authenticated the request, when there
// is one, so a handler like GET /api/me/bundle can add its sealed MK.
func withAPIKey(r *http.Request, k *store.APIKey) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), apiKeyCtxKey, k))
}

// requestAPIKey returns the API key attached by requireAuth, or nil when the
// request authenticated with a cookie or a sign-in JWT instead.
func requestAPIKey(r *http.Request) *store.APIKey {
	k, _ := r.Context().Value(apiKeyCtxKey).(*store.APIKey)
	return k
}

// withTokenScope stores what a content-origin token is limited to.
func withTokenScope(r *http.Request, scope tokenScope) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), tokenScopeCtxKey, scope))
}

// requestTokenScope returns the scope attached by requireAuth, zero when the
// request is not carrying a content-origin token.
func requestTokenScope(r *http.Request) tokenScope {
	scope, _ := r.Context().Value(tokenScopeCtxKey).(tokenScope)
	return scope
}

// requireAuth implements the "Any" auth rule: a session cookie, a sign-in
// JWT, or an API key.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, key, scope, err := s.resolveAny(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if u == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		r = withUser(r, u)
		if key != nil {
			r = withAPIKey(r, key)
		}
		if scope.Artifact != "" {
			r = withTokenScope(r, scope)
		}
		if !s.successionGate(w, r, u) {
			return
		}
		next(w, r)
	}
}

// requireSession implements the "Session" auth rule: a session cookie or a
// sign-in JWT, but never an API key or a content-origin token.
func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cred, isKey, err := extractCredential(r, s.sessionCookieName())
		if err != nil || isKey {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if cred == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		u, scope, err := s.userFromJWT(cred)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if scope.Artifact != "" {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if !s.successionGate(w, r, u) {
			return
		}
		next(w, withUser(r, u))
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if !requestUser(r).IsAdmin {
			writeError(w, http.StatusForbidden, "admin access required")
			return
		}
		next(w, r)
	})
}

// setSessionCookie installs the JWT as an HttpOnly cookie so browser page
// loads and same-origin fetches are authenticated with the same login.
func (s *Server) setSessionCookie(w http.ResponseWriter, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName(),
		Value:    token,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// safeNext validates a ?next= redirect target: relative paths only.
// Browsers read a backslash as a slash, so "/\evil.com" is "//evil.com".
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, `\`) {
		return "/"
	}
	if u, err := url.Parse(next); err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return next
}
