package server

import (
	"context"
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

const userCtxKey ctxKey = iota

// currentUser resolves the request identity from, in order: the Authorization
// bearer credential (JWT or API key) or the session cookie. It returns
// (nil, nil) for anonymous requests and an error only for credentials that are
// present but invalid.
func (s *Server) currentUser(r *http.Request) (*store.User, error) {
	if u, ok := r.Context().Value(userCtxKey).(*store.User); ok {
		return u, nil
	}
	cred := ""
	if h := r.Header.Get("Authorization"); h != "" {
		var ok bool
		cred, ok = strings.CutPrefix(h, "Bearer ")
		if !ok {
			return nil, errors.New("unsupported Authorization scheme")
		}
	} else if c, err := r.Cookie(s.sessionCookieName()); err == nil {
		cred = c.Value
	}
	if cred == "" {
		return nil, nil
	}
	if auth.IsAPIKey(cred) {
		return s.userFromAPIKey(cred)
	}
	return s.userFromJWT(cred)
}

func (s *Server) userFromJWT(token string) (*store.User, error) {
	claims, err := auth.VerifyJWT(s.secret, token)
	if err != nil {
		return nil, err
	}
	u, err := s.store.UserByID(claims.UserID)
	if err != nil {
		return nil, auth.ErrInvalidToken
	}
	if u.Disabled || u.TokenVersion != claims.TokenVersion {
		return nil, auth.ErrInvalidToken
	}
	return u, nil
}

func (s *Server) userFromAPIKey(token string) (*store.User, error) {
	id, secret, ok := auth.ParseAPIKey(token)
	if !ok {
		return nil, errors.New("malformed API key")
	}
	key, err := s.store.APIKeyByID(id)
	if err != nil {
		return nil, errors.New("unknown API key")
	}
	if key.RevokedAt != "" || key.SecretHash != auth.HashAPIKeySecret(secret) {
		return nil, errors.New("invalid API key")
	}
	u, err := s.store.UserByID(key.UserID)
	if err != nil || u.Disabled {
		return nil, errors.New("invalid API key")
	}
	return u, nil
}

// withUser stores the resolved user in the request context so handlers can
// read it back cheaply via requestUser.
func withUser(r *http.Request, u *store.User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userCtxKey, u))
}

// requestUser returns the user attached by requireAuth/requireAdmin (never nil
// inside those handlers).
func requestUser(r *http.Request) *store.User {
	u, _ := r.Context().Value(userCtxKey).(*store.User)
	return u
}

// requireAuth rejects anonymous or invalidly-authenticated API requests.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := s.currentUser(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if u == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
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
