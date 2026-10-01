package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/mail"
)

// cookieTestServer boots a server with the given public URL so tests can
// drive s.secure without touching the shared testServer helper.
func cookieTestServer(t *testing.T, publicURL string) *Server {
	t.Helper()
	s, err := New(Config{
		DataDir:    t.TempDir(),
		PublicURL:  publicURL,
		AdminEmail: "admin@example.com",
		TokenTTL:   time.Hour,
		Mail:       &mail.Capture{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.dbs.Close()
		s.store.Close()
	})
	return s
}

func TestSessionCookieNameInsecure(t *testing.T) {
	s := cookieTestServer(t, "http://cairn.example")
	if got := s.sessionCookieName(); got != "cairn_session" {
		t.Errorf("sessionCookieName() = %q, want %q", got, "cairn_session")
	}
}

func TestSessionCookieNameSecure(t *testing.T) {
	s := cookieTestServer(t, "https://cairn.example")
	if got := s.sessionCookieName(); got != "__Host-cairn_session" {
		t.Errorf("sessionCookieName() = %q, want %q", got, "__Host-cairn_session")
	}
}

func checkSessionCookieAttrs(t *testing.T, s *Server, secure bool) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.setSessionCookie(rec, "jwt-value", time.Hour)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != s.sessionCookieName() {
		t.Errorf("name = %q, want %q", c.Name, s.sessionCookieName())
	}
	if c.Value != "jwt-value" {
		t.Errorf("value = %q", c.Value)
	}
	if !c.HttpOnly {
		t.Error("not HttpOnly")
	}
	if c.Path != "/" {
		t.Errorf("path = %q, want /", c.Path)
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", c.SameSite)
	}
	if c.Domain != "" {
		t.Errorf("Domain = %q, want empty", c.Domain)
	}
	if c.Secure != secure {
		t.Errorf("Secure = %v, want %v", c.Secure, secure)
	}
}

func TestSetSessionCookieInsecure(t *testing.T) {
	s := cookieTestServer(t, "http://cairn.example")
	checkSessionCookieAttrs(t, s, false)
}

func TestSetSessionCookieSecure(t *testing.T) {
	s := cookieTestServer(t, "https://cairn.example")
	checkSessionCookieAttrs(t, s, true)
}

// TestClearSessionCookieMatchesSet ensures the cookie that clears a session
// uses the exact same name and attributes as the one that sets it — a
// mismatch would leave the original cookie behind.
func TestClearSessionCookieMatchesSet(t *testing.T) {
	for _, baseURL := range []string{"http://cairn.example", "https://cairn.example"} {
		s := cookieTestServer(t, baseURL)
		rec := httptest.NewRecorder()
		s.clearSessionCookie(rec)
		cookies := rec.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("got %d cookies, want 1", len(cookies))
		}
		c := cookies[0]
		if c.Name != s.sessionCookieName() {
			t.Errorf("%s: clear name = %q, want %q", baseURL, c.Name, s.sessionCookieName())
		}
		if c.MaxAge >= 0 {
			t.Errorf("%s: MaxAge = %d, want negative", baseURL, c.MaxAge)
		}
		if c.Path != "/" || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Domain != "" {
			t.Errorf("%s: clear attrs = %+v", baseURL, c)
		}
		if c.Secure != s.secure {
			t.Errorf("%s: Secure = %v, want %v", baseURL, c.Secure, s.secure)
		}
	}
}
