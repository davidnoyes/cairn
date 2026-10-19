package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/mail"
	"github.com/aloisdeniel/cairn/internal/server"
)

const (
	googleTestClientID = "client-id.apps.googleusercontent.com"
	googleTestSecret   = "client-secret"
	googleTestPassword = "correct horse battery staple"
)

// googleServer is a real server with Google sign-in on, and a fake Google
// whose consent step approves at once as whoever is set in email.
type googleServer struct {
	host  string
	email string
	fake  *httptest.Server
}

func newGoogleServer(t *testing.T) *googleServer {
	t.Helper()
	g := &googleServer{email: "ada@example.com"}
	mux := http.NewServeMux()
	// The authorization endpoint sends the browser straight back.
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=the-code&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.PostForm.Get("code") != "the-code" || r.PostForm.Get("client_secret") != googleTestSecret {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		enc := func(v any) string {
			b, _ := json.Marshal(v)
			return base64.RawURLEncoding.EncodeToString(b)
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": enc(map[string]string{"alg": "RS256"}) + "." + enc(map[string]any{
			"iss": "https://accounts.google.com", "aud": googleTestClientID, "exp": time.Now().Add(time.Hour).Unix(),
			"email": g.email, "email_verified": true, "hd": "example.com", "name": "Ada Lovelace",
		}) + ".sig"})
	})
	g.fake = httptest.NewServer(mux)
	t.Cleanup(g.fake.Close)

	ts := httptest.NewUnstartedServer(nil)
	g.host = "http://" + ts.Listener.Addr().String()
	s, err := server.New(server.Config{
		DataDir:            t.TempDir(),
		PublicURL:          g.host,
		SignupDomains:      []string{"example.com"},
		AdminEmail:         "admin@example.com",
		Mail:               &mail.Capture{},
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		GoogleClientID:     googleTestClientID,
		GoogleClientSecret: googleTestSecret,
		GoogleAuthURL:      g.fake.URL + "/authorize",
		GoogleTokenURL:     g.fake.URL + "/token",
	})
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = s.Handler()
	ts.Start()
	t.Cleanup(ts.Close)
	return g
}

// browser is an http.Client with a cookie jar, as a person's browser is.
func newBrowser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

// mustGet fetches u and returns the status and body.
func mustGet(t *testing.T, hc *http.Client, u string) (int, string) {
	t.Helper()
	resp, err := hc.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// signUpWithGoogle makes the account for g.email, through the Google step the
// web page does, with the proof in the browser's cookie.
func (g *googleServer) signUpWithGoogle(t *testing.T) {
	t.Helper()
	hc := newBrowser(t)
	if code, _ := mustGet(t, hc, g.host+"/auth/google?next=/signup"); code != http.StatusOK {
		t.Fatalf("Google round trip: %d", code)
	}
	c := client.New(g.host, "")
	c.HTTP = hc
	if _, err := c.Signup(g.email, "Ada", googleTestPassword); err != nil {
		t.Fatalf("Signup: %v", err)
	}
}

// playBrowser stands in for the browser cairn login opens: the /auth/cli
// page, Google when it has no proof, the page's confirm, and the loopback
// address the server names. A callback with a wrong state goes first when
// wrongState is set.
func (g *googleServer) playBrowser(t *testing.T, wrongState bool) func(string) error {
	return func(pageURL string) error {
		hc := newBrowser(t)
		page, err := url.Parse(pageURL)
		if err != nil {
			t.Error(err)
			return err
		}
		if code, body := mustGet(t, hc, pageURL); code != http.StatusOK || !strings.Contains(body, `src="/cli.js"`) {
			t.Errorf("GET %s: %d", pageURL, code)
		}
		if code, _ := mustGet(t, hc, g.host+"/api/auth/google"); code != http.StatusUnauthorized {
			t.Errorf("GET /api/auth/google before Google: %d, want 401", code)
		}
		// The page's script sends the browser through Google and back.
		if code, _ := mustGet(t, hc, g.host+"/auth/google?next="+url.QueryEscape(page.RequestURI())); code != http.StatusOK {
			t.Errorf("Google round trip: %d", code)
		}
		port, err := strconv.Atoi(page.Query().Get("port"))
		if err != nil {
			t.Error(err)
			return err
		}
		body, _ := json.Marshal(map[string]any{"port": port, "state": page.Query().Get("state")})
		req, _ := http.NewRequest("POST", g.host+"/api/auth/cli", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := hc.Do(req)
		if err != nil {
			t.Error(err)
			return err
		}
		defer resp.Body.Close()
		var out struct{ Redirect string }
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("POST /api/auth/cli: %d %v", resp.StatusCode, err)
			return err
		}
		if wrongState {
			bad := strings.Replace(out.Redirect, "state="+page.Query().Get("state"), "state=not-the-state-not-the-state", 1)
			if code, _ := mustGet(t, hc, bad); code != http.StatusBadRequest {
				t.Errorf("a callback with the wrong state: %d, want 400", code)
			}
			if code, _ := mustGet(t, hc, strings.Replace(out.Redirect, "/callback?", "/elsewhere?", 1)); code != http.StatusBadRequest {
				t.Errorf("another path: %d, want 400", code)
			}
		}
		if code, body := mustGet(t, hc, out.Redirect); code != http.StatusOK || !strings.Contains(body, "close this tab") {
			t.Errorf("GET %s: %d %q", out.Redirect, code, body)
		}
		return nil
	}
}

// useBrowser makes cairn login use b as its browser for the test, and a
// config file of its own.
func useBrowser(t *testing.T, b func(string) error) {
	t.Helper()
	old := openBrowser
	openBrowser = b
	t.Cleanup(func() { openBrowser = old })
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
}

func TestLoginWithGoogleSavesAWorkingKey(t *testing.T) {
	g := newGoogleServer(t)
	g.signUpWithGoogle(t)
	useBrowser(t, g.playBrowser(t, false))

	withStdin(t, googleTestPassword+"\n")
	done := captureStdout(t)
	err := runLogin([]string{"--host", g.host, "--password-stdin"})
	out := done()
	if err != nil {
		t.Fatalf("runLogin: %v", err)
	}
	if !strings.Contains(out, g.host+"/auth/cli?port=") || !strings.Contains(out, "logged in to "+g.host+" as ada@example.com") {
		t.Errorf("output %q", out)
	}
	cfg := loadConfig()
	if cfg.Host != g.host || cfg.Email != "ada@example.com" || len(strings.Split(cfg.APIKey, "_")) != 4 {
		t.Fatalf("config %+v", cfg)
	}
	done = captureStdout(t)
	err = runWhoami(nil)
	if out := done(); err != nil || !strings.Contains(out, "ada@example.com") {
		t.Fatalf("whoami with the saved key: %v, %q", err, out)
	}
}

func TestLoginWithGoogleRefusesAWrongState(t *testing.T) {
	g := newGoogleServer(t)
	g.signUpWithGoogle(t)
	useBrowser(t, g.playBrowser(t, true))

	withStdin(t, googleTestPassword+"\n")
	if err := runLogin([]string{"--host", g.host, "--password-stdin"}); err != nil {
		t.Fatalf("runLogin after a refused callback: %v", err)
	}
	if loadConfig().APIKey == "" {
		t.Error("login saved no key")
	}
}

func TestLoginWithGoogleChecksTheEmailFlag(t *testing.T) {
	g := newGoogleServer(t)
	g.signUpWithGoogle(t)
	useBrowser(t, g.playBrowser(t, false))

	withStdin(t, googleTestPassword+"\n")
	err := runLogin([]string{"--host", g.host, "--email", "grace@example.com", "--password-stdin"})
	if err == nil || !strings.Contains(err.Error(), "ada@example.com") || !strings.Contains(err.Error(), "grace@example.com") {
		t.Fatalf("runLogin with another --email: %v", err)
	}
	if cfg := loadConfig(); cfg.APIKey != "" {
		t.Errorf("a refused login saved %+v", cfg)
	}

	// The same address, written differently, is accepted.
	useBrowser(t, g.playBrowser(t, false))
	withStdin(t, googleTestPassword+"\n")
	if err := runLogin([]string{"--host", g.host, "--email", " Ada@Example.com ", "--password-stdin"}); err != nil {
		t.Fatalf("runLogin with the same address in other case: %v", err)
	}
}

func TestLoginWithGoogleWrongPassphraseSavesNothing(t *testing.T) {
	g := newGoogleServer(t)
	g.signUpWithGoogle(t)
	useBrowser(t, g.playBrowser(t, false))

	withStdin(t, "not the passphrase\n")
	if err := runLogin([]string{"--host", g.host, "--password-stdin"}); err == nil {
		t.Fatal("login with a wrong passphrase succeeded")
	}
	if cfg := loadConfig(); cfg.APIKey != "" {
		t.Errorf("a failed login saved %+v", cfg)
	}
}

func TestSignupAndForgotRefuseOnAGoogleServer(t *testing.T) {
	g := newGoogleServer(t)
	for _, tc := range []struct {
		run  func([]string) error
		page string
	}{
		{runSignup, "/signup"},
		{runForgot, "/forgot"},
	} {
		// Stdin is empty, so any prompt would fail with EOF instead.
		withStdin(t, "")
		done := captureStdout(t)
		err := tc.run([]string{"--host", g.host, "--email", "ada@example.com"})
		out := done()
		if err == nil || !strings.Contains(err.Error(), g.host+tc.page) {
			t.Errorf("%s: error %v, want one naming %s", tc.page, err, g.host+tc.page)
		}
		if strings.Contains(out, "password") || strings.Contains(out, "email:") {
			t.Errorf("%s prompted: %q", tc.page, out)
		}
	}
}
