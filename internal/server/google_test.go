package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/clock"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
	"github.com/aloisdeniel/cairn/internal/store"
)

const (
	testGoogleClientID = "client-id.apps.googleusercontent.com"
	testGoogleSecret   = "client-secret"
	testPublicURL      = "https://cairn.example.com"
	needGoogle         = "sign in with Google first"
)

// fakeGoogle stands in for Google's token endpoint. It checks the code, the
// client secret, the redirect URI, and the PKCE verifier against the
// challenge the test saw on the redirect to the consent page, then answers
// with an unsigned ID token carrying the claims the test sets.
type fakeGoogle struct {
	challenge string
	redirect  string // the redirect URI the server must send: the public URL and /auth/google/callback
	claims    map[string]any
}

func (f *fakeGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge ||
		r.PostForm.Get("code") != "the-code" ||
		r.PostForm.Get("client_id") != testGoogleClientID ||
		r.PostForm.Get("client_secret") != testGoogleSecret ||
		r.PostForm.Get("grant_type") != "authorization_code" ||
		r.PostForm.Get("redirect_uri") != f.redirect {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	json.NewEncoder(w).Encode(map[string]string{
		"id_token": enc(map[string]string{"alg": "RS256"}) + "." + enc(f.claims) + ".sig",
	})
}

// googleWorld is a server with Google sign-in on, a fake Google, and a fake
// clock. Requests go through s.Handler(), so the request protection and the
// app CSP are in the path.
type googleWorld struct {
	t      *testing.T
	s      *Server
	clk    *clock.Fake
	fake   *fakeGoogle
	mail   *mail.Capture
	google *httptest.Server
}

func newGoogleWorld(t *testing.T, edit ...func(*Config)) *googleWorld {
	t.Helper()
	w := &googleWorld{t: t, clk: clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)), mail: &mail.Capture{}}
	w.fake = &fakeGoogle{}
	w.google = httptest.NewServer(w.fake)
	cfg := Config{
		DataDir:            t.TempDir(),
		PublicURL:          testPublicURL,
		ContentDomain:      "cairn-content.example.net",
		AdminEmail:         "admin@example.com",
		SignupDomains:      []string{"example.com"},
		TokenTTL:           time.Hour,
		Mail:               w.mail,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:              w.clk,
		GoogleClientID:     testGoogleClientID,
		GoogleClientSecret: testGoogleSecret,
		GoogleAuthURL:      "https://google.test/authorize",
		GoogleTokenURL:     w.google.URL,
	}
	for _, e := range edit {
		e(&cfg)
	}
	w.fake.redirect = cfg.PublicURL + "/auth/google/callback"
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w.s = s
	t.Cleanup(func() {
		w.google.Close()
		s.store.Close()
	})
	w.setClaims("ada@example.com")
	return w
}

// setClaims makes the fake Google answer with valid claims for email.
func (w *googleWorld) setClaims(email string) {
	w.fake.claims = map[string]any{
		"iss":            "https://accounts.google.com",
		"aud":            testGoogleClientID,
		"exp":            w.clk.Now().Add(time.Hour).Unix(),
		"email":          email,
		"email_verified": true,
		"hd":             email[strings.LastIndex(email, "@")+1:],
		"name":           "Ada Lovelace",
	}
}

// browser holds cookies the way a browser does: it sends one only to a path
// its Path covers, and drops one a response expires.
type browser struct {
	w       *googleWorld
	cookies map[string]*http.Cookie
}

func (w *googleWorld) browser() *browser {
	return &browser{w: w, cookies: map[string]*http.Cookie{}}
}

func (b *browser) do(method, path string, body any) *httptest.ResponseRecorder {
	b.w.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			b.w.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, testPublicURL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", testPublicURL)
	}
	for _, c := range b.cookies {
		if strings.HasPrefix(req.URL.Path, c.Path) {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	b.w.s.Handler().ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return rec
}

func (b *browser) cookie(name string) string {
	if c := b.cookies[name]; c != nil {
		return c.Value
	}
	return ""
}

// start follows /auth/google and returns the state sent to Google. It also
// tells the fake Google the PKCE challenge it was sent.
func (b *browser) start(next string) (state string) {
	b.w.t.Helper()
	rec := b.do("GET", "/auth/google?next="+url.QueryEscape(next), nil)
	if rec.Code != http.StatusFound {
		b.w.t.Fatalf("start: status %d", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		b.w.t.Fatal(err)
	}
	b.w.fake.challenge = loc.Query().Get("code_challenge")
	return loc.Query().Get("state")
}

// callback finishes sign-in at Google's return address.
func (b *browser) callback(state string) *httptest.ResponseRecorder {
	return b.do("GET", "/auth/google/callback?code=the-code&state="+url.QueryEscape(state), nil)
}

// signIn runs the whole Google step for email and returns the callback
// response, which has made a proof when it is a redirect.
func (b *browser) signIn(email string) *httptest.ResponseRecorder {
	b.w.t.Helper()
	b.w.setClaims(email)
	return b.callback(b.start("/app"))
}

// proofCookieName is the proof's cookie behind https.
const proofCookieName = "__Host-cairn_google"

func (b *browser) mustSignIn(email string) {
	b.w.t.Helper()
	if rec := b.signIn(email); rec.Code != http.StatusFound || b.cookie(proofCookieName) == "" {
		b.w.t.Fatalf("Google sign-in for %s: status %d, proof cookie %q", email, rec.Code, b.cookie(proofCookieName))
	}
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
}

// wantError checks a JSON error response's status and message.
func wantError(t *testing.T, rec *httptest.ResponseRecorder, status int, msg string) {
	t.Helper()
	var out struct {
		Error string `json:"error"`
	}
	decodeBody(t, rec, &out)
	if rec.Code != status || out.Error != msg {
		t.Fatalf("status %d error %q, want %d %q", rec.Code, out.Error, status, msg)
	}
}

func (w *googleWorld) loginBody(email, password string, extra map[string]string) map[string]string {
	body := map[string]string{"email": email, "authKey": e2e.B64(testAuthKey(password))}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

// newProof stores a proof for email directly and returns its b64 token, the
// way the command-line tool receives one.
func (w *googleWorld) newProof(email string, ttl time.Duration) string {
	w.t.Helper()
	raw, hash, err := newLinkToken()
	if err != nil {
		w.t.Fatal(err)
	}
	if err := w.s.store.CreateGoogleProof(hash, email, "", w.clk.Now().Add(ttl)); err != nil {
		w.t.Fatal(err)
	}
	return e2e.B64(raw)
}

func TestGoogleFullSignIn(t *testing.T) {
	w := newGoogleWorld(t)
	seedAccount(t, w.s, "ada@example.com", "pw", false)
	b := w.browser()

	rec := b.do("GET", "/auth/google?next=/shared/x", nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	q := loc.Query()
	if rec.Code != http.StatusFound || loc.Host != "google.test" || loc.Path != "/authorize" {
		t.Fatalf("start: status %d to %s", rec.Code, loc)
	}
	for k, want := range map[string]string{
		"client_id": testGoogleClientID, "redirect_uri": testPublicURL + "/auth/google/callback",
		"response_type": "code", "scope": "openid email profile", "prompt": "select_account",
		"code_challenge_method": "S256",
	} {
		if q.Get(k) != want {
			t.Errorf("authorize %s = %q, want %q", k, q.Get(k), want)
		}
	}
	oauth := rec.Result().Cookies()
	if len(oauth) != 1 || oauth[0].Name != "__Secure-cairn_oauth" || oauth[0].Path != "/auth/google" ||
		!oauth[0].HttpOnly || !oauth[0].Secure || oauth[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("oauth cookie: %+v", oauth)
	}

	state := b.start("/shared/x")
	rec = b.callback(state)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/shared/x" {
		t.Fatalf("callback: status %d, location %q", rec.Code, rec.Header().Get("Location"))
	}
	proof := b.cookies[proofCookieName]
	if proof == nil || proof.Path != "/" || !proof.HttpOnly || !proof.Secure || proof.SameSite != http.SameSiteStrictMode {
		t.Fatalf("proof cookie: %+v", proof)
	}
	if b.cookie("__Secure-cairn_oauth") != "" {
		t.Error("the oauth cookie outlived the callback")
	}

	var who struct{ Email, Name string }
	rec = b.do("GET", "/api/auth/google", nil)
	decodeBody(t, rec, &who)
	if rec.Code != http.StatusOK || who.Email != "ada@example.com" || who.Name != "Ada Lovelace" {
		t.Fatalf("GET /api/auth/google: %d %+v", rec.Code, who)
	}
	if rec := b.do("GET", "/api/auth/google", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /api/auth/google used the proof: %d", rec.Code)
	}

	if rec := b.do("POST", "/api/auth/prelogin", map[string]string{"email": "ada@example.com"}); rec.Code != http.StatusOK {
		t.Fatalf("prelogin: %d", rec.Code)
	}
	rec = b.do("POST", "/api/auth/login", w.loginBody("ada@example.com", "pw", nil))
	var out loginResponse
	decodeBody(t, rec, &out)
	if rec.Code != http.StatusOK || out.User.Email != "ada@example.com" || out.Bundle.MKPassword == "" {
		t.Fatalf("login: %d %+v", rec.Code, out)
	}
	if b.cookie("__Host-cairn_session") == "" {
		t.Error("login set no session cookie")
	}
	if b.cookie(proofCookieName) != "" {
		t.Error("login left the proof cookie")
	}
	rec = b.do("POST", "/api/auth/login", w.loginBody("ada@example.com", "pw", map[string]string{"googleProof": proof.Value}))
	wantError(t, rec, http.StatusForbidden, needGoogle)
}

func TestGoogleLoginNeedsAProofForTheSameAddress(t *testing.T) {
	cases := []struct {
		name  string
		proof func(w *googleWorld, b *browser) string // the googleProof field
		setup func(w *googleWorld, b *browser)
	}{
		{name: "no proof"},
		{name: "another address's proof", setup: func(w *googleWorld, b *browser) { b.mustSignIn("grace@example.com") }},
		{name: "another address's proof in the field", proof: func(w *googleWorld, b *browser) string {
			return w.newProof("grace@example.com", 10*time.Minute)
		}},
		{name: "a used proof", setup: func(w *googleWorld, b *browser) {
			b.mustSignIn("ada@example.com")
			w.mustUseCookieProof(b)
		}},
		{name: "an expired proof", setup: func(w *googleWorld, b *browser) {
			b.mustSignIn("ada@example.com")
			w.clk.Advance(10 * time.Minute)
		}},
		{name: "an unknown token", proof: func(w *googleWorld, b *browser) string { return e2e.B64(bytes.Repeat([]byte{9}, 32)) }},
		{name: "a malformed token", proof: func(w *googleWorld, b *browser) string { return "not base64!" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newGoogleWorld(t)
			seedAccount(t, w.s, "ada@example.com", "pw", false)
			b := w.browser()
			if tc.setup != nil {
				tc.setup(w, b)
			}
			extra := map[string]string{}
			if tc.proof != nil {
				extra["googleProof"] = tc.proof(w, b)
			}
			// A correct passphrase gets no answer without the proof.
			rec := b.do("POST", "/api/auth/login", w.loginBody("ada@example.com", "pw", extra))
			wantError(t, rec, http.StatusForbidden, needGoogle)
			if b.cookie("__Host-cairn_session") != "" {
				t.Error("a session was issued without a proof")
			}
		})
	}
}

// mustUseCookieProof uses the proof the browser holds, as a sign-in would.
func (w *googleWorld) mustUseCookieProof(b *browser) {
	w.t.Helper()
	raw, err := e2e.UnB64(b.cookie(proofCookieName))
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.s.store.UseGoogleProof(hashToken(raw), w.clk.Now()); err != nil {
		w.t.Fatal(err)
	}
}

// Without a proof, a wrong passphrase is refused for the proof, not as a
// failed guess, so nobody can try passphrases without one.
func TestGoogleLoginChecksTheProofBeforeThePassphrase(t *testing.T) {
	w := newGoogleWorld(t)
	seedAccount(t, w.s, "ada@example.com", "pw", false)
	b := w.browser()
	rec := b.do("POST", "/api/auth/login", w.loginBody("ada@example.com", "wrong", nil))
	wantError(t, rec, http.StatusForbidden, needGoogle)
}

func TestGoogleWrongPassphraseKeepsTheProof(t *testing.T) {
	w := newGoogleWorld(t)
	seedAccount(t, w.s, "ada@example.com", "pw", false)
	b := w.browser()
	b.mustSignIn("ada@example.com")

	rec := b.do("POST", "/api/auth/login", w.loginBody("ada@example.com", "wrong", nil))
	wantError(t, rec, http.StatusUnauthorized, "invalid email or password")
	if b.cookie(proofCookieName) == "" {
		t.Error("a failed sign-in cleared the proof cookie")
	}
	if rec := b.do("GET", "/api/auth/google", nil); rec.Code != http.StatusOK {
		t.Fatalf("proof after a failed sign-in: %d", rec.Code)
	}
	if rec := b.do("POST", "/api/auth/login", w.loginBody("ada@example.com", "pw", nil)); rec.Code != http.StatusOK {
		t.Fatalf("second, correct attempt: %d %s", rec.Code, rec.Body)
	}
}

func TestGoogleLoginWithTheProofField(t *testing.T) {
	w := newGoogleWorld(t)
	seedAccount(t, w.s, "ada@example.com", "pw", false)
	cli := w.browser() // no cookies: the command-line tool
	proof := w.newProof("ada@example.com", 2*time.Minute)

	rec := cli.do("POST", "/api/auth/login", w.loginBody("ada@example.com", "pw", map[string]string{"googleProof": proof, "client": "cli"}))
	var out loginResponse
	decodeBody(t, rec, &out)
	if rec.Code != http.StatusOK || out.Token == "" {
		t.Fatalf("login with googleProof: %d %s", rec.Code, rec.Body)
	}
	rec = cli.do("POST", "/api/auth/login", w.loginBody("ada@example.com", "pw", map[string]string{"googleProof": proof, "client": "cli"}))
	wantError(t, rec, http.StatusForbidden, needGoogle)
}

func TestGoogleCallbackRefusals(t *testing.T) {
	cases := []struct {
		name   string
		claims func(c map[string]any)
		state  string // replaces the real state when set
		cookie bool   // drop the oauth cookie
		want   int
	}{
		{name: "state mismatch", state: "forged", want: http.StatusBadRequest},
		{name: "no oauth cookie", cookie: true, want: http.StatusBadRequest},
		{name: "other issuer", claims: func(c map[string]any) { c["iss"] = "https://evil.example" }, want: http.StatusUnauthorized},
		{name: "other audience", claims: func(c map[string]any) { c["aud"] = "someone-else" }, want: http.StatusUnauthorized},
		{name: "expired", claims: func(c map[string]any) { c["exp"] = time.Date(2026, 10, 1, 8, 59, 0, 0, time.UTC).Unix() }, want: http.StatusUnauthorized},
		{name: "no email", claims: func(c map[string]any) { delete(c, "email") }, want: http.StatusUnauthorized},
		{name: "unverified email", claims: func(c map[string]any) { c["email_verified"] = false }, want: http.StatusUnauthorized},
		{name: "no hd for a signup domain", claims: func(c map[string]any) { delete(c, "hd") }, want: http.StatusUnauthorized},
		{name: "another hd for a signup domain", claims: func(c map[string]any) { c["hd"] = "other.org" }, want: http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newGoogleWorld(t)
			if tc.claims != nil {
				tc.claims(w.fake.claims)
			}
			b := w.browser()
			state := b.start("/app")
			if tc.state != "" {
				state = tc.state
			}
			if tc.cookie {
				delete(b.cookies, "__Secure-cairn_oauth")
			}
			rec := b.callback(state)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d", rec.Code, tc.want)
			}
			if !strings.Contains(rec.Body.String(), `data-error="`) || strings.Contains(rec.Body.String(), `data-error=""`) {
				t.Errorf("no error on the sign-in page: %s", rec.Body)
			}
			if b.cookie(proofCookieName) != "" {
				t.Error("a proof cookie was set")
			}
			wantError(t, b.do("GET", "/api/auth/google", nil), http.StatusUnauthorized, needGoogle)
		})
	}
}

// Google's error code never reaches the page, which would otherwise show
// whatever text a crafted link carried.
func TestGoogleCallbackRefusesAGoogleError(t *testing.T) {
	w := newGoogleWorld(t)
	b := w.browser()
	state := b.start("/app")
	rec := b.do("GET", "/auth/google/callback?error=Call+0800+to+unlock&state="+url.QueryEscape(state), nil)
	body := rec.Body.String()
	if rec.Code != http.StatusUnauthorized || !strings.Contains(body, "Google sign-in was cancelled.") || strings.Contains(body, "0800") {
		t.Fatalf("status %d: %s", rec.Code, body)
	}
	if b.cookie(proofCookieName) != "" {
		t.Fatal("a cancelled sign-in made a proof")
	}
}

// A failed token exchange (here, a verifier Google does not accept) makes no
// proof.
func TestGoogleCallbackRefusesAFailedExchange(t *testing.T) {
	w := newGoogleWorld(t)
	b := w.browser()
	state := b.start("/app")
	w.fake.challenge = "not the challenge"
	if rec := b.callback(state); rec.Code != http.StatusUnauthorized || b.cookie(proofCookieName) != "" {
		t.Fatalf("status %d, proof %q", rec.Code, b.cookie(proofCookieName))
	}
}

func TestGoogleCallbackErrorPageEscapesAndKeepsNext(t *testing.T) {
	w := newGoogleWorld(t)
	w.fake.claims["email_verified"] = false
	b := w.browser()
	rec := b.callback(b.start("/shared/x?a=1&b=2"))
	body := rec.Body.String()
	if rec.Code != http.StatusUnauthorized || !strings.Contains(body, `data-next="/shared/x?a=1&amp;b=2"`) {
		t.Fatalf("status %d: %s", rec.Code, body)
	}
	if rec.Header().Get("Content-Security-Policy") != appCSP {
		t.Errorf("CSP %q", rec.Header().Get("Content-Security-Policy"))
	}
}

func TestGoogleHostedDomainRule(t *testing.T) {
	w := newGoogleWorld(t, func(c *Config) { c.AdminEmail = "root@ops.example.org" })

	// The administrator's own domain is not a signup domain, so a personal
	// account passes without hd.
	b := w.browser()
	w.setClaims("root@ops.example.org")
	delete(w.fake.claims, "hd")
	if rec := b.callback(b.start("/")); rec.Code != http.StatusFound || b.cookie(proofCookieName) == "" {
		t.Fatalf("admin without hd: %d", rec.Code)
	}

	// A signup domain's address with the matching hd passes, whatever the case.
	b = w.browser()
	w.setClaims("ada@example.com")
	w.fake.claims["hd"] = "Example.COM"
	if rec := b.callback(b.start("/")); rec.Code != http.StatusFound || b.cookie(proofCookieName) == "" {
		t.Fatalf("matching hd: %d", rec.Code)
	}
}

func TestGoogleHostedDomainAppliesToAnAdminInASignupDomain(t *testing.T) {
	w := newGoogleWorld(t) // admin@example.com is in a signup domain
	b := w.browser()
	w.setClaims("admin@example.com")
	delete(w.fake.claims, "hd")
	if rec := b.callback(b.start("/")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin in a signup domain without hd: %d", rec.Code)
	}
}

func TestGoogleEmailIsNormalized(t *testing.T) {
	w := newGoogleWorld(t)
	b := w.browser()
	w.setClaims("Ada@Example.com")
	w.fake.claims["hd"] = "example.com"
	b.callback(b.start("/"))
	var who struct{ Email string }
	decodeBody(t, b.do("GET", "/api/auth/google", nil), &who)
	if who.Email != "ada@example.com" {
		t.Errorf("proof address %q", who.Email)
	}
}

func TestGoogleSignupWithAProof(t *testing.T) {
	w := newGoogleWorld(t)
	b := w.browser()
	b.mustSignIn("ada@example.com")
	signup := func(email string) *httptest.ResponseRecorder {
		return b.do("POST", "/api/auth/signup", map[string]any{
			"email": email, "name": "Ada", "authKey": e2e.B64(testAuthKey("pw")), "bundle": testBundleWire(),
		})
	}

	rec := signup("Ada@example.com")
	var out map[string]string
	decodeBody(t, rec, &out)
	if rec.Code != http.StatusCreated || out["status"] != "active" {
		t.Fatalf("signup: %d %s", rec.Code, rec.Body)
	}
	u, err := w.s.store.UserByEmail("ada@example.com")
	if err != nil || u.VerifiedAt == "" {
		t.Fatalf("account after signup: %v %+v", err, u)
	}
	if _, ok := w.mail.Last("ada@example.com"); ok {
		t.Error("signup sent mail")
	}
	// Signup does not use the proof.
	if rec := b.do("GET", "/api/auth/google", nil); rec.Code != http.StatusOK {
		t.Errorf("proof after signup: %d", rec.Code)
	}
	// The address now has an account, and the proof shows the caller owns it.
	wantError(t, signup("ada@example.com"), http.StatusConflict, "an account for this address already exists")
	// And the new account signs in.
	if rec := b.do("POST", "/api/auth/login", w.loginBody("ada@example.com", "pw", nil)); rec.Code != http.StatusOK {
		t.Fatalf("login after signup: %d %s", rec.Code, rec.Body)
	}
}

func TestGoogleSignupRefusals(t *testing.T) {
	body := func(email string) map[string]any {
		return map[string]any{"email": email, "name": "Ada", "authKey": e2e.B64(testAuthKey("pw")), "bundle": testBundleWire()}
	}
	t.Run("no proof", func(t *testing.T) {
		w := newGoogleWorld(t)
		wantError(t, w.browser().do("POST", "/api/auth/signup", body("ada@example.com")), http.StatusForbidden, needGoogle)
		if _, err := w.s.store.UserByEmail("ada@example.com"); err == nil {
			t.Error("an account was created")
		}
	})
	t.Run("another address's proof", func(t *testing.T) {
		w := newGoogleWorld(t)
		b := w.browser()
		b.mustSignIn("grace@example.com")
		wantError(t, b.do("POST", "/api/auth/signup", body("ada@example.com")), http.StatusForbidden, needGoogle)
	})
	t.Run("an expired proof", func(t *testing.T) {
		w := newGoogleWorld(t)
		b := w.browser()
		b.mustSignIn("ada@example.com")
		w.clk.Advance(10 * time.Minute)
		wantError(t, b.do("POST", "/api/auth/signup", body("ada@example.com")), http.StatusForbidden, needGoogle)
	})
	t.Run("a domain that may not sign up", func(t *testing.T) {
		w := newGoogleWorld(t)
		b := w.browser()
		b.mustSignIn("ada@gmail.com")
		wantError(t, b.do("POST", "/api/auth/signup", body("ada@gmail.com")), http.StatusForbidden, "this email domain may not sign up")
	})
}

func TestGoogleForgotReturnsAResetToken(t *testing.T) {
	w := newGoogleWorld(t)
	seedAccount(t, w.s, "ada@example.com", "pw", false)
	b := w.browser()
	b.mustSignIn("ada@example.com")

	// A body naming the proof's own address is as good as none.
	rec := b.do("POST", "/api/auth/forgot", map[string]string{"email": "Ada@Example.com"})
	var out map[string]string
	decodeBody(t, rec, &out)
	if rec.Code != http.StatusOK || out["token"] == "" || len(out) != 1 {
		t.Fatalf("forgot: %d %s", rec.Code, rec.Body)
	}
	if _, ok := w.mail.Last("ada@example.com"); ok {
		t.Error("forgot sent mail")
	}
	// The token is the one a reset link carries.
	var begin resetBeginResponse
	rec = b.do("POST", "/api/auth/reset/begin", map[string]string{"token": out["token"]})
	decodeBody(t, rec, &begin)
	if rec.Code != http.StatusOK || begin.Email != "ada@example.com" {
		t.Fatalf("reset/begin: %d %s", rec.Code, rec.Body)
	}
	raw, _ := e2e.UnB64(out["token"])
	if tok, err := w.s.store.PeekToken(hashToken(raw), "reset", w.clk.Now()); err != nil || tok.UserID != begin.ID {
		t.Fatalf("stored reset token: %v %+v", err, tok)
	}
	// Forgot used the proof.
	if rec := b.do("GET", "/api/auth/google", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("proof after forgot: %d, want 401", rec.Code)
	}
	wantError(t, b.do("POST", "/api/auth/forgot", struct{}{}), http.StatusForbidden, needGoogle)

	// The token lasts 30 minutes, as a mailed link does.
	w.clk.Advance(30*time.Minute - time.Second)
	if _, err := w.s.store.PeekToken(hashToken(raw), "reset", w.clk.Now()); err != nil {
		t.Errorf("reset token expired early: %v", err)
	}
	w.clk.Advance(time.Second)
	if _, err := w.s.store.PeekToken(hashToken(raw), "reset", w.clk.Now()); err == nil {
		t.Error("reset token outlived 30 minutes")
	}
}

func TestGoogleForgotRefusals(t *testing.T) {
	t.Run("no proof", func(t *testing.T) {
		w := newGoogleWorld(t)
		seedAccount(t, w.s, "ada@example.com", "pw", false)
		wantError(t, w.browser().do("POST", "/api/auth/forgot", map[string]string{"email": "ada@example.com"}), http.StatusForbidden, needGoogle)
	})
	t.Run("a body address other than the proof's", func(t *testing.T) {
		w := newGoogleWorld(t)
		seedAccount(t, w.s, "ada@example.com", "pw", false)
		seedAccount(t, w.s, "grace@example.com", "pw", false)
		b := w.browser()
		b.mustSignIn("ada@example.com")
		wantError(t, b.do("POST", "/api/auth/forgot", map[string]string{"email": "grace@example.com"}), http.StatusForbidden, needGoogle)
		if rec := b.do("GET", "/api/auth/google", nil); rec.Code != http.StatusOK {
			t.Errorf("the refused request used the proof: %d", rec.Code)
		}
	})
	t.Run("no account", func(t *testing.T) {
		w := newGoogleWorld(t)
		b := w.browser()
		b.mustSignIn("ada@example.com")
		wantError(t, b.do("POST", "/api/auth/forgot", struct{}{}), http.StatusNotFound, "no account for this address")
		// The proof is still good for signing up.
		if rec := b.do("GET", "/api/auth/google", nil); rec.Code != http.StatusOK {
			t.Errorf("proof after a forgot with no account: %d", rec.Code)
		}
	})
	t.Run("an unverified account", func(t *testing.T) {
		w := newGoogleWorld(t)
		b := w.browser()
		b.mustSignIn("ada@example.com")
		if _, err := w.s.store.CreateAccount("ada@example.com", "Ada", "x", mustBundle(t), false); err != nil {
			t.Fatal(err)
		}
		wantError(t, b.do("POST", "/api/auth/forgot", struct{}{}), http.StatusNotFound, "no account for this address")
	})
	t.Run("an unknown field is still refused", func(t *testing.T) {
		w := newGoogleWorld(t)
		b := w.browser()
		b.mustSignIn("ada@example.com")
		if rec := b.do("POST", "/api/auth/forgot", map[string]string{"nope": "x"}); rec.Code != http.StatusBadRequest {
			t.Errorf("status %d, want 400", rec.Code)
		}
	})
}

func mustBundle(t *testing.T) store.Bundle {
	t.Helper()
	b, err := decodeBundle(testBundleWire())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAuthConfig(t *testing.T) {
	w := newGoogleWorld(t)
	var out map[string]any
	decodeBody(t, w.browser().do("GET", "/api/auth/config", nil), &out)
	host := strings.TrimPrefix(testPublicURL, "https://")
	if len(out) != 3 || out["google"] != true || out["passkeys"] != true || out["rpId"] != host {
		t.Errorf("with Google: %v, want google, passkeys, and rpId %q", out, host)
	}

	_, ts := testServer(t)
	c := &testClient{t: t, base: ts.URL}
	out = nil
	c.mustDo("GET", "/api/auth/config", nil, &out, http.StatusOK)
	if v, ok := out["google"]; !ok || v != false {
		t.Errorf("without Google: %v", out)
	}
}

// Without a public URL there is no relying party ID, so passkeys are off:
// config says so, names no rpId, and enrollment answers 404 rather than
// storing a passkey that could never sign in.
func TestAuthConfigWithoutAPublicURL(t *testing.T) {
	w := newGoogleWorld(t, func(c *Config) { c.GoogleClientID, c.GoogleClientSecret, c.PublicURL = "", "", "" })
	serve := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		w.s.mux.ServeHTTP(rec, req)
		return rec
	}
	var out map[string]any
	if err := json.Unmarshal(serve("GET", "/api/auth/config").Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if _, named := out["rpId"]; out["passkeys"] != false || named {
		t.Errorf("config without a public URL: %v", out)
	}
	rec := httptest.NewRecorder()
	w.s.handleCreatePasskey(rec, httptest.NewRequest("POST", "/api/me/passkeys", strings.NewReader("{}")))
	if rec.Code != http.StatusNotFound {
		t.Errorf("enroll without a public URL: %d %s, want 404", rec.Code, rec.Body)
	}
}

func TestGoogleOffRoutes(t *testing.T) {
	_, ts := testServer(t)
	c := &testClient{t: t, base: ts.URL}
	for _, p := range []string{"/api/auth/google"} {
		c.mustDo("GET", p, nil, nil, http.StatusNotFound)
	}
	for _, p := range []string{"/auth/google", "/auth/google/callback"} {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s with Google off: %d", p, resp.StatusCode)
		}
	}
}

func TestNewChecksGoogleConfig(t *testing.T) {
	base := Config{
		DataDir:       t.TempDir(),
		Mail:          &mail.Capture{},
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		PublicURL:     testPublicURL,
		ContentDomain: "cairn-content.example.net",
	}
	cases := []struct {
		name string
		edit func(c *Config)
		want string
	}{
		{"a client ID without a secret", func(c *Config) { c.GoogleClientID = testGoogleClientID }, "client secret"},
		{"a client ID without a public URL", func(c *Config) {
			c.GoogleClientID, c.GoogleClientSecret, c.PublicURL, c.ContentDomain = testGoogleClientID, testGoogleSecret, "", ""
		}, "public URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.DataDir = t.TempDir()
			tc.edit(&cfg)
			_, err := New(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New: %v, want an error naming the %s", err, tc.want)
			}
		})
	}
}

func TestGoogleCookieNamesOutsideHTTPS(t *testing.T) {
	w := newGoogleWorld(t, func(c *Config) { c.PublicURL, c.ContentDomain = "http://127.0.0.1:8787", "" })
	b := w.browser()
	rec := b.do("GET", "/auth/google", nil)
	if cs := rec.Result().Cookies(); len(cs) != 1 || cs[0].Name != "cairn_oauth" || cs[0].Secure {
		t.Fatalf("oauth cookie: %+v", cs)
	}
	w.setClaims("ada@example.com")
	b.callback(b.start("/"))
	if b.cookie("cairn_google") == "" {
		t.Fatalf("no cairn_google cookie after sign-in: %+v", b.cookies)
	}
	if c := b.cookies["cairn_google"]; c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("proof cookie: %+v", c)
	}
}

func TestGooglePagesCarryTheMode(t *testing.T) {
	w := newGoogleWorld(t)
	b := w.browser()
	for _, p := range []string{"/login", "/signup", "/forgot"} {
		rec := b.do("GET", p, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `data-google="1"`) {
			t.Errorf("%s with Google: %d, no data-google=1", p, rec.Code)
		}
	}

	_, ts := testServer(t)
	for _, p := range []string{"/login", "/signup", "/forgot"} {
		resp := get(t, ts.URL+p, "", "text/html")
		page := body(t, resp)
		if resp.StatusCode != http.StatusOK || !strings.Contains(page, `data-google=""`) {
			t.Errorf("%s without Google: %d, want data-google=\"\"", p, resp.StatusCode)
		}
	}
}

// The callback runs next through the safe-next rule again: the oauth cookie
// is unsigned and scoped to a path, so a sibling host could plant one.
func TestGoogleCallbackSanitizesAPlantedNext(t *testing.T) {
	w := newGoogleWorld(t)
	b := w.browser()
	state := b.start("/app")
	c := b.cookies[secureOAuthCookie]
	raw, err := e2e.UnB64(c.Value)
	if err != nil {
		t.Fatal(err)
	}
	var st oauthState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	st.Next = "//evil.example/steal"
	raw, _ = json.Marshal(st)
	c.Value = e2e.B64(raw)
	rec := b.callback(state)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("status %d, Location %q, want 302 to /", rec.Code, rec.Header().Get("Location"))
	}
}

// Wherever next points when sign-in starts, the browser lands on this
// server after Google: an outside address, a scheme, or a path a browser
// reads as another host all become /.
func TestGoogleSignInNeverLeavesTheServer(t *testing.T) {
	for _, next := range []string{"https://evil.example/x", "//evil.example/x", `/\evil.example`, "javascript:alert(1)", "app", ""} {
		w := newGoogleWorld(t)
		b := w.browser()
		w.setClaims("ada@example.com")
		rec := b.callback(b.start(next))
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
			t.Errorf("next %q: status %d, Location %q, want 302 to /", next, rec.Code, rec.Header().Get("Location"))
		}
	}
	w := newGoogleWorld(t)
	b := w.browser()
	w.setClaims("ada@example.com")
	if loc := b.callback(b.start("/shared/x?y=1")).Header().Get("Location"); loc != "/shared/x?y=1" {
		t.Errorf("a local next became %q", loc)
	}
}
