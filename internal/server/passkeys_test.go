package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/aloisdeniel/cairn/internal/webauthn"
	"github.com/aloisdeniel/cairn/internal/webauthn/webauthntest"
)

const (
	testRPID          = "cairn.example.com"
	passkeyFailedText = "passkey sign-in failed"
	testIP            = "192.0.2.1" // httptest's default RemoteAddr host
)

var passkeyMK = bytes.Repeat([]byte{0x33}, sealedKeyLen)

// credID returns a distinct valid credential ID, base64url, from a seed byte.
func credID(seed byte) string {
	return e2e.B64(bytes.Repeat([]byte{seed}, 32))
}

// enrollBody is a valid POST /api/me/passkeys body for a, signed for password.
func enrollBody(a *webauthntest.Authenticator, id, password string) map[string]any {
	return map[string]any{
		"authKey":   e2e.B64(testAuthKey(password)),
		"id":        id,
		"name":      "laptop",
		"publicKey": e2e.B64(a.SPKI()),
		"alg":       a.Alg(),
		"mk":        e2e.B64(passkeyMK),
	}
}

// newSessionWorld is newGoogleWorld with its fake clock at the real time,
// because a session's expiry is checked against the real clock: a session
// issued at the fake clock's usual date would already be over.
func newSessionWorld(t *testing.T, edit ...func(*Config)) *googleWorld {
	t.Helper()
	w := newGoogleWorld(t, edit...)
	w.clk.Set(time.Now())
	return w
}

// passkeyWorld is a server with a public URL and no Google, with ada
// signed in and a second account, grace, seeded.
type passkeyWorld struct {
	*googleWorld
	ada, grace *store.User
	b          *browser // ada, signed in
}

func newPasskeyWorld(t *testing.T) *passkeyWorld {
	t.Helper()
	w := newSessionWorld(t, func(c *Config) { c.GoogleClientID = "" })
	p := &passkeyWorld{googleWorld: w, b: w.browser()}
	p.ada = seedAccount(t, w.s, "ada@example.com", "pw", false)
	p.grace = seedAccount(t, w.s, "grace@example.com", "pw", false)
	if rec := p.b.do("POST", "/api/auth/login", w.loginBody("ada@example.com", "pw", nil)); rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	return p
}

// enroll enrolls a under id for ada and requires it to succeed.
func (p *passkeyWorld) enroll(a *webauthntest.Authenticator, id string) {
	p.t.Helper()
	if rec := p.b.do("POST", "/api/me/passkeys", enrollBody(a, id, "pw")); rec.Code != http.StatusCreated {
		p.t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
}

// begin asks for a challenge and returns it, raw.
func (p *passkeyWorld) begin(b *browser) []byte {
	p.t.Helper()
	rec := b.do("POST", "/api/auth/passkey/begin", map[string]string{})
	var out struct{ Challenge, RPID string }
	decodeBody(p.t, rec, &out)
	raw, err := e2e.UnB64(out.Challenge)
	if rec.Code != http.StatusOK || err != nil || len(raw) != 32 {
		p.t.Fatalf("begin: %d %s", rec.Code, rec.Body)
	}
	return raw
}

func (p *passkeyWorld) expect(challenge []byte) webauthn.Expect {
	return webauthn.Expect{RPID: testRPID, Origin: testPublicURL, Challenge: challenge}
}

// finishBody is the POST /api/auth/passkey/finish body for an assertion.
func finishBody(id string, as webauthn.Assertion, userHandle string) map[string]string {
	return map[string]string{
		"credentialId":      id,
		"clientDataJSON":    e2e.B64(as.ClientDataJSON),
		"authenticatorData": e2e.B64(as.AuthenticatorData),
		"signature":         e2e.B64(as.Signature),
		"userHandle":        e2e.B64([]byte(userHandle)),
	}
}

// signInWith runs begin and finish on b with a fresh challenge, the
// assertion changed by opts.
func (p *passkeyWorld) signInWith(b *browser, a *webauthntest.Authenticator, id, userHandle string, opts ...webauthntest.Option) *httptest.ResponseRecorder {
	p.t.Helper()
	as := a.Assert(p.expect(p.begin(b)), opts...)
	return b.do("POST", "/api/auth/passkey/finish", finishBody(id, as, userHandle))
}

func TestPasskeyEnrollListDelete(t *testing.T) {
	p := newPasskeyWorld(t)
	a := webauthntest.New(webauthn.AlgES256)
	id := credID(1)

	var created createPasskeyResponse
	rec := p.b.do("POST", "/api/me/passkeys", map[string]any{
		"authKey": e2e.B64(testAuthKey("pw")), "id": id, "name": "  ",
		"publicKey": e2e.B64(a.SPKI()), "alg": a.Alg(), "mk": e2e.B64(passkeyMK),
	})
	decodeBody(t, rec, &created)
	if rec.Code != http.StatusCreated || created.ID != id || created.Name != "passkey" || created.CreatedAt == "" {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
	if got, err := p.s.store.PasskeyByID(id); err != nil || !bytes.Equal(got.MK, passkeyMK) || got.UserID != p.ada.ID || got.Alg != a.Alg() {
		t.Fatalf("stored passkey: %+v, %v", got, err)
	}

	var list []passkeyView
	rec = p.b.do("GET", "/api/me/passkeys", nil)
	decodeBody(t, rec, &list)
	if rec.Code != http.StatusOK || len(list) != 1 || list[0].ID != id || list[0].Name != "passkey" || list[0].LastUsedAt != "" {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "lastUsedAt") || strings.Contains(rec.Body.String(), "mk") {
		t.Errorf("list shows more than it should: %s", rec.Body)
	}

	rec = p.b.do("DELETE", "/api/me/passkeys/"+id, nil)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"ok":true}` {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	rec = p.b.do("GET", "/api/me/passkeys", nil)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("list after delete: %d %s", rec.Code, rec.Body)
	}
	if rec := p.b.do("DELETE", "/api/me/passkeys/"+id, nil); rec.Code != http.StatusNotFound {
		t.Errorf("second delete: %d, want 404", rec.Code)
	}
}

func TestPasskeyEnrollRefusals(t *testing.T) {
	a := webauthntest.New(webauthn.AlgES256)
	ed := webauthntest.New(webauthn.AlgEdDSA)
	cases := []struct {
		name   string
		edit   func(body map[string]any)
		status int
	}{
		{"wrong authKey", func(b map[string]any) { b["authKey"] = e2e.B64(testAuthKey("other")) }, http.StatusUnauthorized},
		{"malformed authKey", func(b map[string]any) { b["authKey"] = "not base64!" }, http.StatusUnauthorized},
		{"id with padding", func(b map[string]any) { b["id"] = credID(1) + "=" }, http.StatusBadRequest},
		{"id in the standard alphabet", func(b map[string]any) { b["id"] = strings.Repeat("+/", 12) }, http.StatusBadRequest},
		{"id too short", func(b map[string]any) { b["id"] = e2e.B64(bytes.Repeat([]byte{1}, 15)) }, http.StatusBadRequest},
		{"id too long", func(b map[string]any) { b["id"] = e2e.B64(bytes.Repeat([]byte{1}, 1024)) }, http.StatusBadRequest},
		{"empty id", func(b map[string]any) { b["id"] = "" }, http.StatusBadRequest},
		{"public key not base64", func(b map[string]any) { b["publicKey"] = "***" }, http.StatusBadRequest},
		{"public key not SPKI", func(b map[string]any) { b["publicKey"] = e2e.B64([]byte("hello")) }, http.StatusBadRequest},
		{"key does not match alg", func(b map[string]any) { b["publicKey"] = e2e.B64(ed.SPKI()) }, http.StatusBadRequest},
		{"unsupported alg", func(b map[string]any) { b["alg"] = -35 }, http.StatusBadRequest},
		{"mk not base64", func(b map[string]any) { b["mk"] = "***" }, http.StatusBadRequest},
		{"mk wrong length", func(b map[string]any) { b["mk"] = e2e.B64(passkeyMK[1:]) }, http.StatusBadRequest},
		{"name too long", func(b map[string]any) { b["name"] = strings.Repeat("n", maxNameLen+1) }, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPasskeyWorld(t)
			body := enrollBody(a, credID(1), "pw")
			tc.edit(body)
			if rec := p.b.do("POST", "/api/me/passkeys", body); rec.Code != tc.status {
				t.Fatalf("status %d (%s), want %d", rec.Code, rec.Body, tc.status)
			}
			if list, _ := p.s.store.ListPasskeys(p.ada.ID); len(list) != 0 {
				t.Errorf("a refused enrollment stored %d passkeys", len(list))
			}
		})
	}
}

func TestPasskeyEnrollRefusesAnAPIKey(t *testing.T) {
	p := newPasskeyWorld(t)
	mk := e2e.B64(passkeyMK)
	if rec := p.b.do("POST", "/api/keys", map[string]any{
		"authKey": e2e.B64(testAuthKey("pw")), "name": "k",
		"keyId": "00112233445566ff", "authSecret": "00112233445566778899aabbccddeeff", "mk": mk,
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create key: %d", rec.Code)
	}
	body, _ := json.Marshal(enrollBody(webauthntest.New(webauthn.AlgES256), credID(1), "pw"))
	req := httptest.NewRequest("POST", testPublicURL+"/api/me/passkeys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer cairn_00112233445566ff_00112233445566778899aabbccddeeff")
	rec := httptest.NewRecorder()
	p.s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("enroll with an API key: %d %s, want 401", rec.Code, rec.Body)
	}
	if list, _ := p.s.store.ListPasskeys(p.ada.ID); len(list) != 0 {
		t.Errorf("an API key enrolled %d passkeys", len(list))
	}
}

func TestPasskeyDuplicateIDIs409(t *testing.T) {
	p := newPasskeyWorld(t)
	p.enroll(webauthntest.New(webauthn.AlgES256), credID(1))
	// The same credential ID, even by the same user with another key.
	other := enrollBody(webauthntest.New(webauthn.AlgEdDSA), credID(1), "pw")
	if rec := p.b.do("POST", "/api/me/passkeys", other); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d %s, want 409", rec.Code, rec.Body)
	}
	// Another user's.
	g := p.browser()
	if rec := g.do("POST", "/api/auth/login", p.loginBody("grace@example.com", "pw", nil)); rec.Code != http.StatusOK {
		t.Fatalf("login: %d", rec.Code)
	}
	if rec := g.do("POST", "/api/me/passkeys", enrollBody(webauthntest.New(webauthn.AlgES256), credID(1), "pw")); rec.Code != http.StatusConflict {
		t.Fatalf("another user's duplicate: %d %s, want 409", rec.Code, rec.Body)
	}
}

func TestPasskeyDeleteOfAnotherUsersIs404(t *testing.T) {
	p := newPasskeyWorld(t)
	p.enroll(webauthntest.New(webauthn.AlgES256), credID(1))
	g := p.browser()
	g.do("POST", "/api/auth/login", p.loginBody("grace@example.com", "pw", nil))
	if rec := g.do("DELETE", "/api/me/passkeys/"+credID(1), nil); rec.Code != http.StatusNotFound {
		t.Fatalf("delete another user's: %d, want 404", rec.Code)
	}
	if _, err := p.s.store.PasskeyByID(credID(1)); err != nil {
		t.Errorf("the passkey is gone: %v", err)
	}
	if rec := g.do("GET", "/api/me/passkeys", nil); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("grace sees %s", rec.Body)
	}
}

func TestPasskeySignIn(t *testing.T) {
	for name, alg := range map[string]int{"ES256": webauthn.AlgES256, "EdDSA": webauthn.AlgEdDSA, "RS256": webauthn.AlgRS256} {
		t.Run(name, func(t *testing.T) {
			p := newPasskeyWorld(t)
			a := webauthntest.New(alg)
			p.enroll(a, credID(1))

			out := p.browser() // signed out
			challenge := p.begin(out)
			as := a.Assert(p.expect(challenge))
			rec := out.do("POST", "/api/auth/passkey/finish", finishBody(credID(1), as, p.ada.ID))
			var got passkeyLoginResponse
			decodeBody(t, rec, &got)
			if rec.Code != http.StatusOK || got.User.Email != "ada@example.com" || got.Bundle.MKPassword == "" ||
				got.PasskeyMK != e2e.B64(passkeyMK) {
				t.Fatalf("finish: %d %s", rec.Code, rec.Body)
			}
			if out.cookie("__Host-cairn_session") == "" {
				t.Fatal("finish set no session cookie")
			}
			var me meView
			rec = out.do("GET", "/api/me", nil)
			decodeBody(t, rec, &me)
			if rec.Code != http.StatusOK || me.Email != "ada@example.com" {
				t.Fatalf("session cookie: %d %s", rec.Code, rec.Body)
			}

			pk, err := p.s.store.PasskeyByID(credID(1))
			if err != nil || pk.SignCount != 1 || pk.LastUsedAt == "" {
				t.Fatalf("after sign-in: %+v, %v", pk, err)
			}
			var list []passkeyView
			decodeBody(t, out.do("GET", "/api/me/passkeys", nil), &list)
			if len(list) != 1 || list[0].LastUsedAt == "" {
				t.Errorf("list after sign-in: %+v", list)
			}

			// A second sign-in with a higher counter works, and an empty user
			// handle is allowed.
			if rec := p.signInWith(out, a, credID(1), ""); rec.Code != http.StatusOK {
				t.Fatalf("second sign-in: %d %s", rec.Code, rec.Body)
			}
			if pk, _ := p.s.store.PasskeyByID(credID(1)); pk.SignCount != 2 {
				t.Errorf("counter = %d, want 2", pk.SignCount)
			}
		})
	}
}

func TestPasskeyBegin(t *testing.T) {
	p := newPasskeyWorld(t)
	rec := p.b.do("POST", "/api/auth/passkey/begin", map[string]string{})
	var out map[string]string
	decodeBody(t, rec, &out)
	if rec.Code != http.StatusOK || out["rpId"] != testRPID || len(out) != 2 {
		t.Fatalf("begin: %d %s", rec.Code, rec.Body)
	}
	if rec := p.b.do("POST", "/api/auth/passkey/begin", map[string]string{"extra": "x"}); rec.Code != http.StatusBadRequest {
		t.Errorf("begin with an unknown field: %d, want 400", rec.Code)
	}
}

// Every refusal is 401 and counts one failure against the client's address.
func TestPasskeyFinishRefusals(t *testing.T) {
	type env struct {
		p *passkeyWorld
		a *webauthntest.Authenticator
	}
	cases := []struct {
		name   string
		status int
		msg    string
		run    func(e env) *httptest.ResponseRecorder
	}{
		{"unknown credential", http.StatusUnauthorized, passkeyFailedText, func(e env) *httptest.ResponseRecorder {
			return e.p.signInWith(e.p.browser(), e.a, credID(9), e.p.ada.ID)
		}},
		{"challenge never issued", http.StatusUnauthorized, passkeyFailedText, func(e env) *httptest.ResponseRecorder {
			as := e.a.Assert(e.p.expect(bytes.Repeat([]byte{7}, 32)))
			return e.p.browser().do("POST", "/api/auth/passkey/finish", finishBody(credID(1), as, e.p.ada.ID))
		}},
		{"challenge reused", http.StatusUnauthorized, passkeyFailedText, func(e env) *httptest.ResponseRecorder {
			b := e.p.browser()
			challenge := e.p.begin(b)
			first := e.a.Assert(e.p.expect(challenge))
			if rec := b.do("POST", "/api/auth/passkey/finish", finishBody(credID(1), first, e.p.ada.ID)); rec.Code != http.StatusOK {
				e.p.t.Fatalf("first use: %d", rec.Code)
			}
			// A new, valid assertion over the same challenge: only the
			// challenge's single use refuses it.
			second := e.a.Assert(e.p.expect(challenge))
			return b.do("POST", "/api/auth/passkey/finish", finishBody(credID(1), second, e.p.ada.ID))
		}},
		{"challenge expired", http.StatusUnauthorized, passkeyFailedText, func(e env) *httptest.ResponseRecorder {
			b := e.p.browser()
			as := e.a.Assert(e.p.expect(e.p.begin(b)))
			e.p.clk.Advance(2*time.Minute + time.Second)
			return b.do("POST", "/api/auth/passkey/finish", finishBody(credID(1), as, e.p.ada.ID))
		}},
		{"wrong origin", http.StatusUnauthorized, passkeyFailedText, func(e env) *httptest.ResponseRecorder {
			return e.p.signInWith(e.p.browser(), e.a, credID(1), e.p.ada.ID, webauthntest.WithOrigin("https://evil.example.com"))
		}},
		{"wrong RP ID", http.StatusUnauthorized, passkeyFailedText, func(e env) *httptest.ResponseRecorder {
			return e.p.signInWith(e.p.browser(), e.a, credID(1), e.p.ada.ID, webauthntest.WithRPID("example.com"))
		}},
		{"user verification clear", http.StatusUnauthorized, passkeyFailedText, func(e env) *httptest.ResponseRecorder {
			return e.p.signInWith(e.p.browser(), e.a, credID(1), e.p.ada.ID, webauthntest.WithFlags(0x01))
		}},
		{"bad signature", http.StatusUnauthorized, passkeyFailedText, func(e env) *httptest.ResponseRecorder {
			return e.p.signInWith(e.p.browser(), e.a, credID(1), e.p.ada.ID, webauthntest.WithBadSignature())
		}},
		{"counter does not advance", http.StatusUnauthorized, passkeyFailedText, func(e env) *httptest.ResponseRecorder {
			if rec := e.p.signInWith(e.p.browser(), e.a, credID(1), e.p.ada.ID); rec.Code != http.StatusOK {
				e.p.t.Fatalf("first sign-in: %d", rec.Code)
			}
			return e.p.signInWith(e.p.browser(), e.a, credID(1), e.p.ada.ID, webauthntest.WithCounter(1))
		}},
		{"user handle of another user", http.StatusUnauthorized, passkeyFailedText, func(e env) *httptest.ResponseRecorder {
			return e.p.signInWith(e.p.browser(), e.a, credID(1), e.p.grace.ID)
		}},
		{"owner deactivated", http.StatusForbidden, "account deactivated", func(e env) *httptest.ResponseRecorder {
			if err := e.p.s.store.SetUserDisabled(e.p.ada.ID, true); err != nil {
				e.p.t.Fatal(err)
			}
			return e.p.signInWith(e.p.browser(), e.a, credID(1), e.p.ada.ID)
		}},
		{"malformed field", http.StatusBadRequest, "malformed assertion", func(e env) *httptest.ResponseRecorder {
			b := e.p.browser()
			body := finishBody(credID(1), e.a.Assert(e.p.expect(e.p.begin(b))), e.p.ada.ID)
			body["signature"] = "***"
			return b.do("POST", "/api/auth/passkey/finish", body)
		}},
		{"client data not JSON", http.StatusUnauthorized, passkeyFailedText, func(e env) *httptest.ResponseRecorder {
			b := e.p.browser()
			body := finishBody(credID(1), e.a.Assert(e.p.expect(e.p.begin(b))), e.p.ada.ID)
			body["clientDataJSON"] = e2e.B64([]byte("not json"))
			return b.do("POST", "/api/auth/passkey/finish", body)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPasskeyWorld(t)
			a := webauthntest.New(webauthn.AlgES256)
			p.enroll(a, credID(1))
			rec := tc.run(env{p, a})
			wantError(t, rec, tc.status, tc.msg)
			if len(rec.Result().Cookies()) > 0 {
				t.Errorf("a refusal set cookies: %v", rec.Result().Cookies())
			}
			// A success inside the case (the setup) is not a failure; only the
			// refusals count.
			want := 1
			if got := len(p.s.signIn.ip.events[testIP]); got != want {
				t.Errorf("failures recorded for the address = %d, want %d", got, want)
			}
		})
	}
}

// A challenge is spent by a refused assertion too: the same assertion, now
// correct in every respect, cannot be sent again.
func TestPasskeyFinishSpendsTheChallengeOnRefusal(t *testing.T) {
	p := newPasskeyWorld(t)
	a := webauthntest.New(webauthn.AlgES256)
	p.enroll(a, credID(1))
	b := p.browser()
	challenge := p.begin(b)
	bad := a.Assert(p.expect(challenge), webauthntest.WithBadSignature())
	if rec := b.do("POST", "/api/auth/passkey/finish", finishBody(credID(1), bad, p.ada.ID)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature: %d", rec.Code)
	}
	good := a.Assert(p.expect(challenge))
	if rec := b.do("POST", "/api/auth/passkey/finish", finishBody(credID(1), good, p.ada.ID)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("retry on a spent challenge: %d, want 401", rec.Code)
	}
}

func TestPasskeyFinishFailuresBlockTheAddress(t *testing.T) {
	p := newPasskeyWorld(t)
	a := webauthntest.New(webauthn.AlgES256)
	p.enroll(a, credID(1))
	b := p.browser()
	for i := 0; i < 20; i++ {
		if rec := p.signInWith(b, a, credID(9), ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, rec.Code)
		}
	}
	rec := p.signInWith(b, a, credID(1), p.ada.ID)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("a valid assertion after 20 failures: %d %s, want 429", rec.Code, rec.Body)
	}
	// The window ends and the same passkey works again.
	p.clk.Advance(16 * time.Minute)
	if rec := p.signInWith(b, a, credID(1), p.ada.ID); rec.Code != http.StatusOK {
		t.Fatalf("after the window: %d %s", rec.Code, rec.Body)
	}
}

func TestPasskeyChallengeLimits(t *testing.T) {
	clk := newGoogleWorld(t).clk
	c := newChallenges(clk)
	first, ok, err := c.issue()
	if !ok || err != nil {
		t.Fatal("first issue refused")
	}
	for i := 1; i < maxChallenges; i++ {
		if _, ok, _ := c.issue(); !ok {
			t.Fatalf("issue %d refused, want up to %d", i, maxChallenges)
		}
	}
	if _, ok, _ := c.issue(); ok {
		t.Fatal("issued past the limit")
	}
	if !c.consume(first) {
		t.Fatal("a spent slot did not free")
	}
	if _, ok, _ := c.issue(); !ok {
		t.Fatal("no room after a challenge was spent")
	}
	if _, ok, _ := c.issue(); ok {
		t.Fatal("issued past the limit again")
	}
	// Expired challenges are dropped to make room.
	clk.Advance(challengeTTL + time.Second)
	if _, ok, _ := c.issue(); !ok {
		t.Fatal("expired challenges did not make room")
	}
	if len(c.m) != 1 {
		t.Errorf("%d challenges held after the sweep, want 1", len(c.m))
	}
}

func TestPasskeyBeginFullAnswers503(t *testing.T) {
	p := newPasskeyWorld(t)
	for i := 0; i < maxChallenges; i++ {
		if _, ok, _ := p.s.passkeyChallenges.issue(); !ok {
			t.Fatal("could not fill")
		}
	}
	rec := p.b.do("POST", "/api/auth/passkey/begin", map[string]string{})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("begin when full: %d, want 503", rec.Code)
	}
}

func TestPasskeysNeedAPublicURL(t *testing.T) {
	w := newGoogleWorld(t, func(c *Config) { c.GoogleClientID, c.GoogleClientSecret, c.PublicURL = "", "", "" })
	if w.s.appHost != "" {
		t.Fatalf("appHost = %q", w.s.appHost)
	}
	// Straight to the routes: without a public URL the host-based routing in
	// front of them would answer for its own reasons.
	for _, path := range []string{"/api/auth/passkey/begin", "/api/auth/passkey/finish"} {
		req := httptest.NewRequest("POST", path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		w.s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "404 page not found") {
			t.Errorf("%s: %d %q, want the handler's 404", path, rec.Code, rec.Body)
		}
	}
}

// With Google on, a passkey sign-in also needs the owner's proof, which is
// checked before any signature work and used only on success.
func TestPasskeySignInOnAGoogleServer(t *testing.T) {
	w := newSessionWorld(t)
	p := &passkeyWorld{googleWorld: w}
	p.ada = seedAccount(t, w.s, "ada@example.com", "pw", false)
	p.grace = seedAccount(t, w.s, "grace@example.com", "pw", false)
	a := webauthntest.New(webauthn.AlgES256)

	// Enroll: sign in with a password, which needs and uses a proof.
	p.b = w.browser()
	p.b.mustSignIn("ada@example.com")
	if rec := p.b.do("POST", "/api/auth/login", w.loginBody("ada@example.com", "pw", nil)); rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	p.enroll(a, credID(1))

	t.Run("no proof", func(t *testing.T) {
		b := w.browser()
		wantError(t, p.signInWith(b, a, credID(1), p.ada.ID), http.StatusForbidden, needGoogle)
		if b.cookie("__Host-cairn_session") != "" {
			t.Error("a session was issued without a proof")
		}
	})
	t.Run("the proof comes before the signature", func(t *testing.T) {
		wantError(t, p.signInWith(w.browser(), a, credID(1), p.ada.ID, webauthntest.WithBadSignature()), http.StatusForbidden, needGoogle)
	})
	t.Run("another address's proof", func(t *testing.T) {
		b := w.browser()
		b.mustSignIn("grace@example.com")
		wantError(t, p.signInWith(b, a, credID(1), p.ada.ID), http.StatusForbidden, needGoogle)
		if b.cookie("__Host-cairn_session") != "" {
			t.Error("a session was issued with another address's proof")
		}
	})
	t.Run("the owner's proof", func(t *testing.T) {
		b := w.browser()
		b.mustSignIn("ada@example.com")
		token := b.cookie(proofCookieName)
		rec := p.signInWith(b, a, credID(1), p.ada.ID)
		var got passkeyLoginResponse
		decodeBody(t, rec, &got)
		if rec.Code != http.StatusOK || got.PasskeyMK != e2e.B64(passkeyMK) {
			t.Fatalf("finish: %d %s", rec.Code, rec.Body)
		}
		if b.cookie("__Host-cairn_session") == "" {
			t.Error("no session cookie")
		}
		if b.cookie(proofCookieName) != "" {
			t.Error("the proof cookie was kept")
		}
		if pr, err := w.s.peekProof(token); err != nil || pr != nil {
			t.Errorf("the proof was not used: %+v, %v", pr, err)
		}
	})
	t.Run("a refused assertion keeps the proof", func(t *testing.T) {
		b := w.browser()
		b.mustSignIn("ada@example.com")
		token := b.cookie(proofCookieName)
		wantError(t, p.signInWith(b, a, credID(1), p.ada.ID, webauthntest.WithBadSignature()), http.StatusUnauthorized, passkeyFailedText)
		if pr, err := w.s.peekProof(token); err != nil || pr == nil {
			t.Errorf("a refused assertion used the proof: %+v, %v", pr, err)
		}
		if rec := p.signInWith(b, a, credID(1), p.ada.ID); rec.Code != http.StatusOK {
			t.Errorf("retry with the proof: %d %s", rec.Code, rec.Body)
		}
	})
}

func TestPasskeyIsRemovedByKeyRotation(t *testing.T) {
	w := newRotWorld(t)
	a := webauthntest.New(webauthn.AlgES256)
	w.rot.mustDo("POST", "/api/me/passkeys", enrollBody(a, credID(1), w.rot.email+"-password"), nil, http.StatusCreated)
	if list, _ := w.s.store.ListPasskeys(w.rot.id); len(list) != 1 {
		t.Fatalf("%d passkeys before rotation", len(list))
	}
	r := w.rotation(t)
	w.rot.mustDo("POST", "/api/me/rotate", r.request(), nil, http.StatusOK)
	if list, err := w.s.store.ListPasskeys(w.rot.id); err != nil || len(list) != 0 {
		t.Fatalf("%d passkeys after rotation, %v", len(list), err)
	}
}

func TestPasskeyAndAccountDeletion(t *testing.T) {
	s, ts := testServer(t)
	u := seedAccount(t, s, "ada@example.com", "pw", false)
	c := &testClient{t: t, base: ts.URL}
	loginAgain(t, c, "ada@example.com", "pw")
	c.mustDo("POST", "/api/me/passkeys", enrollBody(webauthntest.New(webauthn.AlgES256), credID(1), "pw"), nil, http.StatusCreated)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	admin.mustDo("DELETE", "/api/admin/users/"+u.ID, nil, nil, http.StatusOK)
	if _, err := s.store.PasskeyByID(credID(1)); err != store.ErrNotFound {
		t.Fatalf("passkey after the account was deleted: %v, want ErrNotFound", err)
	}
}

func TestPasskeyAndResetWithoutTheRecoveryCode(t *testing.T) {
	s, ts := testServer(t)
	seedAccount(t, s, "ada@example.com", "old-pw", false)
	c := &testClient{t: t, base: ts.URL}
	loginAgain(t, c, "ada@example.com", "old-pw")
	c.mustDo("POST", "/api/me/passkeys", enrollBody(webauthntest.New(webauthn.AlgES256), credID(1), "old-pw"), nil, http.StatusCreated)

	forgotPassword(t, ts.URL, "ada@example.com")
	resetMail, _ := mailer(s).Last("ada@example.com")
	c.mustDo("POST", "/api/auth/reset/complete", map[string]any{
		"token": extractFragmentToken(t, resetMail.Body), "mode": "new",
		"authKey": e2e.B64(testAuthKey("new-pw")), "bundle": testBundleWire(),
	}, nil, http.StatusOK)

	loginAgain(t, c, "ada@example.com", "new-pw")
	var archives []archiveView
	c.mustDo("GET", "/api/me/archives", nil, &archives, http.StatusOK)
	if len(archives) != 1 || len(archives[0].Passkeys) != 1 ||
		archives[0].Passkeys[0].ID != credID(1) || archives[0].Passkeys[0].MK != e2e.B64(passkeyMK) {
		t.Fatalf("archives: %+v, want the passkey's id and sealed MK", archives)
	}
	var list []passkeyView
	c.mustDo("GET", "/api/me/passkeys", nil, &list, http.StatusOK)
	if len(list) != 0 {
		t.Errorf("passkeys after the reset: %+v", list)
	}
	if _, err := s.store.PasskeyByID(credID(1)); err != store.ErrNotFound {
		t.Errorf("passkey row after the reset: %v, want ErrNotFound", err)
	}
}

func TestPasskeyAndResetWithTheRecoveryCode(t *testing.T) {
	s, ts := testServer(t)
	w, seed, _ := signedBundleWire(t)
	bundle, err := decodeBundle(w)
	if err != nil {
		t.Fatal(err)
	}
	u := seedAccountWith(t, s, "ada@example.com", "pw", false, bundle)
	c := &testClient{t: t, base: ts.URL}
	loginAgain(t, c, "ada@example.com", "pw")
	c.mustDo("POST", "/api/me/passkeys", enrollBody(webauthntest.New(webauthn.AlgES256), credID(1), "pw"), nil, http.StatusCreated)

	forgotPassword(t, ts.URL, "ada@example.com")
	resetMail, _ := mailer(s).Last("ada@example.com")
	rawToken := extractFragmentToken(t, resetMail.Body)
	tokenBytes, err := e2e.UnB64(rawToken)
	if err != nil {
		t.Fatal(err)
	}
	proofBody, _ := json.Marshal(resetProofBody{V: 1, User: u.ID, Token: hashToken(tokenBytes)})
	sig, err := e2e.Sign(seed, "reset", proofBody)
	if err != nil {
		t.Fatal(err)
	}
	newKDF, _ := json.Marshal(e2e.Params{Alg: "argon2id", Memory: 65536, Time: 3, Threads: 1, Salt: bytes.Repeat([]byte{0x09}, 16)})
	c.mustDo("POST", "/api/auth/reset/complete", map[string]any{
		"token": rawToken, "mode": "recovery", "authKey": e2e.B64(testAuthKey("new-pw")),
		"kdf": json.RawMessage(newKDF), "mkPassword": e2e.B64(bytes.Repeat([]byte{0x0a}, sealedKeyLen)),
		"proof": e2e.B64(sig),
	}, nil, http.StatusOK)

	pk, err := s.store.PasskeyByID(credID(1))
	if err != nil || pk.UserID != u.ID || !bytes.Equal(pk.MK, passkeyMK) {
		t.Fatalf("passkey after a recovery reset: %+v, %v", pk, err)
	}
	if archives, _ := s.store.Archives(u.ID); len(archives) != 0 {
		t.Errorf("a recovery reset made %d archives", len(archives))
	}
}
