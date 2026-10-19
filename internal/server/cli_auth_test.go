package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const cliTestState = "abcdefghijklmnop0123456789_-ABC"

func TestCLIPageRendersThePortAndState(t *testing.T) {
	w := newGoogleWorld(t)
	rec := w.browser().do("GET", "/auth/cli?port=40000&state="+cliTestState, nil)
	page := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != appCSP {
		t.Errorf("CSP %q, want the app CSP", got)
	}
	for _, want := range []string{`data-port="40000"`, `data-state="` + cliTestState + `"`, `src="/cli.js"`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %s", want)
		}
	}
}

func TestCLIPageRefusesBadPortOrState(t *testing.T) {
	w := newGoogleWorld(t)
	long := strings.Repeat("a", 129)
	for name, query := range map[string]string{
		"no port":           "state=" + cliTestState,
		"no state":          "port=40000",
		"port not a number": "port=abc&state=" + cliTestState,
		"port 1023":         "port=1023&state=" + cliTestState,
		"port 65536":        "port=65536&state=" + cliTestState,
		"state too short":   "port=40000&state=abcdefghijklmno",
		"state too long":    "port=40000&state=" + long,
		"state bad char":    "port=40000&state=abcdefghijklmnop%22%3E%3Cscript%3E",
	} {
		if rec := w.browser().do("GET", "/auth/cli?"+query, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
	}
	// The bounds themselves are fine.
	for _, query := range []string{
		"port=1024&state=abcdefghijklmnop",
		"port=65535&state=" + strings.Repeat("a", 128),
	} {
		if rec := w.browser().do("GET", "/auth/cli?"+query, nil); rec.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", query, rec.Code)
		}
	}
}

func TestCLIRoutesAre404WithGoogleOff(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/auth/cli?port=40000&state=" + cliTestState)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /auth/cli with Google off: %d", resp.StatusCode)
	}
	c := &testClient{t: t, base: ts.URL}
	c.mustDo("POST", "/api/auth/cli", map[string]any{"port": 40000, "state": cliTestState}, nil, http.StatusNotFound)
}

func TestCLIProofNeedsAProof(t *testing.T) {
	w := newGoogleWorld(t)
	b := w.browser()
	wantError(t, b.do("POST", "/api/auth/cli", map[string]any{"port": 40000, "state": cliTestState}), http.StatusForbidden, needGoogle)

	// An unknown token in the cookie is no proof either.
	b.cookies[proofCookieName] = &http.Cookie{Name: proofCookieName, Value: "bm90IGEgcHJvb2Y", Path: "/"}
	wantError(t, b.do("POST", "/api/auth/cli", map[string]any{"port": 40000, "state": cliTestState}), http.StatusForbidden, needGoogle)
}

func TestCLIProofRefusesBadPortOrState(t *testing.T) {
	w := newGoogleWorld(t)
	b := w.browser()
	b.mustSignIn("ada@example.com")
	for name, body := range map[string]map[string]any{
		"port 1023":       {"port": 1023, "state": cliTestState},
		"port 65536":      {"port": 65536, "state": cliTestState},
		"port as string":  {"port": "40000", "state": cliTestState},
		"state too short": {"port": 40000, "state": "abcdefghijklmno"},
		"state bad char":  {"port": 40000, "state": "abcdefghijklmnop&x=1"},
		"no state":        {"port": 40000},
	} {
		if rec := b.do("POST", "/api/auth/cli", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
	}
	// A refusal leaves the proof alone.
	if rec := b.do("GET", "/api/auth/google", nil); rec.Code != http.StatusOK {
		t.Errorf("the proof after refusals: %d", rec.Code)
	}
}

func TestCLIProofHandsOverANewProof(t *testing.T) {
	w := newGoogleWorld(t)
	seedAccount(t, w.s, "ada@example.com", "pw", false)
	b := w.browser()
	b.mustSignIn("ada@example.com")
	browserProof := b.cookie(proofCookieName)

	rec := b.do("POST", "/api/auth/cli", map[string]any{"port": 40000, "state": cliTestState})
	var out struct{ Redirect string }
	decodeBody(t, rec, &out)
	const prefix = "http://127.0.0.1:40000/callback?"
	if rec.Code != http.StatusOK || !strings.HasPrefix(out.Redirect, prefix) {
		t.Fatalf("status %d, redirect %q", rec.Code, out.Redirect)
	}
	q, err := url.ParseQuery(strings.TrimPrefix(out.Redirect, prefix))
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("state") != cliTestState || q.Get("email") != "ada@example.com" || q.Get("proof") == "" || len(q) != 3 {
		t.Fatalf("redirect query %v", q)
	}
	if q.Get("proof") == browserProof {
		t.Error("the tool got the browser's own proof")
	}

	// The cookie's proof is spent and the cookie cleared.
	if b.cookie(proofCookieName) != "" {
		t.Error("the proof cookie outlived the hand-over")
	}
	b.cookies[proofCookieName] = &http.Cookie{Name: proofCookieName, Value: browserProof, Path: "/"}
	wantError(t, b.do("POST", "/api/auth/cli", map[string]any{"port": 40000, "state": cliTestState}), http.StatusForbidden, needGoogle)

	// The new proof signs in once, as googleProof.
	cli := w.browser()
	body := w.loginBody("ada@example.com", "pw", map[string]string{"googleProof": q.Get("proof"), "client": "cli"})
	if rec := cli.do("POST", "/api/auth/login", body); rec.Code != http.StatusOK {
		t.Fatalf("login with the handed-over proof: %d %s", rec.Code, rec.Body)
	}
	wantError(t, cli.do("POST", "/api/auth/login", body), http.StatusForbidden, needGoogle)
}

func TestCLIProofForAnotherAddressIsRefused(t *testing.T) {
	w := newGoogleWorld(t)
	seedAccount(t, w.s, "ada@example.com", "pw", false)
	b := w.browser()
	b.mustSignIn("grace@example.com")
	rec := b.do("POST", "/api/auth/cli", map[string]any{"port": 40000, "state": cliTestState})
	var out struct{ Redirect string }
	decodeBody(t, rec, &out)
	q, _ := url.ParseQuery(out.Redirect[strings.Index(out.Redirect, "?")+1:])
	body := w.loginBody("ada@example.com", "pw", map[string]string{"googleProof": q.Get("proof")})
	wantError(t, w.browser().do("POST", "/api/auth/login", body), http.StatusForbidden, needGoogle)
}

func TestCLIProofExpiresAfterTwoMinutes(t *testing.T) {
	w := newGoogleWorld(t)
	seedAccount(t, w.s, "ada@example.com", "pw", false)
	b := w.browser()
	b.mustSignIn("ada@example.com")
	rec := b.do("POST", "/api/auth/cli", map[string]any{"port": 40000, "state": cliTestState})
	var out struct{ Redirect string }
	decodeBody(t, rec, &out)
	q, _ := url.ParseQuery(out.Redirect[strings.Index(out.Redirect, "?")+1:])
	body := w.loginBody("ada@example.com", "pw", map[string]string{"googleProof": q.Get("proof")})

	w.clk.Advance(2*time.Minute - time.Second)
	if rec := w.browser().do("POST", "/api/auth/login", w.loginBody("ada@example.com", "wrong", map[string]string{"googleProof": q.Get("proof")})); rec.Code != http.StatusUnauthorized {
		t.Fatalf("just before two minutes the proof must still pass the proof check: %d", rec.Code)
	}
	w.clk.Advance(2 * time.Second)
	wantError(t, w.browser().do("POST", "/api/auth/login", body), http.StatusForbidden, needGoogle)
}
