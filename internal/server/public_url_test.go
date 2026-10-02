package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// TestEmailedLinksUsePublicURLNotHost covers L3: a verification link is built
// from --public-url, never from a hostile request Host header.
func TestEmailedLinksUsePublicURLNotHost(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) {
		c.SignupDomains = []string{"example.com"}
		c.PublicURL = "https://cairn.example"
		c.ContentDomain = "localhost"
	})
	body, err := json.Marshal(map[string]any{
		"email": "ada@example.com", "name": "Ada", "authKey": e2e.B64(testAuthKey("pw")), "bundle": testBundleWire(),
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", ts.URL+"/api/auth/signup", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = "evil.example" // what a forwarded/hostile request might claim
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("signup: status %d, want 202", resp.StatusCode)
	}

	msg, ok := mailer(s).Last("ada@example.com")
	if !ok {
		t.Fatal("no verification mail sent")
	}
	if !strings.Contains(msg.Body, "https://cairn.example/verify#token=") {
		t.Errorf("verify link doesn't use the public URL: %q", msg.Body)
	}
	if strings.Contains(msg.Body, "evil.example") {
		t.Errorf("verify link leaked the request Host: %q", msg.Body)
	}
}

// TestResetLinkUsesPublicURLNotHost is the reset half of L3.
func TestResetLinkUsesPublicURLNotHost(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) { c.PublicURL, c.ContentDomain = "https://cairn.example", "localhost" })
	seedAccount(t, s, "ada@example.com", "pw", false)
	req, err := http.NewRequest("POST", ts.URL+"/api/auth/forgot", strings.NewReader(`{"email":"ada@example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = "evil.example"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("forgot: status %d, want 202", resp.StatusCode)
	}

	msg, ok := mailer(s).Last("ada@example.com")
	if !ok {
		t.Fatal("no reset mail sent")
	}
	if !strings.Contains(msg.Body, "https://cairn.example/reset#token=") {
		t.Errorf("reset link doesn't use the public URL: %q", msg.Body)
	}
	if strings.Contains(msg.Body, "evil.example") {
		t.Errorf("reset link leaked the request Host: %q", msg.Body)
	}
}
