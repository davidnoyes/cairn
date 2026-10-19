package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/mail"
	"github.com/aloisdeniel/cairn/internal/server"
)

// TestWhoamiShowsTheServerRole signs in as a member and as a viewer account
// and checks whoami names the role in both its text and its JSON.
func TestWhoamiShowsTheServerRole(t *testing.T) {
	m := &mail.Capture{}
	s, err := server.New(server.Config{
		DataDir:       t.TempDir(),
		SignupDomains: []string{"example.com"},
		ViewerDomains: []string{"viewers.test"},
		AdminEmail:    "admin@example.com",
		Mail:          m,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	password := "correct horse battery staple"
	for email, role := range map[string]string{"ada@example.com": "member", "carol@viewers.test": "viewer"} {
		signupVerify(t, ts.URL, m, email, password)
		t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
		withStdin(t, password+"\n")
		if err := runLogin([]string{"--host", ts.URL, "--email", email, "--password-stdin"}); err != nil {
			t.Fatalf("runLogin %s: %v", email, err)
		}

		done := captureStdout(t)
		err := runWhoami(nil)
		out := done()
		if err != nil {
			t.Fatalf("runWhoami: %v", err)
		}
		if want := email + " (Ada) — " + role + " on "; !strings.Contains(out, want) {
			t.Errorf("whoami output = %q, want it to contain %q", out, want)
		}

		done = captureStdout(t)
		err = runWhoami([]string{"--json"})
		out = done()
		if err != nil {
			t.Fatalf("runWhoami --json: %v", err)
		}
		var got struct {
			User struct {
				Role string `json:"role"`
			} `json:"user"`
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil || got.User.Role != role {
			t.Errorf("whoami --json = %q (%v), want user.role %q", out, err, role)
		}
	}
}
