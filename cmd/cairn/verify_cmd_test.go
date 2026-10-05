package main

import (
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
	"github.com/aloisdeniel/cairn/internal/release"
	"github.com/aloisdeniel/cairn/internal/server"
)

// newReleaseServer boots a real server whose public URL is its loopback
// address, so its content origin is *.localhost on the same port, as a
// local deployment's is.
func newReleaseServer(t *testing.T) (string, *mail.Capture) {
	t.Helper()
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "http://127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	m := &mail.Capture{}
	s, err := server.New(server.Config{
		DataDir:       t.TempDir(),
		PublicURL:     origin,
		SignupDomains: []string{"example.com"},
		AdminEmail:    "admin@example.com",
		TokenTTL:      time.Hour,
		Mail:          m,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.Listener.Close()
	ts.Listener = ln
	ts.Start()
	t.Cleanup(ts.Close)
	return origin, m
}

// releaseKey returns a fresh release key's seed and base64url public key.
func releaseKey(t *testing.T) ([]byte, string) {
	t.Helper()
	seed, pub, err := e2e.GenerateEd25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return seed, e2e.B64(pub)
}

// writeManifest signs this binary's manifest, after change, and writes it to
// a temp file.
func writeManifest(t *testing.T, seed []byte, change func(*release.Manifest)) string {
	t.Helper()
	m, err := server.ReleaseManifest("v9.9.9-test")
	if err != nil {
		t.Fatal(err)
	}
	if change != nil {
		change(&m)
	}
	signed, err := release.Sign(seed, m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runVerifyOut(t *testing.T, args ...string) (string, error) {
	t.Helper()
	done := captureStdout(t)
	err := runVerify(args)
	return done(), err
}

func TestVerifyPassesAgainstAnUnchangedServer(t *testing.T) {
	host, _ := newReleaseServer(t)
	seed, pub := releaseKey(t)
	out, err := runVerifyOut(t, "--allow-skip", "--manifest", writeManifest(t, seed, nil), "--key", pub, host)
	if err != nil {
		t.Fatalf("runVerify: %v\n%s", err, out)
	}
	if !strings.Contains(out, "v9.9.9-test") {
		t.Errorf("output does not name the release:\n%s", out)
	}
	if !strings.Contains(out, " 0 changed, 0 failed, 1 skipped") {
		t.Errorf("output does not total a clean run with /app skipped:\n%s", out)
	}
	if !strings.Contains(out, "skipped") || !strings.Contains(out, host+"/app") {
		t.Errorf("output does not say /app was skipped:\n%s", out)
	}
}

func TestVerifyFailsOnASkippedPageUnlessAllowed(t *testing.T) {
	host, _ := newReleaseServer(t)
	seed, pub := releaseKey(t)
	manifest := writeManifest(t, seed, nil)
	out, err := runVerifyOut(t, "--manifest", manifest, "--key", pub, host)
	if err == nil {
		t.Fatalf("runVerify passed with a page skipped and no --allow-skip:\n%s", out)
	}
	for _, want := range []string{"1 skipped", "cairn login", "--allow-skip"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
	if !strings.Contains(out, " 0 changed, 0 failed, 1 skipped") {
		t.Errorf("output lost its summary line:\n%s", out)
	}
	if out, err := runVerifyOut(t, "--allow-skip", "--manifest", manifest, "--key", pub, host); err != nil {
		t.Errorf("runVerify --allow-skip: %v\n%s", err, out)
	}
}

func TestVerifyPinsTheVersion(t *testing.T) {
	host, _ := newReleaseServer(t)
	seed, pub := releaseKey(t)
	manifest := writeManifest(t, seed, nil)
	if out, err := runVerifyOut(t, "--allow-skip", "--version", "v9.9.9-test", "--manifest", manifest, "--key", pub, host); err != nil {
		t.Errorf("runVerify with the served version: %v\n%s", err, out)
	}
	_, err := runVerifyOut(t, "--allow-skip", "--version", "v1.0.0", "--manifest", manifest, "--key", pub, host)
	if err == nil || !strings.Contains(err.Error(), "v9.9.9-test") || !strings.Contains(err.Error(), "v1.0.0") {
		t.Errorf("runVerify with another version: %v, want an error naming both", err)
	}
}

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"http://localhost:8790", "http://localhost:8790", true},
		{"https://Cairn.Example.com", "https://cairn.example.com", true},
		{"https://cairn.example.com:443", "https://cairn.example.com", true},
		{"https://cairn.example.com/path", "https://cairn.example.com", true},
		{"https://cairn.example.com", "http://cairn.example.com", false},
		{"https://cairn.example.com:8443", "https://cairn.example.com", false},
		{"https://cairn.example.com", "https://other.example.com", false},
		{"", "https://cairn.example.com", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := sameOrigin(c.a, c.b); got != c.want {
			t.Errorf("sameOrigin(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestVerifyFailsAndNamesAChangedFile(t *testing.T) {
	host, _ := newReleaseServer(t)
	seed, pub := releaseKey(t)
	manifest := writeManifest(t, seed, func(m *release.Manifest) {
		for i := range m.Assets {
			if m.Assets[i].Path == "/login.js" {
				m.Assets[i].SHA256 = strings.Repeat("0", 64)
			}
		}
	})
	out, err := runVerifyOut(t, "--manifest", manifest, "--key", pub, host)
	if err == nil {
		t.Fatalf("runVerify passed a server whose /login.js differs from the release:\n%s", out)
	}
	if !strings.Contains(out, "changed") || !strings.Contains(out, host+"/login.js") {
		t.Errorf("output does not name /login.js as changed:\n%s", out)
	}
	if !strings.Contains(err.Error(), "1 changed") {
		t.Errorf("error = %v, want it to count the change", err)
	}
}

func TestVerifyChecksTheHomePageWhenSignedIn(t *testing.T) {
	host, m := newReleaseServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)
	withStdin(t, password+"\n")
	if err := runLogin([]string{"--host", host, "--email", email, "--password-stdin"}); err != nil {
		t.Fatalf("runLogin: %v", err)
	}
	seed, pub := releaseKey(t)
	out, err := runVerifyOut(t, "--manifest", writeManifest(t, seed, nil), "--key", pub)
	if err != nil {
		t.Fatalf("runVerify: %v\n%s", err, out)
	}
	if !strings.Contains(out, " 0 changed, 0 failed, 0 skipped") {
		t.Errorf("signed in, /app should be checked, not skipped:\n%s", out)
	}
}

func TestVerifySendsNoKeyToAnotherHost(t *testing.T) {
	// Each server gets its own CAIRN_CONFIG, so start the other one first,
	// or it would drop the login this test needs.
	other, _ := newReleaseServer(t)
	host, m := newReleaseServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)
	withStdin(t, password+"\n")
	if err := runLogin([]string{"--host", host, "--email", email, "--password-stdin"}); err != nil {
		t.Fatalf("runLogin: %v", err)
	}
	seed, pub := releaseKey(t)
	manifest := writeManifest(t, seed, nil)
	out, err := runVerifyOut(t, "--allow-skip", "--manifest", manifest, "--key", pub, other)
	if err != nil {
		t.Fatalf("runVerify: %v\n%s", err, out)
	}
	if !strings.Contains(out, "1 skipped") {
		t.Errorf("the login's key went to a server it is not for:\n%s", out)
	}
	// The login is in effect: its own server gets the key.
	if out, err := runVerifyOut(t, "--manifest", manifest, "--key", pub, host); err != nil || !strings.Contains(out, " 0 skipped") {
		t.Errorf("runVerify on the login's server: %v\n%s", err, out)
	}
}

func TestVerifyRefusesAnUntrustedManifest(t *testing.T) {
	host, _ := newReleaseServer(t)
	seed, _ := releaseKey(t)
	_, other := releaseKey(t)
	_, err := runVerifyOut(t, "--manifest", writeManifest(t, seed, nil), "--key", other, host)
	if !errors.Is(err, release.ErrUntrusted) {
		t.Errorf("runVerify: %v, want ErrUntrusted", err)
	}
}

func TestVerifyNeedsAKey(t *testing.T) {
	host, _ := newReleaseServer(t)
	seed, _ := releaseKey(t)
	_, err := runVerifyOut(t, "--manifest", writeManifest(t, seed, nil), host)
	if !errors.Is(err, release.ErrNoKeys) || !strings.Contains(err.Error(), "--key") {
		t.Errorf("runVerify: %v, want ErrNoKeys naming --key", err)
	}
}

func TestVerifyRefusesAMalformedKey(t *testing.T) {
	host, _ := newReleaseServer(t)
	_, err := runVerifyOut(t, "--key", "not-a-key", host)
	if !errors.Is(err, e2e.ErrFormat) {
		t.Errorf("runVerify: %v, want ErrFormat", err)
	}
}

func TestVerifyNeedsAManifestFromSomewhere(t *testing.T) {
	host, _ := newReleaseServer(t)
	_, pub := releaseKey(t)
	_, err := runVerifyOut(t, "--allow-skip", "--key", pub, host)
	if err == nil || !strings.Contains(err.Error(), "--manifest") {
		t.Errorf("runVerify: %v, want an error naming --manifest", err)
	}
}

func TestVerifyReadsTheServersManifest(t *testing.T) {
	host, _ := newReleaseServer(t)
	seed, pub := releaseKey(t)
	signed, err := os.ReadFile(writeManifest(t, seed, nil))
	if err != nil {
		t.Fatal(err)
	}
	old := release.Signed
	release.Signed = signed
	t.Cleanup(func() { release.Signed = old })
	out, err := runVerifyOut(t, "--allow-skip", "--key", pub, host)
	if err != nil {
		t.Fatalf("runVerify: %v\n%s", err, out)
	}
	if !strings.Contains(out, "v9.9.9-test") {
		t.Errorf("output does not name the server's release:\n%s", out)
	}
}

func TestVerifyNeedsAServer(t *testing.T) {
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	_, pub := releaseKey(t)
	_, err := runVerifyOut(t, "--key", pub)
	if err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("runVerify with no server and no login: %v, want usage", err)
	}
}
