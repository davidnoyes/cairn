package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
	"github.com/aloisdeniel/cairn/internal/server"
)

// withStdin temporarily replaces os.Stdin with a pipe fed by content, for
// commands and helpers that read from it.
func withStdin(t *testing.T, content string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(content); err != nil {
		t.Fatal(err)
	}
	w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })
}

func TestReadPasswordOrStdin(t *testing.T) {
	withStdin(t, "hunter2\nignored\n")
	got, err := readPasswordOrStdin(true, "password: ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hunter2" {
		t.Errorf("readPasswordOrStdin = %q, want %q", got, "hunter2")
	}
}

func TestReadPasswordOrStdinNoTrailingNewline(t *testing.T) {
	withStdin(t, "hunter2")
	got, err := readPasswordOrStdin(true, "password: ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hunter2" {
		t.Errorf("readPasswordOrStdin = %q, want %q", got, "hunter2")
	}
}

// A single-group display makes randIndex deterministic (always 0), so these
// tests don't need to guess which group confirmRecoveryCode asks for.

func TestConfirmRecoveryCodeAccepted(t *testing.T) {
	withStdin(t, "ABCD\n")
	if err := confirmRecoveryCode("ABCD"); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmRecoveryCodeCaseInsensitive(t *testing.T) {
	withStdin(t, "abcd\n")
	if err := confirmRecoveryCode("ABCD"); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmRecoveryCodeRejected(t *testing.T) {
	withStdin(t, "WRONG\n")
	if err := confirmRecoveryCode("ABCD"); err == nil {
		t.Fatal("a wrong group was accepted")
	}
}

func TestApiKeyBearer(t *testing.T) {
	full := "cairn_0011223344556677_00112233445566778899aabbccddeeff_" + strings.Repeat("ab", 32)
	bearer, err := apiKeyBearer(full)
	if err != nil {
		t.Fatal(err)
	}
	want := "cairn_0011223344556677_00112233445566778899aabbccddeeff"
	if bearer != want {
		t.Errorf("apiKeyBearer = %q, want %q", bearer, want)
	}
	if _, err := apiKeyBearer("not-a-key"); err == nil {
		t.Error("a malformed key was accepted")
	}
}

func TestApiClientMissingCredentials(t *testing.T) {
	t.Setenv("CAIRN_HOST", "")
	t.Setenv("CAIRN_API_KEY", "")
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	if _, err := apiClient(); err == nil {
		t.Fatal("apiClient succeeded with no host and no config")
	}
}

func TestApiClientFromEnv(t *testing.T) {
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	t.Setenv("CAIRN_HOST", "http://example.test")
	t.Setenv("CAIRN_API_KEY", "cairn_0011223344556677_00112233445566778899aabbccddeeff_"+strings.Repeat("ab", 32))
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "http://example.test" {
		t.Errorf("Host = %q", c.Host)
	}
	if c.Token != "cairn_0011223344556677_00112233445566778899aabbccddeeff" {
		t.Errorf("Token leaked keySecret: %q", c.Token)
	}
}

func TestConfigRoundTrip(t *testing.T) {
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	want := cliConfig{Host: "http://example.test", Email: "ada@example.com", APIKey: "cairn_x_y_z"}
	if err := saveConfig(want); err != nil {
		t.Fatal(err)
	}
	got := loadConfig()
	if got != want {
		t.Errorf("loadConfig() = %+v, want %+v", got, want)
	}
}

func TestRunSignupRequiresHostAndEmail(t *testing.T) {
	if err := runSignup([]string{}); err == nil {
		t.Fatal("runSignup with no flags succeeded")
	}
	if err := runSignup([]string{"--host", "http://example.test"}); err == nil {
		t.Fatal("runSignup with no --email succeeded")
	}
}

func TestRunConfirmEmailRequiresLink(t *testing.T) {
	if err := runConfirmEmail([]string{}); err == nil {
		t.Fatal("runConfirmEmail with no link succeeded")
	}
}

func TestRunForgotRequiresHostAndEmail(t *testing.T) {
	if err := runForgot([]string{}); err == nil {
		t.Fatal("runForgot with no flags succeeded")
	}
}

func TestRunResetRequiresExactlyOneMode(t *testing.T) {
	link := "http://example.test/reset#token=abc"
	err := runReset([]string{link})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("runReset with neither --recovery-code nor --no-recovery-code = %v, want an \"exactly one\" error", err)
	}
	err = runReset([]string{link, "--recovery-code", "AAAA", "--no-recovery-code"})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("runReset with both --recovery-code and --no-recovery-code = %v, want an \"exactly one\" error", err)
	}
}

func TestRunResetRequiresLink(t *testing.T) {
	if err := runReset([]string{"--recovery-code", "AAAA"}); err == nil {
		t.Fatal("runReset with no link succeeded")
	}
}

// TestRunResetNoRecoveryCodeRefusesNonTerminal points at a closed server, so
// the test only passes if runReset refuses before it would ever contact it.
func TestRunResetNoRecoveryCodeRefusesNonTerminal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("runReset contacted the server before confirming --yes")
	}))
	ts.Close()
	link := ts.URL + "/reset#token=abc"
	withStdin(t, "") // a pipe, not a terminal
	err := runReset([]string{link, "--no-recovery-code"})
	want := "refusing to continue on a non-terminal without --yes"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("runReset --no-recovery-code without --yes on a non-terminal = %v, want %q", err, want)
	}
}

func TestRunKeysRevokeRequiresID(t *testing.T) {
	if err := keysRevoke([]string{}); err == nil {
		t.Fatal("keysRevoke with no id succeeded")
	}
}

func TestRunKeysUnknownSubcommand(t *testing.T) {
	if err := runKeys([]string{"bogus"}); err == nil {
		t.Fatal("runKeys accepted an unknown subcommand")
	}
	if err := runKeys([]string{}); err == nil {
		t.Fatal("runKeys with no subcommand succeeded")
	}
}

// newTestServer boots a real server on a temp data dir with a recording
// mailer, duplicated from internal/client/account_test.go (unexported there,
// so not reusable across packages).
func newTestServer(t *testing.T) (host string, m *mail.Capture) {
	t.Helper()
	m = &mail.Capture{}
	s, err := server.New(server.Config{
		DataDir:       t.TempDir(),
		SignupDomains: []string{"example.com"},
		AdminEmail:    "admin@example.com",
		Mail:          m,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts.URL, m
}

// verifyLink pulls the "<path>#token=..." link out of the last mail sent to
// email, duplicated from internal/client/account_test.go.
func verifyLink(t *testing.T, m *mail.Capture, email string) string {
	t.Helper()
	msg, ok := m.Last(email)
	if !ok {
		t.Fatalf("no mail sent to %s", email)
	}
	i := strings.Index(msg.Body, "#token=")
	if i < 0 {
		t.Fatalf("no link in mail body: %q", msg.Body)
	}
	rest := msg.Body[strings.LastIndexAny(msg.Body[:i], " \n\t")+1:]
	end := strings.IndexAny(rest, " \n\t")
	if end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// signupVerify creates and verifies an account through the real server,
// ready for runLogin.
func signupVerify(t *testing.T, host string, m *mail.Capture, email, password string) {
	t.Helper()
	if _, err := client.New(host, "").Signup(email, "Ada", password); err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if err := client.New(host, "").ConfirmEmail(verifyLink(t, m, email)); err != nil {
		t.Fatalf("ConfirmEmail: %v", err)
	}
}

// captureStdout temporarily replaces os.Stdout with a pipe; the returned
// function restores it and returns everything written in the meantime.
func captureStdout(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	return func() string {
		w.Close()
		os.Stdout = old
		data, _ := io.ReadAll(r)
		return string(data)
	}
}

func TestRunLoginWritesConfig(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))

	withStdin(t, password+"\n")
	if err := runLogin([]string{"--host", host, "--email", email, "--password-stdin"}); err != nil {
		t.Fatalf("runLogin: %v", err)
	}
	cfg := loadConfig()
	if cfg.Host != host || cfg.Email != email {
		t.Fatalf("loadConfig() = %+v, want host %q and email %q", cfg, host, email)
	}
	if len(strings.Split(cfg.APIKey, "_")) != 4 {
		t.Fatalf("APIKey = %q, want a four-part key", cfg.APIKey)
	}
}

func TestRunLoginMissingEmailErrors(t *testing.T) {
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	withStdin(t, "") // no email typed, and EOF immediately
	if err := runLogin([]string{"--host", "http://example.test"}); err == nil {
		t.Fatal("runLogin with no --email and no input succeeded")
	}
}

func TestRunWhoamiPrintsEmailAndFingerprint(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	withStdin(t, password+"\n")
	if err := runLogin([]string{"--host", host, "--email", email, "--password-stdin"}); err != nil {
		t.Fatalf("runLogin: %v", err)
	}

	done := captureStdout(t)
	err := runWhoami(nil)
	out := done()
	if err != nil {
		t.Fatalf("runWhoami: %v", err)
	}
	if !strings.Contains(out, email) {
		t.Errorf("whoami output = %q, missing email", out)
	}
	if !strings.Contains(out, "fingerprint:") {
		t.Errorf("whoami output = %q, missing fingerprint", out)
	}
}

func TestKeysListShowsDeviceKey(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	withStdin(t, password+"\n")
	if err := runLogin([]string{"--host", host, "--email", email, "--password-stdin"}); err != nil {
		t.Fatalf("runLogin: %v", err)
	}
	cfg := loadConfig()
	key, err := e2e.ParseAPIKey(cfg.APIKey)
	if err != nil {
		t.Fatal(err)
	}

	done := captureStdout(t)
	err = keysList(nil)
	out := done()
	if err != nil {
		t.Fatalf("keysList: %v", err)
	}
	if !strings.Contains(out, key.KeyID) {
		t.Errorf("keys list output = %q, missing key id %q", out, key.KeyID)
	}
	if !strings.Contains(out, "(device)") {
		t.Errorf("keys list output = %q, missing device marker", out)
	}
}

// dummyFullAPIKey looks like a real four-part key without needing a live
// server; it parses, but authenticates nothing.
var dummyFullAPIKey = "cairn_0011223344556677_00112233445566778899aabbccddeeff_" + strings.Repeat("ab", 32)

func TestRunLogoutRevokesKeyAndClearsConfig(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)
	out, err := client.New(host, "").Login(email, password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	if err := saveConfig(cliConfig{Host: host, Email: email, APIKey: out.APIKey}); err != nil {
		t.Fatal(err)
	}

	if err := runLogout(nil); err != nil {
		t.Fatalf("runLogout: %v", err)
	}
	if got := loadConfig(); got != (cliConfig{}) {
		t.Errorf("loadConfig() = %+v, want cleared", got)
	}
	bearer, err := apiKeyBearer(out.APIKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.New(host, bearer).Me(); err == nil {
		t.Error("the revoked device key still authenticates")
	}
}

func TestRunLogoutServerDownKeepsConfigAndErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.Close() // refuses every connection
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	want := cliConfig{Host: ts.URL, Email: "ada@example.com", APIKey: dummyFullAPIKey}
	if err := saveConfig(want); err != nil {
		t.Fatal(err)
	}

	done := captureStdout(t)
	err := runLogout(nil)
	out := done()
	if err == nil {
		t.Fatal("runLogout against a down server succeeded")
	}
	if !strings.Contains(err.Error(), "could not revoke key 0011223344556677") {
		t.Errorf("runLogout error = %v, want it to name the key id", err)
	}
	if got := loadConfig(); got != want {
		t.Errorf("loadConfig() = %+v, want unchanged %+v", got, want)
	}
	if out != "" {
		t.Errorf("stdout = %q, want nothing printed", out)
	}
}

func TestRunLogoutAlreadyRevokedKeyClearsConfig(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)
	out, err := client.New(host, "").Login(email, password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	key, err := e2e.ParseAPIKey(out.APIKey)
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := apiKeyBearer(out.APIKey)
	if err != nil {
		t.Fatal(err)
	}
	// Revoke it out of band, the way an admin or another device would.
	if err := client.New(host, bearer).RevokeKey(key.KeyID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	if err := saveConfig(cliConfig{Host: host, Email: email, APIKey: out.APIKey}); err != nil {
		t.Fatal(err)
	}

	if err := runLogout(nil); err != nil {
		t.Fatalf("runLogout with an already-revoked key: %v", err)
	}
	if got := loadConfig(); got != (cliConfig{}) {
		t.Errorf("loadConfig() = %+v, want cleared", got)
	}
}

func TestKeysRevokeOwnKeyLogsOut(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)
	out, err := client.New(host, "").Login(email, password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	key, err := e2e.ParseAPIKey(out.APIKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	if err := saveConfig(cliConfig{Host: host, Email: email, APIKey: out.APIKey}); err != nil {
		t.Fatal(err)
	}

	done := captureStdout(t)
	err = keysRevoke([]string{key.KeyID})
	got := done()
	if err != nil {
		t.Fatalf("keysRevoke: %v", err)
	}
	if !strings.Contains(got, "you are now logged out") {
		t.Errorf("keysRevoke output = %q, want it to mention being logged out", got)
	}
	if cfg := loadConfig(); cfg != (cliConfig{}) {
		t.Errorf("loadConfig() = %+v, want cleared", cfg)
	}
}
