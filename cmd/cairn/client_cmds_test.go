package main

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/clock"
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

// The prompt shows the code with the asked-for group blanked out, so the
// user knows which part to type without counting groups.
func TestConfirmRecoveryCodePromptBlanksOneGroup(t *testing.T) {
	const display = "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ"
	withStdin(t, "WRONG\n")
	done := captureStdout(t)
	_ = confirmRecoveryCode(display)
	out := done()
	m := regexp.MustCompile(`type the missing group: (\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("prompt = %q, want the code with a group blanked", out)
	}
	got, want := strings.Split(m[1], "-"), strings.Split(display, "-")
	blanked := 0
	for i := range want {
		switch got[i] {
		case want[i]:
		case strings.Repeat("_", len(want[i])):
			blanked++
		default:
			t.Fatalf("group %d = %q, want %q or blanks", i, got[i], want[i])
		}
	}
	if len(got) != len(want) || blanked != 1 {
		t.Fatalf("prompt code %q blanks %d groups, want 1", m[1], blanked)
	}
}

func TestConfirmRecoveryCodeRejected(t *testing.T) {
	withStdin(t, "WRONG\n")
	if err := confirmRecoveryCode("ABCD"); err == nil {
		t.Fatal("a wrong group was accepted")
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
	if c.Key == nil || c.Key.KeyID != "0011223344556677" {
		t.Errorf("Key = %v, want the parsed key", c.Key)
	}

	t.Setenv("CAIRN_API_KEY", "not-a-key")
	if _, err := apiClient(); err == nil {
		t.Error("apiClient accepted a malformed key")
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
	return newTestServerAt(t, nil)
}

// newTestServerAt is newTestServer on clk, which a test moves to pass the
// server's waiting periods; nil is the wall clock.
func newTestServerAt(t *testing.T, clk clock.Clock) (host string, m *mail.Capture) {
	t.Helper()
	m = &mail.Capture{}
	s, err := server.New(server.Config{
		Clock:         clk,
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
	key, err := e2e.ParseAPIKey(out.APIKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.New(host, bearerOf(key)).Me(); err == nil {
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
	// Revoke it out of band, the way an admin or another device would.
	if err := client.New(host, bearerOf(key)).RevokeKey(key.KeyID); err != nil {
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

// captureStderr is captureStdout for os.Stderr.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	return func() string {
		w.Close()
		os.Stderr = old
		data, _ := io.ReadAll(r)
		return string(data)
	}
}

// saveDummyLogin stores a config holding dummyFullAPIKey for host.
func saveDummyLogin(t *testing.T, host string) cliConfig {
	t.Helper()
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	cfg := cliConfig{Host: host, Email: "ada@example.com", APIKey: dummyFullAPIKey}
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestRunLogoutForceClearsConfigAndWarnsWhenRevokeFails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.Close() // refuses every connection
	saveDummyLogin(t, ts.URL)

	doneErr := captureStderr(t)
	doneOut := captureStdout(t)
	err := runLogout([]string{"--force"})
	stdout, stderr := doneOut(), doneErr()
	if err != nil {
		t.Fatalf("runLogout --force: %v", err)
	}
	if got := loadConfig(); got != (cliConfig{}) {
		t.Errorf("loadConfig() = %+v, want cleared", got)
	}
	want := "key 0011223344556677 may still be valid; revoke it after logging in again, or from another device, with `cairn keys revoke 0011223344556677`"
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
	if !strings.Contains(stdout, "logged out") {
		t.Errorf("stdout = %q, want logged out", stdout)
	}
}

func TestRunLogoutForceStaysQuietWhenRevokeSucceeds(t *testing.T) {
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
	doneErr := captureStderr(t)
	doneOut := captureStdout(t)
	err = runLogout([]string{"--force"})
	doneOut()
	if stderr := doneErr(); err != nil || stderr != "" {
		t.Errorf("runLogout --force = %v, stderr %q; want success and silence", err, stderr)
	}
}

func TestRunLogoutFailureErrorMentionsForce(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.Close()
	saveDummyLogin(t, ts.URL)
	err := runLogout(nil)
	if err == nil || !strings.HasSuffix(err.Error(), "; you are still logged in (use --force to log out locally anyway)") {
		t.Errorf("runLogout error = %v, want the --force hint at the end", err)
	}
}

func TestRunLogoutServerErrorKeepsConfigAndNamesKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
	}))
	t.Cleanup(ts.Close)
	want := saveDummyLogin(t, ts.URL)

	err := runLogout(nil)
	if err == nil {
		t.Fatal("runLogout against a 500 succeeded")
	}
	if !strings.Contains(err.Error(), "could not revoke key 0011223344556677") {
		t.Errorf("runLogout error = %v, want it to name the key id", err)
	}
	if got := loadConfig(); got != want {
		t.Errorf("loadConfig() = %+v, want unchanged %+v", got, want)
	}
}

func TestRunLogoutTimesOutOnBlackHoledHost(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(func() { close(release) })
	want := saveDummyLogin(t, ts.URL)
	old := logoutTimeout
	logoutTimeout = 100 * time.Millisecond
	t.Cleanup(func() { logoutTimeout = old })

	start := time.Now()
	err := runLogout(nil)
	if err == nil {
		t.Fatal("runLogout against a blocked host succeeded")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Errorf("runLogout error = %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("runLogout took %v, want it bounded by the timeout", elapsed)
	}
	if got := loadConfig(); got != want {
		t.Errorf("loadConfig() = %+v, want unchanged %+v", got, want)
	}
}

func TestRunLogoutUnreadableKeyWarnsAndClears(t *testing.T) {
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	if err := saveConfig(cliConfig{Host: "http://example.test", Email: "ada@example.com", APIKey: "not-a-key"}); err != nil {
		t.Fatal(err)
	}
	doneErr := captureStderr(t)
	doneOut := captureStdout(t)
	err := runLogout(nil)
	doneOut()
	stderr := doneErr()
	if err != nil {
		t.Fatalf("runLogout: %v", err)
	}
	if !strings.Contains(stderr, "stored API key is unreadable; clearing it without revoking") {
		t.Errorf("stderr = %q, want the unreadable-key warning", stderr)
	}
	if got := loadConfig(); got != (cliConfig{}) {
		t.Errorf("loadConfig() = %+v, want cleared", got)
	}
}

func TestRunLogoutEmptyConfigIsSilent(t *testing.T) {
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	doneErr := captureStderr(t)
	doneOut := captureStdout(t)
	err := runLogout(nil)
	doneOut()
	if stderr := doneErr(); err != nil || stderr != "" {
		t.Errorf("runLogout on an empty config = %v, stderr %q; want success and silence", err, stderr)
	}
}

func TestKeysRevokeOtherKeyLeavesConfigIntact(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)
	here, err := client.New(host, "").Login(email, password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	other, err := client.New(host, "").Login(email, password)
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}
	otherKey, err := e2e.ParseAPIKey(other.APIKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	want := cliConfig{Host: host, Email: email, APIKey: here.APIKey}
	if err := saveConfig(want); err != nil {
		t.Fatal(err)
	}

	done := captureStdout(t)
	err = keysRevoke([]string{otherKey.KeyID})
	got := done()
	if err != nil {
		t.Fatalf("keysRevoke: %v", err)
	}
	if strings.Contains(got, "logged out") {
		t.Errorf("keysRevoke output = %q, want no logged-out text", got)
	}
	if cfg := loadConfig(); cfg != want {
		t.Errorf("loadConfig() = %+v, want unchanged %+v", cfg, want)
	}
}

func TestReadPasswordOrStdinStripsCRLF(t *testing.T) {
	withStdin(t, "pw\r\n")
	got, err := readPasswordOrStdin(true, "password: ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "pw" {
		t.Errorf("readPasswordOrStdin = %q, want %q", got, "pw")
	}
}

func TestRunLoginEmptyStdinRefused(t *testing.T) {
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	withStdin(t, "")
	err := runLogin([]string{"--host", "http://127.0.0.1:1", "--email", "ada@example.com", "--password-stdin"})
	if !errors.Is(err, client.ErrEmptyPassword) {
		t.Errorf("runLogin with empty stdin: err = %v, want ErrEmptyPassword", err)
	}
}

func TestRunLogoutWarnsThatAnEnvKeyStaysValid(t *testing.T) {
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	t.Setenv("CAIRN_API_KEY", dummyFullAPIKey)
	doneErr := captureStderr(t)
	doneOut := captureStdout(t)
	err := runLogout(nil)
	doneOut()
	if stderr := doneErr(); err != nil || !strings.Contains(stderr, "CAIRN_API_KEY stays valid") {
		t.Errorf("runLogout with CAIRN_API_KEY set = %v, stderr %q; want a warning that the env key stays valid", err, stderr)
	}
}
