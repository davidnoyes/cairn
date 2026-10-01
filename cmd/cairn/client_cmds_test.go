package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if err := runReset([]string{link}); err == nil {
		t.Fatal("runReset with neither --recovery-code nor --no-recovery-code succeeded")
	}
	if err := runReset([]string{link, "--recovery-code", "AAAA", "--no-recovery-code"}); err == nil {
		t.Fatal("runReset with both --recovery-code and --no-recovery-code succeeded")
	}
}

func TestRunResetRequiresLink(t *testing.T) {
	if err := runReset([]string{"--recovery-code", "AAAA"}); err == nil {
		t.Fatal("runReset with no link succeeded")
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
