package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunServeRequiresSMTPURL(t *testing.T) {
	t.Setenv("CAIRN_SMTP_URL", "")
	err := runServe([]string{"--data-dir", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "--smtp-url (or CAIRN_SMTP_URL) is required") {
		t.Errorf("runServe without a mailer: %v", err)
	}
}

func TestRunServeRejectsABadMailScheme(t *testing.T) {
	err := runServe([]string{"--data-dir", t.TempDir(), "--smtp-url", "http://mail.example.com"})
	if err == nil || !strings.Contains(err.Error(), "scheme must be log:// or smtp://") {
		t.Errorf("runServe with an http mailer: %v", err)
	}
}

func TestRunServeFailsWhenTheAddressIsTaken(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	err = runServe([]string{"--addr", l.Addr().String(), "--data-dir", t.TempDir(), "--smtp-url", "log://"})
	if err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("runServe on a taken port: %v", err)
	}
}

// TestRunServeBootsServesAndShutsDown drives the real entry point: flags and
// environment in, a listening server out, a signal to stop it.
func TestRunServeBootsServesAndShutsDown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	dir := t.TempDir()
	t.Setenv("CAIRN_MAX_UPLOAD_MB", "not-a-number") // falls back to the default
	t.Setenv("CAIRN_TOKEN_TTL", "1h")

	done := make(chan error, 1)
	go func() {
		done <- runServe([]string{"--addr", addr, "--data-dir", dir, "--smtp-url", "log://",
			"--public-url", "http://" + addr, "--signup-domain", "example.com", "--signup-domain", "example.org"})
	}()

	var body string
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("/healthz = %d", resp.StatusCode)
			}
			body = string(b)
			break
		}
		select {
		case err := <-done:
			t.Fatalf("server exited before listening: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never listened: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("/healthz body = %q", body)
	}
	if _, err := os.Stat(filepath.Join(dir, "cairn.db")); err != nil {
		t.Errorf("the data dir was not initialised: %v", err)
	}

	// The command's signal handler is installed, so this stops the server
	// rather than the test binary.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runServe returned %v after SIGTERM, want a clean shutdown", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("runServe did not return after SIGTERM")
	}
	if _, err := http.Get("http://" + addr + "/healthz"); err == nil {
		t.Error("the server still answers after shutdown")
	}
}

func TestStringListAccumulates(t *testing.T) {
	var l stringList
	_ = l.Set("a.com")
	_ = l.Set("b.com")
	if len(l) != 2 || l.String() != "a.com,b.com" {
		t.Errorf("stringList = %v (%q)", []string(l), l.String())
	}
}

func TestEnvParsersFallBackOnGarbage(t *testing.T) {
	t.Setenv("CAIRN_T_DUR", "90s")
	t.Setenv("CAIRN_T_INT", "42")
	if got := envDurationOr("CAIRN_T_DUR", time.Hour); got != 90*time.Second {
		t.Errorf("envDurationOr = %v", got)
	}
	if got := envInt64Or("CAIRN_T_INT", 7); got != 42 {
		t.Errorf("envInt64Or = %d", got)
	}
	t.Setenv("CAIRN_T_DUR", "soon")
	t.Setenv("CAIRN_T_INT", "4x")
	if got := envDurationOr("CAIRN_T_DUR", time.Hour); got != time.Hour {
		t.Errorf("envDurationOr(garbage) = %v, want the default", got)
	}
	if got := envInt64Or("CAIRN_T_INT", 7); got != 7 {
		t.Errorf("envInt64Or(garbage) = %d, want the default", got)
	}
	if got := envInt64Or("CAIRN_T_UNSET", 9); got != 9 {
		t.Errorf("envInt64Or(unset) = %d", got)
	}
	if got := envOr("CAIRN_T_UNSET", "dflt"); got != "dflt" {
		t.Errorf("envOr(unset) = %q", got)
	}
}
