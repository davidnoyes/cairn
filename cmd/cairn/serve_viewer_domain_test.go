package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// TestRunServeViewerDomains drives the real entry point with one
// --viewer-domain flag and a comma-separated CAIRN_VIEWER_DOMAINS, and checks
// each listed domain may sign up while an unlisted one is refused.
func TestRunServeViewerDomains(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	t.Setenv("CAIRN_VIEWER_DOMAINS", "From-Env.test, second.test")

	done := make(chan error, 1)
	go func() {
		done <- runServe([]string{"--addr", addr, "--data-dir", t.TempDir(), "--smtp-url", "log://",
			"--public-url", "http://" + addr, "--viewer-domain", "flag.test"})
	}()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if resp, err := http.Get("http://" + addr + "/healthz"); err == nil {
			resp.Body.Close()
			break
		}
		select {
		case err := <-done:
			t.Fatalf("server exited before listening: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("server never listened")
		}
	}

	// A sign-up needs a real bundle only past the domain check, which is the
	// part under test: a 403 is the domain refusal, anything else got past it.
	signup := func(email string) int {
		body, _ := json.Marshal(map[string]any{"email": email, "name": "X", "authKey": e2e.B64(make([]byte, 32)), "bundle": map[string]string{}})
		resp, err := http.Post("http://"+addr+"/api/auth/signup", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for email, want := range map[string]int{
		"a@flag.test":     http.StatusBadRequest, // past the domain check, then a malformed bundle
		"a@from-env.test": http.StatusBadRequest,
		"a@second.test":   http.StatusBadRequest,
		"a@other.test":    http.StatusForbidden,
	} {
		if got := signup(email); got != want {
			t.Errorf("sign-up %s: %d, want %d", email, got, want)
		}
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runServe returned %v after SIGTERM", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("runServe did not return after SIGTERM")
	}
}
