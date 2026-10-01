package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/mail"
)

// TestRunAppliesRequestProtection boots the server through Run, the path
// `cairn serve` takes, rather than through Handler as the other tests do, so
// request protection can't be wired into one and missed in the other.
func TestRunAppliesRequestProtection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	s, err := New(Config{
		Addr:     addr,
		DataDir:  t.TempDir(),
		TokenTTL: time.Hour,
		Mail:     &mail.Capture{},
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	var resp *http.Response
	for range 100 {
		resp, err = http.Post("http://"+addr+"/api/auth/login", "application/x-www-form-urlencoded", strings.NewReader("email=a%40example.com"))
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("form-encoded login through Run: status %d, want 415", resp.StatusCode)
	}
}
