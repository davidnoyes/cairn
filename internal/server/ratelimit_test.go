package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/clock"
)

func TestLimiterBlocksAfterLimitFailures(t *testing.T) {
	clk := clock.NewFake(time.Now())
	l := newLimiter(clk, 5, 15*time.Minute)
	for i := 0; i < 4; i++ {
		if _, blocked := l.blocked("alice"); blocked {
			t.Fatalf("blocked too early at failure %d", i+1)
		}
		l.record("alice")
	}
	// 5th failure: still allowed through (it's the one that reaches the
	// limit), but once recorded, the next check blocks.
	if _, blocked := l.blocked("alice"); blocked {
		t.Fatal("5th attempt blocked, want allowed")
	}
	l.record("alice")
	if _, blocked := l.blocked("alice"); !blocked {
		t.Fatal("6th attempt allowed, want blocked")
	}
}

func TestLimiterRetryAfter(t *testing.T) {
	start := time.Now()
	clk := clock.NewFake(start)
	l := newLimiter(clk, 1, time.Minute)
	l.record("alice")
	clk.Advance(20 * time.Second)
	retryAfter, blocked := l.blocked("alice")
	if !blocked {
		t.Fatal("want blocked")
	}
	if want := 40 * time.Second; retryAfter != want {
		t.Errorf("retryAfter = %v, want %v", retryAfter, want)
	}
}

func TestLimiterEventsAgeOutAtWindowBoundary(t *testing.T) {
	start := time.Now()
	clk := clock.NewFake(start)
	l := newLimiter(clk, 1, time.Minute)
	l.record("alice")
	if _, blocked := l.blocked("alice"); !blocked {
		t.Fatal("want blocked immediately after recording")
	}
	// Exactly at the window boundary the event has aged out.
	clk.Set(start.Add(time.Minute))
	if _, blocked := l.blocked("alice"); blocked {
		t.Fatal("want not blocked exactly at the window boundary")
	}
}

func TestLimiterKeysAreIndependent(t *testing.T) {
	clk := clock.NewFake(time.Now())
	l := newLimiter(clk, 1, time.Minute)
	l.record("alice")
	if _, blocked := l.blocked("alice"); !blocked {
		t.Fatal("alice should be blocked")
	}
	if _, blocked := l.blocked("bob"); blocked {
		t.Fatal("bob should not be blocked by alice's events")
	}
}

func TestLimiterTakeRespectsLimit(t *testing.T) {
	clk := clock.NewFake(time.Now())
	l := newLimiter(clk, 3, time.Hour)
	for i := 0; i < 3; i++ {
		if !l.take("a@example.com") {
			t.Fatalf("take %d: want true", i+1)
		}
	}
	if l.take("a@example.com") {
		t.Fatal("4th take: want false")
	}
}

func TestLimiterPruneEmptiesMap(t *testing.T) {
	start := time.Now()
	clk := clock.NewFake(start)
	l := newLimiter(clk, 5, time.Minute)
	l.record("alice")
	l.record("bob")
	clk.Advance(2 * time.Minute)
	// Any call that touches a key prunes it.
	l.blocked("alice")
	l.blocked("bob")
	l.mu.Lock()
	n := len(l.events)
	l.mu.Unlock()
	if n != 0 {
		t.Errorf("events map has %d keys after everything expired, want 0", n)
	}
}

func TestLimiterConcurrentUse(t *testing.T) {
	clk := clock.NewFake(time.Now())
	l := newLimiter(clk, 100, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				l.take("shared")
				l.blocked("shared")
				l.record("other")
			}
		}()
	}
	wg.Wait()
}

func TestWriteRateLimited(t *testing.T) {
	rec := httptest.NewRecorder()
	writeRateLimited(rec, 30500*time.Millisecond)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "31" {
		t.Errorf("Retry-After = %q, want %q (rounded up)", got, "31")
	}
	if ct := rec.Header().Get("Content-Type"); ct == "" {
		t.Error("missing Content-Type")
	}
}

func TestNewSignInLimiters(t *testing.T) {
	clk := clock.NewFake(time.Now())
	l := newSignInLimiters(clk)
	for i := 0; i < 5; i++ {
		l.account.record("ada@example.com")
	}
	if _, blocked := l.account.blocked("ada@example.com"); !blocked {
		t.Error("account limiter should block after 5 failures")
	}
	for i := 0; i < 20; i++ {
		l.ip.record("1.2.3.4")
	}
	if _, blocked := l.ip.blocked("1.2.3.4"); !blocked {
		t.Error("ip limiter should block after 20 failures")
	}
}

func TestNewMailLimiter(t *testing.T) {
	clk := clock.NewFake(time.Now())
	l := newMailLimiter(clk)
	for i := 0; i < 3; i++ {
		if !l.take("ada@example.com") {
			t.Fatalf("take %d: want true", i+1)
		}
	}
	if l.take("ada@example.com") {
		t.Error("4th email: want blocked")
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct{ remoteAddr, want string }{
		{"203.0.113.5:54321", "203.0.113.5"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"no-port", "no-port"},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = c.remoteAddr
		req.Header.Set("X-Forwarded-For", "9.9.9.9")
		if got := clientIP(req); got != c.want {
			t.Errorf("clientIP(%q) = %q, want %q", c.remoteAddr, got, c.want)
		}
	}
}
