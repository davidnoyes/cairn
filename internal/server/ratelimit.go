package server

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/aloisdeniel/cairn/internal/clock"
)

// limiter enforces a sliding-window rate limit: at most limit events per key
// within the window ending now, measured on clk so tests can move time
// without sleeping. Safe for concurrent use.
type limiter struct {
	clk    clock.Clock
	limit  int
	window time.Duration

	mu     sync.Mutex
	events map[string][]time.Time
}

func newLimiter(clk clock.Clock, limit int, window time.Duration) *limiter {
	return &limiter{clk: clk, limit: limit, window: window, events: make(map[string][]time.Time)}
}

// prune drops events that fell out of the window and, once a key has none
// left, removes the key entirely so memory doesn't grow with distinct keys
// over time. Events are stored oldest-first, so the surviving ones are a
// suffix of the slice. Must be called with mu held.
func (l *limiter) prune(key string, now time.Time) []time.Time {
	cutoff := now.Add(-l.window)
	evs := l.events[key]
	i := 0
	for i < len(evs) && !evs[i].After(cutoff) {
		i++
	}
	evs = evs[i:]
	if len(evs) == 0 {
		delete(l.events, key)
		return nil
	}
	l.events[key] = evs
	return evs
}

// blocked reports whether key already has limit events inside the window. On
// true, retryAfter is how long until the oldest of those events leaves the
// window.
func (l *limiter) blocked(key string) (retryAfter time.Duration, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clk.Now()
	evs := l.prune(key, now)
	if len(evs) < l.limit {
		return 0, false
	}
	retryAfter = evs[0].Add(l.window).Sub(now)
	if retryAfter < 0 {
		retryAfter = 0
	}
	return retryAfter, true
}

// record adds an event for key at the current time.
func (l *limiter) record(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clk.Now()
	evs := l.prune(key, now)
	l.events[key] = append(evs, now)
}

// take atomically checks and records: if key isn't blocked it records an
// event and returns true, otherwise it returns false without recording.
func (l *limiter) take(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clk.Now()
	evs := l.prune(key, now)
	if len(evs) >= l.limit {
		return false
	}
	l.events[key] = append(evs, now)
	return true
}

// writeRateLimited answers a rate-limited request with 429 and a Retry-After
// header in whole seconds, rounded up so the client never retries too early.
func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	secs := int((retryAfter + time.Second - 1) / time.Second)
	if secs < 0 {
		secs = 0
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, "too many requests")
}

// signInLimiters pairs the two sign-in failure limits the design calls for:
// five failures per account and 20 per client IP, both in a 15-minute window.
type signInLimiters struct {
	account *limiter
	ip      *limiter
}

func newSignInLimiters(clk clock.Clock) *signInLimiters {
	return &signInLimiters{
		account: newLimiter(clk, 5, 15*time.Minute),
		ip:      newLimiter(clk, 20, 15*time.Minute),
	}
}

// newMailLimiter enforces three emails per address per hour, across sign-up,
// verification, and reset.
func newMailLimiter(clk clock.Clock) *limiter {
	return newLimiter(clk, 3, time.Hour)
}

// clientIP returns the request's immediate peer address, not any
// client-supplied header: without a trusted reverse proxy stripping it,
// X-Forwarded-For can be set by the client itself, which would let an
// attacker pick their own rate-limit bucket.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
