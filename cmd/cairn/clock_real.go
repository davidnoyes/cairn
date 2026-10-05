//go:build !e2eclock

package main

import "github.com/aloisdeniel/cairn/internal/clock"

// serveClock is the server's clock: the wall clock. The browser tests build
// with the e2eclock tag instead; see clock_e2e.go.
func serveClock() (clock.Clock, error) { return clock.Real{}, nil }
