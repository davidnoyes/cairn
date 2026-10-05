//go:build e2eclock

package main

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/aloisdeniel/cairn/internal/clock"
)

// testClockEnv names the file that holds the clock's offset.
const testClockEnv = "CAIRN_TEST_CLOCK_FILE"

// serveClock, in a build for the browser tests only, runs the server's clock
// ahead of the wall clock by the duration in the file testClockEnv names, so
// a test can pass the successor's waiting period without waiting. A release
// build never contains it.
func serveClock() (clock.Clock, error) {
	path := os.Getenv(testClockEnv)
	if path == "" {
		return nil, errors.New("this is a test build: set " + testClockEnv)
	}
	return offsetClock(path), nil
}

// offsetClock reads its file on every call. A missing or malformed file
// means no offset.
type offsetClock string

func (c offsetClock) Now() time.Time {
	b, _ := os.ReadFile(string(c))
	d, _ := time.ParseDuration(strings.TrimSpace(string(b)))
	return time.Now().Add(d)
}
