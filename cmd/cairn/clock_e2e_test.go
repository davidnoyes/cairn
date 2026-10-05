//go:build e2eclock

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// init lets the package's other tests serve under this build too: an empty
// offset file means no offset.
func init() {
	os.Setenv(testClockEnv, os.DevNull)
}

func TestE2EClockReadsTheOffsetFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "offset")
	t.Setenv(testClockEnv, path)
	clk, err := serveClock()
	if err != nil {
		t.Fatal(err)
	}

	near := func(what string, want time.Time) {
		t.Helper()
		if d := clk.Now().Sub(want); d < -time.Minute || d > time.Minute {
			t.Errorf("%s: Now() is %v from %v", what, d, want)
		}
	}
	near("no file", time.Now())
	if err := os.WriteFile(path, []byte("360h\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	near("after writing 360h", time.Now().Add(360*time.Hour))
	if err := os.WriteFile(path, []byte("not a duration"), 0o600); err != nil {
		t.Fatal(err)
	}
	near("a malformed file", time.Now())
}

func TestE2EClockNeedsTheEnv(t *testing.T) {
	t.Setenv(testClockEnv, "")
	if _, err := serveClock(); err == nil {
		t.Error("an e2eclock build started without " + testClockEnv)
	}
}
