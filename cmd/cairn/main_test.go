package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

// TestMain keeps a stray shell environment from steering these tests at a
// real server or a real config: CAIRN_HOST and CAIRN_API_KEY override the
// saved config, so a test that logs out or revokes a key would otherwise act
// on whatever account the developer's shell points at. It also swaps in the
// cheap password KDFs: under -race the real ones dominate the run time.
func TestMain(m *testing.M) {
	e2e.UseFastKDFForTests()
	auth.UseMinCostForTests()
	os.Unsetenv("CAIRN_HOST")
	os.Unsetenv("CAIRN_API_KEY")
	dir, err := os.MkdirTemp("", "cairn-cmd-test")
	if err != nil {
		panic(err)
	}
	os.Setenv("CAIRN_CONFIG", filepath.Join(dir, "config.json"))
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
