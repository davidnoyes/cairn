package server

import (
	"os"
	"testing"

	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

// TestMain swaps in the cheap password KDFs: under -race the real Argon2id
// and bcrypt dominate the run time of tests that sign up many users.
func TestMain(m *testing.M) {
	e2e.UseFastKDFForTests()
	auth.UseMinCostForTests()
	os.Exit(m.Run())
}
