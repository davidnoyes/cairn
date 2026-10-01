package web

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVendorChecksums pins every vendored third-party file to the checksum
// recorded in vendor/SHA256SUMS, so an accidental edit or a swapped file
// fails the build. Every file in vendor/ other than documentation must be
// listed.
func TestVendorChecksums(t *testing.T) {
	f, err := os.Open("vendor/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	listed := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		sum, name, ok := strings.Cut(sc.Text(), "  ")
		if !ok {
			t.Fatalf("malformed line %q", sc.Text())
		}
		data, err := os.ReadFile(filepath.Join("vendor", name))
		if err != nil {
			t.Fatal(err)
		}
		got := sha256.Sum256(data)
		if hex.EncodeToString(got[:]) != sum {
			t.Errorf("%s: checksum %x, want %s", name, got, sum)
		}
		listed[name] = true
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("vendor")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || n == "SHA256SUMS" || n == "README.md" || strings.HasPrefix(n, "LICENSE.") {
			continue
		}
		if !listed[n] {
			t.Errorf("vendor/%s has no checksum in SHA256SUMS", n)
		}
	}
}
