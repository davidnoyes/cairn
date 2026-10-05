package client

import (
	"bytes"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

func TestVersionFilesReturnsEveryFileDecrypted(t *testing.T) {
	e := newDataEnv(t)
	v2, err := e.ada.Push(e.artifact, "", writeTree(t, resealSite), "second", "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.ada.VersionFiles(e.artifact, v2.ID)
	if err != nil {
		t.Fatalf("VersionFiles: %v", err)
	}
	if len(got) != len(resealSite) {
		t.Fatalf("VersionFiles = %d files, want %d", len(got), len(resealSite))
	}
	for p, want := range resealSite {
		if !bytes.Equal(got[p], want) {
			t.Errorf("%s = %q, want %q", p, got[p], want)
		}
	}
	if _, err := e.ada.VersionFiles(e.artifact, "no-such-version"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("an unknown version: %v", err)
	}
}

func TestVersionFilesRefusesABlobThatDoesNotMatchItsManifest(t *testing.T) {
	e := newDataEnv(t)
	ada := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	intercept(ada, &tamper{before: func(req *http.Request) *http.Response {
		if req.Method == "GET" && strings.Contains(req.URL.Path, "/blobs/") {
			return replyJSON(req, 200, nil, "not the blob")
		}
		return nil
	}})
	if _, err := ada.VersionFiles(e.artifact, e.version); err == nil || !strings.Contains(err.Error(), "index.html") {
		t.Fatalf("VersionFiles with a foreign blob: %v", err)
	}
}

// TestVersionFilesChecksTheHashBeforeOpening serves the same file sealed
// again: it opens under the version's AK, and its hash is not the manifest's.
func TestVersionFilesChecksTheHashBeforeOpening(t *testing.T) {
	e := newDataEnv(t)
	ak := e.open(t, e.ada, false).aks[1]
	ada := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	intercept(ada, &tamper{before: func(req *http.Request) *http.Response {
		if req.Method != "GET" || !strings.Contains(req.URL.Path, "/blobs/") {
			return nil
		}
		other, err := e2e.SealBlob(rand.Reader, ak, e2e.BlobContext{Artifact: e.artifact, Version: e.version, Kind: "content", Name: "index.html"}, []byte("<html>hi</html>"))
		if err != nil {
			t.Fatal(err)
		}
		return replyJSON(req, 200, nil, string(other))
	}})
	if _, err := ada.VersionFiles(e.artifact, e.version); err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("VersionFiles with a resealed blob: %v, want a hash mismatch", err)
	}
}

func TestCheckFilePath(t *testing.T) {
	for _, p := range []string{"a", "a/b.txt", "dir/ü.json"} {
		if err := CheckFilePath(p); err != nil {
			t.Errorf("CheckFilePath(%q) = %v", p, err)
		}
	}
	for _, p := range []string{"", "/a", "a//b", "a/../b", ".", `a\b`, "a\x00", "\xff"} {
		if err := CheckFilePath(p); err != ErrInvalidPath {
			t.Errorf("CheckFilePath(%q) = %v, want ErrInvalidPath", p, err)
		}
	}
}
