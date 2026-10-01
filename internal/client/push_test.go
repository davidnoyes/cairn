package client

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// recordingTransport notes the X-Cairn-Epoch header of every version write
// and, when status is set, answers those writes with it instead of sending
// them.
type recordingTransport struct {
	mu      sync.Mutex
	epochs  []string
	status  int
	forward http.RoundTripper
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != "GET" && strings.Contains(req.URL.Path, "/versions") {
		rt.mu.Lock()
		rt.epochs = append(rt.epochs, req.Header.Get("X-Cairn-Epoch"))
		rt.mu.Unlock()
		if rt.status != 0 {
			return &http.Response{
				StatusCode: rt.status, Header: http.Header{}, Request: req,
				Body: io.NopCloser(strings.NewReader(`{"error":"the artifact moved to a new epoch"}`)),
			}, nil
		}
	}
	return rt.forward.RoundTrip(req)
}

func recordWrites(c *Client, status int) *recordingTransport {
	rt := &recordingTransport{status: status, forward: http.DefaultTransport}
	c.HTTP = &http.Client{Transport: rt}
	return rt
}

func siteDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>hi</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPushDeclaresTheChainEpoch(t *testing.T) {
	c := authedClient(t)
	a, err := c.CreateArtifact("site", "")
	if err != nil {
		t.Fatal(err)
	}
	rt := recordWrites(c, 0)
	v, err := c.Push(a.ID, "", siteDir(t), "v1", "")
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if _, err := c.Push(a.ID, v.ID, siteDir(t), "v1", ""); err != nil {
		t.Fatalf("Push over a version: %v", err)
	}
	if len(rt.epochs) != 2 || rt.epochs[0] != "1" || rt.epochs[1] != "1" {
		t.Errorf("declared epochs = %q, want [1 1]", rt.epochs)
	}
}

// TestPushRefusesAStaleEpoch pins epoch 2 for an artifact whose chain is at
// epoch 1, and checks nothing is sent.
func TestPushRefusesAStaleEpoch(t *testing.T) {
	c := authedClient(t)
	a, err := c.CreateArtifact("site", "")
	if err != nil {
		t.Fatal(err)
	}
	k := mustUnlock(t, c)
	m, _ := c.Membership(a.ID)
	if _, err := c.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Epochs[a.ID] = e2e.KeyringEpoch{Epoch: 2, Seq: 1, Head: e2e.BodyHash(m.Records[0].Body)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rt := recordWrites(c, 0)
	if _, err := c.Push(a.ID, "", siteDir(t), "v1", ""); !errors.Is(err, e2e.ErrStaleEpoch) {
		t.Errorf("Push under an epoch older than the pin: %v, want ErrStaleEpoch", err)
	}
	if len(rt.epochs) != 0 {
		t.Errorf("Push sent %d version writes, want none", len(rt.epochs))
	}
	if vs, _ := c.ListVersions(a.ID); len(vs) != 0 {
		t.Errorf("versions after a refused push: %d", len(vs))
	}
}

func TestPushNamesAMovedEpoch(t *testing.T) {
	c := authedClient(t)
	a, err := c.CreateArtifact("site", "")
	if err != nil {
		t.Fatal(err)
	}
	recordWrites(c, http.StatusConflict)
	_, err = c.Push(a.ID, "", siteDir(t), "v1", "")
	if !errors.Is(err, ErrEpochMoved) || !strings.Contains(err.Error(), "run the command again") {
		t.Errorf("Push on a 409: %v, want ErrEpochMoved asking to run the command again", err)
	}
}
