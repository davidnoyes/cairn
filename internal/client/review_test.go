package client

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// pushOne pushes a one-file version as c and returns its ID.
func pushOne(t *testing.T, c *Client, artifact string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>hi</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := c.Push(artifact, "", dir, "v", "")
	if err != nil {
		t.Fatal(err)
	}
	return v.ID
}

// withReview is a copy of c whose GET /review answers with entries.
func withReview(t *testing.T, c *Client, artifact string, entries ...map[string]any) *Client {
	return rewritingList(t, c, "/api/artifacts/"+artifact+"/review", func([]map[string]any) []map[string]any {
		return entries
	})
}

func TestReviewListsWhatTheServerListsAndTheChainAllows(t *testing.T) {
	w := newSharing(t)
	vid := pushOne(t, w.ada, w.artifact)
	list, err := w.ada.Review(w.artifact)
	if err != nil || len(list) != 0 {
		t.Fatalf("Review with nothing to review = %v, %v", list, err)
	}

	cat := "u-removed"
	c := withReview(t, w.ada, w.artifact, map[string]any{"id": vid, "seq": 1, "pushedBy": cat, "createdAt": "2026-01-02T03:04:05Z"},
		map[string]any{"id": "v-gone", "seq": 2, "pushedBy": nil, "createdAt": "2026-01-03T00:00:00Z"})
	list, err = c.Review(w.artifact)
	if err != nil {
		t.Fatal(err)
	}
	want := []ReviewVersion{{ID: vid, Seq: 1, PushedBy: cat, CreatedAt: "2026-01-02T03:04:05Z"}, {ID: "v-gone", Seq: 2, CreatedAt: "2026-01-03T00:00:00Z"}}
	if len(list) != 2 || list[0] != want[0] || list[1] != want[1] {
		t.Errorf("Review = %+v, want %+v", list, want)
	}
}

func TestReviewReportsAnEntryTheChainContradicts(t *testing.T) {
	w := newSharing(t)
	vid := pushOne(t, w.ada, w.artifact)
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	for name, pusher := range map[string]string{"the owner": w.userID(t, w.ada), "a listed editor": w.userID(t, w.bob)} {
		c := withReview(t, w.ada, w.artifact, map[string]any{"id": vid, "seq": 1, "pushedBy": pusher, "createdAt": "x"})
		list, err := c.Review(w.artifact)
		if !errors.Is(err, ErrReviewInconsistent) {
			t.Errorf("an entry pushed by %s: %v, %v, want ErrReviewInconsistent", name, list, err)
		}
	}
}

func TestVouchSignsAndStoresTheOwnersVouch(t *testing.T) {
	w := newSharing(t)
	vid := pushOne(t, w.ada, w.artifact)
	if err := w.ada.Vouch(w.artifact, vid); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Vouch *e2e.Envelope `json:"vouch"`
	}
	if err := w.ada.doJSON("GET", "/api/artifacts/"+w.artifact+"/versions/"+vid, nil, &got); err != nil {
		t.Fatal(err)
	}
	if got.Vouch == nil || got.Vouch.Signer != w.userID(t, w.ada) {
		t.Fatalf("stored vouch = %+v", got.Vouch)
	}
	var body e2e.VouchBody
	k, err := w.ada.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := e2e.OpenEnvelope(*got.Vouch, k.Ed25519Pub, "vouch", &body); err != nil {
		t.Fatal(err)
	}
	if body != (e2e.VouchBody{V: 1, Artifact: w.artifact, Version: vid}) {
		t.Errorf("vouch body = %+v", body)
	}
}

func TestVouchRefusesANonOwnerBeforeAnyRequest(t *testing.T) {
	w := newSharing(t)
	vid := pushOne(t, w.ada, w.artifact)
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	// Verifying the chain stores bob's keyring, but no request may touch
	// the vouch endpoint.
	var puts []string
	bob := NewWithKey(w.bob.Host, *w.bob.Key)
	bob.Anchors = w.bob.Anchors
	bob.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/vouch") {
			puts = append(puts, r.Method+" "+r.URL.Path)
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	err := bob.Vouch(w.artifact, vid)
	if !errors.Is(err, ErrVouchNotOwner) {
		t.Errorf("Vouch by an editor: %v, want ErrVouchNotOwner", err)
	}
	if len(puts) != 0 {
		t.Errorf("a refused vouch sent %v to the vouch endpoint", puts)
	}
}
