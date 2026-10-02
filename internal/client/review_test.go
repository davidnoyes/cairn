package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
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
	versions, err := w.ada.ListVersions(w.artifact)
	if err != nil || len(versions) != 1 || versions[0].ManifestHash == "" {
		t.Fatalf("ListVersions = %+v, %v; want one version with a manifestHash", versions, err)
	}
	if body != (e2e.VouchBody{V: 1, Artifact: w.artifact, Version: vid, Manifest: versions[0].ManifestHash}) {
		t.Errorf("vouch body = %+v, want the version's manifestHash %s", body, versions[0].ManifestHash)
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

// countingVouchPuts wraps c's transport to record each request to a vouch
// endpoint.
func countingVouchPuts(c *Client) *[]string {
	var puts []string
	inner := c.HTTP.Transport
	if inner == nil {
		inner = http.DefaultTransport
	}
	c.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/vouch") {
			puts = append(puts, r.Method+" "+r.URL.Path)
		}
		return inner.RoundTrip(r)
	})}
	return &puts
}

// The listed manifestHash is the server's word: a vouch signs it only when
// the manifest the server serves opens, verifies, and hashes to it.
func TestVouchRefusesAManifestTheListedHashDoesNotMatch(t *testing.T) {
	w := newSharing(t)
	vid := pushOne(t, w.ada, w.artifact)
	versions := "/api/artifacts/" + w.artifact + "/versions"
	cases := map[string]*Client{
		"a listed hash that is not the manifest's": rewritingList(t, w.ada, versions, func(list []map[string]any) []map[string]any {
			for _, v := range list {
				v["manifestHash"] = strings.Repeat("0", 64)
			}
			return list
		}),
		"a manifest that does not open": rewriting(w.ada, versions+"/"+vid+"/manifest", func([]byte) []byte {
			return []byte("not a blob")
		}),
	}
	for name, c := range cases {
		puts := countingVouchPuts(c)
		if err := c.Vouch(w.artifact, vid); !errors.Is(err, ErrVouchManifest) {
			t.Errorf("%s: Vouch = %v, want ErrVouchManifest", name, err)
		}
		if len(*puts) != 0 {
			t.Errorf("%s: a refused vouch sent %v", name, *puts)
		}
	}
}

// An editor's manifest is signed by the editor, whose key the owner finds in
// the directory and checks against the fingerprint the chain lists.
func TestVouchOpensAnEditorsManifest(t *testing.T) {
	w := newSharing(t)
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	vid := pushOne(t, w.bob, w.artifact)
	if err := w.ada.Vouch(w.artifact, vid); err != nil {
		t.Errorf("Vouch for an editor's version: %v", err)
	}
}

// tampering is a copy of c whose GETs are altered on the way back: edits maps
// a path to a rewrite of its 200 body, and a path in down answers 404.
func tampering(c *Client, edits map[string]func([]byte) []byte, down ...string) *Client {
	out := NewWithKey(c.Host, *c.Key)
	out.Anchors = c.Anchors
	out.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			return http.DefaultTransport.RoundTrip(r)
		}
		if slices.Contains(down, r.URL.Path) {
			return answerStatus(http.StatusNotFound, "user not found")(r)
		}
		resp, err := http.DefaultTransport.RoundTrip(r)
		edit := edits[r.URL.Path]
		if err != nil || edit == nil || resp.StatusCode != http.StatusOK {
			return resp, err
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		data = edit(data)
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
		return resp, nil
	})}
	return out
}

// forgedManifest is the edits that make the server serve, for version vid,
// a manifest signed as signer under seed, whose body is the real one after
// edit, sealed under the owner's AK for the version's real epoch and listed
// under its own body hash. Only what edit changes can then make a vouch fail.
func forgedManifest(t *testing.T, c *Client, artifact, vid, signer string, seed []byte, edit func(*e2e.ManifestBody)) map[string]func([]byte) []byte {
	t.Helper()
	k := mustUnlock(t, c)
	va, err := c.VerifyArtifact(k, artifact, "")
	if err != nil {
		t.Fatal(err)
	}
	aks, err := c.callerAKs(k, artifact, va.Chain)
	if err != nil {
		t.Fatal(err)
	}
	versions, err := c.ListVersions(artifact)
	if err != nil || len(versions) == 0 {
		t.Fatalf("ListVersions = %v, %v", versions, err)
	}
	v := versions[slices.IndexFunc(versions, func(v *store.Version) bool { return v.ID == vid })]
	ak := aks[v.Epoch]
	ctx := e2e.BlobContext{Artifact: artifact, Version: vid, Kind: "manifest"}
	sealed, err := c.getBytes("/api/artifacts/" + artifact + "/versions/" + vid + "/manifest")
	if err != nil {
		t.Fatal(err)
	}
	realJSON, err := e2e.OpenBlob(ak, ctx, sealed)
	if err != nil {
		t.Fatal(err)
	}
	var orig e2e.Envelope
	var body e2e.ManifestBody
	if err := json.Unmarshal(realJSON, &orig); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(orig.Body, &body); err != nil {
		t.Fatal(err)
	}
	edit(&body)
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(seed, signer, "manifest", bodyJSON)
	if err != nil {
		t.Fatal(err)
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := e2e.SealBlob(rand.Reader, ak, ctx, envJSON)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]func([]byte) []byte{
		"/api/artifacts/" + artifact + "/versions/" + vid + "/manifest": func([]byte) []byte { return forged },
		"/api/artifacts/" + artifact + "/versions": func(list []byte) []byte {
			var entries []map[string]any
			if err := json.Unmarshal(list, &entries); err != nil {
				t.Error(err)
				return list
			}
			for _, e := range entries {
				if e["id"] == vid {
					e["manifestHash"] = e2e.BodyHash(bodyJSON)
				}
			}
			out, err := json.Marshal(entries)
			if err != nil {
				t.Error(err)
			}
			return out
		},
	}
}

// vouchRefused fails the test unless vouching for vid through c is refused
// with ErrVouchManifest and a message containing want, and sends no vouch.
func vouchRefused(t *testing.T, c *Client, artifact, vid, want string) {
	t.Helper()
	puts := countingVouchPuts(c)
	err := c.Vouch(artifact, vid)
	if !errors.Is(err, ErrVouchManifest) || !strings.Contains(err.Error(), want) {
		t.Errorf("Vouch = %v, want ErrVouchManifest containing %q", err, want)
	}
	if len(*puts) != 0 {
		t.Errorf("a refused vouch sent %v", *puts)
	}
}

// The signer of a manifest must be someone the chain lists, under keys whose
// fingerprint it lists, and the body must name the version it came with.
func TestVouchRefusesAManifestThatDoesNotBelong(t *testing.T) {
	w := newSharing(t)
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	vid := pushOne(t, w.bob, w.artifact)
	adaID, bobID := w.userID(t, w.ada), w.userID(t, w.bob)
	attacker := bytes.Repeat([]byte{9}, 32)
	attackerPub := ed25519.NewKeyFromSeed(attacker).Public().(ed25519.PublicKey)
	same := func(*e2e.ManifestBody) {}
	adaSeed := mustUnlock(t, w.ada).Ed25519Seed
	bobSeed := mustUnlock(t, w.bob).Ed25519Seed
	otherVersion := "00000000-0000-4000-8000-000000000000"

	t.Run("a signer the chain never lists", func(t *testing.T) {
		c := tampering(w.ada, forgedManifest(t, w.ada, w.artifact, vid, "u-stranger", attacker, same))
		vouchRefused(t, c, w.artifact, vid, "never lists")
	})
	t.Run("a directory key the chain does not list", func(t *testing.T) {
		edits := forgedManifest(t, w.ada, w.artifact, vid, bobID, attacker, same)
		edits["/api/users/"+bobID] = func(b []byte) []byte {
			var u map[string]any
			if err := json.Unmarshal(b, &u); err != nil {
				t.Error(err)
			}
			u["ed25519Pub"] = e2e.B64(attackerPub)
			out, _ := json.Marshal(u)
			return out
		}
		vouchRefused(t, tampering(w.ada, edits), w.artifact, vid, "not the ones the chain lists")
	})
	t.Run("a bad signature", func(t *testing.T) {
		c := tampering(w.ada, forgedManifest(t, w.ada, w.artifact, vid, bobID, attacker, same))
		vouchRefused(t, c, w.artifact, vid, "signature does not verify")
	})
	for name, edit := range map[string]func(*e2e.ManifestBody){
		"another artifact": func(b *e2e.ManifestBody) { b.Artifact = "other-artifact" },
		"another version":  func(b *e2e.ManifestBody) { b.Version = otherVersion },
		"another epoch":    func(b *e2e.ManifestBody) { b.Epoch++ },
	} {
		t.Run("a body naming "+name, func(t *testing.T) {
			c := tampering(w.ada, forgedManifest(t, w.ada, w.artifact, vid, adaID, adaSeed, edit))
			vouchRefused(t, c, w.artifact, vid, "names another artifact, version, or epoch")
			c = tampering(w.ada, forgedManifest(t, w.ada, w.artifact, vid, bobID, bobSeed, edit))
			vouchRefused(t, c, w.artifact, vid, "names another artifact, version, or epoch")
		})
	}
	t.Run("no key for the version's epoch", func(t *testing.T) {
		c := tampering(w.ada, map[string]func([]byte) []byte{
			"/api/artifacts/" + w.artifact + "/versions": func(list []byte) []byte {
				var entries []map[string]any
				if err := json.Unmarshal(list, &entries); err != nil {
					t.Error(err)
				}
				for _, e := range entries {
					e["epoch"] = 7
				}
				out, _ := json.Marshal(entries)
				return out
			},
		})
		vouchRefused(t, c, w.artifact, vid, "no key for epoch 7")
	})
}

// An editor who rotated keys after pushing signed the version under keys the
// directory no longer shows, and the owner can still vouch for it.
func TestVouchOpensARotatedEditorsManifest(t *testing.T) {
	w := newSharing(t)
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	vid := pushOne(t, w.bob, w.artifact)
	before := mustUnlock(t, w.bob).FP
	rotateOK(t, w.bob, false)
	if mustUnlock(t, w.bob).FP == before {
		t.Fatal("bob's keys did not change")
	}
	if err := w.ada.Vouch(w.artifact, vid); err != nil {
		t.Errorf("Vouch for a rotated editor's version: %v", err)
	}
}

// The owner's own older keys are found the same way.
func TestVouchOpensTheOwnersManifestAfterTheyRotated(t *testing.T) {
	w := newSharing(t)
	vid := pushOne(t, w.ada, w.artifact)
	before := mustUnlock(t, w.ada).FP
	rotateOK(t, w.ada, true)
	if mustUnlock(t, w.ada).FP == before {
		t.Fatal("ada's keys did not change")
	}
	if err := w.ada.Vouch(w.artifact, vid); err != nil {
		t.Errorf("Vouch for the owner's version after rotating: %v", err)
	}
}

// A disabled or deleted account is not in the directory and serves no
// rotation records, so its keys cannot be checked: the vouch is refused, and
// the message says why.
func TestVouchRefusesAVersionWhoseSignerIsGone(t *testing.T) {
	w := newSharing(t)
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	vid := pushOne(t, w.bob, w.artifact)
	bobID := w.userID(t, w.bob)
	c := tampering(w.ada, nil, "/api/users/"+bobID, "/api/users/"+bobID+"/rotations")
	puts := countingVouchPuts(c)
	err := c.Vouch(w.artifact, vid)
	var api *APIError
	if !errors.Is(err, ErrVouchManifest) || errors.As(err, &api) || !strings.Contains(err.Error(), "no longer published") ||
		!strings.Contains(err.Error(), "delete the version") {
		t.Errorf("Vouch for a version of a gone signer = %v, want ErrVouchManifest saying the keys are no longer published", err)
	}
	if len(*puts) != 0 {
		t.Errorf("a refused vouch sent %v", *puts)
	}
}

func TestGetBytesRefusesABodyOverTheCap(t *testing.T) {
	w := newSharing(t)
	path := "/api/artifacts/" + w.artifact + "/big"
	c := tampering(w.ada, nil)
	c.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Request: r,
			Body: io.NopCloser(io.LimitReader(zeroReader{}, maxManifestBytes+1))}, nil
	})}
	if _, err := c.getBytes(path); !errors.Is(err, ErrVouchManifest) || !strings.Contains(err.Error(), "larger than 16 MiB") {
		t.Errorf("getBytes of an oversize body = %v, want ErrVouchManifest naming the cap", err)
	}
	c.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Request: r,
			Body: io.NopCloser(io.LimitReader(zeroReader{}, maxManifestBytes))}, nil
	})}
	if data, err := c.getBytes(path); err != nil || len(data) != maxManifestBytes {
		t.Errorf("getBytes of a body at the cap = %d bytes, %v, want them all", len(data), err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestGetBytesReportsTheServersMessage(t *testing.T) {
	w := newSharing(t)
	c := tampering(w.ada, nil)
	c.HTTP = &http.Client{Transport: roundTripFunc(answerStatus(http.StatusForbidden, "you may not read this"))}
	_, err := c.getBytes("/api/artifacts/" + w.artifact + "/versions/x/manifest")
	var api *APIError
	if !errors.As(err, &api) || api.Status != http.StatusForbidden || api.Message != "you may not read this" {
		t.Errorf("getBytes on a 403 = %v, want the server's message", err)
	}
}
