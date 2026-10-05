package client

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// versionsByID lists the artifact's versions as c, keyed by ID.
func versionsByID(t *testing.T, c *Client, artifact string) map[string]*store.Version {
	t.Helper()
	list, err := c.ListVersions(artifact)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*store.Version{}
	for _, v := range list {
		out[v.ID] = v
	}
	return out
}

var resealSite = map[string][]byte{
	"index.html":    []byte("<html>two</html>"),
	"assets/a.css":  []byte("body{}"),
	"assets/b.json": []byte(`{"n":1}`),
}

func TestResealReplacesTheLatestVersion(t *testing.T) {
	e := newDataEnv(t)
	v2, err := e.ada.Push(e.artifact, "", writeTree(t, resealSite), "second", "what changed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ada.Public(e.artifact, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	before := versionsByID(t, e.ada, e.artifact)

	res, err := e.ada.Unshare(e.artifact, "bob@example.com")
	if err != nil || res.ResealErr != nil || !res.NewEpoch {
		t.Fatalf("Unshare = %+v, %v", res, err)
	}
	if res.Resealed.Versions != 1 || len(res.Resealed.Skipped) != 0 {
		t.Fatalf("Resealed = %+v, want the latest version only", res.Resealed)
	}
	after := versionsByID(t, e.ada, e.artifact)
	got := after[v2.ID]
	if got == nil || got.Seq != v2.Seq || got.Epoch != 2 || got.Name != "second" || got.Changelog != "what changed" || got.ManifestHash == before[v2.ID].ManifestHash {
		t.Fatalf("the replaced version = %+v, was %+v", got, before[v2.ID])
	}
	if after[e.version].Epoch != 1 || after[e.version].ManifestHash != before[e.version].ManifestHash {
		t.Errorf("an earlier version changed: %+v", after[e.version])
	}
	k := mustUnlock(t, e.ada)
	o := openPushed(t, e.ada, e.artifact, v2.ID, 2)
	if o.env.Signer != k.UserID {
		t.Errorf("signed by %q, want the caller %q", o.env.Signer, k.UserID)
	}
	var body e2e.ManifestBody
	if err := e2e.OpenEnvelope(o.env, k.Ed25519Pub, "manifest", &body); err != nil || body.Epoch != 2 || body.Version != v2.ID {
		t.Errorf("the manifest does not verify under the caller's key: %+v, %v", body, err)
	}
	if len(o.files) != len(resealSite) {
		t.Errorf("%d files, want %d", len(o.files), len(resealSite))
	}
	for path, want := range resealSite {
		if string(o.files[path]) != string(want) {
			t.Errorf("%s = %q, want %q", path, o.files[path], want)
		}
	}
	va, err := e.ada.VerifyArtifact(k, e.artifact, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ada.checkManifest(k, va.Chain, e.artifact, got); err != nil {
		t.Errorf("checkManifest: %v", err)
	}
	// The new public link's AK opens it.
	l, err := e2e.ParseLink(res.Link)
	if err != nil {
		t.Fatal(err)
	}
	sealed := rawGet(t, e.ada, "/api/artifacts/"+e.artifact+"/versions/"+v2.ID+"/manifest")
	if _, err := e2e.OpenBlob(l.AK, e2e.BlobContext{Artifact: e.artifact, Version: v2.ID, Kind: "manifest"}, sealed); err != nil {
		t.Errorf("the new link does not open the manifest: %v", err)
	}

	again, err := e.ada.Reseal(e.artifact)
	if err != nil || again.Versions != 0 || len(again.Skipped) != 0 {
		t.Fatalf("a second Reseal = %+v, %v, want nothing", again, err)
	}
	if v := versionsByID(t, e.ada, e.artifact)[v2.ID]; v.ManifestHash != got.ManifestHash {
		t.Error("a second Reseal replaced the version again")
	}
}

// TestResealPicksTheHighestSeqWhateverTheOrder has the server list the
// versions newest last in one run (TestResealReplacesTheLatestVersion) and
// reversed here.
func TestResealPicksTheHighestSeqWhateverTheOrder(t *testing.T) {
	e := newDataEnv(t)
	v2, err := e.ada.Push(e.artifact, "", writeTree(t, resealSite), "second", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	ada := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	intercept(ada, &tamper{after: func(req *http.Request, resp *http.Response) {
		if req.Method != "GET" || !strings.HasSuffix(req.URL.Path, "/versions") {
			return
		}
		var list []json.RawMessage
		if err := json.Unmarshal(readBody(t, resp), &list); err != nil {
			t.Fatal(err)
		}
		slices.Reverse(list)
		b, _ := json.Marshal(list)
		resp.Body = replyJSON(req, 200, nil, string(b)).Body
	}})
	if res, err := ada.Unshare(e.artifact, "bob@example.com"); err != nil || res.ResealErr != nil || res.Resealed.Versions != 1 {
		t.Fatalf("Unshare = %+v, %v", res, err)
	}
	vs := versionsByID(t, e.ada, e.artifact)
	if vs[v2.ID].Epoch != 2 || vs[e.version].Epoch != 1 {
		t.Errorf("epochs: latest %d, earlier %d, want 2 and 1", vs[v2.ID].Epoch, vs[e.version].Epoch)
	}
}

func TestResealLeavesARemovedEditorsLatestVersion(t *testing.T) {
	e := newDataEnv(t)
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	bobs, err := e.bob.Push(e.artifact, "", writeTree(t, resealSite), "bob's", "")
	if err != nil {
		t.Fatal(err)
	}
	before := versionsByID(t, e.ada, e.artifact)[bobs.ID]
	res, err := e.ada.Unshare(e.artifact, "bob@example.com")
	if err != nil || res.ResealErr != nil {
		t.Fatalf("Unshare = %+v, %v", res, err)
	}
	if res.Resealed.Versions != 0 || len(res.Resealed.Skipped) != 1 || !strings.Contains(res.Resealed.Skipped[0], "review") || !strings.Contains(res.Resealed.Skipped[0], bobs.ID) {
		t.Fatalf("Resealed = %+v, want bob's version left for the owner's review", res.Resealed)
	}
	if got := versionsByID(t, e.ada, e.artifact)[bobs.ID]; got.Epoch != 1 || got.ManifestHash != before.ManifestHash {
		t.Errorf("the version = %+v, want it untouched", got)
	}
}

func TestResealLeavesADemotedEditorsLatestVersion(t *testing.T) {
	e := newDataEnv(t)
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	bobs, err := e.bob.Push(e.artifact, "", writeTree(t, resealSite), "bob's", "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.ada.Share(e.artifact, "bob@example.com", "viewer", false)
	if err != nil || !res.NewEpoch || res.ResealErr != nil {
		t.Fatalf("Share = %+v, %v", res, err)
	}
	if res.Resealed.Versions != 0 || len(res.Resealed.Skipped) != 1 {
		t.Fatalf("Resealed = %+v, want the demoted editor's version left", res.Resealed)
	}
	if got := versionsByID(t, e.ada, e.artifact)[bobs.ID]; got.Epoch != 1 {
		t.Errorf("the version is under epoch %d, want 1", got.Epoch)
	}
}

// resealTampered unshares bob while ada's requests are changed, and returns
// what the re-seal did and the state of the one version.
func resealTampered(t *testing.T, tp *tamper) (*ResealResult, *store.Version) {
	t.Helper()
	return resealTamperedIn(t, func(*dataEnv) *tamper { return tp })
}

// resealTamperedIn is resealTampered with the tamper built from the world.
func resealTamperedIn(t *testing.T, tp func(e *dataEnv) *tamper) (*ResealResult, *store.Version) {
	t.Helper()
	e := newDataEnv(t)
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	ada := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	intercept(ada, tp(e))
	res, err := ada.Unshare(e.artifact, "bob@example.com")
	if err != nil || res.ResealErr != nil {
		t.Fatalf("Unshare = %+v, %v", res, err)
	}
	return res.Resealed, versionsByID(t, e.ada, e.artifact)[e.version]
}

func TestResealSkipsAVersionWhoseBlobDoesNotMatchItsManifest(t *testing.T) {
	res, v := resealTampered(t, &tamper{before: func(req *http.Request) *http.Response {
		if req.Method == "GET" && strings.Contains(req.URL.Path, "/blobs/") {
			return replyJSON(req, 200, nil, "not the blob")
		}
		return nil
	}})
	if res.Versions != 0 || len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0], "index.html") || v.Epoch != 1 {
		t.Fatalf("Resealed = %+v, epoch %d, want the version skipped and unchanged", res, v.Epoch)
	}
}

// TestResealSkipsABlobThatOpensButIsNotTheManifestsBlob serves the same file
// sealed again: it opens under the version's AK, and its hash is not the
// manifest's.
func TestResealSkipsABlobThatOpensButIsNotTheManifestsBlob(t *testing.T) {
	res, v := resealTamperedIn(t, func(e *dataEnv) *tamper {
		ak := e.open(t, e.ada, false).aks[1]
		return &tamper{before: func(req *http.Request) *http.Response {
			if req.Method != "GET" || !strings.Contains(req.URL.Path, "/blobs/") {
				return nil
			}
			other, err := e2e.SealBlob(rand.Reader, ak, e2e.BlobContext{Artifact: e.artifact, Version: e.version, Kind: "content", Name: "index.html"}, []byte("<html>hi</html>"))
			if err != nil {
				t.Fatal(err)
			}
			return replyJSON(req, 200, nil, string(other))
		}}
	})
	if res.Versions != 0 || len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0], "hash") || v.Epoch != 1 {
		t.Fatalf("Resealed = %+v, epoch %d, want the version skipped for its hash", res, v.Epoch)
	}
}

func TestResealSkipsAVersionWhoseManifestDoesNotMatchItsHash(t *testing.T) {
	res, v := resealTampered(t, &tamper{after: func(req *http.Request, resp *http.Response) {
		if req.Method != "GET" || !strings.HasSuffix(req.URL.Path, "/versions") {
			return
		}
		var list []map[string]any
		if err := json.Unmarshal(readBody(t, resp), &list); err != nil {
			t.Fatal(err)
		}
		for _, v := range list {
			v["manifestHash"] = strings.Repeat("0", 64)
		}
		b, _ := json.Marshal(list)
		resp.Body = replyJSON(req, 200, nil, string(b)).Body
	}})
	if res.Versions != 0 || len(res.Skipped) != 1 || v.Epoch != 1 {
		t.Fatalf("Resealed = %+v, epoch %d, want the version skipped", res, v.Epoch)
	}
}

func TestResealSkipsAVersionWhoseBlobCannotBeFetched(t *testing.T) {
	res, v := resealTampered(t, &tamper{before: func(req *http.Request) *http.Response {
		if req.Method == "GET" && strings.Contains(req.URL.Path, "/blobs/") {
			return replyJSON(req, 404, nil, `{"error":"gone"}`)
		}
		return nil
	}})
	if res.Versions != 0 || len(res.Skipped) != 1 || v.Epoch != 1 {
		t.Fatalf("Resealed = %+v, epoch %d, want the version skipped", res, v.Epoch)
	}
}
