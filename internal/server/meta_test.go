package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// An encrypted metadata field as the PUT carries it. The server cannot read
// the blob, so these helpers seal real blobs and sign real records as an
// actor, and a test breaks one field to see a refusal.

type metaRequest struct {
	a             actor
	aid, vid      string // vid is empty for an artifact field
	field         string
	body          e2e.RecordBody
	blob          []byte
	seed          []byte // signs the record; the actor's own when nil
	signer        string // the record's signer; the actor's own when empty
	record        any    // replaces the signed record when set
	blobB64       *string
	extraTopLevel map[string]any
}

// newMeta builds a write of field, sealed under epoch's AK.
func newMeta(t *testing.T, a actor, aid, vid, field string, epoch int, plain string) *metaRequest {
	t.Helper()
	blob := sealFor(t, aid, vid, "meta", field, epoch, []byte(plain))
	return &metaRequest{
		a: a, aid: aid, vid: vid, field: field, blob: blob,
		body: e2e.RecordBody{V: 1, Artifact: aid, Version: vid, Kind: "meta", Name: field, Epoch: epoch, SHA256: e2e.BodyHash(blob)},
	}
}

func (q *metaRequest) path() string {
	p := "/api/artifacts/" + q.aid
	if q.vid != "" {
		p += "/versions/" + q.vid
	}
	return p + "/meta/" + q.field
}

func (q *metaRequest) request(t *testing.T) map[string]any {
	t.Helper()
	var rec any = q.record
	if rec == nil {
		seed, signer := q.seed, q.signer
		if seed == nil {
			seed = q.a.keys.seed
		}
		if signer == "" {
			signer = q.a.id
		}
		rec = json.RawMessage(signedBody(t, seed, signer, "record", q.body))
	}
	blob := e2e.B64(q.blob)
	if q.blobB64 != nil {
		blob = *q.blobB64
	}
	req := map[string]any{"record": rec, "blob": blob}
	for k, v := range q.extraTopLevel {
		req[k] = v
	}
	return req
}

func (q *metaRequest) send(t *testing.T) *http.Response {
	t.Helper()
	return q.a.do("PUT", q.path(), q.request(t), nil)
}

// metaItem is one field as a view carries it.
type metaItem struct {
	Record    json.RawMessage `json:"record"`
	SignerKey string          `json:"signerKey"`
	Blob      string          `json:"blob"`
}

// artifactMeta reads the artifact view's meta as c.
func artifactMeta(t *testing.T, c *testClient, aid string) map[string]metaItem {
	t.Helper()
	var v struct {
		Meta map[string]metaItem `json:"meta"`
	}
	c.mustDo("GET", "/api/artifacts/"+aid, nil, &v, http.StatusOK)
	return v.Meta
}

// versionMeta reads one version's meta as c.
func versionMeta(t *testing.T, c *testClient, aid, vid string) map[string]metaItem {
	t.Helper()
	var v struct {
		Meta map[string]metaItem `json:"meta"`
	}
	c.mustDo("GET", "/api/artifacts/"+aid+"/versions/"+vid, nil, &v, http.StatusOK)
	return v.Meta
}

// refOf is a 64-hex resource value for ref, as a client's blind index would
// be; the server cannot tell it from one.
func refOf(ref string) string { return e2e.BodyHash([]byte(ref)) }

func sameMeta(a, b map[string]metaItem) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func mustMeta(t *testing.T, q *metaRequest) {
	t.Helper()
	resp := q.send(t)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT %s: %d, want 200", q.path(), resp.StatusCode)
	}
}

type metaWorld struct {
	s             *Server
	base          string
	owner, editor actor
	viewer        actor
	o             *owned
	vid           string
}

func newMetaWorld(t *testing.T) *metaWorld {
	t.Helper()
	s, ts := testServer(t)
	w := &metaWorld{s: s, base: ts.URL}
	w.owner = seedKeyedAccount(t, s, ts.URL, "owner@example.com")
	w.editor = seedKeyedAccount(t, s, ts.URL, "editor@example.com")
	w.viewer = seedKeyedAccount(t, s, ts.URL, "viewer@example.com")
	w.o = newArtifact(t, w.owner, "meta")
	w.vid = pushVersion(t, w.owner.testClient, w.o.id)
	w.o.share("editor", w.editor)
	w.o.share("viewer", w.viewer)
	return w
}

func TestMetaWriteAppearsInViews(t *testing.T) {
	w := newMetaWorld(t)
	aid, vid := w.o.id, w.vid

	if m := artifactMeta(t, w.owner.testClient, aid); len(m) != 0 {
		t.Fatalf("a fresh artifact has meta %+v, want none", m)
	}
	name := newMeta(t, w.owner, aid, "", "name", 1, "My artifact")
	mustMeta(t, name)
	mustMeta(t, newMeta(t, w.owner, aid, "", "description", 1, "About it"))
	mustMeta(t, newMeta(t, w.owner, aid, vid, "name", 1, "first"))

	check := func(c *testClient) {
		t.Helper()
		m := artifactMeta(t, c, aid)
		if len(m) != 2 || m["name"].Blob != e2e.B64(name.blob) || m["name"].SignerKey != e2e.B64(w.owner.keys.epub) {
			t.Errorf("artifact meta = %+v", m)
		}
		var rec e2e.Envelope
		if err := json.Unmarshal(m["name"].Record, &rec); err != nil || rec.Signer != w.owner.id {
			t.Errorf("record = %s: %v", m["name"].Record, err)
		}
		if m["description"].Blob == "" {
			t.Errorf("no description in %+v", m)
		}
		vm := versionMeta(t, c, aid, vid)
		if len(vm) != 1 || vm["name"].Blob == "" {
			t.Errorf("version meta = %+v, want only name (no changelog was written)", vm)
		}
	}
	check(w.owner.testClient)
	check(w.viewer.testClient) // a viewer reads every field

	// The list view and the versions list carry the same.
	var list []struct {
		ID   string              `json:"id"`
		Meta map[string]metaItem `json:"meta"`
	}
	w.owner.mustDo("GET", "/api/artifacts", nil, &list, http.StatusOK)
	if len(list) != 1 || len(list[0].Meta) != 2 {
		t.Errorf("list = %+v", list)
	}
	var versions []struct {
		ID   string              `json:"id"`
		Meta map[string]metaItem `json:"meta"`
	}
	w.owner.mustDo("GET", "/api/artifacts/"+aid+"/versions", nil, &versions, http.StatusOK)
	if len(versions) != 1 || len(versions[0].Meta) != 1 {
		t.Errorf("versions = %+v", versions)
	}
}

func TestMetaWriteReplacesTheField(t *testing.T) {
	w := newMetaWorld(t)
	first := newMeta(t, w.owner, w.o.id, "", "name", 1, "one")
	mustMeta(t, first)
	second := newMeta(t, w.editor, w.o.id, "", "name", 1, "two")
	mustMeta(t, second) // an editor may write
	m := artifactMeta(t, w.owner.testClient, w.o.id)
	if len(m) != 1 || m["name"].Blob != e2e.B64(second.blob) || m["name"].SignerKey != e2e.B64(w.editor.keys.epub) {
		t.Fatalf("meta = %+v, want the editor's replacement", m)
	}
	// An empty plaintext is a field with no value, and still a field.
	mustMeta(t, newMeta(t, w.owner, w.o.id, w.vid, "changelog", 1, ""))
	if vm := versionMeta(t, w.owner.testClient, w.o.id, w.vid); len(vm) != 1 {
		t.Errorf("version meta = %+v", vm)
	}
}

func TestMetaWriteRefusals(t *testing.T) {
	w := newMetaWorld(t)
	aid, vid := w.o.id, w.vid
	other := newArtifact(t, w.owner, "other")
	otherVid := pushVersion(t, w.owner.testClient, other.id)
	otherKey := newUserKeys(t)
	huge := strings.Repeat("x", 17<<10)

	// Seed both scopes so "unchanged" means something.
	mustMeta(t, newMeta(t, w.owner, aid, "", "name", 1, "seeded"))
	mustMeta(t, newMeta(t, w.owner, aid, vid, "name", 1, "seeded"))

	type tc struct {
		name   string
		vid    string
		field  string
		edit   func(q *metaRequest)
		status int
	}
	notBase64 := "not*base64!"
	short := e2e.B64([]byte("CRNB\x01tooshort"))
	cases := []tc{
		{"unknown artifact field", "", "bogus", nil, http.StatusBadRequest},
		{"a version field on the artifact", "", "changelog", nil, http.StatusBadRequest},
		{"an artifact field on the version", vid, "description", nil, http.StatusBadRequest},
		{"unknown version field", vid, "bogus", nil, http.StatusBadRequest},
		{"record names another artifact", "", "name", func(q *metaRequest) { q.body.Artifact = other.id }, http.StatusBadRequest},
		{"record names another version", vid, "name", func(q *metaRequest) { q.body.Version = otherVid }, http.StatusBadRequest},
		{"version record names no version", vid, "name", func(q *metaRequest) { q.body.Version = "" }, http.StatusBadRequest},
		{"artifact record names a version", "", "name", func(q *metaRequest) { q.body.Version = vid }, http.StatusBadRequest},
		{"record has another kind", "", "name", func(q *metaRequest) { q.body.Kind = "file" }, http.StatusBadRequest},
		{"record names another field", "", "name", func(q *metaRequest) { q.body.Name = "description" }, http.StatusBadRequest},
		{"record sha256 is not the blob's", "", "name", func(q *metaRequest) { q.body.SHA256 = strings.Repeat("0", 64) }, http.StatusBadRequest},
		{"blob is not a sealed blob", "", "name", func(q *metaRequest) {
			q.blob = []byte("plain text, no header, but long enough to be sealed")
			q.body.SHA256 = e2e.BodyHash(q.blob)
		}, http.StatusBadRequest},
		{"blob is too short to be sealed", "", "name", func(q *metaRequest) {
			q.blob = append([]byte("CRNB\x01"), 1, 2, 3)
			q.body.SHA256 = e2e.BodyHash(q.blob)
		}, http.StatusBadRequest},
		{"blob is not base64", "", "name", func(q *metaRequest) { q.blobB64 = &notBase64 }, http.StatusBadRequest},
		{"blob shape only in the base64", "", "name", func(q *metaRequest) { q.blobB64 = &short }, http.StatusBadRequest},
		{"record does not decode strictly", "", "name", func(q *metaRequest) {
			body, _ := json.Marshal(map[string]any{"v": 1, "artifact": aid, "version": "", "kind": "meta", "name": "name", "epoch": 1, "sha256": q.body.SHA256, "extra": 1})
			env, _ := e2e.NewEnvelope(w.owner.keys.seed, w.owner.id, "record", body)
			q.record = env
		}, http.StatusBadRequest},
		{"record is not an envelope", "", "name", func(q *metaRequest) { q.record = "garbage" }, http.StatusBadRequest},
		{"request has another field", "", "name", func(q *metaRequest) { q.extraTopLevel = map[string]any{"name": "plain"} }, http.StatusBadRequest},
		{"blob over 17 KiB", "", "name", func(q *metaRequest) {
			q.blob = sealFor(t, aid, "", "meta", "name", 1, []byte(huge))
			q.body.SHA256 = e2e.BodyHash(q.blob)
		}, http.StatusRequestEntityTooLarge},
		{"signed under another key", "", "name", func(q *metaRequest) { q.seed = otherKey.seed }, http.StatusForbidden},
		{"signed as another user", "", "name", func(q *metaRequest) { q.signer = w.editor.id }, http.StatusForbidden},
		{"another epoch than the current one (ahead)", "", "name", func(q *metaRequest) { q.body.Epoch = 2 }, http.StatusConflict},
		{"another epoch than the current one (behind)", vid, "name", func(q *metaRequest) { q.body.Epoch = 0 }, http.StatusConflict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			beforeA := artifactMeta(t, w.owner.testClient, aid)
			beforeV := versionMeta(t, w.owner.testClient, aid, vid)
			q := newMeta(t, w.owner, aid, c.vid, c.field, 1, "attempt")
			if c.edit != nil {
				c.edit(q)
			}
			if got := status0(t, q.send(t)); got != c.status {
				t.Errorf("status %d, want %d", got, c.status)
			}
			if !sameMeta(beforeA, artifactMeta(t, w.owner.testClient, aid)) || !sameMeta(beforeV, versionMeta(t, w.owner.testClient, aid, vid)) {
				t.Error("a refused write changed a stored field")
			}
		})
	}

	t.Run("a blob of exactly the largest size lands", func(t *testing.T) {
		q := newMeta(t, w.owner, aid, "", "description", 1, strings.Repeat("y", e2e.MaxMetaPlaintext))
		if got := status0(t, q.send(t)); got != http.StatusOK {
			t.Errorf("status %d, want 200", got)
		}
	})
	t.Run("a version of another artifact is 404", func(t *testing.T) {
		q := newMeta(t, w.owner, aid, otherVid, "name", 1, "x")
		if got := status0(t, q.send(t)); got != http.StatusNotFound {
			t.Errorf("status %d, want 404", got)
		}
		if vm := versionMeta(t, w.owner.testClient, other.id, otherVid); len(vm) != 0 {
			t.Errorf("other artifact's version meta = %+v", vm)
		}
	})
}

func TestMetaWriteChecksTheEpochAfterAChange(t *testing.T) {
	w := newMetaWorld(t)
	mustMeta(t, newMeta(t, w.owner, w.o.id, "", "name", 1, "before"))
	stale := newMeta(t, w.owner, w.o.id, "", "name", 1, "stale")
	before := artifactMeta(t, w.owner.testClient, w.o.id)

	w.o.apply(w.o.nextEpoch())

	if got := status0(t, stale.send(t)); got != http.StatusConflict {
		t.Errorf("a write under the old epoch: %d, want 409", got)
	}
	if !sameMeta(before, artifactMeta(t, w.owner.testClient, w.o.id)) {
		t.Error("a refused stale write changed the field")
	}
	mustMeta(t, newMeta(t, w.owner, w.o.id, "", "name", 2, "after"))
}

func TestMetaWriteOnlyForOwnerAndEditor(t *testing.T) {
	w := newMetaWorld(t)
	aid, vid := w.o.id, w.vid
	mustMeta(t, newMeta(t, w.owner, aid, "", "name", 1, "seeded"))
	mustMeta(t, newMeta(t, w.owner, aid, vid, "name", 1, "seeded"))
	stranger := seedKeyedAccount(t, w.s, w.base, "stranger@example.com")
	publicBy := seedKeyedAccount(t, w.s, w.base, "public@example.com")
	link := w.o.makePublic()
	next := w.o.next()
	next.PublicWrites = true
	w.o.apply(next)
	publicBy.link = link
	anon := &testClient{t: t, base: w.base, link: link}

	beforeA := artifactMeta(t, w.owner.testClient, aid)
	beforeV := versionMeta(t, w.owner.testClient, aid, vid)
	for _, c := range []struct {
		name   string
		a      actor
		vid    string
		status int
	}{
		{"viewer, artifact", w.viewer, "", http.StatusForbidden},
		{"viewer, version", w.viewer, vid, http.StatusForbidden},
		{"public writer with a session, artifact", publicBy, "", http.StatusForbidden},
		{"public writer with a session, version", publicBy, vid, http.StatusForbidden},
		{"link holder with no session", actor{testClient: anon, id: w.viewer.id, keys: w.viewer.keys}, "", http.StatusForbidden},
		{"a user with no access", stranger, "", http.StatusNotFound},
	} {
		t.Run(c.name, func(t *testing.T) {
			q := newMeta(t, c.a, aid, c.vid, "name", 2, "x")
			if got := status0(t, q.send(t)); got != c.status {
				t.Errorf("status %d, want %d", got, c.status)
			}
		})
	}
	if !sameMeta(beforeA, artifactMeta(t, w.owner.testClient, aid)) || !sameMeta(beforeV, versionMeta(t, w.owner.testClient, aid, vid)) {
		t.Error("a refused writer changed a stored field")
	}
}

func TestRemovedPlaintextRoutes(t *testing.T) {
	w := newMetaWorld(t)
	base := "/api/artifacts/" + w.o.id
	for _, p := range []string{base, base + "/versions/" + w.vid} {
		if got := w.owner.do("PATCH", p, map[string]any{"name": "x"}, nil).StatusCode; got != http.StatusMethodNotAllowed {
			t.Errorf("PATCH %s: %d, want 405", p, got)
		}
	}
	// Creating an artifact takes no name or description.
	id := "11111111-1111-4111-8111-111111111111"
	b := firstRecord(t, w.owner, id)
	for _, f := range []string{"name", "description"} {
		req := map[string]any{"id": id, f: "plain", "membership": signRecord(t, w.owner, b), "wraps": []any{}, "estate": []any{testEstate(t, id, 1)}}
		if got, _ := status(w.owner.testClient, "POST", "/api/artifacts", req); got != http.StatusBadRequest {
			t.Errorf("POST /api/artifacts with %s: %d, want 400", f, got)
		}
	}
	// A push takes no name or changelog.
	for _, f := range []string{"name", "changelog"} {
		p := newPush(t, w.o.id, "", 1, map[string]string{"index.html": "x"})
		p.Version[f] = "plain"
		if got := status0(t, w.owner.send("POST", base+"/versions", p)); got != http.StatusBadRequest {
			t.Errorf("a push with a %s in its version part: %d, want 400", f, got)
		}
	}
}

func TestResourceValueMustBeABlindIndex(t *testing.T) {
	w := newMetaWorld(t)
	base := "/api/artifacts/" + w.o.id + "/resources"
	good := strings.Repeat("ab12", 16)
	for _, bad := range []string{
		"", "session-123", strings.ToUpper(good), good[:63], good + "0", strings.Repeat("g", 64),
		good[:63] + " ", " " + good[:63], good[:32] + "\n" + good[33:],
	} {
		if got, _ := status(w.owner.testClient, "POST", base, map[string]any{"type": "claude-session", "value": bad}); got != http.StatusBadRequest {
			t.Errorf("value %q: %d, want 400", bad, got)
		}
	}
	var rs []struct{ ID string }
	var view struct {
		Resources []struct {
			ID    string `json:"id"`
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"resources"`
	}
	w.owner.mustDo("GET", "/api/artifacts/"+w.o.id, nil, &view, http.StatusOK)
	if len(view.Resources) != 0 {
		t.Fatalf("a refused value was stored: %+v (%v)", view.Resources, rs)
	}
	w.owner.mustDo("POST", base, map[string]any{"type": "claude-session", "value": good}, nil, http.StatusCreated)
	w.owner.mustDo("GET", "/api/artifacts/"+w.o.id, nil, &view, http.StatusOK)
	if len(view.Resources) != 1 || view.Resources[0].Value != good || view.Resources[0].Type != "claude-session" {
		t.Errorf("resources = %+v", view.Resources)
	}
}

// walkDataDir returns every file under dir, as path to bytes, including the
// SQLite database and its WAL.
func walkDataDir(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[p] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestNoPlaintextMetadataUnderTheDataDir is the milestone's check that no
// artifact name, description, changelog, or resource value reaches the disk:
// a client sends sealed blobs and blind indexes, and a marker in any request
// field would show here.
func TestNoPlaintextMetadataUnderTheDataDir(t *testing.T) {
	w := newMetaWorld(t)
	aid, vid := w.o.id, w.vid
	markers := []string{
		"MARKER-artifact-name-7f3a", "MARKER-artifact-description-91cc",
		"MARKER-version-name-51de", "MARKER-version-changelog-b2e0",
		"MARKER-resource-value-0d44",
	}
	mustMeta(t, newMeta(t, w.owner, aid, "", "name", 1, markers[0]))
	mustMeta(t, newMeta(t, w.owner, aid, "", "description", 1, markers[1]))
	mustMeta(t, newMeta(t, w.owner, aid, vid, "name", 1, markers[2]))
	mustMeta(t, newMeta(t, w.owner, aid, vid, "changelog", 1, markers[3]))
	// A rewrite, so the old rows are in the WAL and free pages too.
	mustMeta(t, newMeta(t, w.owner, aid, "", "name", 1, markers[0]+"-again"))
	index, err := e2e.BlindIndex(bytes.Repeat([]byte{4}, 32), "claude-session", markers[4])
	if err != nil {
		t.Fatal(err)
	}
	w.owner.mustDo("POST", "/api/artifacts/"+aid+"/resources", map[string]any{"type": "claude-session", "value": index}, nil, http.StatusCreated)
	// A plaintext resource value is refused, so it is never written either.
	w.owner.do("POST", "/api/artifacts/"+aid+"/resources", map[string]any{"type": "claude-session", "value": markers[4]}, nil)

	files := walkDataDir(t, w.s.cfg.DataDir)
	if len(files) < 3 {
		t.Fatalf("walked %d files under the data dir, want the database among them", len(files))
	}
	for path, b := range files {
		for _, m := range markers {
			if bytes.Contains(b, []byte(m)) {
				t.Errorf("%q appears in %s", m, path)
			}
		}
	}
}
