package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// createArtifact creates a private artifact owned by c, a seedAccount user,
// and returns its ID.
func createArtifact(t *testing.T, c *testClient, name string) string {
	t.Helper()
	return newArtifact(t, placeholderActor(t, c), name).id
}

// createPublicArtifact is createArtifact made public; it also returns the
// link token that opens it.
func createPublicArtifact(t *testing.T, c *testClient, name string) (id, link string) {
	t.Helper()
	o := newArtifact(t, placeholderActor(t, c), name)
	return o.id, o.makePublic()
}

// pushed is what a push answers.
type pushed struct {
	ID           string `json:"id"`
	Seq          int    `json:"seq"`
	Epoch        int    `json:"epoch"`
	ManifestHash string `json:"manifestHash"`
	PushedBy     string `json:"pushedBy"`
	Name         string `json:"name"`
	Changelog    string `json:"changelog"`
}

// storedBytes reads a file under the version's content dir.
func storedBytes(t *testing.T, s *Server, aid, vid, rel string) []byte {
	t.Helper()
	v, err := s.store.VersionByID(aid, vid)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(s.layout.ContentDir(aid, v.ContentDir), rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// contentDirs lists the content dirs the artifact has on disk.
func contentDirs(t *testing.T, s *Server, aid string) []string {
	t.Helper()
	entries, err := os.ReadDir(s.layout.ArtifactContentRoot(aid))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

const plainMarker = "PLAINTEXT-MARKER-4f1c"

func TestPushStoresCiphertextUnderTheClientsID(t *testing.T) {
	s, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	aid := createArtifact(t, admin, "demo")
	me := placeholderActor(t, admin)

	p := newPush(t, aid, "", 1, map[string]string{
		"index.html": "<h1>" + plainMarker + "</h1>",
		"app.js":     "console.log('" + plainMarker + "')",
	})
	p.Version["name"], p.Version["changelog"] = "v1", "initial"
	resp := admin.send("POST", "/api/artifacts/"+aid+"/versions", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("push: %d", resp.StatusCode)
	}
	v := decode[pushed](t, resp)
	if v.ID != p.Version["id"] || v.Seq != 1 || v.Epoch != 1 || v.ManifestHash != p.ManifestHash ||
		v.PushedBy != me.id || v.Name != "v1" || v.Changelog != "initial" {
		t.Errorf("answer %+v, want the pushed id, seq 1, epoch 1, hash %s, pusher %s, name v1", v, p.ManifestHash, me.id)
	}

	// The stored bytes are the uploaded ciphertext, byte for byte.
	if got := storedBytes(t, s, aid, v.ID, "manifest"); !bytes.Equal(got, p.Manifest) {
		t.Error("the stored manifest differs from the uploaded one")
	}
	for _, b := range p.Blobs {
		if got := storedBytes(t, s, aid, v.ID, "blobs/"+b.ID); !bytes.Equal(got, b.Data) {
			t.Errorf("stored blob %s differs from the uploaded one", b.ID)
		}
	}
	// Nothing under the data dir holds the plaintext, the database included.
	err := filepath.WalkDir(s.cfg.DataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err == nil && bytes.Contains(b, []byte(plainMarker)) {
			t.Errorf("%s holds the plaintext", path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// Both reads of the version show what the push recorded.
	var got, listed []pushed
	var one pushed
	admin.mustDo("GET", "/api/artifacts/"+aid+"/versions/"+v.ID, nil, &one, http.StatusOK)
	admin.mustDo("GET", "/api/artifacts/"+aid+"/versions", nil, &listed, http.StatusOK)
	got = append(listed, one)
	for _, g := range got {
		if g.ID != v.ID || g.Epoch != 1 || g.ManifestHash != p.ManifestHash || g.PushedBy != me.id {
			t.Errorf("read back %+v, want epoch 1, hash %s, pusher %s", g, p.ManifestHash, me.id)
		}
	}
	if len(listed) != 1 {
		t.Errorf("%d versions listed, want 1", len(listed))
	}
}

func TestPushRefusals(t *testing.T) {
	s, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	aid := createArtifact(t, admin, "demo")
	base := "/api/artifacts/" + aid + "/versions"
	files := map[string]string{"index.html": "x", "a.js": "y"}

	zipish := []byte("PK\x03\x04 not really a zip")
	withBlobID := func(i int, id string) func(*pushParts) {
		return func(p *pushParts) { p.Blobs[i].ID = id }
	}
	short := func(b []byte) []byte { return b[:e2e.BlobMinSize-1] }
	badVersionByte := func(b []byte) []byte {
		c := bytes.Clone(b)
		c[4] = 2
		return c
	}
	badMagic := func(b []byte) []byte {
		c := bytes.Clone(b)
		c[0] = 'X'
		return c
	}
	cases := []struct {
		name   string
		mutate func(p *pushParts)
		status int
		msg    string
	}{
		{"the old archive part", func(p *pushParts) { p.Extra = []extraPart{{"archive", "artifact.zip", zipish}} }, 400, "update the cairn tool"},
		{"the old file part", func(p *pushParts) { p.Extra = []extraPart{{"file", "artifact.zip", zipish}} }, 400, "update the cairn tool"},
		{"no version part", func(p *pushParts) { p.Version = nil }, 400, "'version' and 'manifest'"},
		{"two version parts", func(p *pushParts) {
			p.Extra = []extraPart{{"version", "", []byte(`{}`)}}
		}, 400, "two 'version' parts"},
		{"a version part that is not JSON", func(p *pushParts) { p.VersionRaw = []byte("{") }, 400, "'version'"},
		{"a version part with trailing data", func(p *pushParts) {
			raw, _ := json.Marshal(p.Version)
			p.VersionRaw = append(raw, []byte(` {"id":"x"}`)...)
		}, 400, "trailing data"},
		{"a version part with a second, empty object", func(p *pushParts) {
			raw, _ := json.Marshal(p.Version)
			p.VersionRaw = append(raw, []byte(` {}`)...)
		}, 400, "trailing data"},
		{"a version part with a stray closing brace", func(p *pushParts) {
			raw, _ := json.Marshal(p.Version)
			p.VersionRaw = append(raw, '}')
		}, 400, "trailing data"},
		{"a version part with a stray closing bracket", func(p *pushParts) {
			raw, _ := json.Marshal(p.Version)
			p.VersionRaw = append(raw, ']')
		}, 400, "trailing data"},
		{"an epoch that is a string", func(p *pushParts) { p.Version["epoch"] = "1" }, 400, "invalid 'version' part"},
		{"an epoch with a fraction", func(p *pushParts) { p.Version["epoch"] = 1.5 }, 400, "invalid 'version' part"},
		{"an epoch beyond int", func(p *pushParts) { p.Version["epoch"] = 1e30 }, 400, "invalid 'version' part"},
		{"a version part over its 1 MiB cap", func(p *pushParts) {
			p.VersionRaw = []byte(`{"id":"` + strings.Repeat("a", 2<<20) + `"}`)
		}, 400, "invalid 'version' part"},
		{"no blob", func(p *pushParts) { p.Blobs = nil }, 400, "at least one blob"},
		{"a version part with an unknown field", func(p *pushParts) { p.Version["extra"] = 1 }, 400, "'version'"},
		{"a version id in capitals", func(p *pushParts) { p.Version["id"] = strings.ToUpper(p.Version["id"].(string)) }, 409, "lowercase UUID"},
		{"a version id that is not a UUID", func(p *pushParts) { p.Version["id"] = "not-a-uuid" }, 409, "lowercase UUID"},
		{"no version id", func(p *pushParts) { p.Version["id"] = "" }, 409, "lowercase UUID"},
		{"a stale epoch", func(p *pushParts) { p.Version["epoch"] = 2 }, 409, "new epoch"},
		{"epoch zero", func(p *pushParts) { p.Version["epoch"] = 0 }, 400, "names no epoch"},
		{"a negative epoch", func(p *pushParts) { p.Version["epoch"] = -1 }, 400, "names no epoch"},
		{"no epoch", func(p *pushParts) { delete(p.Version, "epoch") }, 400, "names no epoch"},
		{"a manifestHash in capitals", func(p *pushParts) { p.Version["manifestHash"] = strings.ToUpper(p.ManifestHash) }, 400, "manifestHash"},
		{"a short manifestHash", func(p *pushParts) { p.Version["manifestHash"] = p.ManifestHash[:63] }, 400, "manifestHash"},
		{"a long manifestHash", func(p *pushParts) { p.Version["manifestHash"] = p.ManifestHash + "0" }, 400, "manifestHash"},
		{"no manifestHash", func(p *pushParts) { p.Version["manifestHash"] = "" }, 400, "manifestHash"},
		{"no manifest", func(p *pushParts) { p.Manifest = nil }, 400, "'manifest'"},
		{"two manifests", func(p *pushParts) { p.Extra = []extraPart{{"manifest", "manifest", p.Manifest}} }, 400, "two 'manifest'"},
		{"a manifest with no blob header", func(p *pushParts) { p.Manifest = badMagic(p.Manifest) }, 400, "manifest is not a Cairn blob"},
		{"a manifest with another version byte", func(p *pushParts) { p.Manifest = badVersionByte(p.Manifest) }, 400, "manifest is not a Cairn blob"},
		{"a manifest too short for a chunk", func(p *pushParts) { p.Manifest = short(p.Manifest) }, 400, "manifest is not a Cairn blob"},
		{"a manifest that is only a header", func(p *pushParts) { p.Manifest = p.Manifest[:37] }, 400, "manifest is not a Cairn blob"},
		{"an empty manifest", func(p *pushParts) { p.Manifest = []byte{} }, 400, "manifest is not a Cairn blob"},
		{"a blob with no blob header", func(p *pushParts) { p.Blobs[0].Data = badMagic(p.Blobs[0].Data) }, 400, "is not a Cairn blob"},
		{"a blob with another version byte", func(p *pushParts) { p.Blobs[1].Data = badVersionByte(p.Blobs[1].Data) }, 400, "is not a Cairn blob"},
		{"a blob too short for a chunk", func(p *pushParts) { p.Blobs[0].Data = short(p.Blobs[0].Data) }, 400, "is not a Cairn blob"},
		{"an empty blob", func(p *pushParts) { p.Blobs[0].Data = []byte{} }, 400, "is not a Cairn blob"},
		{"a blob ID in capitals", func(p *pushParts) { withBlobID(0, "ABCDEF0123456789ABCDEF0123456789")(p) }, 400, "blob's filename"},
		{"a 31-character blob ID", withBlobID(0, strings.Repeat("a", 31)), 400, "blob's filename"},
		{"a 33-character blob ID", withBlobID(0, strings.Repeat("a", 33)), 400, "blob's filename"},
		{"a blob ID that is not hex", withBlobID(0, strings.Repeat("g", 32)), 400, "blob's filename"},
		{"a blob ID with a directory", withBlobID(0, "x/"+strings.Repeat("a", 32)), 400, "blob's filename"},
		{"a blob ID that climbs out", withBlobID(0, "../"+strings.Repeat("a", 29)), 400, "blob's filename"},
		{"no blob ID", withBlobID(0, ""), 400, "blob's filename"},
		{"a blob ID used twice", func(p *pushParts) { p.Blobs[1].ID = p.Blobs[0].ID }, 400, "appears twice"},
		{"an unknown part", func(p *pushParts) { p.Extra = []extraPart{{"extra", "", []byte("x")}} }, 400, "unexpected part"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPush(t, aid, "", 1, files)
			tc.mutate(p)
			resp := admin.send("POST", base, p)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != tc.status || !strings.Contains(string(body), tc.msg) {
				t.Errorf("status %d %s, want %d naming %q", resp.StatusCode, body, tc.status, tc.msg)
			}
		})
	}

	// A refusal leaves nothing behind: no version, and no content dir.
	var versions []any
	admin.mustDo("GET", base, nil, &versions, http.StatusOK)
	if len(versions) != 0 {
		t.Errorf("%d versions after refused pushes", len(versions))
	}
	if dirs := contentDirs(t, s, aid); len(dirs) != 0 {
		t.Errorf("content dirs left behind: %v", dirs)
	}

	// The replace route reads a push with the same code, so the shape
	// refusals hold there too, and the version it names stays as it was.
	first := newPush(t, aid, "", 1, files)
	vid := decode[pushed](t, admin.send("POST", base, first)).ID
	onPUT := map[string]bool{
		"no version part": true, "a version part that is not JSON": true, "a version part with trailing data": true,
		"a version part with a stray closing brace": true, "a version part with a stray closing bracket": true,
		"no blob": true, "no epoch": true, "an epoch that is a string": true, "an epoch with a fraction": true,
		"an epoch beyond int": true, "no manifest": true, "a blob ID used twice": true,
	}
	for _, tc := range cases {
		if !onPUT[tc.name] {
			continue
		}
		t.Run("PUT "+tc.name, func(t *testing.T) {
			p := newPush(t, aid, vid, 1, files)
			tc.mutate(p)
			resp := admin.send("PUT", base+"/"+vid, p)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != tc.status || !strings.Contains(string(body), tc.msg) {
				t.Errorf("status %d %s, want %d naming %q", resp.StatusCode, body, tc.status, tc.msg)
			}
		})
	}
	if got := storedBytes(t, s, aid, vid, "manifest"); !bytes.Equal(got, first.Manifest) {
		t.Error("a refused replace changed the stored manifest")
	}
	if dirs := contentDirs(t, s, aid); len(dirs) != 1 {
		t.Errorf("content dirs after refused replaces: %v, want just the first push's", dirs)
	}
}

func TestPushRefusesAnIDAnyVersionUses(t *testing.T) {
	s, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	aid := createArtifact(t, admin, "one")
	other := createArtifact(t, admin, "two")

	first := newPush(t, aid, "", 1, map[string]string{"index.html": "x"})
	resp := admin.send("POST", "/api/artifacts/"+aid+"/versions", first)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("push: %d", resp.StatusCode)
	}
	id := decode[pushed](t, resp).ID

	for _, target := range []string{aid, other} {
		again := newPush(t, target, id, 1, map[string]string{"index.html": "other"})
		resp := admin.send("POST", "/api/artifacts/"+target+"/versions", again)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "already exists") {
			t.Errorf("reusing the id on %s: %d %s, want 409 naming a version that exists", target, resp.StatusCode, body)
		}
	}
	if got := storedBytes(t, s, aid, id, "manifest"); !bytes.Equal(got, first.Manifest) {
		t.Error("the refused push changed the stored manifest")
	}
	if dirs := contentDirs(t, s, other); len(dirs) != 0 {
		t.Errorf("content dirs left on the other artifact: %v", dirs)
	}
	if dirs := contentDirs(t, s, aid); len(dirs) != 1 {
		t.Errorf("content dirs on the first artifact: %v, want just the first push's", dirs)
	}
}

func TestPushOverTheSizeLimit(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) { c.MaxUploadMB = 1 })
	seedAccount(t, s, "admin@example.com", "admin-password", true)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	aid := createArtifact(t, admin, "demo")

	big := newPush(t, aid, "", 1, map[string]string{"index.html": strings.Repeat("a", 1<<20+1)})
	resp := admin.send("POST", "/api/artifacts/"+aid+"/versions", big)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(string(body), "maximum size") {
		t.Errorf("oversize push: %d %s, want 413", resp.StatusCode, body)
	}
	if dirs := contentDirs(t, s, aid); len(dirs) != 0 {
		t.Errorf("content dirs left behind: %v", dirs)
	}
	small := newPush(t, aid, "", 1, map[string]string{"index.html": strings.Repeat("a", 1<<19)})
	if resp := admin.send("POST", "/api/artifacts/"+aid+"/versions", small); resp.StatusCode != http.StatusCreated {
		t.Errorf("push within the limit: %d", resp.StatusCode)
	}
}

// The cap counts the whole multipart body, framing included, so the test
// finds the largest file whose body still fits: that push succeeds, and a
// file one byte larger is refused with 413.
func TestPushAtTheSizeLimit(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) { c.MaxUploadMB = 1 })
	seedAccount(t, s, "admin@example.com", "admin-password", true)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	aid := createArtifact(t, admin, "demo")
	base := "/api/artifacts/" + aid + "/versions"
	bodyLen := func(n int) int {
		_, b := newPush(t, aid, "", 1, map[string]string{"index.html": strings.Repeat("a", n)}).body(t)
		return len(b)
	}
	limit := 1 << 20
	fit, over := 0, limit
	for fit+1 < over {
		mid := (fit + over) / 2
		if bodyLen(mid) <= limit {
			fit = mid
		} else {
			over = mid
		}
	}
	if bodyLen(fit) > limit || bodyLen(fit+1) <= limit {
		t.Fatalf("search failed: %d bytes fit (body %d), %d do not (body %d), limit %d", fit, bodyLen(fit), fit+1, bodyLen(fit+1), limit)
	}
	if resp := admin.send("POST", base, newPush(t, aid, "", 1, map[string]string{"index.html": strings.Repeat("a", fit)})); resp.StatusCode != http.StatusCreated {
		t.Errorf("a push whose body is %d of %d bytes: %d, want 201", bodyLen(fit), limit, resp.StatusCode)
	}
	resp := admin.send("POST", base, newPush(t, aid, "", 1, map[string]string{"index.html": strings.Repeat("a", fit+1)}))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(string(body), "maximum size") {
		t.Errorf("a push whose body is %d of %d bytes: %d %s, want 413", bodyLen(fit+1), limit, resp.StatusCode, body)
	}
}

// The upload cap can run out while the server reads the version part, which
// is under its own 1 MiB cap: that is 413, not a malformed part.
func TestPushWhoseVersionPartHitsTheUploadCap(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) { c.MaxUploadMB = 1 })
	seedAccount(t, s, "admin@example.com", "admin-password", true)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	aid := createArtifact(t, admin, "demo")
	for name, tail := range map[string]string{
		"in the value":         `{"id":"` + strings.Repeat("a", 1<<20-100) + `"}`,
		"in the data after it": `{"id":""}` + strings.Repeat(" ", 1<<20-100),
	} {
		p := newPush(t, aid, "", 1, map[string]string{"index.html": "x"})
		p.VersionRaw = []byte(tail)
		resp := admin.send("POST", "/api/artifacts/"+aid+"/versions", p)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(string(body), "maximum size") {
			t.Errorf("a version part that reaches the cap %s: %d %s, want 413", name, resp.StatusCode, body)
		}
	}
}

// A push and a re-upload declare their epoch in the version part, and the
// artifact's current epoch is the only one the server takes.
func TestPushEpoch(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	o := newArtifact(t, a, "epochs")
	o.apply(o.nextEpoch()) // epoch 2
	base := "/api/artifacts/" + o.id + "/versions"

	first := newPush(t, o.id, "", 2, map[string]string{"index.html": "x"})
	v := decode[pushed](t, a.send("POST", base, first))
	if v.Epoch != 2 {
		t.Fatalf("pushed at epoch %d, want 2", v.Epoch)
	}
	for _, stale := range []int{1, 3} {
		for _, method := range []string{"POST", "PUT"} {
			vid, path := "", base
			if method == "PUT" {
				vid, path = v.ID, base+"/"+v.ID
			}
			resp := a.send(method, path, newPush(t, o.id, vid, stale, map[string]string{"index.html": "x"}))
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "new epoch") {
				t.Errorf("%s declaring epoch %d at epoch 2: %d %s, want 409 naming a new epoch", method, stale, resp.StatusCode, body)
			}
		}
	}
	var versions []pushed
	a.mustDo("GET", base, nil, &versions, http.StatusOK)
	if len(versions) != 1 || versions[0].ManifestHash != first.ManifestHash {
		t.Errorf("versions after refused pushes: %+v, want only the first, unchanged", versions)
	}
	if dirs := contentDirs(t, s, o.id); len(dirs) != 1 {
		t.Errorf("content dirs: %v, want one", dirs)
	}
}

func TestReplaceVersion(t *testing.T) {
	s, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	aid := createArtifact(t, admin, "demo")
	base := "/api/artifacts/" + aid + "/versions"

	p1 := newPush(t, aid, "", 1, map[string]string{"index.html": "one"})
	p1.Version["name"], p1.Version["changelog"] = "v1", "first"
	v := decode[pushed](t, admin.send("POST", base, p1))
	v2 := decode[pushed](t, admin.pushPlain(aid))
	oldBlob := p1.Blobs[0].ID

	p2 := newPush(t, aid, v.ID, 1, map[string]string{"index.html": "two", "extra.js": "x"})
	resp := admin.send("PUT", base+"/"+v.ID, p2)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("replace: %d", resp.StatusCode)
	}
	got := decode[pushed](t, resp)
	if got.ID != v.ID || got.Seq != v.Seq || got.ManifestHash != p2.ManifestHash || got.ManifestHash == p1.ManifestHash {
		t.Errorf("replaced %+v, want the same id and seq with hash %s", got, p2.ManifestHash)
	}
	// An empty name and changelog keep the old ones.
	if got.Name != "v1" || got.Changelog != "first" {
		t.Errorf("replaced name %q changelog %q, want v1 and first kept", got.Name, got.Changelog)
	}
	if b := storedBytes(t, s, aid, v.ID, "manifest"); !bytes.Equal(b, p2.Manifest) {
		t.Error("the stored manifest is not the replacement")
	}
	// The old dir is gone, so the old blob is unreachable; the other version stays.
	if r := admin.doRaw("GET", base+"/"+v.ID+"/blobs/"+oldBlob, nil); r.StatusCode != http.StatusNotFound {
		t.Errorf("old blob after the replace: %d, want 404", r.StatusCode)
	}
	if dirs := contentDirs(t, s, aid); len(dirs) != 2 {
		t.Errorf("content dirs after the replace: %v, want two, one per version", dirs)
	}
	if r := admin.doRaw("GET", base+"/"+v2.ID+"/manifest", nil); r.StatusCode != http.StatusOK {
		t.Errorf("the other version's manifest: %d", r.StatusCode)
	}

	refusals := []struct {
		name   string
		path   string
		mutate func(p *pushParts)
		status int
		msg    string
	}{
		{"another version's id", base + "/" + v.ID, func(p *pushParts) { p.Version["id"] = v2.ID }, 400, "id in the URL"},
		{"an unknown version", base + "/00000000-0000-4000-8000-000000000000", func(p *pushParts) {}, 404, "not found"},
		{"the old archive part", base + "/" + v.ID, func(p *pushParts) { p.Extra = []extraPart{{"archive", "a.zip", []byte("PK")}} }, 400, "update the cairn tool"},
		{"a stale epoch", base + "/" + v.ID, func(p *pushParts) { p.Version["epoch"] = 2 }, 409, "new epoch"},
		{"a bad manifestHash", base + "/" + v.ID, func(p *pushParts) { p.Version["manifestHash"] = "x" }, 400, "manifestHash"},
		{"a short blob", base + "/" + v.ID, func(p *pushParts) { p.Blobs[0].Data = p.Blobs[0].Data[:10] }, 400, "is not a Cairn blob"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			p := newPush(t, aid, v.ID, 1, map[string]string{"index.html": "three"})
			tc.mutate(p)
			resp := admin.send("PUT", tc.path, p)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != tc.status || !strings.Contains(string(body), tc.msg) {
				t.Errorf("status %d %s, want %d naming %q", resp.StatusCode, body, tc.status, tc.msg)
			}
		})
	}
	if b := storedBytes(t, s, aid, v.ID, "manifest"); !bytes.Equal(b, p2.Manifest) {
		t.Error("a refused replace changed the stored manifest")
	}
	if dirs := contentDirs(t, s, aid); len(dirs) != 2 {
		t.Errorf("content dirs after refused replaces: %v, want two", dirs)
	}
}

func TestReadStoredBlobs(t *testing.T) {
	s, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	aid, link := createPublicArtifact(t, admin, "demo")
	base := "/api/artifacts/" + aid + "/versions"

	p := newPush(t, aid, "", 1, map[string]string{"index.html": "one", "b.js": "two"})
	v := decode[pushed](t, admin.send("POST", base, p))
	other := newPush(t, aid, "", 1, map[string]string{"index.html": "other"})
	ov := decode[pushed](t, admin.send("POST", base, other))
	vbase := base + "/" + v.ID

	fetch := func(c *testClient, path string) (*http.Response, []byte) {
		resp := c.doRaw("GET", path, nil)
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	check := func(c *testClient, path string, want []byte) {
		t.Helper()
		resp, b := fetch(c, path)
		if resp.StatusCode != http.StatusOK || !bytes.Equal(b, want) {
			t.Errorf("GET %s: %d, %d bytes, want 200 and %d bytes", path, resp.StatusCode, len(b), len(want))
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
			t.Errorf("GET %s Content-Type %q, want application/octet-stream", path, ct)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("GET %s Cache-Control %q, want no-store", path, cc)
		}
	}
	check(admin, vbase+"/manifest", p.Manifest)
	for _, b := range p.Blobs {
		check(admin, vbase+"/blobs/"+b.ID, b.Data)
	}
	// A public artifact reads to its link token, and a private one to nobody.
	anon := &testClient{t: t, base: ts.URL, link: link}
	check(anon, vbase+"/manifest", p.Manifest)
	check(anon, vbase+"/blobs/"+p.Blobs[0].ID, p.Blobs[0].Data)
	if resp, _ := fetch(&testClient{t: t, base: ts.URL}, vbase+"/manifest"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("manifest without the link token: %d, want 404", resp.StatusCode)
	}

	notFound := map[string]string{
		"a blob ID no version holds":      vbase + "/blobs/" + strings.Repeat("a", 32),
		"another version's blob":          vbase + "/blobs/" + other.Blobs[0].ID,
		"a blob ID in capitals":           vbase + "/blobs/" + strings.ToUpper(p.Blobs[0].ID),
		"a short blob ID":                 vbase + "/blobs/" + p.Blobs[0].ID[:31],
		"a long blob ID":                  vbase + "/blobs/" + p.Blobs[0].ID + "0",
		"a path in the blob ID":           vbase + "/blobs/..%2fmanifest",
		"a path climbing out":             vbase + "/blobs/..%2f..%2f" + p.Blobs[0].ID,
		"the manifest as a blob":          vbase + "/blobs/manifest",
		"an unknown version's manifest":   base + "/00000000-0000-4000-8000-000000000000/manifest",
		"an unknown version's blob":       base + "/00000000-0000-4000-8000-000000000000/blobs/" + p.Blobs[0].ID,
		"a blob ID with a trailing slash": vbase + "/blobs/" + p.Blobs[0].ID + "/",
	}
	for name, path := range notFound {
		if resp, _ := fetch(admin, path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: GET %s: %d, want 404", name, path, resp.StatusCode)
		}
	}
	if b := storedBytes(t, s, aid, ov.ID, "blobs/"+other.Blobs[0].ID); !bytes.Equal(b, other.Blobs[0].Data) {
		t.Error("the other version's blob changed")
	}
}

// An older cairn tool pushed `name`, `changelog`, then a zip as `archive`.
// Whichever part the server reads first, the answer tells the person to
// update the tool.
func TestPushFromAnOldClient(t *testing.T) {
	_, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	aid := createArtifact(t, admin, "demo")

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("name", "v1")
	mw.WriteField("changelog", "first")
	w, err := mw.CreateFormFile("archive", "artifact.zip")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("PK\x03\x04 not really a zip"))
	mw.Close()
	req, err := http.NewRequest("POST", ts.URL+"/api/artifacts/"+aid+"/versions", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	admin.setHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "update the cairn tool") {
		t.Errorf("old push: %d %s, want 400 telling the person to update the cairn tool", resp.StatusCode, body)
	}
}

// A part's Content-Transfer-Encoding must not change the bytes the server
// keeps: the stored blob is what was sent.
func TestPushStoresAPartAsSent(t *testing.T) {
	s, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	aid := createArtifact(t, admin, "demo")

	p := newPush(t, aid, "", 1, map[string]string{"index.html": "x"})
	// "=41" and a soft line break would decode to different bytes.
	p.Blobs[0].Data = append(p.Blobs[0].Data, []byte("=41=\r\n")...)
	p.Blobs[0].Encoding = "quoted-printable"
	resp := admin.send("POST", "/api/artifacts/"+aid+"/versions", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("push: %d", resp.StatusCode)
	}
	v := decode[pushed](t, resp)
	if got := storedBytes(t, s, aid, v.ID, "blobs/"+p.Blobs[0].ID); !bytes.Equal(got, p.Blobs[0].Data) {
		t.Error("the stored blob differs from the bytes sent")
	}
}

func TestWriteBlobRefusesAnExistingFile(t *testing.T) {
	p := newPush(t, "a", "", 1, map[string]string{"index.html": "x"})
	dest := filepath.Join(t.TempDir(), "blob")
	if err := writeBlob(dest, bytes.NewReader(p.Blobs[0].Data)); err != nil {
		t.Fatal(err)
	}
	other := newPush(t, "a", "", 1, map[string]string{"index.html": "y"})
	if err := writeBlob(dest, bytes.NewReader(other.Blobs[0].Data)); !errors.Is(err, fs.ErrExist) {
		t.Errorf("writeBlob over an existing file: %v, want ErrExist", err)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, p.Blobs[0].Data) {
		t.Error("the second write changed the first blob")
	}
}

// A version's manifest and blobs are read through its own artifact only,
// whoever asks and however they authenticate.
func TestStoredReadsAreScopedToTheArtifact(t *testing.T) {
	s, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	me := placeholderActor(t, admin)
	a := createArtifact(t, admin, "a")
	b := createArtifact(t, admin, "b")
	pa := newPush(t, a, "", 1, map[string]string{"index.html": "a"})
	va := decode[pushed](t, admin.send("POST", "/api/artifacts/"+a+"/versions", pa))
	admin.pushPlain(b).Body.Close()

	bToken := &testClient{t: t, base: ts.URL, token: mintContentToken(t, s, me.id, b)}
	paths := []string{
		"/api/artifacts/%s/versions/" + va.ID + "/manifest",
		"/api/artifacts/%s/versions/" + va.ID + "/blobs/" + pa.Blobs[0].ID,
	}
	for _, tmpl := range paths {
		own := fmt.Sprintf(tmpl, a)
		if r := admin.doRaw("GET", own, nil); r.StatusCode != http.StatusOK {
			t.Errorf("GET %s: %d, want 200", own, r.StatusCode)
		}
		cross := fmt.Sprintf(tmpl, b)
		wantCode(t, admin, "GET", cross, http.StatusNotFound)
		wantCode(t, bToken, "GET", cross, http.StatusNotFound)
	}
}

// A manifest part is capped at e2e.MaxManifestBytes, the most the client
// reads, whatever the upload cap is: one byte over is 413 naming the limit
// and leaves the stored version as it was, and the cap itself is accepted.
func TestManifestPartCap(t *testing.T) {
	s, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	aid := createArtifact(t, admin, "demo")
	base := "/api/artifacts/" + aid + "/versions"
	padded := func(p *pushParts, n int) *pushParts {
		p.Manifest = append(bytes.Clone(p.Manifest), make([]byte, n-len(p.Manifest))...)
		return p
	}
	first := newPush(t, aid, "", 1, map[string]string{"index.html": "one"})
	v := decode[pushed](t, admin.send("POST", base, first))

	over := func(method, path string, p *pushParts) {
		t.Helper()
		resp := admin.send(method, path, padded(p, e2e.MaxManifestBytes+1))
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(string(body), "manifest") || !strings.Contains(string(body), "16 MiB") {
			t.Errorf("%s with a manifest one byte over the cap: %d %s, want 413 naming the 16 MiB limit", method, resp.StatusCode, body)
		}
	}
	t.Run("push", func(t *testing.T) {
		over("POST", base, newPush(t, aid, "", 1, map[string]string{"index.html": "two"}))
		if dirs := contentDirs(t, s, aid); len(dirs) != 1 {
			t.Errorf("content dirs after a refused push: %v, want just the first version's", dirs)
		}
		if got := decode[[]pushed](t, admin.doRaw("GET", base, nil)); len(got) != 1 || got[0].ManifestHash != first.ManifestHash {
			t.Errorf("versions after a refused push: %+v, want the first alone and unchanged", got)
		}
		if resp := admin.send("POST", base, padded(newPush(t, aid, "", 1, map[string]string{"index.html": "four"}), e2e.MaxManifestBytes)); resp.StatusCode != http.StatusCreated {
			t.Errorf("POST with a manifest at the cap: %d, want 201", resp.StatusCode)
		}
	})
	t.Run("replace", func(t *testing.T) {
		dirs := contentDirs(t, s, aid)
		over("PUT", base+"/"+v.ID, newPush(t, aid, v.ID, 1, map[string]string{"index.html": "three"}))
		if b := storedBytes(t, s, aid, v.ID, "manifest"); !bytes.Equal(b, first.Manifest) {
			t.Error("a refused replace changed the stored manifest")
		}
		if after := contentDirs(t, s, aid); len(after) != len(dirs) {
			t.Errorf("content dirs after a refused replace: %v, want %v", after, dirs)
		}
		if resp := admin.send("PUT", base+"/"+v.ID, padded(newPush(t, aid, v.ID, 1, map[string]string{"index.html": "five"}), e2e.MaxManifestBytes)); resp.StatusCode != http.StatusOK {
			t.Errorf("PUT with a manifest at the cap: %d, want 200", resp.StatusCode)
		}
	})
}
