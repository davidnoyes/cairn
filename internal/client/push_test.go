package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/server"
)

// recordingTransport notes the epoch in the version part of every version
// write and, when status is set, answers those writes with it instead of
// sending them.
type recordingTransport struct {
	mu      sync.Mutex
	epochs  []string
	status  int
	body    string // the error answered with status; the epoch one if empty
	forward http.RoundTripper
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != "GET" && strings.Contains(req.URL.Path, "/versions") && !strings.Contains(req.URL.Path, "/meta/") {
		data, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(data))
		rt.mu.Lock()
		rt.epochs = append(rt.epochs, versionPartEpoch(req.Header.Get("Content-Type"), data))
		rt.mu.Unlock()
		if rt.status != 0 {
			body := rt.body
			if body == "" {
				body = "the artifact moved to a new epoch; run the command again"
			}
			return &http.Response{
				StatusCode: rt.status, Header: http.Header{}, Request: req,
				Body: io.NopCloser(strings.NewReader(`{"error":"` + body + `"}`)),
			}, nil
		}
	}
	return rt.forward.RoundTrip(req)
}

// versionPartEpoch is the epoch in the "version" part of a multipart push.
func versionPartEpoch(contentType string, body []byte) string {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "?"
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		part, err := mr.NextPart()
		if err != nil {
			return "?"
		}
		if part.FormName() != "version" {
			continue
		}
		var v struct {
			Epoch int `json:"epoch"`
		}
		if err := json.NewDecoder(part).Decode(&v); err != nil {
			return "?"
		}
		return strconv.Itoa(v.Epoch)
	}
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

// writeTree writes files (slash path to content) under a fresh dir.
func writeTree(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// rawGet reads path as c, which must be signed in, and returns the body.
func rawGet(t *testing.T, c *Client, path string) []byte {
	t.Helper()
	req, err := http.NewRequest("GET", c.Host+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, resp.StatusCode, b)
	}
	return b
}

// opened is what a reader holding AK finds in a pushed version.
type opened struct {
	env      e2e.Envelope
	body     e2e.ManifestBody
	files    map[string][]byte // path to plaintext
	blobByID map[string][]byte // blob ID to stored ciphertext
}

// openPushed fetches version vid of artifact as c and opens its manifest and
// every file with c's own AK for epoch, failing the test if anything does not
// open under the context the format prescribes. It does not check the
// signature: the caller knows whose key to check it under.
func openPushed(t *testing.T, c *Client, artifact, vid string, epoch int) opened {
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
	ak := aks[epoch]
	base := "/api/artifacts/" + artifact + "/versions/" + vid
	manifest := rawGet(t, c, base+"/manifest")
	envJSON, err := e2e.OpenBlob(ak, e2e.BlobContext{Artifact: artifact, Version: vid, Kind: "manifest"}, manifest)
	if err != nil {
		t.Fatalf("opening the manifest blob: %v", err)
	}
	var o opened
	if err := json.Unmarshal(envJSON, &o.env); err != nil {
		t.Fatalf("the manifest blob does not hold an envelope: %v", err)
	}
	if err := e2e.DecodeStrict(o.env.Body, &o.body); err != nil {
		t.Fatalf("the manifest body: %v", err)
	}
	o.files, o.blobByID = map[string][]byte{}, map[string][]byte{}
	for _, f := range o.body.Files {
		blob := rawGet(t, c, base+"/blobs/"+f.Blob)
		if e2e.BodyHash(blob) != f.SHA256 {
			t.Errorf("%s: the manifest's sha256 is not the stored blob's", f.Path)
		}
		pt, err := e2e.OpenBlob(ak, e2e.BlobContext{Artifact: artifact, Version: vid, Kind: "content", Name: f.Path}, blob)
		if err != nil {
			t.Fatalf("opening %s: %v", f.Path, err)
		}
		if int64(len(pt)) != f.Size {
			t.Errorf("%s: manifest size %d, plaintext %d bytes", f.Path, f.Size, len(pt))
		}
		o.files[f.Path], o.blobByID[f.Blob] = pt, blob
	}
	return o
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

// TestPushSealsAndSignsWhatItUploads opens what a push left on the server
// the way a reader would: the manifest under the version's context, its
// signature under the pusher's key, and every file under its own context.
func TestPushSealsAndSignsWhatItUploads(t *testing.T) {
	c := authedClient(t)
	a, err := c.CreateArtifact("site", "")
	if err != nil {
		t.Fatal(err)
	}
	// An empty file, a nested one, and one that spans several chunks.
	big := bytes.Repeat([]byte("0123456789abcdef"), 3*e2e.BlobChunkSize/16+5)
	tree := map[string][]byte{
		"index.html":      []byte("<h1>marker-one</h1>"),
		"a/c":             []byte("sorts after a-b, though the walk reaches it first"),
		"a-b":             []byte("x"),
		"empty.txt":       {},
		"assets/app.js":   []byte("console.log('marker-two')"),
		"assets/deep/big": big,
	}
	v, err := c.Push(a.ID, "", writeTree(t, tree), "v1", "first")
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if v.Epoch != 1 || v.Name != "v1" || v.Changelog != "first" || len(v.ManifestHash) != 64 {
		t.Errorf("pushed version = %+v", v)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(v.ID) {
		t.Errorf("version ID %q is not a lowercase UUIDv4", v.ID)
	}

	o := openPushed(t, c, a.ID, v.ID, 1)
	k := mustUnlock(t, c)
	if o.env.Signer != k.UserID {
		t.Errorf("manifest signer = %q, want %q", o.env.Signer, k.UserID)
	}
	var body e2e.ManifestBody
	if err := e2e.OpenEnvelope(o.env, k.Ed25519Pub, "manifest", &body); err != nil {
		t.Fatalf("the manifest signature does not verify under the pusher's key: %v", err)
	}
	if e2e.BodyHash(o.env.Body) != v.ManifestHash {
		t.Errorf("the version's manifestHash is not the hash of the manifest body")
	}
	if body.V != 1 || body.Artifact != a.ID || body.Version != v.ID || body.Epoch != 1 {
		t.Errorf("manifest header = %+v", body)
	}
	if len(o.files) != len(tree) {
		t.Errorf("manifest lists %d files, want %d", len(o.files), len(tree))
	}
	var paths []string
	for _, f := range body.Files {
		paths = append(paths, f.Path)
		if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(f.Blob) {
			t.Errorf("%s: blob ID %q is not 32 lowercase hex characters", f.Path, f.Blob)
		}
		if !bytes.Equal(o.files[f.Path], tree[f.Path]) {
			t.Errorf("%s does not open to what was pushed", f.Path)
		}
	}
	if !slices.IsSorted(paths) {
		t.Errorf("manifest files are not sorted by path: %v", paths)
	}
	// A blob opens under its own path and no other.
	var blob []byte
	for _, f := range body.Files {
		if f.Path == "assets/app.js" {
			blob = o.blobByID[f.Blob]
		}
	}
	ak := func() []byte {
		va, _ := c.VerifyArtifact(k, a.ID, "")
		aks, _ := c.callerAKs(k, a.ID, va.Chain)
		return aks[1]
	}()
	if _, err := e2e.OpenBlob(ak, e2e.BlobContext{Artifact: a.ID, Version: v.ID, Kind: "content", Name: "index.html"}, blob); err == nil {
		t.Error("a blob opened under another file's path")
	}

	// The server holds no plaintext.
	for _, b := range o.blobByID {
		if bytes.Contains(b, []byte("marker-")) {
			t.Error("a stored blob holds plaintext")
		}
	}
}

func TestPushOverwriteKeepsTheVersionID(t *testing.T) {
	c := authedClient(t)
	a, err := c.CreateArtifact("site", "")
	if err != nil {
		t.Fatal(err)
	}
	v1, err := c.Push(a.ID, "", writeTree(t, map[string][]byte{"index.html": []byte("one")}), "v1", "")
	if err != nil {
		t.Fatal(err)
	}
	oldO := openPushed(t, c, a.ID, v1.ID, 1)
	v2, err := c.Push(a.ID, v1.ID, writeTree(t, map[string][]byte{"index.html": []byte("two"), "b.js": []byte("b")}), "", "")
	if err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if v2.ID != v1.ID || v2.Seq != v1.Seq || v2.ManifestHash == v1.ManifestHash {
		t.Errorf("overwrite answered %+v after %+v, want the same id and seq and a new hash", v2, v1)
	}
	o := openPushed(t, c, a.ID, v1.ID, 1)
	if o.body.Version != v1.ID || string(o.files["index.html"]) != "two" || len(o.files) != 2 {
		t.Errorf("after the overwrite: version %s, %d files, index.html %q", o.body.Version, len(o.files), o.files["index.html"])
	}
	for id := range oldO.blobByID {
		req, _ := http.NewRequest("GET", c.Host+"/api/artifacts/"+a.ID+"/versions/"+v1.ID+"/blobs/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+c.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("an old blob after the overwrite: %d, want 404", resp.StatusCode)
		}
	}
	if vs, _ := c.ListVersions(a.ID); len(vs) != 1 {
		t.Errorf("%d versions after an overwrite, want 1", len(vs))
	}
}

func TestPushRefusesATreeTheServerWouldRefuse(t *testing.T) {
	c := authedClient(t)
	a, err := c.CreateArtifact("site", "")
	if err != nil {
		t.Fatal(err)
	}
	rt := recordWrites(c, 0)

	noIndex := writeTree(t, map[string][]byte{"app.js": []byte("x")})
	nestedOnly := writeTree(t, map[string][]byte{"site/index.html": []byte("x")})
	linked := siteDir(t)
	if err := os.Symlink("index.html", filepath.Join(linked, "alias.html")); err != nil {
		t.Fatal(err)
	}
	backslash := siteDir(t)
	if err := os.WriteFile(filepath.Join(backslash, `a\b.txt`), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct{ dir, want string }{
		"no index.html":            {noIndex, "index.html"},
		"index.html only nested":   {nestedOnly, "index.html"},
		"a symlink":                {linked, "alias.html"},
		"a backslash in the name":  {backslash, "valid path"},
		"a directory that is gone": {filepath.Join(t.TempDir(), "gone"), "no such file"},
	}
	for name, tc := range cases {
		if _, err := c.Push(a.ID, "", tc.dir, "v1", ""); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Push = %v, want an error naming %q", name, err, tc.want)
		}
	}
	if len(rt.epochs) != 0 {
		t.Errorf("a refused tree sent %d version writes", len(rt.epochs))
	}
	if vs, _ := c.ListVersions(a.ID); len(vs) != 0 {
		t.Errorf("%d versions after refused trees", len(vs))
	}
}

// Only the owner and a listed editor push, and an editor's manifest is
// signed with the editor's key and sealed with the AK from the editor's own
// wrap.
func TestPushNeedsTheOwnerOrAnEditor(t *testing.T) {
	w := newSharing(t)
	rt := recordWrites(w.bob, 0)
	if _, err := w.bob.Push(w.artifact, "", siteDir(t), "v1", ""); err == nil {
		t.Fatal("a stranger's Push went through")
	}
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	rt.epochs = nil
	if _, err := w.bob.Push(w.artifact, "", siteDir(t), "v1", ""); !errors.Is(err, ErrCannotPush) {
		t.Errorf("a viewer's Push: %v, want ErrCannotPush", err)
	}
	if len(rt.epochs) != 0 {
		t.Errorf("a viewer's Push sent %d version writes, want none", len(rt.epochs))
	}

	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	v, err := w.bob.Push(w.artifact, "", writeTree(t, map[string][]byte{"index.html": []byte("from bob")}), "v1", "")
	if err != nil {
		t.Fatalf("an editor's Push: %v", err)
	}
	o := openPushed(t, w.bob, w.artifact, v.ID, 1)
	bob := mustUnlock(t, w.bob)
	var body e2e.ManifestBody
	if o.env.Signer != bob.UserID || e2e.OpenEnvelope(o.env, bob.Ed25519Pub, "manifest", &body) != nil {
		t.Errorf("the editor's manifest is not signed by the editor: signer %q", o.env.Signer)
	}
	if string(o.files["index.html"]) != "from bob" || v.PushedBy != bob.UserID {
		t.Errorf("the editor's push: %q, pushedBy %q", o.files["index.html"], v.PushedBy)
	}
	// The owner opens the editor's push with the AK of the estate copy.
	if got := openPushed(t, w.ada, w.artifact, v.ID, 1); string(got.files["index.html"]) != "from bob" {
		t.Errorf("the owner reads the editor's push as %q", got.files["index.html"])
	}
}

// After a new epoch a push is sealed under the new AK, and says so.
func TestPushUsesTheCurrentEpoch(t *testing.T) {
	w := newSharing(t)
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "viewer", false); err != nil { // demotion: epoch 2
		t.Fatal(err)
	}
	v, err := w.ada.Push(w.artifact, "", siteDir(t), "v1", "")
	if err != nil {
		t.Fatal(err)
	}
	if v.Epoch != 2 {
		t.Fatalf("pushed at epoch %d, want 2", v.Epoch)
	}
	if o := openPushed(t, w.ada, w.artifact, v.ID, 2); o.body.Epoch != 2 {
		t.Errorf("manifest epoch %d, want 2", o.body.Epoch)
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

// Only the epoch 409 is ErrEpochMoved: any other conflict keeps its message.
func TestPushKeepsAnotherConflict(t *testing.T) {
	c := authedClient(t)
	a, err := c.CreateArtifact("site", "")
	if err != nil {
		t.Fatal(err)
	}
	rt := recordWrites(c, http.StatusConflict)
	rt.body = "reference matches more than one artifact"
	_, err = c.Push(a.ID, "", siteDir(t), "v1", "")
	if errors.Is(err, ErrEpochMoved) || err == nil || !strings.Contains(err.Error(), rt.body) {
		t.Errorf("Push on another 409: %v, want the server's message", err)
	}
}

func TestPushReportsTheServersSizeLimit(t *testing.T) {
	c := authedClient(t)
	a, err := c.CreateArtifact("site", "")
	if err != nil {
		t.Fatal(err)
	}
	rt := recordWrites(c, http.StatusRequestEntityTooLarge)
	rt.body = "the push exceeds the maximum size of 1 MiB"
	_, err = c.Push(a.ID, "", siteDir(t), "v1", "")
	var apiErr *APIError
	if err == nil || !strings.Contains(err.Error(), "larger than the server's limit") ||
		!strings.Contains(err.Error(), "--max-upload-mb") || !errors.As(err, &apiErr) || apiErr.Status != 413 {
		t.Errorf("Push on a 413: %v, want the server's limit named, wrapping the 413", err)
	}
}

// The same over a real server with a 1 MiB cap: the server refuses the push
// before it has read it all, and the client must still report the 413.
func TestPushOverARealServersSizeLimit(t *testing.T) {
	host, m := newTestServer(t, func(c *server.Config) { c.MaxUploadMB = 1 })
	signupVerify(t, host, m, "ada@example.com", testPassword)
	out, err := New(host, "").Login("ada@example.com", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	c := keyedFor(t, host, out.APIKey)
	a, err := c.CreateArtifact("site", "")
	if err != nil {
		t.Fatal(err)
	}
	dir := siteDir(t)
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), bytes.Repeat([]byte{'a'}, 3<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = c.Push(a.ID, "", dir, "v1", "")
	var apiErr *APIError
	if err == nil || !strings.Contains(err.Error(), "larger than the server's limit") || !errors.As(err, &apiErr) || apiErr.Status != 413 {
		t.Errorf("Push of 3 MiB to a server capped at 1 MiB: %v, want the server's limit named, wrapping the 413", err)
	}
}

// json.Marshal would rewrite an invalid byte in the manifest while the blob
// is sealed under the name on disk, so the tree is refused.
func TestCheckUTF8Path(t *testing.T) {
	if err := checkUTF8Path("bad\xff.txt"); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("checkUTF8Path(invalid) = %v, want an error naming UTF-8", err)
	}
	if err := checkUTF8Path("café/index.html"); err != nil {
		t.Errorf("checkUTF8Path(valid) = %v", err)
	}
}

// checkRelPaths is what pushFiles asks about a tree's paths, so this reaches
// the UTF-8 check on every OS, which a real file named so cannot.
func TestCheckRelPaths(t *testing.T) {
	if err := checkRelPaths([]string{"index.html", "bad\xff.txt"}); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("checkRelPaths with a name that is not UTF-8 = %v, want an error naming UTF-8", err)
	}
	if err := checkRelPaths([]string{"index.html", `a\b.txt`}); err == nil || !strings.Contains(err.Error(), "not a valid path") {
		t.Errorf("checkRelPaths with a backslash = %v, want an invalid path", err)
	}
	if err := checkRelPaths([]string{"index.html", "../x"}); err == nil || !strings.Contains(err.Error(), "not a valid path") {
		t.Errorf("checkRelPaths with a path that climbs out = %v, want an invalid path", err)
	}
	if err := checkRelPaths([]string{"index.html", "café/a.js"}); err != nil {
		t.Errorf("checkRelPaths(valid) = %v", err)
	}
}

// macOS refuses to create such a file, so this one runs where the
// filesystem allows it.
func TestCheckTreeRefusesAnInvalidUTF8Name(t *testing.T) {
	dir := siteDir(t)
	if err := os.WriteFile(filepath.Join(dir, "bad\xff.txt"), []byte("x"), 0o644); err != nil {
		t.Skipf("this filesystem refuses a name that is not UTF-8: %v", err)
	}
	if err := CheckTree(dir); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("CheckTree = %v, want an error naming UTF-8", err)
	}
}
