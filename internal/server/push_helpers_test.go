package server

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"sort"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/google/uuid"
)

// A push as the multipart request carries it. The server cannot read any of
// it, so newPush builds a well-formed body with real blobs and a real signed
// manifest, and a test breaks one field to see the server refuse it.

type pushBlob struct {
	ID   string
	Data []byte
	// Encoding, when set, is sent as the part's Content-Transfer-Encoding.
	Encoding string
}

type extraPart struct {
	Name, Filename string
	Data           []byte
}

type pushParts struct {
	// Version is the JSON of the "version" part, unless VersionRaw is set.
	Version    map[string]any
	VersionRaw []byte
	Manifest   []byte
	Blobs      []pushBlob
	Extra      []extraPart
	// ManifestHash is hex(SHA-256) of the manifest envelope's body.
	ManifestHash string
}

// pushSeed signs every manifest newPush builds.
var pushSeed = bytes.Repeat([]byte{7}, 32)

// newPush seals files (path to content) under testAK(aid, epoch) as version
// vid, and signs and seals their manifest. An empty vid is a fresh UUID.
func newPush(t *testing.T, aid, vid string, epoch int, files map[string]string) *pushParts {
	t.Helper()
	if vid == "" {
		vid = uuid.NewString()
	}
	ak := testAK(aid, epoch)
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	p := &pushParts{}
	manifest := e2e.ManifestBody{V: 1, Artifact: aid, Version: vid, Epoch: epoch, Files: []e2e.ManifestFile{}}
	for _, path := range paths {
		blob, err := e2e.SealBlob(rand.Reader, ak, e2e.BlobContext{Artifact: aid, Version: vid, Kind: "content", Name: path}, []byte(files[path]))
		if err != nil {
			t.Fatal(err)
		}
		id := randomBlobID(t)
		p.Blobs = append(p.Blobs, pushBlob{ID: id, Data: blob})
		manifest.Files = append(manifest.Files, e2e.ManifestFile{Path: path, Blob: id, Size: int64(len(files[path])), SHA256: e2e.BodyHash(blob)})
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(pushSeed, "signer", "manifest", body)
	if err != nil {
		t.Fatal(err)
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	p.Manifest, err = e2e.SealBlob(rand.Reader, ak, e2e.BlobContext{Artifact: aid, Version: vid, Kind: "manifest"}, envJSON)
	if err != nil {
		t.Fatal(err)
	}
	p.ManifestHash = e2e.BodyHash(body)
	p.Version = map[string]any{"id": vid, "epoch": epoch, "manifestHash": p.ManifestHash}
	return p
}

func randomBlobID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b)
}

// body serializes p as a multipart request body.
func (p *pushParts) body(t *testing.T) (contentType string, body []byte) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part := func(name, filename string, data []byte, encoding string) {
		h := textproto.MIMEHeader{}
		disp := fmt.Sprintf(`form-data; name=%q`, name)
		if filename != "" {
			disp += fmt.Sprintf(`; filename=%q`, filename)
		}
		h.Set("Content-Disposition", disp)
		if encoding != "" {
			h.Set("Content-Transfer-Encoding", encoding)
		}
		w, err := mw.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(data)
	}
	raw := p.VersionRaw
	if raw == nil && p.Version != nil {
		var err error
		if raw, err = json.Marshal(p.Version); err != nil {
			t.Fatal(err)
		}
	}
	if raw != nil {
		part("version", "", raw, "")
	}
	if p.Manifest != nil {
		part("manifest", "manifest", p.Manifest, "")
	}
	for _, b := range p.Blobs {
		part("blob", b.ID, b.Data, b.Encoding)
	}
	for _, e := range p.Extra {
		part(e.Name, e.Filename, e.Data, "")
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return mw.FormDataContentType(), buf.Bytes()
}

// send issues p as method on path.
func (c *testClient) send(method, path string, p *pushParts) *http.Response {
	c.t.Helper()
	ct, body := p.body(c.t)
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", ct)
	c.setHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp
}

// currentEpoch is the epoch of artifact aid as c reads it, or 1 when c
// cannot read it.
func (c *testClient) currentEpoch(aid string) int {
	c.t.Helper()
	var a struct {
		Epoch int `json:"epoch"`
	}
	if resp := c.do("GET", "/api/artifacts/"+aid, nil, &a); resp.StatusCode != http.StatusOK || a.Epoch == 0 {
		return 1
	}
	return a.Epoch
}

// pushFiles pushes files at the artifact's current epoch: a new version for
// POST, or as vid for PUT.
func (c *testClient) pushFiles(method, aid, vid string, files map[string]string) *http.Response {
	c.t.Helper()
	path := "/api/artifacts/" + aid + "/versions"
	if method == "PUT" {
		path += "/" + vid
	}
	return c.send(method, path, newPush(c.t, aid, vid, c.currentEpoch(aid), files))
}

// upload pushes files as c would, at the artifact's current epoch: a new
// version for POST, or the version in the path for PUT.
func (c *testClient) upload(method, path string, files map[string]string) *http.Response {
	c.t.Helper()
	rest := strings.TrimPrefix(path, "/api/artifacts/")
	aid, tail, _ := strings.Cut(rest, "/versions")
	vid := strings.TrimPrefix(tail, "/")
	p := newPush(c.t, aid, vid, c.currentEpoch(aid), files)
	return c.send(method, path, p)
}

// pushPlain is the one-file push most tests need, at the artifact's current
// epoch, as a new version.
func (c *testClient) pushPlain(aid string) *http.Response {
	c.t.Helper()
	return c.pushFiles("POST", aid, "", map[string]string{"index.html": "x"})
}
