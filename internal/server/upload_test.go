package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"testing"
)

// zipFrom builds an in-memory zip from name->content pairs.
func zipFrom(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func (c *testClient) upload(method, path string, archive []byte, fields map[string]string) *http.Response {
	c.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("archive", "a.zip")
	fw.Write(archive)
	mw.Close()
	req, _ := http.NewRequest(method, c.base+path, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func createArtifact(t *testing.T, c *testClient, name string, public bool) string {
	t.Helper()
	var a struct {
		ID string `json:"id"`
	}
	c.mustDo("POST", "/api/artifacts", map[string]any{"name": name, "public": public}, &a, http.StatusCreated)
	return a.ID
}

func TestUploadAndReplace(t *testing.T) {
	_, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	aid := createArtifact(t, admin, "demo", false)

	// Upload v1
	resp := admin.upload("POST", "/api/artifacts/"+aid+"/versions", zipFrom(t, map[string]string{
		"index.html": "<h1>v1</h1>",
		"app.js":     "console.log(1)",
	}), map[string]string{"name": "v1", "changelog": "initial"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %d", resp.StatusCode)
	}
	v := decode[struct {
		ID  string `json:"id"`
		Seq int    `json:"seq"`
	}](t, resp)
	if v.Seq != 1 {
		t.Errorf("seq: %d", v.Seq)
	}

	// Zip wrapped in a single top-level folder works too
	resp = admin.upload("POST", "/api/artifacts/"+aid+"/versions", zipFrom(t, map[string]string{
		"myapp/index.html": "<h1>v2</h1>",
		"myapp/style.css":  "body{}",
	}), nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("wrapped upload: %d", resp.StatusCode)
	}
	v2 := decode[struct {
		ID  string `json:"id"`
		Seq int    `json:"seq"`
	}](t, resp)
	if v2.Seq != 2 {
		t.Errorf("seq: %d", v2.Seq)
	}

	// Replace v2 content
	resp = admin.upload("PUT", "/api/artifacts/"+aid+"/versions/"+v2.ID, zipFrom(t, map[string]string{
		"index.html": "<h1>v2 fixed</h1>",
	}), map[string]string{"changelog": "fixed"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("replace: %d", resp.StatusCode)
	}

	// Anonymous cannot upload. The multipart body is neither JSON nor octet-stream, so
	// request protection refuses it (415) before the handler's own auth check
	// would (401) — still a rejection either way.
	anon := &testClient{t: t, base: ts.URL}
	resp = anon.upload("POST", "/api/artifacts/"+aid+"/versions", zipFrom(t, map[string]string{"index.html": "x"}), nil)
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("anonymous upload: %d", resp.StatusCode)
	}
}

func TestUploadRejections(t *testing.T) {
	_, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	aid := createArtifact(t, admin, "demo", false)
	base := "/api/artifacts/" + aid + "/versions"

	cases := []struct {
		name  string
		files map[string]string
	}{
		{"no index.html", map[string]string{"app.js": "x"}},
		{"zip slip", map[string]string{"index.html": "x", "../evil.txt": "pwn"}},
		{"absolute path", map[string]string{"index.html": "x", "/etc/passwd": "pwn"}},
	}
	for _, tc := range cases {
		resp := admin.upload("POST", base, zipFrom(t, tc.files), nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", tc.name, resp.StatusCode)
		}
		resp.Body.Close()
	}
	// Not a zip at all
	resp := admin.upload("POST", base, []byte("plain text"), nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("not-a-zip: %d", resp.StatusCode)
	}
	resp.Body.Close()
	// No stray versions were created
	var versions []any
	admin.mustDo("GET", base, nil, &versions, http.StatusOK)
	if len(versions) != 0 {
		t.Errorf("stray versions: %d", len(versions))
	}
}

func TestDBAPIOverHTTP(t *testing.T) {
	_, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")

	// Public artifact with one version
	aid := createArtifact(t, admin, "demo", true)
	resp := admin.upload("POST", "/api/artifacts/"+aid+"/versions", zipFrom(t, map[string]string{"index.html": "x"}), nil)
	v := decode[struct {
		ID string `json:"id"`
	}](t, resp)
	dbPath := fmt.Sprintf("/api/artifacts/%s/versions/%s/db", aid, v.ID)

	// Authenticated batch creates schema and data atomically
	admin.mustDo("POST", dbPath+"/batch", map[string]any{"statements": []map[string]any{
		{"sql": "CREATE TABLE votes (item TEXT PRIMARY KEY, count INTEGER)"},
		{"sql": "INSERT INTO votes VALUES (?, ?)", "params": []any{"go", 1}},
	}}, nil, http.StatusOK)

	// Anonymous read works on a public artifact
	anon := &testClient{t: t, base: ts.URL}
	var res struct {
		Rows [][]any `json:"rows"`
	}
	anon.mustDo("POST", dbPath+"/query", map[string]any{"sql": "SELECT item, count FROM votes"}, &res, http.StatusOK)
	if len(res.Rows) != 1 || res.Rows[0][0] != "go" {
		t.Errorf("anon read: %+v", res.Rows)
	}

	// Anonymous write is rejected by the query_only connection
	r := anon.do("POST", dbPath+"/query", map[string]any{"sql": "UPDATE votes SET count = 99"}, nil)
	if r.StatusCode != http.StatusBadRequest {
		t.Errorf("anon write: %d", r.StatusCode)
	}
	anon.mustDo("POST", dbPath+"/query", map[string]any{"sql": "SELECT count FROM votes"}, &res, http.StatusOK)
	if fmt.Sprint(res.Rows[0][0]) != "1" {
		t.Errorf("anon write went through: %+v", res.Rows)
	}

	// Multi-statement rejected
	r = admin.do("POST", dbPath+"/query", map[string]any{"sql": "SELECT 1; DROP TABLE votes"}, nil)
	if r.StatusCode != http.StatusBadRequest {
		t.Errorf("multi-statement: %d", r.StatusCode)
	}

	// Private artifact: anonymous read is rejected
	pid := createArtifact(t, admin, "private-demo", false)
	resp = admin.upload("POST", "/api/artifacts/"+pid+"/versions", zipFrom(t, map[string]string{"index.html": "x"}), nil)
	pv := decode[struct {
		ID string `json:"id"`
	}](t, resp)
	r = anon.do("POST", fmt.Sprintf("/api/artifacts/%s/versions/%s/db/query", pid, pv.ID), map[string]any{"sql": "SELECT 1"}, nil)
	if r.StatusCode != http.StatusUnauthorized {
		t.Errorf("private anon query: %d", r.StatusCode)
	}

	// Download
	req, _ := http.NewRequest("GET", ts.URL+dbPath+"/download", nil)
	req.Header.Set("Authorization", "Bearer "+admin.token)
	dl, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer dl.Body.Close()
	if dl.StatusCode != http.StatusOK {
		t.Errorf("download: %d", dl.StatusCode)
	}
	head := make([]byte, 16)
	dl.Body.Read(head)
	if !bytes.HasPrefix(head, []byte("SQLite format 3")) {
		t.Errorf("download not a sqlite file: %q", head)
	}
}
