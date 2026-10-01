package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func (c *testClient) doRaw(method, path string, body []byte) *http.Response {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp
}

func TestFilesAPIOverHTTP(t *testing.T) {
	s, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")

	// Public artifact with one version
	aid := createArtifact(t, admin, "demo", true)
	resp := admin.upload("POST", "/api/artifacts/"+aid+"/versions", zipFrom(t, map[string]string{"index.html": "x"}), nil)
	v := decode[struct {
		ID string `json:"id"`
	}](t, resp)
	base := fmt.Sprintf("/api/artifacts/%s/versions/%s/files", aid, v.ID)

	// A never-written version lists as empty
	var list []fileInfo
	admin.mustDo("GET", base, nil, &list, http.StatusOK)
	if len(list) != 0 {
		t.Errorf("initial list: %+v", list)
	}

	// Authenticated upload, including a nested path
	r := admin.doRaw("PUT", base+"/notes/hello.txt", []byte("hello file"))
	up := decode[fileInfo](t, r)
	if r.StatusCode != http.StatusOK || up.Path != "notes/hello.txt" || up.Size != 10 {
		t.Fatalf("upload: %d %+v", r.StatusCode, up)
	}
	admin.doRaw("PUT", base+"/data.json", []byte(`{"a":1}`)).Body.Close()

	admin.mustDo("GET", base, nil, &list, http.StatusOK)
	if len(list) != 2 || list[0].Path != "data.json" || list[1].Path != "notes/hello.txt" {
		t.Errorf("list: %+v", list)
	}

	// Anonymous download works on a public artifact, with a derived type
	anon := &testClient{t: t, base: ts.URL}
	dl := anon.doRaw("GET", base+"/notes/hello.txt", nil)
	body, _ := io.ReadAll(dl.Body)
	dl.Body.Close()
	if dl.StatusCode != http.StatusOK || string(body) != "hello file" {
		t.Errorf("anon download: %d %q", dl.StatusCode, body)
	}
	if ct := dl.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content type: %q", ct)
	}

	// Anonymous writes are rejected. Request protection refuses the upload,
	// which declares no Content-Type, before the handler runs (415); the
	// bodiless DELETE passes protection and the handler refuses it (401).
	if r := anon.doRaw("PUT", base+"/evil.txt", []byte("x")); r.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("anon upload: %d", r.StatusCode)
	}
	if r := anon.doRaw("DELETE", base+"/notes/hello.txt", nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("anon delete: %d", r.StatusCode)
	}

	// Overwrite replaces content
	admin.doRaw("PUT", base+"/notes/hello.txt", []byte("v2")).Body.Close()
	dl = admin.doRaw("GET", base+"/notes/hello.txt", nil)
	body, _ = io.ReadAll(dl.Body)
	dl.Body.Close()
	if string(body) != "v2" {
		t.Errorf("overwrite: %q", body)
	}

	// Percent-encoded traversal is rejected (literal ".." never reaches the
	// handler: the mux redirects it away)
	if r := admin.doRaw("PUT", base+"/%2e%2e/escape.txt", []byte("x")); r.StatusCode != http.StatusBadRequest {
		t.Errorf("traversal upload: %d", r.StatusCode)
	}
	if r := anon.doRaw("GET", base+"/%2e%2e%2f%2e%2e/secret", nil); r.StatusCode != http.StatusBadRequest {
		t.Errorf("traversal download: %d", r.StatusCode)
	}

	// A file path cannot be extended as a directory
	if r := admin.doRaw("PUT", base+"/data.json/child.txt", []byte("x")); r.StatusCode != http.StatusConflict {
		t.Errorf("file-as-dir upload: %d", r.StatusCode)
	}

	// Missing files are 404s
	if r := anon.doRaw("GET", base+"/nope.txt", nil); r.StatusCode != http.StatusNotFound {
		t.Errorf("missing download: %d", r.StatusCode)
	}
	if r := admin.doRaw("DELETE", base+"/nope.txt", nil); r.StatusCode != http.StatusNotFound {
		t.Errorf("missing delete: %d", r.StatusCode)
	}

	// Delete removes the file (and its now-empty parent dir on disk)
	if r := admin.doRaw("DELETE", base+"/notes/hello.txt", nil); r.StatusCode != http.StatusOK {
		t.Errorf("delete: %d", r.StatusCode)
	}
	if r := anon.doRaw("GET", base+"/notes/hello.txt", nil); r.StatusCode != http.StatusNotFound {
		t.Errorf("deleted still served: %d", r.StatusCode)
	}
	admin.mustDo("GET", base, nil, &list, http.StatusOK)
	if len(list) != 1 || list[0].Path != "data.json" {
		t.Errorf("list after delete: %+v", list)
	}

	// Private artifact: anonymous reads are rejected
	pid := createArtifact(t, admin, "private-demo", false)
	resp = admin.upload("POST", "/api/artifacts/"+pid+"/versions", zipFrom(t, map[string]string{"index.html": "x"}), nil)
	pv := decode[struct {
		ID string `json:"id"`
	}](t, resp)
	pbase := fmt.Sprintf("/api/artifacts/%s/versions/%s/files", pid, pv.ID)
	admin.doRaw("PUT", pbase+"/secret.txt", []byte("s")).Body.Close()
	if r := anon.doRaw("GET", pbase+"/secret.txt", nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("private anon download: %d", r.StatusCode)
	}
	if r := anon.doRaw("GET", pbase, nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("private anon list: %d", r.StatusCode)
	}

	// Deleting the version removes its file storage from disk
	filesDir := s.layout.VersionFilesDir(aid, v.ID)
	if _, err := os.Stat(filesDir); err != nil {
		t.Fatalf("files dir missing before version delete: %v", err)
	}
	admin.mustDo("DELETE", "/api/artifacts/"+aid+"/versions/"+v.ID, nil, nil, http.StatusOK)
	if _, err := os.Stat(filesDir); !os.IsNotExist(err) {
		t.Errorf("files dir survived version delete: %v", err)
	}
}
