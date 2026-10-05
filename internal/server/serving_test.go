package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// noRedirectClient returns a client that surfaces redirects instead of
// following them.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func get(t *testing.T, url, token, accept string) *http.Response {
	t.Helper()
	return getLinked(t, "", url, token, accept)
}

// getLinked is get that also sends link, when set, as X-Cairn-Link-Token.
func getLinked(t *testing.T, link, url, token, accept string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if link != "" {
		req.Header.Set("X-Cairn-Link-Token", link)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// setupArtifact creates an artifact with one version as the admin. When
// public, link is the token that opens it; otherwise it is empty.
func setupArtifact(t *testing.T, ts string, public bool) (admin *testClient, aid, vid, link string) {
	admin = login(t, ts, "admin@example.com", "admin-password")
	if public {
		aid, link = createPublicArtifact(t, admin, "site")
	} else {
		aid = createArtifact(t, admin, "site")
	}
	resp := admin.upload("POST", "/api/artifacts/"+aid+"/versions", map[string]string{
		"index.html":     "<h1>hello v1</h1><script src=\"./cairn.js\"></script>",
		"app.js":         "console.log('app')",
		"sub/index.html": "<h1>sub page</h1>",
	})
	v := decode[struct {
		ID string `json:"id"`
	}](t, resp)
	return admin, aid, v.ID, link
}

func TestMermaidJS(t *testing.T) {
	t.Skip("the server stores ciphertext, so the app origin has no files to serve; the app-origin file serving and its tests go in the content-origin change")
	_, ts := testServer(t)

	// Global route
	resp := get(t, ts.URL+"/mermaid.js", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("global mermaid.js: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("mermaid.js content-type: %s", ct)
	}
	if !strings.Contains(body(t, resp), "mermaid-boot.js — auto-render bootstrap") {
		t.Errorf("mermaid.js missing bootstrap marker")
	}
}

// TestSqlJSVendored checks the bundled sql.js is served at the app origin, so
// no page needs a CDN to load it. The content origin serves it under /_cairn/.
func TestSqlJSVendored(t *testing.T) {
	_, ts := testServer(t)
	for name, want := range map[string]string{"sql-wasm.js": "javascript", "sql-wasm.wasm": "application/wasm"} {
		resp := get(t, ts.URL+"/"+name, "", "")
		b := body(t, resp)
		if resp.StatusCode != http.StatusOK || len(b) < 1000 {
			t.Errorf("%s: status %d, %d bytes", name, resp.StatusCode, len(b))
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, want) {
			t.Errorf("%s: content-type %q, want %q", name, ct, want)
		}
	}
}

// TestArgon2WasmVendored checks the bundled Argon2id WebAssembly module and
// its Go runtime glue are served at the app origin. Unlike sql.js, these are
// not available inside a version's URL space.
func TestArgon2WasmVendored(t *testing.T) {
	_, ts := testServer(t)
	for name, want := range map[string]string{"argon2.wasm": "application/wasm", "wasm_exec.js": "javascript"} {
		resp := get(t, ts.URL+"/"+name, "", "")
		b := body(t, resp)
		if resp.StatusCode != http.StatusOK || len(b) < 1000 {
			t.Errorf("%s: status %d, %d bytes", name, resp.StatusCode, len(b))
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, want) {
			t.Errorf("%s: content-type %q, want %q", name, ct, want)
		}
	}
}
