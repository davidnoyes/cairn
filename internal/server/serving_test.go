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
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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

func setupArtifact(t *testing.T, ts string, public bool) (admin *testClient, aid, vid string) {
	admin = login(t, ts, "admin@example.com", "admin-password")
	aid = createArtifact(t, admin, "site", public)
	resp := admin.upload("POST", "/api/artifacts/"+aid+"/versions", zipFrom(t, map[string]string{
		"index.html":     "<h1>hello v1</h1><script src=\"./cairn.js\"></script>",
		"app.js":         "console.log('app')",
		"sub/index.html": "<h1>sub page</h1>",
	}), map[string]string{"name": "v1"})
	v := decode[struct {
		ID string `json:"id"`
	}](t, resp)
	return admin, aid, v.ID
}

func TestServingRedirectsAndFiles(t *testing.T) {
	_, ts := testServer(t)
	_, aid, vid := setupArtifact(t, ts.URL, true)

	// /artifacts/{id} → latest version canonical URL
	resp := get(t, ts.URL+"/artifacts/"+aid, "", "text/html")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("artifact redirect: %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "/artifacts/"+aid+"/"+vid+"/" {
		t.Errorf("redirect location: %s", loc)
	}

	// Missing trailing slash canonicalized
	resp = get(t, ts.URL+"/artifacts/"+aid+"/"+vid, "", "text/html")
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("no-slash: %d", resp.StatusCode)
	}

	// Index and assets
	resp = get(t, ts.URL+"/artifacts/"+aid+"/"+vid+"/", "", "text/html")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body(t, resp), "hello v1") {
		t.Errorf("index: %d", resp.StatusCode)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors") {
		t.Errorf("missing CSP: %q", csp)
	}
	resp = get(t, ts.URL+"/artifacts/"+aid+"/"+vid+"/app.js", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("asset: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("asset content-type: %s", ct)
	}
	resp.Body.Close()

	// Subdirectory index
	resp = get(t, ts.URL+"/artifacts/"+aid+"/"+vid+"/sub/", "", "text/html")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body(t, resp), "sub page") {
		t.Errorf("subdir index failed")
	}

	// SPA fallback: extension-less HTML navigation gets index.html...
	resp = get(t, ts.URL+"/artifacts/"+aid+"/"+vid+"/some/route", "", "text/html")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body(t, resp), "hello v1") {
		t.Errorf("spa fallback failed")
	}
	// ...but a missing asset really 404s
	resp = get(t, ts.URL+"/artifacts/"+aid+"/"+vid+"/missing.js", "", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing asset: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// cairn.js is injected into the version URL space
	resp = get(t, ts.URL+"/artifacts/"+aid+"/"+vid+"/cairn.js", "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body(t, resp), "cairn.js — client library") {
		t.Errorf("injected cairn.js failed")
	}

	// Path traversal attempts
	for _, p := range []string{"/artifacts/" + aid + "/" + vid + "/../../secret", "/artifacts/" + aid + "/" + vid + "/%2e%2e/%2e%2e/cairn.db"} {
		resp = get(t, ts.URL+p, "", "")
		if resp.StatusCode == http.StatusOK {
			t.Errorf("traversal %s returned 200", p)
		}
		resp.Body.Close()
	}
}

func TestMermaidJS(t *testing.T) {
	_, ts := testServer(t)
	_, aid, vid := setupArtifact(t, ts.URL, true)

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

	// Injected into a version's URL space when the artifact has no mermaid.js
	resp = get(t, ts.URL+"/artifacts/"+aid+"/"+vid+"/mermaid.js", "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body(t, resp), "mermaid-boot.js — auto-render bootstrap") {
		t.Errorf("injected mermaid.js failed")
	}

	// An artifact's own mermaid.js wins
	resp = get(t, ts.URL+"/artifacts/"+aid+"/"+vid+"/app.js", "", "")
	resp.Body.Close()
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	resp = admin.upload("POST", "/api/artifacts/"+aid+"/versions", zipFrom(t, map[string]string{
		"index.html": "<h1>v2</h1>",
		"mermaid.js": "console.log('custom mermaid')",
	}), map[string]string{"name": "v2"})
	v2 := decode[struct {
		ID string `json:"id"`
	}](t, resp)
	resp = get(t, ts.URL+"/artifacts/"+aid+"/"+v2.ID+"/mermaid.js", "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body(t, resp), "custom mermaid") {
		t.Errorf("artifact-provided mermaid.js should win")
	}
}

func TestPrivateGating(t *testing.T) {
	_, ts := testServer(t)
	admin, aid, vid := setupArtifact(t, ts.URL, false)

	// Anonymous browser navigation → login redirect with next
	resp := get(t, ts.URL+"/artifacts/"+aid+"/"+vid+"/", "", "text/html")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("private page: %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login?next=") {
		t.Errorf("login redirect: %s", loc)
	}

	// Authenticated (bearer) works
	resp = get(t, ts.URL+"/artifacts/"+aid+"/"+vid+"/", admin.token, "text/html")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("authed page: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Shared shell also gated
	resp = get(t, ts.URL+"/shared/"+aid, "", "text/html")
	if resp.StatusCode != http.StatusFound {
		t.Errorf("private shell: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSharedShell(t *testing.T) {
	_, ts := testServer(t)
	admin, aid, vid := setupArtifact(t, ts.URL, true)
	// Second version so the picker has two entries
	resp := admin.upload("POST", "/api/artifacts/"+aid+"/versions", zipFrom(t, map[string]string{
		"index.html": "<h1>v2</h1>",
	}), map[string]string{"name": "v2", "changelog": "second"})
	v2 := decode[struct {
		ID string `json:"id"`
	}](t, resp)

	// Latest by default
	resp = get(t, ts.URL+"/shared/"+aid, "", "text/html")
	html := body(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("shell: %d", resp.StatusCode)
	}
	if !strings.Contains(html, "/artifacts/"+aid+"/"+v2.ID+"/") {
		t.Errorf("shell iframe should embed latest version")
	}
	if !strings.Contains(html, "site") {
		t.Errorf("shell missing artifact name")
	}
	if !strings.Contains(html, "pre.mermaid, code.language-mermaid, code.mermaid") {
		t.Errorf("shell missing auto-render Mermaid hook")
	}

	// Pinned version
	resp = get(t, ts.URL+"/shared/"+aid+"/"+vid, "", "text/html")
	html = body(t, resp)
	if !strings.Contains(html, "/artifacts/"+aid+"/"+vid+"/") {
		t.Errorf("pinned shell should embed version %s", vid)
	}

	// Login page renders
	resp = get(t, ts.URL+"/login", "", "text/html")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body(t, resp), "Cairn") {
		t.Errorf("login page failed")
	}
}
