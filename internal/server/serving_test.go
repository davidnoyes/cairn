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
	resp := admin.upload("POST", "/api/artifacts/"+aid+"/versions", zipFrom(t, map[string]string{
		"index.html":     "<h1>hello v1</h1><script src=\"./cairn.js\"></script>",
		"app.js":         "console.log('app')",
		"sub/index.html": "<h1>sub page</h1>",
	}), map[string]string{"name": "v1"})
	v := decode[struct {
		ID string `json:"id"`
	}](t, resp)
	return admin, aid, v.ID, link
}

func TestMermaidJS(t *testing.T) {
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

func TestPrivateGating(t *testing.T) {
	_, ts := testServer(t)
	admin, aid, vid, _ := setupArtifact(t, ts.URL, false)

	// Anonymous browser navigation → login redirect with next
	for _, p := range []string{"/shared/" + aid, "/shared/" + aid + "/" + vid, "/shared/" + aid + "/" + vid + "/x"} {
		resp := get(t, ts.URL+p, "", "text/html")
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("private shell %s: %d", p, resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login?next=") {
			t.Errorf("login redirect: %s", loc)
		}
		resp.Body.Close()
	}

	// Authenticated (bearer) works
	resp := get(t, ts.URL+"/shared/"+aid+"/"+vid, admin.token, "text/html")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("authed shell: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSharedShell(t *testing.T) {
	_, ts := testServer(t)
	admin, aid, vid, link := setupArtifact(t, ts.URL, true)
	// Second version so the picker has two entries
	resp := admin.upload("POST", "/api/artifacts/"+aid+"/versions", zipFrom(t, map[string]string{
		"index.html": "<h1>v2</h1>",
	}), map[string]string{"name": "v2", "changelog": "second"})
	v2 := decode[struct {
		ID string `json:"id"`
	}](t, resp)

	// Latest by default
	resp = getLinked(t, link, ts.URL+"/shared/"+aid, "", "text/html")
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
	if !strings.Contains(body(t, get(t, ts.URL+"/shell.js", "", "")), "pre.mermaid, code.language-mermaid, code.mermaid") {
		t.Errorf("shell.js missing auto-render Mermaid hook")
	}

	// Pinned version
	resp = getLinked(t, link, ts.URL+"/shared/"+aid+"/"+vid, "", "text/html")
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

func TestShellJS(t *testing.T) {
	_, ts := testServer(t)
	_, aid, _, link := setupArtifact(t, ts.URL, true)

	// /shell.js is served with a JS content type
	resp := get(t, ts.URL+"/shell.js", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("shell.js: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("shell.js content-type: %s", ct)
	}
	if !strings.Contains(body(t, resp), "linkAction") {
		t.Errorf("shell.js missing linkAction")
	}

	// The shared shell page loads it
	resp = getLinked(t, link, ts.URL+"/shared/"+aid, "", "text/html")
	if !strings.Contains(body(t, resp), "/shell.js") {
		t.Errorf("shell page should reference /shell.js")
	}
}

// Cairn's own pages change the page rather than opening tabs, so closing a
// tab never strands the viewer; the shell header links back home.
func TestPagesStayInOneTab(t *testing.T) {
	_, ts := testServer(t)
	admin, aid, vid, link := setupArtifact(t, ts.URL, true)

	// Signed out, the mark signs in and comes back, like the sign-in button.
	shell := body(t, getLinked(t, link, ts.URL+"/shared/"+aid, "", "text/html"))
	if want := `<a class="mark" href="/login?next=/shared/` + aid + `/` + vid + `"`; !strings.Contains(shell, want) {
		t.Errorf("signed-out mark should sign in and return: want %s", want)
	}
	signedIn := body(t, getLinked(t, link, ts.URL+"/shared/"+aid, admin.token, "text/html"))
	if !strings.Contains(signedIn, `<a class="mark" href="/"`) {
		t.Errorf("signed-in mark should link home")
	}
	adminResp := get(t, ts.URL+"/admin", admin.token, "text/html")
	if adminResp.StatusCode != http.StatusOK {
		t.Fatalf("admin page: %d", adminResp.StatusCode)
	}
	adminHTML := body(t, adminResp)
	// The admin page builds its version links in JS, so check the source:
	// a version opens in the shell, which has the home link, not full screen.
	adminJS := body(t, get(t, ts.URL+"/admin.js", "", ""))
	if !strings.Contains(adminJS, "open.href = '/shared/' + artifact.id + '/' + v.id;") {
		t.Errorf("admin version links should open the shared view")
	}
	for page, html := range map[string]string{
		"shell":    shell,
		"admin":    adminHTML,
		"admin.js": adminJS,
	} {
		if strings.Contains(html, "_blank") {
			t.Errorf("%s page opens a new tab", page)
		}
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
