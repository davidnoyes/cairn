package server

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// The shell page carries no artifact data and checks no access: the content
// origin and the API enforce access, so the page is the same to everyone.
func TestShellPageChecksNoAccess(t *testing.T) {
	_, ts := testServer(t)
	_, aid, vid, _ := setupArtifact(t, ts.URL, false)

	for _, p := range []string{
		"/shared/" + aid, "/shared/" + aid + "/" + vid, "/shared/" + aid + "/" + vid + "/x",
		"/full/" + aid, "/full/" + aid + "/" + vid, "/full/" + aid + "/" + vid + "/x",
	} {
		resp := get(t, ts.URL+p, "", "text/html")
		html := body(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("anonymous GET %s on a private artifact: %d, want 200", p, resp.StatusCode)
		}
		for _, leak := range []string{"site", "hello", "v1"} {
			if strings.Contains(html, leak) {
				t.Errorf("GET %s carries artifact data %q", p, leak)
			}
		}
	}
}

func TestShellPageBody(t *testing.T) {
	w := newHostWorld(t)
	id, vid := w.art.id, w.vid
	origin := "http://" + id + ".localhost:" + w.port

	for _, tc := range []struct{ path, attrs string }{
		{"/shared/" + id, `data-artifact="` + id + `" data-version="" data-path="/" data-mode="shared"`},
		{"/shared/" + id + "/" + vid, `data-artifact="` + id + `" data-version="` + vid + `" data-path="/" data-mode="shared"`},
		{"/shared/" + id + "/" + vid + "/", `data-artifact="` + id + `" data-version="` + vid + `" data-path="/" data-mode="shared"`},
		{"/shared/" + id + "/" + vid + "/a%20b/c.html", `data-artifact="` + id + `" data-version="` + vid + `" data-path="/a%20b/c.html" data-mode="shared"`},
		{"/full/" + id, `data-artifact="` + id + `" data-version="" data-path="/" data-mode="full"`},
		{"/full/" + id + "/" + vid, `data-artifact="` + id + `" data-version="` + vid + `" data-path="/" data-mode="full"`},
		{"/full/" + id + "/" + vid + "/sub/x", `data-artifact="` + id + `" data-version="` + vid + `" data-path="/sub/x" data-mode="full"`},
		{"/full/" + id + "/" + vid + "/sub/", `data-artifact="` + id + `" data-version="` + vid + `" data-path="/sub/" data-mode="full"`},
		{"/shared/" + id + "/" + vid + "/a..b/.x", `data-artifact="` + id + `" data-version="` + vid + `" data-path="/a..b/.x" data-mode="shared"`},
	} {
		resp := get(t, w.base+tc.path, "", "text/html")
		html := body(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d", tc.path, resp.StatusCode)
		}
		want := "<body " + tc.attrs + ` data-content-origin="` + origin + `">`
		if !strings.Contains(html, want) {
			t.Errorf("GET %s: body element is not %s\n%s", tc.path, want, html)
		}
	}
}

func TestShellPageElements(t *testing.T) {
	w := newHostWorld(t)
	id := w.art.id
	html := body(t, get(t, w.base+"/shared/"+id, "", "text/html"))
	for _, want := range []string{
		`<h1 id="name"`, `<p id="desc"`, `<select id="version"`, `<a id="fullscreen"`,
		`<p id="status" role="status" hidden>`, `<div id="frame-host"`,
		`<a id="account" href="/login?next=/shared/` + id + `">sign in</a>`,
		`href="/shell.css"`, `<script type="module" src="/shell.mjs"></script>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the page lacks %s", want)
		}
	}
	// Nothing the CSP would block, and no third-party font.
	for _, bad := range []string{"<iframe", "fonts.googleapis.com", "fonts.gstatic.com", "<style", " style=", " onchange=", " onclick=", "/shell.js"} {
		if strings.Contains(html, bad) {
			t.Errorf("the page contains %q", bad)
		}
	}
	if strings.Count(html, "<script") != 1 {
		t.Errorf("the page has %d script elements, want the one module", strings.Count(html, "<script"))
	}

	signedIn := body(t, get(t, w.base+"/shared/"+id, w.owner.token, "text/html"))
	if !strings.Contains(signedIn, `<a id="account" href="/">`) || strings.Contains(signedIn, "sign in") {
		t.Errorf("a signed-in page should link the account to /:\n%s", signedIn)
	}
}

func TestShellPageValidatesIDs(t *testing.T) {
	w := newHostWorld(t)
	id, vid := w.art.id, w.vid
	for _, p := range []string{
		"/shared/not-a-uuid", "/full/not-a-uuid",
		"/shared/" + id + "/not-a-uuid", "/full/" + id + "/not-a-uuid",
		"/shared/" + id + "/not-a-uuid/x",
		"/shared/" + id + "/zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", // the right length, no UUID
		"/shared/" + id + "/" + strings.ReplaceAll(vid, "-", ""),  // a UUID uuid.Parse accepts, uncanonical
		"/shared/" + id + "/{" + vid + "}",                        // likewise
		"/full/" + id + "/urn:uuid:" + vid,                        // likewise
		"/shared/" + strings.ToUpper(id),                          // a reference, and no resource has this value
		"/shared/" + id + "/" + strings.ToUpper(vid),
		"/full/" + id + "/" + strings.ToUpper(vid),
		// A subpath the browser would resolve out of the version.
		"/shared/" + id + "/" + vid + "/%2e%2e/api/artifacts/" + id + "/versions/" + vid + "/files/x.html",
		"/shared/" + id + "/" + vid + "/.%2e/api/x",
		"/full/" + id + "/" + vid + "/a/%2E%2E/%2e%2e/api/x",
		"/shared/" + id + "/" + vid + "/%2e/x",
		"/shared/" + id + "/" + vid + "/a%2fb",
		"/shared/" + id + "/" + vid + "/a%5Cb",
		"/shared/" + id + "/" + vid + "/a%00b",
	} {
		resp := get(t, w.base+p, w.owner.token, "text/html")
		body(t, resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", p, resp.StatusCode)
		}
	}
}

// validSubpath judges the escaped path the browser would resolve; the mux
// cleans some of these cases away before a handler sees them, so test it
// directly as well.
func TestValidSubpath(t *testing.T) {
	for p, want := range map[string]bool{
		"/":         true,
		"/a/b.html": true,
		"/a/":       true,
		"/a%20b":    true,
		"/a//b":     false,
		"//":        false,
		"/%2e%2e/x": false,
		"/a/.":      false,
		"/a/..":     false,
		"/a%2fb":    false,
		"/a%5cb":    false,
		"/a%00b":    false,
		"/%zz":      false,
	} {
		if got := validSubpath(p); got != want {
			t.Errorf("validSubpath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestShellPageResolvesReferences(t *testing.T) {
	w := newHostWorld(t)
	id, vid := w.art.id, w.vid
	w.owner.mustDo("POST", "/api/artifacts/"+id+"/resources", map[string]any{"type": "claude-session", "value": refOf("sess-9")}, nil, http.StatusCreated)

	for from, to := range map[string]string{
		"/shared/" + refOf("sess-9"):                         "/shared/" + id,
		"/shared/" + refOf("sess-9") + "/" + vid:             "/shared/" + id + "/" + vid,
		"/shared/" + refOf("sess-9") + "/" + vid + "/a%20b/": "/shared/" + id + "/" + vid + "/a%20b/",
		"/shared/" + refOf("sess-9") + "?x=1":                "/shared/" + id + "?x=1",
		"/full/" + refOf("sess-9"):                           "/full/" + id,
		"/full/" + refOf("sess-9") + "/" + vid + "/p":        "/full/" + id + "/" + vid + "/p",
	} {
		resp := get(t, w.base+from, w.owner.token, "text/html")
		body(t, resp)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != to {
			t.Errorf("GET %s: %d %q, want 302 to %s", from, resp.StatusCode, resp.Header.Get("Location"), to)
		}
	}
	// A caller who cannot read the artifact gets a 404, not a sign-in redirect.
	for _, tok := range []string{w.outside.token, ""} {
		resp := get(t, w.base+"/shared/"+refOf("sess-9"), tok, "text/html")
		body(t, resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("an unreadable reference: %d, want 404", resp.StatusCode)
		}
	}
}

func TestShellAssets(t *testing.T) {
	_, ts := testServer(t)
	for path, want := range map[string]string{"/shell.css": "text/css", "/shell.mjs": "javascript", "/viewer.mjs": "javascript"} {
		resp := get(t, ts.URL+path, "", "")
		body(t, resp)
		if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), want) {
			t.Errorf("GET %s: %d %q, want 200 %s", path, resp.StatusCode, resp.Header.Get("Content-Type"), want)
		}
	}
	// The old shell script is gone.
	resp := get(t, ts.URL+"/shell.js", "", "")
	body(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /shell.js: %d, want 404", resp.StatusCode)
	}
}

// TestShellModuleGraphIsServed follows the shell's relative imports from
// /shell.mjs and requires each module to be served on the app origin: one
// missing module stops the shell before it shows anything.
func TestShellModuleGraphIsServed(t *testing.T) {
	_, ts := testServer(t)
	imp := regexp.MustCompile(`from '\./([a-z0-9-]+\.mjs)'`)
	seen := map[string]bool{"shell.mjs": true}
	queue := []string{"shell.mjs"}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		resp := get(t, ts.URL+"/"+name, "", "")
		src := body(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET /%s: %d, want 200", name, resp.StatusCode)
			continue
		}
		for _, m := range imp.FindAllStringSubmatch(src, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				queue = append(queue, m[1])
			}
		}
	}
	if !seen["viewer.mjs"] || !seen["content.mjs"] {
		t.Errorf("the import walk found %v; want it to reach viewer.mjs and content.mjs", seen)
	}
}

// TestShellPageLoadsNothingCSPBlocks checks the page's own markup: the shell
// CSP has no data: source, so an inline data: icon is refused and logged.
func TestShellPageLoadsNothingCSPBlocks(t *testing.T) {
	_, ts := testServer(t)
	resp := get(t, ts.URL+"/shared/0b0e1313-5a5c-4a0e-9c52-2f1d0f6f2b11", "", "text/html")
	page := body(t, resp)
	if strings.Contains(page, "data:") {
		t.Errorf("the shell page references a data: URL, which its CSP blocks")
	}
	if !strings.Contains(page, `href="/icon.svg"`) {
		t.Errorf("the shell page does not use /icon.svg as its icon")
	}
}

func TestContentOriginFollowsPublicURL(t *testing.T) {
	id := "0b0e1313-5a5c-4a0e-9c52-2f1d0f6f2b11"
	s, _ := newTestServer(t, func(c *Config) {
		c.PublicURL = "https://cairn.example.com:8443"
		c.ContentDomain = "Cairn-Content.NET."
	})
	if got, want := s.contentOrigin(id), "https://"+id+".cairn-content.net:8443"; got != want {
		t.Errorf("contentOrigin = %q, want %q", got, want)
	}
	s, _ = newTestServer(t, func(c *Config) {
		c.PublicURL = "https://cairn.example.com"
		c.ContentDomain = "cairn-content.net"
	})
	if got, want := s.contentOrigin(id), "https://"+id+".cairn-content.net"; got != want {
		t.Errorf("contentOrigin = %q, want %q", got, want)
	}
}

func TestLoginPageRenders(t *testing.T) {
	_, ts := testServer(t)
	resp := get(t, ts.URL+"/login", "", "text/html")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body(t, resp), "Cairn") {
		t.Errorf("login page failed")
	}
}

// Cairn's own pages change the page rather than opening tabs, so closing a
// tab never strands the viewer: the app page's artifact links open the
// shell, which has the account link back home.
func TestPagesStayInOneTab(t *testing.T) {
	_, ts := testServer(t)
	admin, aid, _, link := setupArtifact(t, ts.URL, true)

	shell := body(t, getLinked(t, link, ts.URL+"/shared/"+aid, "", "text/html"))
	appResp := get(t, ts.URL+"/app", admin.token, "text/html")
	if appResp.StatusCode != http.StatusOK {
		t.Fatalf("app page: %d", appResp.StatusCode)
	}
	appHTML := body(t, appResp)
	// The app page builds its artifact links in JS, so check the source.
	appJS := body(t, get(t, ts.URL+"/app.mjs", "", ""))
	if !strings.Contains(appJS, "open.href = '/shared/' + a.id;") {
		t.Errorf("app artifact links should open the shared view")
	}
	for page, html := range map[string]string{
		"shell":  shell,
		"app":    appHTML,
		"app.js": appJS,
	} {
		if strings.Contains(html, "_blank") {
			t.Errorf("%s page opens a new tab", page)
		}
	}
}
