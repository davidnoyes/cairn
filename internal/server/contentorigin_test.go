package server

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
)

// hostWorld is a contentWorld whose server knows its own public URL, so its
// content hosts are <artifact ID>.localhost:<port>.
type hostWorld struct {
	*contentWorld
	port string
}

func newHostWorld(t *testing.T) *hostWorld {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	s, err := New(Config{
		DataDir:    t.TempDir(),
		PublicURL:  "http://127.0.0.1:" + port,
		AdminEmail: "admin@example.com",
		TokenTTL:   time.Hour,
		Mail:       &mail.Capture{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.Listener.Close()
	ts.Listener = ln
	ts.Start()
	t.Cleanup(func() {
		ts.Close()
		s.store.Close()
	})
	return &hostWorld{contentWorld: buildContentWorld(t, s, ts.URL), port: port}
}

func (w *hostWorld) appOrigin() string { return "http://127.0.0.1:" + w.port }

func (w *hostWorld) host(artifactID string) string { return artifactID + ".localhost:" + w.port }

// contentResp is a response from a content host.
type contentResp struct {
	*http.Response
	body string
}

// viaHost sends a request to the server with the given Host header.
func (w *hostWorld) viaHost(t *testing.T, host, method, path string, hdr map[string]string, body []byte) contentResp {
	t.Helper()
	req, err := http.NewRequest(method, w.base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return contentResp{resp, string(b)}
}

// onContent sends a request to the world's artifact's content host.
func (w *hostWorld) onContent(t *testing.T, method, path string, hdr map[string]string, body []byte) contentResp {
	t.Helper()
	return w.viaHost(t, w.host(w.art.id), method, path, hdr, body)
}

func bearer(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

func TestContentOriginServesNoAppRoute(t *testing.T) {
	w := newHostWorld(t)
	for _, p := range []string{"/healthz", "/login", "/app", "/admin", "/signup", "/cairn.js", "/shell.js", "/e2e.mjs", "/app.css",
		"/artifacts/" + w.art.id, "/shared/" + w.art.id, "/"} {
		resp := w.onContent(t, "GET", p, nil, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("content host GET %s: %d, want 404", p, resp.StatusCode)
		}
		// A browser navigation to the same path gets the boot page, never the app page.
		resp = w.onContent(t, "GET", p, map[string]string{"Accept": "text/html"}, nil)
		if resp.StatusCode != http.StatusOK || !strings.Contains(resp.body, "cairn-app-origin") {
			t.Errorf("content host navigation to %s: %d, want the boot page", p, resp.StatusCode)
		}
	}
}

func TestContentOriginBootPage(t *testing.T) {
	w := newHostWorld(t)
	wantCSP := "frame-ancestors " + w.appOrigin()
	for _, tt := range []struct {
		name, path string
		hdr        map[string]string
	}{
		{"boot route", "/_cairn/boot", nil},
		{"navigation", "/some/page", map[string]string{"Accept": "text/html,application/xhtml+xml"}},
		{"navigation to an unknown asset path", "/_cairn/nothing", map[string]string{"Accept": "text/html"}},
	} {
		resp := w.onContent(t, "GET", tt.path, tt.hdr, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: %d, want 200", tt.name, resp.StatusCode)
		}
		if !strings.Contains(resp.body, `<meta name="cairn-app-origin" content="`+w.appOrigin()+`">`) {
			t.Errorf("%s: no app origin meta in %q", tt.name, resp.body)
		}
		if !strings.Contains(resp.body, `<script type="module" src="/_cairn/boot.js"></script>`) {
			t.Errorf("%s: no boot script in %q", tt.name, resp.body)
		}
		if got := resp.Header.Get("Content-Security-Policy"); got != wantCSP {
			t.Errorf("%s: CSP %q, want %q", tt.name, got, wantCSP)
		}
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: nosniff %q", tt.name, got)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s: content type %q", tt.name, ct)
		}
	}
	// Anything that is not a GET asking for HTML is a 404.
	for _, tt := range []struct {
		method, path string
		hdr          map[string]string
	}{
		{"GET", "/some/page", nil},
		{"GET", "/some/page", map[string]string{"Accept": "application/json"}},
		{"GET", "/some/page", map[string]string{"Accept": "*/*"}},
		{"POST", "/some/page", map[string]string{"Accept": "text/html"}},
		{"POST", "/_cairn/boot", nil},
		{"PUT", "/_cairn/boot.js", nil},
		{"DELETE", "/", map[string]string{"Accept": "text/html"}},
	} {
		resp := w.onContent(t, tt.method, tt.path, tt.hdr, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s %v: %d, want 404", tt.method, tt.path, tt.hdr, resp.StatusCode)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s %s: a 404 lacks nosniff", tt.method, tt.path)
		}
	}
}

func TestContentOriginAssets(t *testing.T) {
	w := newHostWorld(t)
	for path, want := range map[string]string{
		"/_cairn/boot.js":       "javascript",
		"/_cairn/frame.js":      "javascript",
		swPath(w):               "javascript",
		"/_cairn/e2e.mjs":       "javascript",
		"/_cairn/content.mjs":   "javascript",
		"/_cairn/data.mjs":      "javascript",
		"/_cairn/cairn.js":      "javascript",
		"/_cairn/mermaid.js":    "javascript",
		"/_cairn/sql-wasm.js":   "javascript",
		"/_cairn/sql-wasm.wasm": "application/wasm",
	} {
		resp := w.onContent(t, "GET", path, nil, nil)
		if resp.StatusCode != http.StatusOK || len(resp.body) == 0 {
			t.Errorf("%s: %d, %d bytes", path, resp.StatusCode, len(resp.body))
			continue
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, want) {
			t.Errorf("%s: content type %q, want %q", path, ct, want)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: no nosniff", path)
		}
		if resp.Header.Get("Content-Security-Policy") != "" {
			t.Errorf("%s: a script carries an HTML policy", path)
		}
	}
	sw := w.onContent(t, "GET", swPath(w), nil, nil)
	if sw.Header.Get("Service-Worker-Allowed") != "/" || sw.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("sw.js headers: Service-Worker-Allowed %q, Cache-Control %q", sw.Header.Get("Service-Worker-Allowed"), sw.Header.Get("Cache-Control"))
	}
	if h := w.onContent(t, "GET", "/_cairn/boot.js", nil, nil).Header.Get("Service-Worker-Allowed"); h != "" {
		t.Errorf("boot.js sends Service-Worker-Allowed %q", h)
	}
	// The allowlist is exact: other embedded and app files are not served.
	for _, p := range []string{"/_cairn/", "/_cairn/shell.js", "/_cairn/login.js", "/_cairn/argon2.wasm", "/_cairn/../login.js", "/_cairn/boot.js/"} {
		if resp := w.onContent(t, "GET", p, nil, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", p, resp.StatusCode)
		}
	}
	// The app origin does not serve /_cairn/ at all.
	if resp := w.viaHost(t, "127.0.0.1:"+w.port, "GET", "/_cairn/boot.js", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("app origin /_cairn/boot.js: %d, want 404", resp.StatusCode)
	}
}

// A browser loads a module script's imports from the same directory, so every
// relative import of a served script must itself be served: a missing one
// stops the worker from starting, which node --test cannot see.
func TestContentOriginServesEveryImport(t *testing.T) {
	importRE := regexp.MustCompile(`(?m)^\s*(?:import|export)\b[^'"]*?from\s+'\./([^']+)'|^import\s+'\./([^']+)'`)
	for path, a := range contentAssets {
		if !strings.HasSuffix(path, ".js") && !strings.HasSuffix(path, ".mjs") {
			continue
		}
		for _, m := range importRE.FindAllStringSubmatch(string(a.data), -1) {
			name := m[1] + m[2]
			if contentAssets["/_cairn/"+name].data == nil {
				t.Errorf("%s imports ./%s, which the content origin does not serve", path, name)
			}
		}
	}
	if contentAssets["/_cairn/sw.js"].data == nil || !importRE.Match(contentAssets["/_cairn/sw.js"].data) {
		t.Fatal("found no import in sw.js: the pattern no longer matches")
	}
}

// swPath is the address the boot page registers the worker at.
func swPath(w *hostWorld) string { return "/_cairn/sw.js?app=" + url.QueryEscape(w.appOrigin()) }

// Artifact code shares the content origin, so it could register the worker
// itself, naming another app origin that the worker would then let frame its
// pages. The server serves the worker only for its own app origin.
func TestContentOriginServesTheWorkerOnlyForItsAppOrigin(t *testing.T) {
	w := newHostWorld(t)
	app := url.QueryEscape(w.appOrigin())
	if resp := w.onContent(t, "GET", swPath(w), nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d, want 200", swPath(w), resp.StatusCode)
	}
	for _, q := range []string{
		"",
		"?",
		"?app=",
		"?app=" + url.QueryEscape("https://evil.example"),
		"?app=" + url.QueryEscape(w.appOrigin()+"/"),
		"?app=" + app + "&app=" + app,
		"?app=" + app + "&x=1",
		"?x=1&app=" + app,
		"?app=" + app + "&a=1;b=2", // ParseQuery keeps app but reports the semicolon
		"?APP=" + app,
	} {
		if resp := w.onContent(t, "GET", "/_cairn/sw.js"+q, nil, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET /_cairn/sw.js%s: %d, want 404", q, resp.StatusCode)
		}
	}
	// Only the worker checks its query; other assets ignore one.
	if resp := w.onContent(t, "GET", "/_cairn/boot.js?app=x", nil, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("GET /_cairn/boot.js?app=x: %d, want 200", resp.StatusCode)
	}
}

func TestContentOriginAPIAllowlist(t *testing.T) {
	w := newHostWorld(t)
	tok := mintContentToken(t, w.s, w.owner.id, w.art.id)
	b := newArtifact(t, w.owner, "other")
	bvid := pushVersion(t, w.owner.testClient, b.id)
	w.owner.mustDo("POST", "/api/artifacts/"+w.art.id+"/resources",
		map[string]string{"type": "claude-session", "value": refOf("w-session")}, nil, http.StatusCreated)

	for pattern := range contentTokenRoutes {
		w.putFile(t)
		rq := w.contentRouteRequest(t, pattern, w.art.id, w.vid, w.blob, w.addr, w.editor.id)
		if resp := w.onContent(t, rq.method, rq.path, rq.withHeader(bearer(tok)), rq.body); resp.StatusCode >= 300 {
			t.Errorf("%s on its host: %d %s, want success", pattern, resp.StatusCode, resp.body)
		}
		if !strings.Contains(pattern, " /api/artifacts/{id}") {
			continue // /api/me and /api/users/{id} name no artifact
		}
		// Another artifact's {id}, by ID or by resource value, and this
		// artifact reached by its own resource value, are all refused.
		for _, ref := range []string{b.id, refOf("w-session")} {
			rq := w.contentRouteRequest(t, pattern, ref, bvid, strings.Repeat("a", 32), strings.Repeat("b", 64), "")
			if resp := w.onContent(t, rq.method, rq.path, rq.withHeader(bearer(tok)), rq.body); resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s with {id} %s: %d %s, want 404", pattern, ref, resp.StatusCode, resp.body)
			}
		}
	}

	// Every other registered route is a 404, whatever credentials ride along.
	apiKey := w.createAPIKey(t)
	creds := map[string]map[string]string{
		"none":          nil,
		"content token": bearer(tok),
		"session":       bearer(w.owner.token),
		"api key":       bearer(apiKey),
		"garbage":       bearer("garbage"),
	}
	refused := 0
	for _, pattern := range w.s.patterns {
		if contentTokenRoutes[pattern] || !strings.Contains(pattern, "/api/") {
			continue
		}
		rq := w.contentRouteRequest(t, pattern, w.art.id, w.vid, w.blob, w.addr, w.editor.id)
		for name, hdr := range creds {
			resp := w.onContent(t, rq.method, rq.path, rq.withHeader(hdr), rq.body)
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s with %s on a content host: %d %s, want 404", pattern, name, resp.StatusCode, resp.body)
			}
			refused++
		}
	}
	if refused < 100 {
		t.Errorf("checked only %d refusals", refused)
	}
	// A path no route has, and the mux's own redirects, are 404s too.
	for _, p := range []string{"/api/nothing", "/api/", "/api/me/", "/api/artifacts/" + w.art.id + "/../../keys"} {
		if resp := w.onContent(t, "GET", p, bearer(tok), nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", p, resp.StatusCode)
		}
	}
	// The content token did not change anything on the other artifact.
	if resp := w.owner.doRaw("GET", "/api/artifacts/"+b.id+"/versions/"+bvid+"/files", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("other artifact's file list: %d", resp.StatusCode)
	}
}

// TestAPIResponsesCannotBecomeDocuments: a stored file is served from the API
// on both hosts, so every API response forbids framing and running script, or
// a link to an uploaded HTML file would run it with the origin's authority.
func TestAPIResponsesCannotBecomeDocuments(t *testing.T) {
	w := newHostWorld(t)
	tok := mintContentToken(t, w.s, w.owner.id, w.art.id)
	check := func(where string, status int, h http.Header) {
		t.Helper()
		if got := h.Get("Content-Security-Policy"); got != apiCSP {
			t.Errorf("%s (%d): Content-Security-Policy %q, want %q", where, status, got, apiCSP)
		}
	}
	for _, p := range []string{w.vbase + "/files/" + w.addr, "/api/me", "/api/nothing"} {
		resp := w.onContent(t, "GET", p, bearer(tok), nil)
		check("content host GET "+p, resp.StatusCode, resp.Header)
	}
	if resp := w.onContent(t, "GET", w.vbase+"/files/"+w.addr, bearer(tok), nil); resp.StatusCode != http.StatusOK {
		t.Errorf("content host file: %d, want 200", resp.StatusCode)
	}
	for _, p := range []string{w.vbase + "/files/" + w.addr, "/api/me", "/api/nothing"} {
		resp := w.owner.doRaw("GET", p, nil)
		resp.Body.Close()
		check("app GET "+p, resp.StatusCode, resp.Header)
	}
	// An app page is not an API response, and keeps its own policy.
	resp := get(t, w.base+"/login", "", "text/html")
	resp.Body.Close()
	if got := resp.Header.Get("Content-Security-Policy"); got == apiCSP {
		t.Errorf("/login took the API policy")
	}
}

// createAPIKey makes an API key for the world's owner and returns its bearer.
func (w *hostWorld) createAPIKey(t *testing.T) string {
	t.Helper()
	w.owner.mustDo("POST", "/api/keys", map[string]any{
		"authKey": e2e.B64(testAuthKey("owner@example.com-password")), "name": "laptop", "device": true,
		"keyId": "00112233445566ff", "authSecret": "00112233445566778899aabbccddeeff",
		"mk": e2e.B64(bytes.Repeat([]byte{0x11}, sealedKeyLen)),
	}, nil, http.StatusCreated)
	return "cairn_00112233445566ff_00112233445566778899aabbccddeeff"
}

func TestContentOriginAuthorization(t *testing.T) {
	w := newHostWorld(t)
	other := newArtifact(t, w.owner, "other")
	files := w.vbase + "/files/" + w.addr
	good := mintContentToken(t, w.s, w.owner.id, w.art.id)
	now := time.Now().Unix()
	expired, err := auth.SignJWT(w.s.secret, auth.Claims{UserID: w.owner.id, Artifact: w.art.id, IssuedAt: now - 600, ExpiresAt: now - 300})
	if err != nil {
		t.Fatal(err)
	}
	cookie := func(v string) map[string]string {
		return map[string]string{"Cookie": w.s.sessionCookieName() + "=" + v}
	}

	for _, tt := range []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"content token for this artifact", bearer(good), http.StatusOK},
		{"content token for another artifact", bearer(mintContentToken(t, w.s, w.owner.id, other.id)), http.StatusUnauthorized},
		{"session token", bearer(w.owner.token), http.StatusUnauthorized},
		{"API key", bearer(w.createAPIKey(t)), http.StatusUnauthorized},
		{"expired token", bearer(expired), http.StatusUnauthorized},
		{"garbage", bearer("not.a.jwt"), http.StatusUnauthorized},
		{"wrong scheme", map[string]string{"Authorization": "Basic " + good}, http.StatusUnauthorized},
		{"no scheme", map[string]string{"Authorization": good}, http.StatusUnauthorized},
		// No credentials is anonymous, which the private artifact refuses as a 404.
		{"nothing", nil, http.StatusNotFound},
		// The session cookie is dropped before dispatch.
		{"owner's session cookie", cookie(w.owner.token), http.StatusNotFound},
		{"content token as a cookie", cookie(good), http.StatusNotFound},
		// A bad bearer is refused even when it comes with a cookie.
		{"session token and cookie", func() map[string]string {
			h := cookie(w.owner.token)
			h["Authorization"] = "Bearer " + w.owner.token
			return h
		}(), http.StatusUnauthorized},
		{"good token and a cookie", func() map[string]string {
			h := cookie("garbage")
			h["Authorization"] = "Bearer " + good
			return h
		}(), http.StatusOK},
	} {
		resp := w.onContent(t, "GET", files, tt.hdr, nil)
		if resp.StatusCode != tt.want {
			t.Errorf("%s: %d %s, want %d", tt.name, resp.StatusCode, resp.body, tt.want)
		}
	}
	// /api/me, which is not an artifact route, applies the same rule.
	if resp := w.onContent(t, "GET", "/api/me", bearer(w.owner.token), nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/api/me with a session token: %d, want 401", resp.StatusCode)
	}
	if resp := w.onContent(t, "GET", "/api/me", cookie(w.owner.token), nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/api/me with only a session cookie: %d, want 401 (anonymous)", resp.StatusCode)
	}
	// The same cookie does reach the app origin, so the 404s above are the
	// content host's doing.
	req, _ := http.NewRequest("GET", w.base+"/api/me", nil)
	req.Header.Set("Cookie", w.s.sessionCookieName()+"="+w.owner.token)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("session cookie on the app origin: %v %v", resp, err)
	}
}

func TestContentOriginLinkTokenAloneIsAnonymousAccess(t *testing.T) {
	w := newHostWorld(t)
	link := w.art.makePublic()
	files := w.vbase + "/files/" + w.addr
	if resp := w.onContent(t, "GET", files, map[string]string{"X-Cairn-Link-Token": link}, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("anonymous with the link token: %d %s, want 200", resp.StatusCode, resp.body)
	}
	if resp := w.onContent(t, "GET", files, nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("anonymous without it: %d, want 404", resp.StatusCode)
	}
	q := newFile(t, w.owner, w.art.id, w.vid, 1, "anon.txt", "x")
	ct, body := q.wire(t)
	if resp := w.onContent(t, "PUT", q.path(), map[string]string{"X-Cairn-Link-Token": link, "Content-Type": ct}, body); resp.StatusCode != http.StatusForbidden {
		t.Errorf("anonymous write without public writes: %d %s, want 403", resp.StatusCode, resp.body)
	}
}

// mint posts to the token route as c.
func mint(t *testing.T, c *testClient, ref string) (int, string, int64) {
	t.Helper()
	var out struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	resp := c.do("POST", "/api/artifacts/"+ref+"/content-token", struct{}{}, &out)
	return resp.StatusCode, out.Token, out.ExpiresAt
}

func TestMintContentToken(t *testing.T) {
	w := newHostWorld(t)
	before := time.Now().Unix()
	for name, c := range map[string]*testClient{"owner": w.owner.testClient, "editor": w.editor.testClient, "viewer": w.viewer.testClient} {
		code, tok, exp := mint(t, c, w.art.id)
		if code != http.StatusOK || tok == "" {
			t.Fatalf("%s: %d, token %q", name, code, tok)
		}
		claims, err := auth.VerifyJWT(w.s.secret, tok)
		if err != nil {
			t.Fatalf("%s: token does not verify: %v", name, err)
		}
		if claims.Artifact != w.art.id || claims.Link || claims.IsAdmin {
			t.Errorf("%s: claims %+v", name, claims)
		}
		if ttl := claims.ExpiresAt - claims.IssuedAt; ttl != 600 {
			t.Errorf("%s: ttl %ds, want 600", name, ttl)
		}
		if exp != claims.ExpiresAt || exp < before+600 || exp > time.Now().Unix()+600 {
			t.Errorf("%s: expiresAt %d, claim %d", name, exp, claims.ExpiresAt)
		}
	}

	// The token carries the caller's own role onto the content host.
	_, viewerTok, _ := mint(t, w.viewer.testClient, w.art.id)
	_, editorTok, _ := mint(t, w.editor.testClient, w.art.id)
	put := func(tok string, as actor) contentResp {
		q := newFile(t, as, w.art.id, w.vid, 1, "b.txt", "x")
		ct, body := q.wire(t)
		h := bearer(tok)
		h["Content-Type"] = ct
		return w.onContent(t, "PUT", q.path(), h, body)
	}
	if resp := put(viewerTok, w.viewer); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer's token writes: %d, want 403", resp.StatusCode)
	}
	if resp := put(editorTok, w.editor); resp.StatusCode != http.StatusOK {
		t.Errorf("editor's token writes: %d, want 200", resp.StatusCode)
	}
	// ...and only for its own artifact.
	b := newArtifact(t, w.owner, "other")
	if resp := w.viaHost(t, w.host(b.id), "GET", "/api/artifacts/"+b.id+"/versions", bearer(viewerTok), nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("token on another artifact's host: %d, want 401", resp.StatusCode)
	}

	// A resource reference resolves to the artifact's ID in the claim.
	w.owner.mustDo("POST", "/api/artifacts/"+w.art.id+"/resources",
		map[string]string{"type": "claude-session", "value": refOf("mint-ref")}, nil, http.StatusCreated)
	_, tok, _ := mint(t, w.owner.testClient, refOf("mint-ref"))
	if claims, err := auth.VerifyJWT(w.s.secret, tok); err != nil || claims.Artifact != w.art.id {
		t.Errorf("claim for a reference: %+v %v, want %s", claims, err, w.art.id)
	}
}

func TestMintContentTokenRefusals(t *testing.T) {
	w := newHostWorld(t)
	apiKey := w.createAPIKey(t)
	contentTok := mintContentToken(t, w.s, w.owner.id, w.art.id)
	for _, tt := range []struct {
		name string
		c    *testClient
		ref  string
		want int
	}{
		{"no credentials", &testClient{t: t, base: w.base}, w.art.id, http.StatusUnauthorized},
		{"API key", &testClient{t: t, base: w.base, token: apiKey}, w.art.id, http.StatusUnauthorized},
		{"content token", &testClient{t: t, base: w.base, token: contentTok}, w.art.id, http.StatusNotFound},
		{"garbage token", &testClient{t: t, base: w.base, token: "garbage"}, w.art.id, http.StatusUnauthorized},
		{"no access", w.outside.testClient, w.art.id, http.StatusNotFound},
		{"unknown artifact", w.owner.testClient, "00000000-0000-4000-8000-000000000000", http.StatusNotFound},
		{"link header, private artifact", &testClient{t: t, base: w.base, token: w.outside.token, link: w.art.linkToken()}, w.art.id, http.StatusNotFound},
	} {
		if code, tok, _ := mint(t, tt.c, tt.ref); code != tt.want || tok != "" {
			t.Errorf("%s: %d, token %q, want %d and no token", tt.name, code, tok, tt.want)
		}
	}
	// Anonymous gets none even holding a valid link.
	w.art.makePublic()
	anon := &testClient{t: t, base: w.base, link: w.art.linkToken()}
	if code, tok, _ := mint(t, anon, w.art.id); code != http.StatusUnauthorized || tok != "" {
		t.Errorf("anonymous with a link: %d, token %q, want 401", code, tok)
	}
	// A session cookie works the way it does on any app route.
	req, _ := http.NewRequest("POST", w.base+"/api/artifacts/"+w.art.id+"/content-token", nil)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: w.s.sessionCookieName(), Value: w.owner.token})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("cookie mint: %d, want 200", resp.StatusCode)
	}
}

func TestMintContentTokenLinkScope(t *testing.T) {
	w := newHostWorld(t)
	link := w.art.makePublic()
	files := w.vbase + "/files/" + w.addr

	// A signed-in caller with no access but the link gets a link-scope token.
	c := &testClient{t: t, base: w.base, token: w.outside.token, link: link}
	code, tok, _ := mint(t, c, w.art.id)
	if code != http.StatusOK {
		t.Fatalf("link mint: %d", code)
	}
	claims, err := auth.VerifyJWT(w.s.secret, tok)
	if err != nil || !claims.Link || claims.Artifact != w.art.id {
		t.Fatalf("claims %+v, %v: want a link-scope token for the artifact", claims, err)
	}
	// It opens what the link opens, when the link token rides with it...
	hdr := bearer(tok)
	hdr["X-Cairn-Link-Token"] = link
	if resp := w.onContent(t, "GET", files, hdr, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("link-scope token with the link: %d, want 200", resp.StatusCode)
	}
	// ...and nothing without it, as the user has no access of their own.
	if resp := w.onContent(t, "GET", files, bearer(tok), nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("link-scope token without the link: %d, want 404", resp.StatusCode)
	}
	// A link holder does not write while public writes are off.
	qc := newFile(t, w.outside, w.art.id, w.vid, 1, "c.txt", "x")
	ct, body := qc.wire(t)
	hdr["Content-Type"] = ct
	if resp := w.onContent(t, "PUT", qc.path(), hdr, body); resp.StatusCode != http.StatusForbidden {
		t.Errorf("link-scope write: %d, want 403", resp.StatusCode)
	}

	// A member who sends the link too does not need it: their token is an
	// ordinary one with their own role.
	m := &testClient{t: t, base: w.base, token: w.editor.token, link: link}
	_, mtok, _ := mint(t, m, w.art.id)
	if claims, err := auth.VerifyJWT(w.s.secret, mtok); err != nil || claims.Link {
		t.Errorf("a member's token: %+v %v, want no link scope", claims, err)
	}

	// A link-scope token for the owner has the link's access and not the
	// owner's, though the user is the owner and the link token is sent.
	now := time.Now().Unix()
	owner, err := w.s.store.UserByID(w.owner.id)
	if err != nil {
		t.Fatal(err)
	}
	ownerLink, err := auth.SignJWT(w.s.secret, auth.Claims{UserID: w.owner.id, TokenVersion: owner.TokenVersion, Artifact: w.art.id, Link: true, IssuedAt: now, ExpiresAt: now + 300})
	if err != nil {
		t.Fatal(err)
	}
	ownerPlain := mintContentToken(t, w.s, w.owner.id, w.art.id)
	for name, tc := range map[string]struct {
		tok  string
		want int
	}{"link scope": {ownerLink, http.StatusForbidden}, "plain": {ownerPlain, http.StatusOK}} {
		h := bearer(tc.tok)
		h["X-Cairn-Link-Token"] = link
		qd := newFile(t, w.owner, w.art.id, w.vid, 1, "d.txt", "x")
		ct, body := qd.wire(t)
		h["Content-Type"] = ct
		if resp := w.onContent(t, "PUT", qd.path(), h, body); resp.StatusCode != tc.want {
			t.Errorf("owner's %s token writes: %d, want %d", name, resp.StatusCode, tc.want)
		}
	}
	// Without the link token, an owner's link-scope token has nothing.
	if resp := w.onContent(t, "GET", files, bearer(ownerLink), nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("owner's link-scope token alone: %d, want 404", resp.StatusCode)
	}
	// It reads no user through /api/users/{id}.
	h := bearer(ownerLink)
	h["X-Cairn-Link-Token"] = link
	if resp := w.onContent(t, "GET", "/api/users/"+w.owner.id, h, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("link-scope user read: %d, want 404", resp.StatusCode)
	}
}

func TestArtifactPagesRedirectToShared(t *testing.T) {
	w := newHostWorld(t)
	id, vid := w.art.id, w.vid
	for from, to := range map[string]string{
		"/artifacts/" + id:                         "/shared/" + id,
		"/artifacts/" + id + "/" + vid:             "/shared/" + id + "/" + vid,
		"/artifacts/" + id + "/" + vid + "/":       "/shared/" + id + "/" + vid + "/",
		"/artifacts/" + id + "/" + vid + "/a/b.js": "/shared/" + id + "/" + vid + "/a/b.js",
		"/artifacts/sess-1":                        "/shared/sess-1",
		"/artifacts/" + id + "?x=1":                "/shared/" + id + "?x=1",
	} {
		resp := w.viaHost(t, "127.0.0.1:"+w.port, "GET", from, map[string]string{"Accept": "text/html"}, nil)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != to {
			t.Errorf("GET %s: %d to %q, want 302 to %q", from, resp.StatusCode, resp.Header.Get("Location"), to)
		}
	}
	// The app origin serves no artifact file: no redirect target is a file
	// read, and an artifact's own path names nothing under /artifacts/.
	if resp := w.viaHost(t, "127.0.0.1:"+w.port, "POST", "/artifacts/"+id, nil, nil); resp.StatusCode == http.StatusOK {
		t.Errorf("POST /artifacts/{id}: %d", resp.StatusCode)
	}
}

func TestSharedRoutesAndShellCSP(t *testing.T) {
	w := newHostWorld(t)
	id, vid := w.art.id, w.vid
	frameSrc := "frame-src http://*.localhost:" + w.port
	for _, p := range []string{
		"/shared/" + id, "/shared/" + id + "/" + vid, "/shared/" + id + "/" + vid + "/some/path",
		"/full/" + id, "/full/" + id + "/" + vid, "/full/" + id + "/" + vid + "/some/path",
	} {
		resp := get(t, w.base+p, w.owner.token, "text/html")
		body(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: %d, want 200", p, resp.StatusCode)
		}
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.HasSuffix(csp, "; "+frameSrc) || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("GET %s: CSP %q, want the app policy plus %q", p, csp, frameSrc)
		}
	}
	// Every other page keeps the app policy and no frame-src.
	for _, p := range []string{"/login", "/signup", "/verify", "/forgot", "/reset"} {
		resp := get(t, w.base+p, "", "text/html")
		body(t, resp)
		if csp := resp.Header.Get("Content-Security-Policy"); csp != appCSP || strings.Contains(csp, "frame-src") {
			t.Errorf("GET %s: CSP %q, want the app policy", p, csp)
		}
	}
	resp := get(t, w.base+"/app", w.owner.token, "text/html")
	body(t, resp)
	if csp := resp.Header.Get("Content-Security-Policy"); csp != appCSP {
		t.Errorf("GET /app: CSP %q", csp)
	}
}

func TestShellCSPFollowsPublicURL(t *testing.T) {
	s, _ := newTestServer(t, func(c *Config) {
		c.PublicURL = "https://cairn.example.com:8443"
		c.ContentDomain = "Cairn-Content.NET."
	})
	if got, want := s.shellCSP(), appCSP+"; frame-src https://*.cairn-content.net:8443"; got != want {
		t.Errorf("shellCSP = %q, want %q", got, want)
	}
	s, _ = newTestServer(t, func(c *Config) {
		c.PublicURL = "https://cairn.example.com"
		c.ContentDomain = "cairn-content.net"
	})
	if got, want := s.shellCSP(), appCSP+"; frame-src https://*.cairn-content.net"; got != want {
		t.Errorf("shellCSP = %q, want %q", got, want)
	}
}

func TestContentHostFollowsPublicURLPort(t *testing.T) {
	s, _ := newTestServer(t, func(c *Config) {
		c.PublicURL = "https://cairn.example.com:8443"
		c.ContentDomain = "cairn-content.net"
	})
	id := "0a1b2c3d-0000-4000-8000-000000000000"
	for host, want := range map[string]bool{
		id + ".cairn-content.net:8443": true,
		id + ".Cairn-Content.NET:8443": true,
		id + ".cairn-content.net":      true,
		id + ".cairn-content.net:443":  true,
		id + ".cairn-content.net.":     false,
	} {
		if _, got := s.contentArtifactOf(host); got != want {
			t.Errorf("contentArtifactOf(%q) = %v, want %v", host, got, want)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/_cairn/boot", nil)
	req.Host = id + ".cairn-content.net:8443"
	s.Handler().ServeHTTP(rec, req)
	if got, want := rec.Header().Get("Content-Security-Policy"), "frame-ancestors https://cairn.example.com:8443"; got != want {
		t.Errorf("boot CSP = %q, want %q", got, want)
	}
}
