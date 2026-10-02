package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/access"
	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

// mintContentToken signs the content-origin token milestone 4 will issue: a
// sign-in JWT for userID carrying an art claim for artifactID.
func mintContentToken(t *testing.T, s *Server, userID, artifactID string) string {
	t.Helper()
	u, err := s.store.UserByID(userID)
	if err != nil {
		t.Fatal(err)
	}
	return mintContentTokenVersion(t, s, userID, artifactID, u.TokenVersion)
}

func mintContentTokenVersion(t *testing.T, s *Server, userID, artifactID string, tokenVersion int) string {
	t.Helper()
	now := time.Now().Unix()
	tok, err := auth.SignJWT(s.secret, auth.Claims{UserID: userID, TokenVersion: tokenVersion,
		Artifact: artifactID, IssuedAt: now, ExpiresAt: now + 300})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// contentWorld is an owner with an artifact that has a version, a database,
// and a file, a listed editor and viewer, and a user with no access.
type contentWorld struct {
	s       *Server
	base    string
	owner   actor
	editor  actor
	viewer  actor
	outside actor
	art     *owned
	vid     string
	vbase   string
}

func newContentWorld(t *testing.T) *contentWorld {
	t.Helper()
	s, ts := testServer(t)
	return buildContentWorld(t, s, ts.URL)
}

// buildContentWorld seeds the world's accounts and artifact on a running
// server at base.
func buildContentWorld(t *testing.T, s *Server, base string) *contentWorld {
	t.Helper()
	w := &contentWorld{s: s, base: base}
	w.owner = seedKeyedAccount(t, s, base, "owner@example.com")
	w.editor = seedKeyedAccount(t, s, base, "editor@example.com")
	w.viewer = seedKeyedAccount(t, s, base, "viewer@example.com")
	w.outside = seedKeyedAccount(t, s, base, "outside@example.com")
	w.art = newArtifact(t, w.owner, "notes")
	w.art.share("editor", w.editor)
	w.art.share("viewer", w.viewer)
	w.vid = pushVersion(t, w.owner.testClient, w.art.id)
	w.vbase = "/api/artifacts/" + w.art.id + "/versions/" + w.vid
	w.putFile(t)
	return w
}

func (w *contentWorld) putFile(t *testing.T) {
	t.Helper()
	if r := w.owner.doRaw("PUT", w.vbase+"/files/a.txt", []byte("hi")); r.StatusCode != http.StatusOK {
		t.Fatalf("seed file: %d", r.StatusCode)
	}
}

// token is a client sending a content token for the world's artifact, minted
// for userID.
func (w *contentWorld) token(t *testing.T, userID string) *testClient {
	return &testClient{t: t, base: w.base, token: mintContentToken(t, w.s, userID, w.art.id)}
}

// wantCode is wantStatus for a response that need not be a JSON object.
func wantCode(t *testing.T, c *testClient, method, path string, want int) {
	t.Helper()
	resp := c.doRaw(method, path, nil)
	resp.Body.Close()
	if resp.StatusCode != want {
		t.Errorf("%s %s: %d, want %d", method, path, resp.StatusCode, want)
	}
}

// contentRouteRequest fills pattern's wildcards, with artID for an artifact's
// {id} and userID for a user's, and gives it a body that succeeds.
func contentRouteRequest(pattern, artID, vid, userID string) (method, path string, body []byte) {
	method, path, found := strings.Cut(pattern, " ")
	if !found {
		method, path = "GET", pattern
	}
	path = strings.NewReplacer("{vid}", vid, "{rid}", "r1", "{path...}", "a.txt").Replace(path)
	if strings.HasPrefix(path, "/api/users/{id}") || strings.HasPrefix(path, "/api/admin/users/{id}") {
		path = strings.Replace(path, "{id}", userID, 1)
	}
	path = strings.Replace(path, "{id}", artID, 1)
	switch {
	case strings.HasSuffix(pattern, "/db/query"):
		body = []byte(`{"sql":"SELECT 1"}`)
	case strings.HasSuffix(pattern, "/db/batch"):
		body = []byte(`{"statements":[{"sql":"CREATE TABLE IF NOT EXISTS pwned (x)"}]}`)
	case strings.HasSuffix(pattern, "/files/{path...}") && method == "PUT":
		body = []byte("hello")
	case method != "GET" && method != "DELETE":
		body = []byte(`{}`)
	}
	return method, path, body
}

// send makes one request with c's credentials and returns the status and body.
func send(t *testing.T, c *testClient, method, path string, body []byte) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(msg))
}

// gateRefusal is the body of the gate's 404.
const gateRefusal = `{"error":"not found"}`

func TestContentTokenRouteTable(t *testing.T) {
	// The allowlist, written out independently of contentTokenRoutes, so that
	// adding or dropping an entry there fails here. See design/e2e-api.md.
	want := map[string]bool{
		"GET /api/me":                                               true,
		"GET /api/users/{id}":                                       true,
		"GET /api/artifacts/{id}/membership":                        true,
		"GET /api/artifacts/{id}/versions":                          true,
		"GET /api/artifacts/{id}/versions/{vid}":                    true,
		"POST /api/artifacts/{id}/versions/{vid}/db/query":          true,
		"POST /api/artifacts/{id}/versions/{vid}/db/batch":          true,
		"GET /api/artifacts/{id}/versions/{vid}/db/download":        true,
		"GET /api/artifacts/{id}/versions/{vid}/files":              true,
		"GET /api/artifacts/{id}/versions/{vid}/files/{path...}":    true,
		"PUT /api/artifacts/{id}/versions/{vid}/files/{path...}":    true,
		"DELETE /api/artifacts/{id}/versions/{vid}/files/{path...}": true,
	}
	if !reflect.DeepEqual(contentTokenRoutes, want) {
		t.Errorf("contentTokenRoutes = %v, want %v", contentTokenRoutes, want)
	}

	w := newContentWorld(t)
	tok := w.token(t, w.owner.id)
	seen := map[string]bool{}
	for _, pattern := range w.s.patterns {
		method, path, body := contentRouteRequest(pattern, w.art.id, w.vid, w.editor.id)
		allowed := contentTokenRoutes[pattern]
		if allowed {
			seen[pattern] = true
			w.putFile(t)
		}
		code, msg := send(t, tok, method, path, body)
		switch {
		case allowed && code != http.StatusOK:
			t.Errorf("%s with a content token: %d %s, want 200", pattern, code, msg)
		case !allowed && (code != http.StatusNotFound || msg != gateRefusal):
			t.Errorf("%s with a content token: %d %s, want 404 %s", pattern, code, msg, gateRefusal)
		}
	}
	for pattern := range contentTokenRoutes {
		if !seen[pattern] {
			t.Errorf("contentTokenRoutes lists %q, which no route registers", pattern)
		}
	}
	if len(w.s.patterns) < 40 {
		t.Errorf("walked only %d patterns", len(w.s.patterns))
	}

	// An ordinary session reaches the routes the token does not, so the 404s
	// are the token's and not the setup's.
	aid := "/api/artifacts/" + w.art.id
	for _, p := range []string{"/api/keys", "/api/me/bundle", "/api/me/keyring", aid, aid + "/keys", aid + "/pending",
		aid + "/review", "/api/users/" + w.editor.id + "/rotations"} {
		wantCode(t, w.owner.testClient, "GET", p, http.StatusOK)
		wantCode(t, tok, "GET", p, http.StatusNotFound)
	}
	wantCode(t, tok, "POST", "/api/auth/logout", http.StatusNotFound)
}

// Every key of contentTokenRoutes is a pattern the mux registers; a renamed
// route would otherwise leave a dead entry that allows nothing.
func TestContentTokenRoutesAreRegisteredPatterns(t *testing.T) {
	w := newContentWorld(t)
	registered := map[string]bool{}
	for _, p := range w.s.patterns {
		registered[p] = true
	}
	for pattern := range contentTokenRoutes {
		if !registered[pattern] {
			t.Errorf("contentTokenRoutes lists %q, which is not a registered pattern", pattern)
		}
	}
}

// Every allowlisted artifact route, given another artifact, answers 404 and
// changes nothing there; that includes reaching it by a resource value.
func TestContentTokenIsScopedToOneArtifact(t *testing.T) {
	w := newContentWorld(t)
	b := newArtifact(t, w.owner, "other")
	bvid := pushVersion(t, w.owner.testClient, b.id)
	bbase := "/api/artifacts/" + b.id + "/versions/" + bvid
	if r := w.owner.doRaw("PUT", bbase+"/files/a.txt", []byte("keep")); r.StatusCode != http.StatusOK {
		t.Fatalf("seed b's file: %d", r.StatusCode)
	}
	w.owner.mustDo("POST", "/api/artifacts/"+b.id+"/resources",
		map[string]string{"type": "claude-session", "value": "b-session"}, nil, http.StatusCreated)
	// The database is created lazily, so seed it, or db/download is a 404
	// whenever the loop reaches it first.
	w.owner.mustDo("POST", w.vbase+"/db/batch",
		map[string]any{"statements": []map[string]any{{"sql": "CREATE TABLE IF NOT EXISTS t (x)"}}}, nil, http.StatusOK)
	tok := w.token(t, w.owner.id)
	for pattern := range contentTokenRoutes {
		if !strings.Contains(pattern, " /api/artifacts/{id}") {
			continue
		}
		for _, ref := range []string{b.id, "b-session"} {
			method, path, body := contentRouteRequest(pattern, ref, bvid, "")
			if code, msg := send(t, tok, method, path, body); code != http.StatusNotFound {
				t.Errorf("%s on another artifact (%s): %d %s, want 404", pattern, ref, code, msg)
			}
		}
		method, path, body := contentRouteRequest(pattern, w.art.id, w.vid, "")
		w.putFile(t)
		if code, msg := send(t, tok, method, path, body); code != http.StatusOK {
			t.Errorf("%s on its own artifact: %d %s, want 200", pattern, code, msg)
		}
	}
	got := w.owner.doRaw("GET", bbase+"/files/a.txt", nil)
	data, _ := io.ReadAll(got.Body)
	got.Body.Close()
	if got.StatusCode != http.StatusOK || string(data) != "keep" {
		t.Errorf("b's file after the token's requests: %d %q, want 200 \"keep\"", got.StatusCode, data)
	}
	var rows struct {
		Rows [][]any `json:"rows"`
	}
	w.owner.mustDo("POST", bbase+"/db/query", map[string]any{"sql": "SELECT name FROM sqlite_master WHERE name = 'pwned'"},
		&rows, http.StatusOK)
	if len(rows.Rows) != 0 {
		t.Errorf("b's database has the token's table: %v", rows.Rows)
	}
}

// The gate reads the token wherever the credential comes from, by the
// pattern the mux would serve.
func TestContentTokenGateEdges(t *testing.T) {
	w := newContentWorld(t)
	tok := mintContentToken(t, w.s, w.owner.id, w.art.id)
	cookie := func(method, path string) (int, string) {
		req, err := http.NewRequest(method, w.base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: w.s.sessionCookieName(), Value: tok})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		msg, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(msg))
	}
	if code, msg := cookie("GET", "/api/keys"); code != http.StatusNotFound || msg != gateRefusal {
		t.Errorf("token as the session cookie, /api/keys: %d %s, want 404", code, msg)
	}
	if code, msg := cookie("GET", "/api/me"); code != http.StatusOK {
		t.Errorf("token as the session cookie, /api/me: %d %s, want 200", code, msg)
	}

	bearer := &testClient{t: t, base: w.base, token: tok}
	wantCode(t, bearer, "HEAD", w.vbase+"/files/a.txt", http.StatusOK)
	wantCode(t, bearer, "OPTIONS", "/api/me", http.StatusNotFound)
	wantCode(t, bearer, "GET", "/api/artifacts/"+w.art.id+"/../../keys", http.StatusNotFound)
	wantCode(t, bearer, "GET", "/api/me/", http.StatusNotFound)

	// An expired token is no credential at all, not a session.
	now := time.Now().Unix()
	expired, err := auth.SignJWT(w.s.secret, auth.Claims{UserID: w.owner.id, TokenVersion: 0,
		Artifact: w.art.id, IssuedAt: now - 600, ExpiresAt: now - 300})
	if err != nil {
		t.Fatal(err)
	}
	old := &testClient{t: t, base: w.base, token: expired}
	wantCode(t, old, "GET", "/api/me", http.StatusUnauthorized)
	wantCode(t, old, "GET", "/api/keys", http.StatusUnauthorized)
}

func TestContentTokenReadsOnlyListedUsers(t *testing.T) {
	w := newContentWorld(t)
	stranger := seedKeyedAccount(t, w.s, w.base, "stranger@example.com")
	tok := w.token(t, w.owner.id)
	wantCode(t, tok, "GET", "/api/users/"+w.owner.id, http.StatusOK)
	wantCode(t, tok, "GET", "/api/users/"+w.editor.id, http.StatusOK)
	wantCode(t, tok, "GET", "/api/users/"+stranger.id, http.StatusNotFound)
	wantCode(t, w.owner.testClient, "GET", "/api/users/"+stranger.id, http.StatusOK)

	// A listed viewer's token reads the same users.
	wantCode(t, w.token(t, w.viewer.id), "GET", "/api/users/"+w.editor.id, http.StatusOK)

	// A token for a user who cannot read the artifact reads nobody through it.
	wantCode(t, w.token(t, w.outside.id), "GET", "/api/users/"+w.owner.id, http.StatusNotFound)

	// Removed from the latest record, a member is no longer readable.
	next := w.art.nextEpoch()
	next.Members = nil
	for _, m := range w.art.latest.Members {
		if m.User != w.editor.id {
			next.Members = append(next.Members, m)
		}
	}
	next.Excluded = []e2e.ExcludedEntry{{User: w.editor.id, FP: w.editor.keys.fp(), Email: e2e.NormalizeEmail(w.editor.email)}}
	w.art.apply(next)
	wantCode(t, tok, "GET", "/api/users/"+w.editor.id, http.StatusNotFound)
	wantCode(t, tok, "GET", "/api/users/"+w.viewer.id, http.StatusOK)
}

func TestContentTokenMe(t *testing.T) {
	w := newContentWorld(t)
	var me struct {
		ID string `json:"id"`
	}
	w.token(t, w.viewer.id).mustDo("GET", "/api/me", nil, &me, http.StatusOK)
	if me.ID != w.viewer.id {
		t.Errorf("/api/me id = %q, want %q", me.ID, w.viewer.id)
	}
}

func TestContentTokenKeepsTheRole(t *testing.T) {
	w := newContentWorld(t)
	tok := w.token(t, w.viewer.id)
	wantCode(t, tok, "GET", w.vbase+"/files/a.txt", http.StatusOK)
	wantCode(t, tok, "GET", "/api/artifacts/"+w.art.id+"/membership", http.StatusOK)
	if r := tok.doRaw("PUT", w.vbase+"/files/b.txt", []byte("x")); r.StatusCode != http.StatusForbidden {
		t.Errorf("viewer token file put: %d, want 403", r.StatusCode)
	}
	if r := w.token(t, w.editor.id).doRaw("PUT", w.vbase+"/files/b.txt", []byte("x")); r.StatusCode != http.StatusOK {
		t.Errorf("editor token file put: %d, want 200", r.StatusCode)
	}
}

func TestContentTokenRevokedByTokenVersion(t *testing.T) {
	w := newContentWorld(t)
	u, err := w.s.store.UserByID(w.owner.id)
	if err != nil {
		t.Fatal(err)
	}
	stale := &testClient{t: t, base: w.base, token: mintContentTokenVersion(t, w.s, w.owner.id, w.art.id, u.TokenVersion+1)}
	wantCode(t, stale, "GET", "/api/me", http.StatusUnauthorized)
}

func contentTokenRequest(path, tok string) *http.Request {
	r := httptest.NewRequest("GET", path, nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

// The gate is the allowlist, but each layer below it refuses a content token
// on its own.
func TestContentTokenBackstops(t *testing.T) {
	w := newContentWorld(t)
	tok := mintContentToken(t, w.s, w.owner.id, w.art.id)

	called := false
	rec := httptest.NewRecorder()
	w.s.requireSession(func(http.ResponseWriter, *http.Request) { called = true })(rec, contentTokenRequest("/api/me", tok))
	if rec.Code != http.StatusNotFound || called {
		t.Errorf("requireSession: %d, handler called %v; want 404 and not called", rec.Code, called)
	}

	if u, err := w.s.currentUser(contentTokenRequest("/", tok)); err == nil || u != nil {
		t.Errorf("currentUser = %v, %v; want an error and no user", u, err)
	}

	c, _, _, err := w.s.callerOf(contentTokenRequest("/", tok))
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != access.ContentToken || c.TokenArtifactID != w.art.id {
		t.Errorf("callerOf: kind %v, artifact %q", c.Kind, c.TokenArtifactID)
	}

	// Past the gate, access.Check scopes the token to its artifact.
	b := newArtifact(t, w.owner, "other")
	rec = httptest.NewRecorder()
	w.s.mux.ServeHTTP(rec, contentTokenRequest("/api/artifacts/"+b.id+"/membership", tok))
	if rec.Code != http.StatusNotFound {
		t.Errorf("mux, other artifact's membership: %d, want 404", rec.Code)
	}

	// The artifact list, reached the same way, shows only the token's own.
	rec = httptest.NewRecorder()
	w.s.mux.ServeHTTP(rec, contentTokenRequest("/api/artifacts", tok))
	var list []gotArtifact
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != w.art.id {
		t.Errorf("mux, artifact list: %+v, want only %s", list, w.art.id)
	}
}
