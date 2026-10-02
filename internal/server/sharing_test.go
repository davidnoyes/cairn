package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/access"
	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/google/uuid"
)

// userKeys is a test user's key pairs. The test holds the private halves, so
// it can sign membership records as the user.
type userKeys struct {
	xpriv, xpub []byte
	seed, epub  []byte
}

func (k userKeys) fp() string { return hex.EncodeToString(e2e.Fingerprint(k.xpub, k.epub)) }

func (k userKeys) pair() e2e.KeyPair {
	return e2e.KeyPair{X25519: e2e.B64(k.xpub), Ed25519: e2e.B64(k.epub)}
}

func newUserKeys(t *testing.T) userKeys {
	t.Helper()
	xpriv, xpub, err := e2e.GenerateX25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed, epub, err := e2e.GenerateEd25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return userKeys{xpriv: xpriv, xpub: xpub, seed: seed, epub: epub}
}

// placeholderKeys are the keys testBundleWire gives every seedAccount user:
// the Ed25519 seed is known, the X25519 key has no private half.
func placeholderKeys() userKeys {
	seed := bytes.Repeat([]byte{5}, 32)
	_, epub, _ := e2e.GenerateEd25519(bytes.NewReader(seed))
	return userKeys{xpub: bytes.Repeat([]byte{3}, 32), seed: seed, epub: epub}
}

// bundleFor is testBundleWire with keys' public halves.
func bundleFor(t *testing.T, keys userKeys) store.Bundle {
	t.Helper()
	w := testBundleWire()
	w.X25519Pub = e2e.B64(keys.xpub)
	w.Ed25519Pub = e2e.B64(keys.epub)
	b, err := decodeBundle(w)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// actor is a signed-in test user with the keys behind their account.
type actor struct {
	*testClient
	id    string
	email string
	keys  userKeys
}

// seedKeyedAccount creates a verified account with fresh real keys and signs
// it in.
func seedKeyedAccount(t *testing.T, s *Server, base, email string) actor {
	t.Helper()
	keys := newUserKeys(t)
	u := seedAccountWith(t, s, email, email+"-password", false, bundleFor(t, keys))
	return actor{testClient: login(t, base, email, email+"-password"), id: u.ID, email: email, keys: keys}
}

// placeholderActor wraps a client signed in as a seedAccount user.
func placeholderActor(t *testing.T, c *testClient) actor {
	t.Helper()
	var me struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	c.mustDo("GET", "/api/me", nil, &me, http.StatusOK)
	return actor{testClient: c, id: me.ID, email: me.Email, keys: placeholderKeys()}
}

// testAK is a deterministic AK for an artifact and epoch.
func testAK(id string, epoch int) []byte {
	sum := sha256.Sum256(fmt.Appendf(nil, "ak|%s|%d", id, epoch))
	return sum[:]
}

func testCommit(t *testing.T, id string, epoch int) string {
	t.Helper()
	c, err := e2e.AKCommit(testAK(id, epoch), id, uint64(epoch))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// testLinkToken is the public link token for an epoch, as the header value.
func testLinkToken(t *testing.T, id string, epoch int) string {
	t.Helper()
	tok, err := e2e.LinkToken(testAK(id, epoch), id, uint64(epoch))
	if err != nil {
		t.Fatal(err)
	}
	return e2e.B64(tok)
}

func testLinkHash(t *testing.T, id string, epoch int) string {
	t.Helper()
	tok, _ := e2e.UnB64(testLinkToken(t, id, epoch))
	return e2e.LinkTokenHash(tok)
}

// fakeWrap has the size of a wrap; the server cannot open one, so it checks
// nothing else.
var fakeWrap = bytes.Repeat([]byte{9}, 81)

func testEstate(t *testing.T, id string, epoch int) map[string]any {
	t.Helper()
	key, err := e2e.EKSealKey(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := e2e.Seal(rand.Reader, key, [][]byte{[]byte("estate"), []byte(id), fmt.Appendf(nil, "%d", epoch)}, testAK(id, epoch))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"epoch": epoch, "sealed": e2e.B64(sealed)}
}

func signRecord(t *testing.T, signer actor, b e2e.MembershipBody) e2e.Envelope {
	t.Helper()
	body, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(signer.keys.seed, signer.id, "membership", body)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// owned is an artifact a test created, with its latest record.
type owned struct {
	t      *testing.T
	owner  actor
	id     string
	latest e2e.MembershipBody
	hash   string
}

func firstRecord(t *testing.T, owner actor, id string) e2e.MembershipBody {
	t.Helper()
	return e2e.MembershipBody{V: 1, Artifact: id, Epoch: 1, Seq: 1, Owner: owner.id, OwnerFP: owner.keys.fp(),
		AKCommit: testCommit(t, id, 1), Members: []e2e.Member{}, Excluded: []e2e.ExcludedEntry{}, Team: "none"}
}

// newArtifact creates a private artifact with no members, as owner.
func newArtifact(t *testing.T, owner actor, name string) *owned {
	t.Helper()
	id := uuid.NewString()
	b := firstRecord(t, owner, id)
	env := signRecord(t, owner, b)
	owner.mustDo("POST", "/api/artifacts", map[string]any{
		"id": id, "name": name, "description": "", "membership": env,
		"wraps": []any{}, "estate": []any{testEstate(t, id, 1)},
	}, nil, http.StatusCreated)
	return &owned{t: t, owner: owner, id: id, latest: b, hash: e2e.BodyHash(env.Body)}
}

// next is the latest record moved on by one at the same epoch.
func (o *owned) next() e2e.MembershipBody {
	b := o.latest
	b.Members = append([]e2e.Member{}, o.latest.Members...)
	b.Excluded = append([]e2e.ExcludedEntry{}, o.latest.Excluded...)
	b.Seq++
	b.Prev = o.hash
	return b
}

// nextEpoch is next at the following epoch.
func (o *owned) nextEpoch() e2e.MembershipBody {
	b := o.next()
	b.Epoch++
	b.AKCommit = testCommit(o.t, o.id, b.Epoch)
	return b
}

// change builds the PUT membership body for b with the wraps, estate copy,
// and link token hash the rules need.
func (o *owned) change(b e2e.MembershipBody) map[string]any {
	listed := map[string]string{}
	for _, m := range o.latest.Members {
		listed[m.User] = m.FP
	}
	wraps := []any{}
	for _, m := range b.Members {
		from := b.Epoch
		if fp, ok := listed[m.User]; !ok || fp != m.FP {
			from = 1
		} else if b.Epoch == o.latest.Epoch {
			continue
		}
		for e := from; e <= b.Epoch; e++ {
			wraps = append(wraps, map[string]any{"user": m.User, "epoch": e, "wrapped": e2e.B64(fakeWrap)})
		}
	}
	estate := []any{}
	if b.Epoch > o.latest.Epoch {
		estate = append(estate, testEstate(o.t, o.id, b.Epoch))
	}
	req := map[string]any{"membership": signRecord(o.t, o.owner, b), "wraps": wraps, "estate": estate}
	if b.Public {
		req["linkTokenHash"] = testLinkHash(o.t, o.id, b.Epoch)
	}
	return req
}

// apply PUTs b and expects it to land.
func (o *owned) apply(b e2e.MembershipBody) {
	o.t.Helper()
	req := o.change(b)
	var out struct {
		Epoch int `json:"epoch"`
	}
	o.owner.mustDo("PUT", "/api/artifacts/"+o.id+"/membership", req, &out, http.StatusOK)
	if out.Epoch != b.Epoch {
		o.t.Fatalf("PUT membership epoch = %d, want %d", out.Epoch, b.Epoch)
	}
	o.latest, o.hash = b, e2e.BodyHash(req["membership"].(e2e.Envelope).Body)
}

// share lists users at the same epoch with role.
func (o *owned) share(role string, users ...actor) {
	o.t.Helper()
	b := o.next()
	for _, u := range users {
		b.Members = append(b.Members, e2e.Member{User: u.id, Role: role, FP: u.keys.fp()})
	}
	sortMembers(b.Members)
	o.apply(b)
}

func sortMembers(ms []e2e.Member) {
	for i := 1; i < len(ms); i++ {
		for j := i; j > 0 && ms[j].User < ms[j-1].User; j-- {
			ms[j], ms[j-1] = ms[j-1], ms[j]
		}
	}
}

// linkToken is the current epoch's link token header value.
func (o *owned) linkToken() string { return testLinkToken(o.t, o.id, o.latest.Epoch) }

// makePublic makes the artifact public at the same epoch.
func (o *owned) makePublic() string {
	o.t.Helper()
	b := o.next()
	b.Public = true
	o.apply(b)
	return o.linkToken()
}

// pushVersion uploads a one-file version and returns its ID.
func pushVersion(t *testing.T, c *testClient, aid string) string {
	t.Helper()
	resp := c.upload("POST", "/api/artifacts/"+aid+"/versions", zipFrom(t, map[string]string{"index.html": "<h1>hi</h1>"}), nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("push: %d", resp.StatusCode)
	}
	return decode[struct {
		ID string `json:"id"`
	}](t, resp).ID
}

// status sends a request and returns the status with the decoded error body.
func status(c *testClient, method, path string, body any) (int, string) {
	c.t.Helper()
	var out map[string]any
	resp := c.do(method, path, body, &out)
	msg, _ := out["error"].(string)
	return resp.StatusCode, msg
}

func wantStatus(t *testing.T, c *testClient, method, path string, body any, want int) {
	t.Helper()
	if got, msg := status(c, method, path, body); got != want {
		t.Errorf("%s %s: %d %q, want %d", method, path, got, msg, want)
	}
}

type gotArtifact struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Owner        string `json:"owner"`
	Access       string `json:"access"`
	Epoch        int    `json:"epoch"`
	Team         string `json:"team"`
	Public       bool   `json:"public"`
	PublicWrites bool   `json:"publicWrites"`
	Transfer     *struct {
		To string `json:"to"`
		By string `json:"by"`
		At string `json:"at"`
	} `json:"transfer"`
}

func listIDs(t *testing.T, c *testClient) map[string]gotArtifact {
	t.Helper()
	var list []gotArtifact
	c.mustDo("GET", "/api/artifacts", nil, &list, http.StatusOK)
	out := map[string]gotArtifact{}
	for _, a := range list {
		out[a.ID] = a
	}
	return out
}

func anonWithLink(t *testing.T, base, link string) *testClient {
	return &testClient{t: t, base: base, link: link}
}

// Tests

func TestShareAndRevoke(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	b := seedKeyedAccount(t, s, ts.URL, "b@example.com")
	o := newArtifact(t, a, "notes")
	vid := pushVersion(t, a.testClient, o.id)
	base := "/api/artifacts/" + o.id
	vbase := base + "/versions/" + vid
	a.mustDo("POST", vbase+"/db/batch", map[string]any{"statements": []map[string]any{
		{"sql": "CREATE TABLE t (x INTEGER)"}, {"sql": "INSERT INTO t VALUES (1)"},
	}}, nil, http.StatusOK)

	// Before sharing, B sees nothing at all.
	if _, ok := listIDs(t, b.testClient)[o.id]; ok {
		t.Error("B lists A's artifact before it is shared")
	}
	for _, req := range []struct{ method, path string }{
		{"GET", base}, {"GET", base + "/versions"}, {"GET", vbase},
		{"GET", vbase + "/files"}, {"GET", base + "/membership"}, {"GET", base + "/keys"},
	} {
		wantStatus(t, b.testClient, req.method, req.path, nil, http.StatusNotFound)
	}
	wantStatus(t, b.testClient, "POST", vbase+"/db/query", map[string]any{"sql": "SELECT x FROM t"}, http.StatusNotFound)
	wantStatus(t, b.testClient, "POST", vbase+"/db/batch", map[string]any{"statements": []map[string]any{{"sql": "DELETE FROM t"}}}, http.StatusNotFound)

	// Shared as an editor through a signed record, B reads and writes.
	o.share("editor", b)
	if v, ok := listIDs(t, b.testClient)[o.id]; !ok || v.Access != "editor" || v.Owner != a.id || v.Epoch != 1 {
		t.Errorf("B's list entry after sharing: %+v (listed %v)", v, ok)
	}
	var view gotArtifact
	b.mustDo("GET", base, nil, &view, http.StatusOK)
	if view.Access != "editor" {
		t.Errorf("B's access: %q", view.Access)
	}
	b.mustDo("POST", vbase+"/db/query", map[string]any{"sql": "SELECT x FROM t"}, nil, http.StatusOK)
	b.mustDo("POST", vbase+"/db/batch", map[string]any{"statements": []map[string]any{{"sql": "INSERT INTO t VALUES (2)"}}}, nil, http.StatusOK)

	// Removed at the next epoch, B loses access.
	next := o.nextEpoch()
	next.Members = []e2e.Member{}
	next.Excluded = []e2e.ExcludedEntry{{User: b.id, FP: b.keys.fp(), Email: e2e.NormalizeEmail(b.email)}}
	o.apply(next)
	if _, ok := listIDs(t, b.testClient)[o.id]; ok {
		t.Error("B still lists the artifact after removal")
	}
	wantStatus(t, b.testClient, "GET", base, nil, http.StatusNotFound)
	wantStatus(t, b.testClient, "POST", vbase+"/db/query", map[string]any{"sql": "SELECT x FROM t"}, http.StatusNotFound)
	wantStatus(t, b.testClient, "GET", base+"/keys", nil, http.StatusNotFound)
}

func TestViewerAndEditorPowers(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	viewer := seedKeyedAccount(t, s, ts.URL, "v@example.com")
	editor := seedKeyedAccount(t, s, ts.URL, "e@example.com")
	o := newArtifact(t, a, "board")
	vid := pushVersion(t, a.testClient, o.id)
	o.share("viewer", viewer)
	o.share("editor", editor)
	base := "/api/artifacts/" + o.id
	vbase := base + "/versions/" + vid
	a.mustDo("POST", vbase+"/db/batch", map[string]any{"statements": []map[string]any{{"sql": "CREATE TABLE t (x INTEGER)"}}}, nil, http.StatusOK)
	batch := map[string]any{"statements": []map[string]any{{"sql": "INSERT INTO t VALUES (1)"}}}
	zip := zipFrom(t, map[string]string{"index.html": "v2"})

	// A viewer reads but cannot write anything.
	viewer.mustDo("GET", base, nil, nil, http.StatusOK)
	viewer.mustDo("GET", base+"/versions", nil, nil, http.StatusOK)
	viewer.mustDo("GET", base+"/membership", nil, nil, http.StatusOK)
	viewer.mustDo("POST", vbase+"/db/query", map[string]any{"sql": "SELECT count(*) FROM t"}, nil, http.StatusOK)
	// The query endpoint gives a viewer the read-only pool.
	wantStatus(t, viewer.testClient, "POST", vbase+"/db/query", map[string]any{"sql": "INSERT INTO t VALUES (9)"}, http.StatusBadRequest)
	wantStatus(t, viewer.testClient, "POST", vbase+"/db/batch", batch, http.StatusForbidden)
	if r := viewer.doRaw("PUT", vbase+"/files/x.txt", []byte("x")); r.StatusCode != http.StatusForbidden {
		t.Errorf("viewer file put: %d", r.StatusCode)
	}
	wantStatus(t, viewer.testClient, "DELETE", vbase+"/files/x.txt", nil, http.StatusForbidden)
	if r := viewer.upload("POST", base+"/versions", zip, nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("viewer push: %d", r.StatusCode)
	}
	if r := viewer.upload("PUT", vbase, zip, nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("viewer replace: %d", r.StatusCode)
	}
	wantStatus(t, viewer.testClient, "PATCH", base, map[string]any{"name": "x"}, http.StatusForbidden)
	wantStatus(t, viewer.testClient, "POST", base+"/resources", map[string]any{"type": "t", "value": "v"}, http.StatusForbidden)
	wantStatus(t, viewer.testClient, "PATCH", vbase, map[string]any{"name": "x"}, http.StatusForbidden)
	wantStatus(t, viewer.testClient, "DELETE", vbase, nil, http.StatusForbidden)
	wantStatus(t, viewer.testClient, "DELETE", vbase+"/files/x.txt", nil, http.StatusForbidden)
	wantStatus(t, viewer.testClient, "DELETE", base, nil, http.StatusForbidden)

	// An editor pushes and writes.
	editor.mustDo("POST", vbase+"/db/query", map[string]any{"sql": "INSERT INTO t VALUES (2)"}, nil, http.StatusOK)
	editor.mustDo("POST", vbase+"/db/batch", batch, nil, http.StatusOK)
	put := func(c *testClient, path string) int {
		req, _ := http.NewRequest("PUT", c.base+path, strings.NewReader("hello"))
		req.Header.Set("Content-Type", "application/octet-stream")
		c.setHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := put(editor.testClient, vbase+"/files/e.txt"); got != http.StatusOK {
		t.Errorf("editor file put: %d", got)
	}
	if got := put(viewer.testClient, vbase+"/files/v.txt"); got != http.StatusForbidden {
		t.Errorf("viewer file put: %d", got)
	}
	r := editor.upload("POST", base+"/versions", zip, nil)
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("editor push: %d", r.StatusCode)
	}
	pushed := decode[struct {
		ID       string `json:"id"`
		PushedBy string `json:"pushedBy"`
		Epoch    int    `json:"epoch"`
	}](t, r)
	var got struct {
		PushedBy string `json:"pushedBy"`
		Epoch    int    `json:"epoch"`
	}
	a.mustDo("GET", base+"/versions/"+pushed.ID, nil, &got, http.StatusOK)
	if got.PushedBy != editor.id || got.Epoch != 1 {
		t.Errorf("pushed version: %+v, want pushedBy %s at epoch 1", got, editor.id)
	}
	if r := editor.upload("PUT", base+"/versions/"+pushed.ID, zip, nil); r.StatusCode != http.StatusOK {
		t.Errorf("editor replace: %d", r.StatusCode)
	}
	// A replacement records whoever replaced it.
	r = a.upload("PUT", base+"/versions/"+pushed.ID, zip, nil)
	replaced := decode[struct {
		PushedBy string `json:"pushedBy"`
	}](t, r)
	if r.StatusCode != http.StatusOK || replaced.PushedBy != a.id {
		t.Errorf("owner replace: %d, pushedBy %q, want %s", r.StatusCode, replaced.PushedBy, a.id)
	}
	editor.mustDo("PATCH", base, map[string]any{"name": "renamed"}, nil, http.StatusOK)
	var res store.Resource
	editor.mustDo("POST", base+"/resources", map[string]any{"type": "t", "value": "v"}, &res, http.StatusCreated)
	wantStatus(t, viewer.testClient, "DELETE", base+"/resources/"+res.ID, nil, http.StatusForbidden)
	editor.mustDo("DELETE", base+"/resources/"+res.ID, nil, nil, http.StatusOK)
	editor.mustDo("PATCH", vbase, map[string]any{"name": "first"}, nil, http.StatusOK)
	editor.mustDo("DELETE", vbase+"/files/e.txt", nil, nil, http.StatusOK)

	// But cannot share, delete, or change membership.
	wantStatus(t, editor.testClient, "PUT", base+"/membership", o.change(o.next()), http.StatusForbidden)
	wantStatus(t, editor.testClient, "DELETE", base, nil, http.StatusForbidden)
	wantStatus(t, editor.testClient, "DELETE", vbase, nil, http.StatusForbidden)

	// The owner deletes a version and the artifact.
	a.mustDo("DELETE", vbase, nil, nil, http.StatusOK)
	a.mustDo("DELETE", base, nil, nil, http.StatusOK)
	wantStatus(t, a.testClient, "GET", base, nil, http.StatusNotFound)
}

func TestTeamWrapGrantsRead(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	withWrap := seedKeyedAccount(t, s, ts.URL, "t1@example.com")
	without := seedKeyedAccount(t, s, ts.URL, "t2@example.com")
	o := newArtifact(t, a, "team")
	vid := pushVersion(t, a.testClient, o.id)
	b := o.next()
	b.Team = "editor"
	o.apply(b)
	if err := s.store.WithArtifact(o.id, func(tx *store.ArtifactTx) error {
		return tx.PutWrap(store.Wrap{UserID: withWrap.id, Epoch: 1, Wrapped: fakeWrap, FP: withWrap.keys.fp()})
	}); err != nil {
		t.Fatal(err)
	}
	base := "/api/artifacts/" + o.id
	vbase := base + "/versions/" + vid

	var view gotArtifact
	withWrap.mustDo("GET", base, nil, &view, http.StatusOK)
	if view.Access != "team" || view.Team != "editor" {
		t.Errorf("team member's view: %+v", view)
	}
	withWrap.mustDo("POST", vbase+"/db/query", map[string]any{"sql": "SELECT 1"}, nil, http.StatusOK)
	var keys struct {
		Wraps []map[string]any `json:"wraps"`
	}
	withWrap.mustDo("GET", base+"/keys", nil, &keys, http.StatusOK)
	if len(keys.Wraps) != 1 {
		t.Errorf("team member's wraps: %+v", keys.Wraps)
	}
	wantStatus(t, withWrap.testClient, "POST", vbase+"/db/batch", map[string]any{"statements": []map[string]any{{"sql": "CREATE TABLE t (x)"}}}, http.StatusForbidden)
	if r := withWrap.upload("POST", base+"/versions", zipFrom(t, map[string]string{"index.html": "x"}), nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("team member push: %d", r.StatusCode)
	}

	wantStatus(t, without.testClient, "GET", base, nil, http.StatusNotFound)
	if _, ok := listIDs(t, without.testClient)[o.id]; ok {
		t.Error("a team member without a wrap lists the artifact")
	}
}

func TestPublicLink(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	b := seedKeyedAccount(t, s, ts.URL, "b@example.com")
	o := newArtifact(t, a, "site")
	vid := pushVersion(t, a.testClient, o.id)
	base := "/api/artifacts/" + o.id
	page := "/artifacts/" + o.id + "/" + vid + "/"

	// While private, the right token for epoch 1 opens nothing.
	early := anonWithLink(t, ts.URL, testLinkToken(t, o.id, 1))
	wantStatus(t, early, "GET", base, nil, http.StatusNotFound)

	link := o.makePublic()
	anon := &testClient{t: t, base: ts.URL}
	wrong := anonWithLink(t, ts.URL, e2e.B64(bytes.Repeat([]byte{1}, 32)))
	garbled := anonWithLink(t, ts.URL, "not base64!")
	right := anonWithLink(t, ts.URL, link)
	for _, c := range []*testClient{anon, wrong, garbled} {
		wantStatus(t, c, "GET", base, nil, http.StatusNotFound)
		wantStatus(t, c, "GET", base+"/versions", nil, http.StatusNotFound)
	}
	var view gotArtifact
	right.mustDo("GET", base, nil, &view, http.StatusOK)
	if view.Access != "link" || !view.Public {
		t.Errorf("link view: %+v", view)
	}
	right.mustDo("GET", base+"/versions", nil, nil, http.StatusOK)
	right.mustDo("GET", base+"/membership", nil, nil, http.StatusOK)
	// Every content read is open to the link, though the keys are not.
	vbase := base + "/versions/" + vid
	a.mustDo("POST", vbase+"/db/batch", map[string]any{"statements": []map[string]any{{"sql": "CREATE TABLE t (x)"}}}, nil, http.StatusOK)
	right.mustDo("GET", vbase, nil, nil, http.StatusOK)
	right.mustDo("GET", vbase+"/files", nil, nil, http.StatusOK)
	if r := right.doRaw("GET", vbase+"/db/download", nil); r.StatusCode != http.StatusOK {
		t.Errorf("link db download: %d", r.StatusCode)
	}
	// A link holder holds no wraps.
	wantStatus(t, right, "GET", base+"/keys", nil, http.StatusForbidden)
	if r := getLink(t, ts.URL+page, link); r.StatusCode != http.StatusOK {
		t.Errorf("page with link: %d", r.StatusCode)
	}
	if r := getLink(t, ts.URL+page, ""); r.StatusCode != http.StatusFound {
		t.Errorf("page without link: %d", r.StatusCode)
	}
	// A signed-in non-member with the token reads at link level.
	b.link = link
	b.mustDo("GET", base, nil, &view, http.StatusOK)
	if view.Access != "link" {
		t.Errorf("signed-in link access: %q", view.Access)
	}
	b.link = ""
	wantStatus(t, b.testClient, "GET", base, nil, http.StatusNotFound)

	// A new epoch needs a new hash, so the old link stops working.
	next := o.nextEpoch()
	next.Public = true
	o.apply(next)
	wantStatus(t, right, "GET", base, nil, http.StatusNotFound)
	newer := anonWithLink(t, ts.URL, o.linkToken())
	newer.mustDo("GET", base, nil, nil, http.StatusOK)

	// Made private, the current link stops too.
	private := o.nextEpoch()
	private.Public = false
	o.apply(private)
	wantStatus(t, newer, "GET", base, nil, http.StatusNotFound)
	stillNewer := anonWithLink(t, ts.URL, o.linkToken())
	wantStatus(t, stillNewer, "GET", base, nil, http.StatusNotFound)
}

// getLink loads a page anonymously, sending link as X-Cairn-Link-Token when
// set, without following redirects.
func getLink(t *testing.T, url, link string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "text/html")
	if link != "" {
		req.Header.Set("X-Cairn-Link-Token", link)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func TestPublicWrites(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	b := seedKeyedAccount(t, s, ts.URL, "b@example.com")
	o := newArtifact(t, a, "guestbook")
	vid := pushVersion(t, a.testClient, o.id)
	vbase := "/api/artifacts/" + o.id + "/versions/" + vid
	a.mustDo("POST", vbase+"/db/batch", map[string]any{"statements": []map[string]any{{"sql": "CREATE TABLE t (x INTEGER)"}}}, nil, http.StatusOK)
	link := o.makePublic()
	batch := map[string]any{"statements": []map[string]any{{"sql": "INSERT INTO t VALUES (1)"}}}
	insert := map[string]any{"sql": "INSERT INTO t VALUES (2)"}

	// Switch off: a signed-in link holder still cannot write.
	b.link = link
	wantStatus(t, b.testClient, "POST", vbase+"/db/batch", batch, http.StatusForbidden)
	wantStatus(t, b.testClient, "POST", vbase+"/db/query", insert, http.StatusBadRequest)

	next := o.next()
	next.PublicWrites = true
	o.apply(next)

	// Switch on: the token and a session together write.
	b.mustDo("POST", vbase+"/db/batch", batch, nil, http.StatusOK)
	b.mustDo("POST", vbase+"/db/query", insert, nil, http.StatusOK)
	// The token alone does not.
	anon := anonWithLink(t, ts.URL, link)
	wantStatus(t, anon, "POST", vbase+"/db/batch", batch, http.StatusForbidden)
	wantStatus(t, anon, "POST", vbase+"/db/query", insert, http.StatusBadRequest)
	// Nor does the session alone.
	b.link = ""
	wantStatus(t, b.testClient, "POST", vbase+"/db/batch", batch, http.StatusNotFound)
	// Public writes do not extend to pushing a version.
	b.link = link
	if r := b.upload("POST", "/api/artifacts/"+o.id+"/versions", zipFrom(t, map[string]string{"index.html": "x"}), nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("link holder push: %d", r.StatusCode)
	}
}

func TestChangedKeyReadsButCannotWrite(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	e := seedKeyedAccount(t, s, ts.URL, "e@example.com")
	o := newArtifact(t, a, "doc")
	vid := pushVersion(t, a.testClient, o.id)
	o.share("editor", e)
	vbase := "/api/artifacts/" + o.id + "/versions/" + vid
	batch := map[string]any{"statements": []map[string]any{{"sql": "CREATE TABLE t (x)"}}}

	hash, err := auth.HashPassword(string(testAuthKey("e@example.com-password")))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.ResetAccount(e.id, hash, bundleFor(t, newUserKeys(t)), time.Now()); err != nil {
		t.Fatal(err)
	}
	relogged := login(t, ts.URL, "e@example.com", "e@example.com-password")
	var view gotArtifact
	relogged.mustDo("GET", "/api/artifacts/"+o.id, nil, &view, http.StatusOK)
	if view.Access != "editor" {
		t.Errorf("access after key change: %q", view.Access)
	}
	relogged.mustDo("POST", vbase+"/db/query", map[string]any{"sql": "SELECT 1"}, nil, http.StatusOK)
	wantStatus(t, relogged, "POST", vbase+"/db/batch", batch, http.StatusForbidden)
	wantStatus(t, relogged, "PATCH", "/api/artifacts/"+o.id, map[string]any{"name": "x"}, http.StatusForbidden)
	if r := relogged.upload("POST", "/api/artifacts/"+o.id+"/versions", zipFrom(t, map[string]string{"index.html": "x"}), nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("changed-key push: %d", r.StatusCode)
	}
}

func TestUnreadableResourceReference(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	b := seedKeyedAccount(t, s, ts.URL, "b@example.com")
	x := newArtifact(t, a, "x")
	a.mustDo("POST", "/api/artifacts/"+x.id+"/resources", map[string]any{"type": "claude-session", "value": "sess-1"}, nil, http.StatusCreated)

	// B cannot see A's artifact through the reference: 404, never 409.
	wantStatus(t, b.testClient, "GET", "/api/artifacts/sess-1", nil, http.StatusNotFound)
	if r := get(t, ts.URL+"/artifacts/sess-1", b.token, ""); r.StatusCode != http.StatusNotFound {
		t.Errorf("B's page via A's reference: %d", r.StatusCode)
	}

	// With an artifact of B's own on the same reference, it resolves to B's.
	y := newArtifact(t, b, "y")
	b.mustDo("POST", "/api/artifacts/"+y.id+"/resources", map[string]any{"type": "claude-session", "value": "sess-1"}, nil, http.StatusCreated)
	var view gotArtifact
	b.mustDo("GET", "/api/artifacts/sess-1", nil, &view, http.StatusOK)
	if view.ID != y.id {
		t.Errorf("B's reference resolved to %s, want %s", view.ID, y.id)
	}

	// An artifact ID B cannot read does not shadow B's own reference of the
	// same value: the ID is looked up among readable artifacts only.
	b.mustDo("POST", "/api/artifacts/"+y.id+"/resources", map[string]any{"type": "t", "value": x.id}, nil, http.StatusCreated)
	b.mustDo("GET", "/api/artifacts/"+x.id, nil, &view, http.StatusOK)
	if view.ID != y.id {
		t.Errorf("B's reference %s resolved to %s, want %s", x.id, view.ID, y.id)
	}
	// For A, who can read x, the ID still comes first.
	a.mustDo("GET", "/api/artifacts/"+x.id, nil, &view, http.StatusOK)
	if view.ID != x.id {
		t.Errorf("A's own ID resolved to %s, want %s", view.ID, x.id)
	}

	// Two of A's own artifacts on one reference are still ambiguous.
	x2 := newArtifact(t, a, "x2")
	a.mustDo("POST", "/api/artifacts/"+x2.id+"/resources", map[string]any{"type": "claude-session", "value": "sess-1"}, nil, http.StatusCreated)
	wantStatus(t, a.testClient, "GET", "/api/artifacts/sess-1", nil, http.StatusConflict)
}

func TestCreateArtifactValidation(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	b := seedKeyedAccount(t, s, ts.URL, "b@example.com")
	create := func(id string, body e2e.MembershipBody, extra map[string]any) (int, string) {
		req := map[string]any{"id": id, "name": "n", "description": "", "membership": signRecord(t, a, body),
			"wraps": []any{}, "estate": []any{testEstate(t, id, 1)}}
		for k, v := range extra {
			req[k] = v
		}
		return status(a.testClient, "POST", "/api/artifacts", req)
	}

	for _, id := range []string{"not-a-uuid", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", strings.ToUpper(uuid.NewString()),
		"{" + uuid.NewString() + "}", strings.ReplaceAll(uuid.NewString(), "-", "")} {
		if got, msg := create(id, firstRecord(t, a, id), nil); got != http.StatusBadRequest || !strings.Contains(msg, "version 4") {
			t.Errorf("id %q: %d %q, want 400 about version 4", id, got, msg)
		}
	}
	// A v4 ID with a non-RFC 4122 variant is not a random UUID either.
	id := uuid.NewString()
	badVariant := id[:19] + "c" + id[20:]
	if got, _ := create(badVariant, firstRecord(t, a, badVariant), nil); got != http.StatusBadRequest {
		t.Errorf("non-RFC variant: %d", got)
	}

	if got, _ := create(id, firstRecord(t, a, id), map[string]any{"public": true}); got != http.StatusBadRequest {
		t.Errorf("public in create: %d", got)
	}
	if got, msg := create(id, firstRecord(t, a, id), map[string]any{"name": ""}); got != http.StatusBadRequest || msg != "name is required" {
		t.Errorf("empty name: %d %q", got, msg)
	}

	// A bad record: 400, naming the rule.
	bad := firstRecord(t, a, id)
	bad.Team = "everyone"
	if got, msg := create(id, bad, nil); got != http.StatusBadRequest || !strings.Contains(msg, "team") {
		t.Errorf("bad team: %d %q", got, msg)
	}
	// Signed by someone else for A's artifact.
	other := firstRecord(t, a, id)
	req := map[string]any{"id": id, "name": "n", "description": "", "membership": signRecord(t, b, other),
		"wraps": []any{}, "estate": []any{testEstate(t, id, 1)}}
	if got, msg := status(a.testClient, "POST", "/api/artifacts", req); got != http.StatusBadRequest || !strings.Contains(msg, "signer") {
		t.Errorf("foreign signer: %d %q", got, msg)
	}
	// Nothing refused was created.
	if _, ok := listIDs(t, a.testClient)[id]; ok {
		t.Fatal("a refused create left an artifact")
	}

	var view gotArtifact
	a.mustDo("POST", "/api/artifacts", map[string]any{"id": id, "name": "n", "description": "d",
		"membership": signRecord(t, a, firstRecord(t, a, id)), "wraps": []any{}, "estate": []any{testEstate(t, id, 1)}}, &view, http.StatusCreated)
	if view.ID != id || view.Owner != a.id || view.Access != "owner" || view.Epoch != 1 || view.Team != "none" || view.Public || view.Transfer != nil {
		t.Errorf("created: %+v", view)
	}
	// The ID is taken now, for A and for anyone else.
	if got, _ := create(id, firstRecord(t, a, id), nil); got != http.StatusConflict {
		t.Errorf("taken id: %d", got)
	}
	breq := map[string]any{"id": id, "name": "n", "description": "", "membership": signRecord(t, b, firstRecord(t, b, id)),
		"wraps": []any{}, "estate": []any{testEstate(t, id, 1)}}
	if got, _ := status(b.testClient, "POST", "/api/artifacts", breq); got != http.StatusConflict {
		t.Errorf("taken id by another user: %d", got)
	}
	// Anonymous cannot create.
	anon := &testClient{t: t, base: ts.URL}
	if got, _ := status(anon, "POST", "/api/artifacts", breq); got != http.StatusUnauthorized {
		t.Errorf("anonymous create: %d", got)
	}
}

func TestPutMembershipRefusals(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	o := newArtifact(t, a, "doc")
	path := "/api/artifacts/" + o.id + "/membership"

	stale := o.next()
	stale.Prev = strings.Repeat("0", 64)
	if got, msg := status(a.testClient, "PUT", path, o.change(stale)); got != http.StatusConflict || !strings.Contains(msg, "prev") {
		t.Errorf("stale prev: %d %q", got, msg)
	}
	bad := o.next()
	bad.Members = []e2e.Member{{User: a.id, Role: "editor", FP: a.keys.fp()}}
	if got, msg := status(a.testClient, "PUT", path, o.change(bad)); got != http.StatusBadRequest || !strings.Contains(msg, "members") {
		t.Errorf("owner listed as member: %d %q", got, msg)
	}
	public := o.next()
	public.Public = true
	req := o.change(public)
	delete(req, "linkTokenHash")
	if got, msg := status(a.testClient, "PUT", path, req); got != http.StatusBadRequest || !strings.Contains(msg, "linkTokenHash") {
		t.Errorf("public without hash: %d %q", got, msg)
	}
	req = o.change(o.next())
	req["public"] = true
	if got, _ := status(a.testClient, "PUT", path, req); got != http.StatusBadRequest {
		t.Errorf("unknown field: %d", got)
	}
	req = o.change(o.next())
	req["wraps"] = []any{map[string]any{"user": a.id, "epoch": 1, "wrapped": "%%%"}}
	if got, _ := status(a.testClient, "PUT", path, req); got != http.StatusBadRequest {
		t.Errorf("bad base64 wrap: %d", got)
	}
	// Nothing refused landed: the next record still applies.
	o.apply(o.next())
}

func TestGetMembership(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	e := seedKeyedAccount(t, s, ts.URL, "e@example.com")
	v := seedKeyedAccount(t, s, ts.URL, "v@example.com")
	o := newArtifact(t, a, "doc")
	o.share("editor", e)
	o.share("viewer", v)
	link := o.makePublic()

	type view struct {
		Records    []e2e.Envelope          `json:"records"`
		Offers     map[string]e2e.Envelope `json:"offers"`
		Owners     map[string]e2e.KeyPair  `json:"owners"`
		Rotations  map[string]any          `json:"rotations"`
		Successors map[string]any          `json:"successors"`
		Keys       map[string]e2e.KeyPair  `json:"keys"`
	}
	var got view
	v.mustDo("GET", "/api/artifacts/"+o.id+"/membership", nil, &got, http.StatusOK)
	if len(got.Records) != 4 || e2e.BodyHash(got.Records[3].Body) != o.hash || got.Records[0].Signer != a.id {
		t.Errorf("records: %d, latest matches %v", len(got.Records), len(got.Records) == 4 && e2e.BodyHash(got.Records[3].Body) == o.hash)
	}
	if len(got.Owners) != 1 || got.Owners[a.keys.fp()] != a.keys.pair() {
		t.Errorf("owners: %+v", got.Owners)
	}
	if got.Offers == nil || len(got.Offers) != 0 || got.Rotations == nil || got.Successors == nil {
		t.Errorf("offers %v rotations %v successors %v", got.Offers, got.Rotations, got.Successors)
	}
	if got.Keys != nil {
		t.Errorf("a viewer got link-scope keys: %+v", got.Keys)
	}
	// The chain the server serves verifies, anchored at the owner.
	if _, err := e2e.VerifyChain(e2e.ChainInput{Artifact: o.id, Records: got.Records, Owners: got.Owners, Offers: got.Offers, Anchor: a.keys.fp()}); err != nil {
		t.Errorf("served chain does not verify: %v", err)
	}

	// Link scope adds every listed editor's keys, and nobody else's.
	var linked view
	anonWithLink(t, ts.URL, link).mustDo("GET", "/api/artifacts/"+o.id+"/membership", nil, &linked, http.StatusOK)
	if len(linked.Keys) != 1 || linked.Keys[e.id] != e.keys.pair() {
		t.Errorf("link keys: %+v", linked.Keys)
	}

	// An accepted offer is served under the transfer hash its record names.
	offer := e2e.Envelope{Body: []byte(`{"offer":1}`), Sig: bytes.Repeat([]byte{1}, 64), Signer: a.id}
	offerHash := e2e.BodyHash(offer.Body)
	accept := o.next()
	accept.Transfer = offerHash
	env := signRecord(t, a, accept)
	if err := s.store.WithArtifact(o.id, func(tx *store.ArtifactTx) error {
		if err := tx.PutOffer(store.Offer{To: e.id, By: "owner", Hash: offerHash, Envelope: &store.Envelope{Body: offer.Body, Sig: offer.Sig, Signer: offer.Signer}}); err != nil {
			return err
		}
		if err := tx.SetOfferState("accepted"); err != nil {
			return err
		}
		commit, _ := hex.DecodeString(accept.AKCommit)
		return tx.AppendRecord(&store.Record{Seq: accept.Seq, Prev: accept.Prev, Epoch: accept.Epoch, OwnerID: accept.Owner, OwnerFp: accept.OwnerFP,
			AKCommit: commit, Team: accept.Team, Public: accept.Public, PublicWrites: accept.PublicWrites, Transfer: offerHash,
			Envelope: store.Envelope{Body: env.Body, Sig: env.Sig, Signer: env.Signer}})
	}); err != nil {
		t.Fatal(err)
	}
	v.mustDo("GET", "/api/artifacts/"+o.id+"/membership", nil, &got, http.StatusOK)
	if o, ok := got.Offers[offerHash]; !ok || !bytes.Equal(o.Body, offer.Body) || o.Signer != a.id {
		t.Errorf("offers after acceptance: %+v", got.Offers)
	}
}

func TestKeysReturnsOnlyTheCallersWraps(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	v := seedKeyedAccount(t, s, ts.URL, "v@example.com")
	w := seedKeyedAccount(t, s, ts.URL, "w@example.com")
	o := newArtifact(t, a, "doc")
	o.share("viewer", v, w)
	next := o.nextEpoch()
	o.apply(next)
	path := "/api/artifacts/" + o.id + "/keys"

	type keys struct {
		Wraps []struct {
			Epoch   int    `json:"epoch"`
			Wrapped string `json:"wrapped"`
			FP      string `json:"fp"`
		} `json:"wraps"`
		Estate []struct {
			Epoch  int    `json:"epoch"`
			Sealed string `json:"sealed"`
		} `json:"estate"`
	}
	var mine keys
	v.mustDo("GET", path, nil, &mine, http.StatusOK)
	if len(mine.Wraps) != 2 || mine.Wraps[0].Epoch != 1 || mine.Wraps[1].Epoch != 2 || mine.Wraps[0].FP != v.keys.fp() ||
		mine.Wraps[0].Wrapped != e2e.B64(fakeWrap) || mine.Estate == nil || len(mine.Estate) != 0 {
		t.Errorf("viewer's keys: %+v", mine)
	}
	var owner keys
	a.mustDo("GET", path, nil, &owner, http.StatusOK)
	if owner.Wraps == nil || len(owner.Wraps) != 0 || len(owner.Estate) != 2 || owner.Estate[1].Epoch != 2 {
		t.Errorf("owner's keys: %+v", owner)
	}
	sealed, _ := e2e.UnB64(owner.Estate[0].Sealed)
	if len(sealed) != 61 {
		t.Errorf("estate copy: %d bytes", len(sealed))
	}
}

func TestArtifactJSONAndPatch(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	e := seedKeyedAccount(t, s, ts.URL, "e@example.com")
	o := newArtifact(t, a, "doc")
	o.share("editor", e)
	base := "/api/artifacts/" + o.id

	var raw map[string]json.RawMessage
	a.mustDo("GET", base, nil, &raw, http.StatusOK)
	for _, k := range []string{"id", "name", "description", "owner", "access", "epoch", "team", "public", "publicWrites", "transfer", "createdAt", "updatedAt"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("artifact JSON lacks %q", k)
		}
	}
	if string(raw["transfer"]) != "null" {
		t.Errorf("transfer: %s", raw["transfer"])
	}

	// An open offer shows as transfer.
	if err := s.store.WithArtifact(o.id, func(tx *store.ArtifactTx) error {
		return tx.PutOffer(store.Offer{To: e.id, By: "admin"})
	}); err != nil {
		t.Fatal(err)
	}
	var view gotArtifact
	e.mustDo("GET", base, nil, &view, http.StatusOK)
	if view.Transfer == nil || view.Transfer.To != e.id || view.Transfer.By != "admin" || view.Transfer.At == "" {
		t.Errorf("transfer: %+v", view.Transfer)
	}

	wantStatus(t, a.testClient, "PATCH", base, map[string]any{"public": true}, http.StatusBadRequest)
	a.mustDo("PATCH", base, map[string]any{"name": "renamed", "description": "d"}, &view, http.StatusOK)
	if view.Name != "renamed" || view.Access != "owner" {
		t.Errorf("patched: %+v", view)
	}
}

func TestAdminWithoutAccessGets404(t *testing.T) {
	s, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	o := newArtifact(t, a, "private")
	vid := pushVersion(t, a.testClient, o.id)
	base := "/api/artifacts/" + o.id
	for _, req := range []struct{ method, path string }{
		{"GET", base}, {"PATCH", base}, {"DELETE", base}, {"GET", base + "/membership"},
		{"GET", base + "/versions/" + vid}, {"DELETE", base + "/versions/" + vid},
	} {
		var body any
		if req.method == "PATCH" {
			body = map[string]any{"name": "x"}
		}
		wantStatus(t, admin, req.method, req.path, body, http.StatusNotFound)
	}
	wantStatus(t, admin, "PUT", base+"/membership", o.change(o.next()), http.StatusNotFound)
	if _, ok := listIDs(t, admin)[o.id]; ok {
		t.Error("the admin lists an artifact they have no access to")
	}
	if r := get(t, ts.URL+"/artifacts/"+o.id+"/"+vid+"/", admin.token, ""); r.StatusCode != http.StatusNotFound {
		t.Errorf("admin page: %d", r.StatusCode)
	}
	if r := get(t, ts.URL+"/shared/"+o.id, admin.token, ""); r.StatusCode != http.StatusNotFound {
		t.Errorf("admin shell: %d", r.StatusCode)
	}
}

func TestLinkHashOnAPrivateArtifactOpensNothing(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	o := newArtifact(t, a, "doc")
	// The store clears the hash when an artifact goes private; the link check
	// must not rely on that alone.
	if err := s.store.WithArtifact(o.id, func(tx *store.ArtifactTx) error {
		return tx.SetPublicToken(testLinkHash(t, o.id, 1), 1)
	}); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, anonWithLink(t, ts.URL, testLinkToken(t, o.id, 1)), "GET", "/api/artifacts/"+o.id, nil, http.StatusNotFound)
}

// TestLinkMatchesRefusesAPrivateArtifact calls linkMatches itself: through
// HTTP the access check also requires a public artifact, so only a direct call
// notices if linkMatches stops requiring it.
func TestLinkMatchesRefusesAPrivateArtifact(t *testing.T) {
	id := uuid.NewString()
	token, err := e2e.UnB64(testLinkToken(t, id, 1))
	if err != nil {
		t.Fatal(err)
	}
	a := &store.Artifact{ID: id, Epoch: 1, PublicEpoch: 1, PublicTokenHash: testLinkHash(t, id, 1)}
	if linkMatches(a, token) {
		t.Error("a private artifact's stored token hash at the current epoch opened a link")
	}
	a.Public = true
	if !linkMatches(a, token) {
		t.Error("the same artifact, public, refused the right token")
	}
}

func TestPushRecordsTheEpochItWasPushedUnder(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	o := newArtifact(t, a, "epochs")
	o.apply(o.nextEpoch())
	zip := zipFrom(t, map[string]string{"index.html": "<h1>hi</h1>"})
	base := "/api/artifacts/" + o.id + "/versions"

	type written struct {
		ID       string `json:"id"`
		PushedBy string `json:"pushedBy"`
		Epoch    int    `json:"epoch"`
	}
	pushed := decode[written](t, a.upload("POST", base, zip, nil))
	if pushed.PushedBy != a.id || pushed.Epoch != 2 {
		t.Errorf("create answer: %+v, want pushedBy %s at epoch 2", pushed, a.id)
	}
	var got written
	a.mustDo("GET", base+"/"+pushed.ID, nil, &got, http.StatusOK)
	if got.PushedBy != a.id || got.Epoch != 2 {
		t.Errorf("stored version: %+v, want pushedBy %s at epoch 2", got, a.id)
	}

	// A replacement after another epoch change records the new epoch.
	o.apply(o.nextEpoch())
	replaced := decode[written](t, a.upload("PUT", base+"/"+pushed.ID, zip, nil))
	if replaced.PushedBy != a.id || replaced.Epoch != 3 {
		t.Errorf("replace answer: %+v, want pushedBy %s at epoch 3", replaced, a.id)
	}
}

func TestConcurrentMembershipWritesOnOnePrev(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	b := seedKeyedAccount(t, s, ts.URL, "b@example.com")
	c := seedKeyedAccount(t, s, ts.URL, "c@example.com")
	o := newArtifact(t, a, "race")
	path := "/api/artifacts/" + o.id + "/membership"

	// Two different valid records that both follow the same latest one.
	var reqs [2]map[string]any
	for i, u := range []actor{b, c} {
		rec := o.next()
		rec.Members = []e2e.Member{{User: u.id, Role: "viewer", FP: u.keys.fp()}}
		reqs[i] = o.change(rec)
	}

	var codes [2]int
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range reqs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes[i], _ = status(a.testClient, "PUT", path, reqs[i])
		}()
	}
	close(start)
	wg.Wait()

	winner := 0
	switch {
	case codes[0] == http.StatusOK && codes[1] == http.StatusConflict:
	case codes[1] == http.StatusOK && codes[0] == http.StatusConflict:
		winner = 1
	default:
		t.Fatalf("statuses = %v, want one 200 and one 409", codes)
	}

	var got struct {
		Records []e2e.Envelope `json:"records"`
	}
	a.mustDo("GET", path, nil, &got, http.StatusOK)
	if len(got.Records) != 2 {
		t.Fatalf("stored chain has %d records, want 2", len(got.Records))
	}
	want := e2e.BodyHash(reqs[winner]["membership"].(e2e.Envelope).Body)
	if e2e.BodyHash(got.Records[1].Body) != want {
		t.Errorf("stored record is not the winner's (request %d)", winner)
	}
}

func TestMembershipOwnersAreKeyedByTheirOwnFingerprint(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	o := newArtifact(t, a, "doc")

	// The owner's keys change after the record that names their old
	// fingerprint. Their new keys must not be served under the old one.
	hash, err := auth.HashPassword(string(testAuthKey("a@example.com-password")))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.ResetAccount(a.id, hash, bundleFor(t, newUserKeys(t)), time.Now()); err != nil {
		t.Fatal(err)
	}
	relogged := login(t, ts.URL, "a@example.com", "a@example.com-password")
	var got struct {
		Owners map[string]e2e.KeyPair `json:"owners"`
	}
	relogged.mustDo("GET", "/api/artifacts/"+o.id+"/membership", nil, &got, http.StatusOK)
	for fp, pair := range got.Owners {
		x, _ := e2e.UnB64(pair.X25519)
		ed, _ := e2e.UnB64(pair.Ed25519)
		if hex.EncodeToString(e2e.Fingerprint(x, ed)) != fp {
			t.Errorf("owners[%s] holds keys with a different fingerprint", fp)
		}
	}
}

func TestLinkTokenIsOnlyForTheStoredEpoch(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	o := newArtifact(t, a, "doc")
	next := o.nextEpoch()
	next.Public = true
	o.apply(next)
	base := "/api/artifacts/" + o.id
	anonWithLink(t, ts.URL, o.linkToken()).mustDo("GET", base, nil, nil, http.StatusOK)
	// A hash stored for an earlier epoch than the artifact's opens nothing,
	// even when the token matches it.
	if err := s.store.WithArtifact(o.id, func(tx *store.ArtifactTx) error {
		return tx.SetPublicToken(testLinkHash(t, o.id, 2), 1)
	}); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, anonWithLink(t, ts.URL, o.linkToken()), "GET", base, nil, http.StatusNotFound)
}

// A wrap under a fingerprint that is no longer the user's marks their key
// changed, even when the record already lists them, or approved them, under
// the new one. The API keeps wraps and approvals in step, so only a direct
// call reaches these.
func TestPendingStateStaleWrap(t *testing.T) {
	latest := &e2e.MembershipBody{Epoch: 2, Team: access.TeamViewer}
	u := &store.KeyedUser{ID: "u", FP: "new"}
	stale := []store.Wrap{{UserID: "u", Epoch: 2, FP: "old"}}
	listed := map[string]e2e.Member{"u": {User: "u", FP: "new"}}
	never := func(string) bool { return false }
	always := func(string) bool { return true }
	cases := []struct {
		name     string
		listed   map[string]e2e.Member
		approval *store.Approval
		explain  func(string) bool
		want     string
	}{
		{"listed under the new key", listed, nil, never, pendingKeyChanged},
		{"listed under the new key, rotation explained", listed, nil, always, pendingRotated},
		{"approved under the new key", nil, &store.Approval{UserID: "u", FP: "new", Epoch: 2}, never, pendingKeyChanged},
	}
	for _, c := range cases {
		if got := pendingState(latest, u, c.listed, stale, c.approval, c.explain); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
