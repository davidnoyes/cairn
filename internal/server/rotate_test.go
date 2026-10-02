package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// Key rotation: POST /api/me/rotate, GET /api/users/{id}/rotations, and what
// a rotation changes in membership and pending. See "Rotating keys" in
// design/e2e-api.md.

var newWrap = bytes.Repeat([]byte{0x55}, 81)

type heldWrap struct {
	artifact string
	epoch    int
	fp       string
}

// heldWraps reads every wrap userID holds, straight from the database.
func heldWraps(t *testing.T, s *Server, userID string) []heldWrap {
	t.Helper()
	rows, err := s.store.DB().Query(`SELECT artifact_id, epoch, fp FROM artifact_keys WHERE user_id = ? ORDER BY artifact_id, epoch`, userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []heldWrap
	for rows.Next() {
		var h heldWrap
		if err := rows.Scan(&h.artifact, &h.epoch, &h.fp); err != nil {
			t.Fatal(err)
		}
		out = append(out, h)
	}
	return out
}

// wrapDump is every wrap row of every artifact, to compare before and after.
func wrapDump(t *testing.T, s *Server) string {
	t.Helper()
	rows, err := s.store.DB().Query(`SELECT artifact_id, epoch, user_id, hex(wrapped), fp FROM artifact_keys ORDER BY 1, 2, 3`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var sb strings.Builder
	for rows.Next() {
		var a, u, w, fp string
		var e int
		if err := rows.Scan(&a, &e, &u, &w, &fp); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&sb, "%s %d %s %s %s\n", a, e, u, w, fp)
	}
	return sb.String()
}

// rotation builds a valid POST /api/me/rotate body for who, moving to keys nk,
// and lets a test break one part of it.
type rotation struct {
	t     *testing.T
	s     *Server
	base  string
	who   actor
	nk    userKeys
	owned []*owned
	next  map[string]bool // artifacts moved to the next epoch
	seq   int
	// wraps defaults to every wrap who holds under their current fingerprint.
	wraps []heldWrap
	built map[string]e2e.MembershipBody
	envs  map[string]e2e.Envelope
}

func newRotation(t *testing.T, s *Server, base string, who actor, owned ...*owned) *rotation {
	t.Helper()
	r := &rotation{t: t, s: s, base: base, who: who, nk: newUserKeys(t), owned: owned, next: map[string]bool{}, seq: 1}
	for _, h := range heldWraps(t, s, who.id) {
		if h.fp == who.keys.fp() {
			r.wraps = append(r.wraps, h)
		}
	}
	return r
}

// asNew is the user under the new keys, signed in again.
func (r *rotation) asNew() actor {
	return actor{testClient: login(r.t, r.base, r.who.email, r.who.email+"-password"), id: r.who.id, email: r.who.email, keys: r.nk}
}

func (r *rotation) body() e2e.RotationBody {
	return e2e.RotationBody{V: 1, User: r.who.id, Seq: r.seq, Old: r.who.keys.pair(), New: r.nk.pair()}
}

// sign signs b under the old key, and under newSeed.
func (r *rotation) sign(b e2e.RotationBody, newSeed []byte) e2e.Envelope {
	r.t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		r.t.Fatal(err)
	}
	env, err := e2e.SignRotation(r.who.keys.seed, newSeed, raw, r.who.id)
	if err != nil {
		r.t.Fatal(err)
	}
	return env
}

func (r *rotation) bundle() bundleWire {
	w := testBundleWire()
	w.X25519Pub = e2e.B64(r.nk.xpub)
	w.Ed25519Pub = e2e.B64(r.nk.epub)
	w.EK = e2e.B64(bytes.Repeat([]byte{0x77}, sealedKeyLen))
	return w
}

func (r *rotation) keyringRev() int {
	r.t.Helper()
	var k keyringBody
	r.who.mustDo("GET", "/api/me/keyring", nil, &k, http.StatusOK)
	return k.Rev
}

// request is the valid body.
func (r *rotation) request() map[string]any {
	r.t.Helper()
	newActor := actor{testClient: r.who.testClient, id: r.who.id, email: r.who.email, keys: r.nk}
	wraps := []any{}
	for _, h := range r.wraps {
		wraps = append(wraps, map[string]any{"artifact": h.artifact, "epoch": h.epoch, "wrapped": e2e.B64(newWrap)})
	}
	records, estate := []any{}, []any{}
	r.built, r.envs = map[string]e2e.MembershipBody{}, map[string]e2e.Envelope{}
	for _, o := range r.owned {
		b := o.next()
		if r.next[o.id] {
			b = o.nextEpoch()
		}
		b.OwnerFP = r.nk.fp()
		ch := o.change(b)
		env := signRecord(r.t, newActor, b)
		r.built[o.id], r.envs[o.id] = b, env
		rec := map[string]any{"artifact": o.id, "membership": env, "wraps": ch["wraps"]}
		if h, ok := ch["linkTokenHash"]; ok {
			rec["linkTokenHash"] = h
		}
		records = append(records, rec)
		for e := 1; e <= b.Epoch; e++ {
			est := testEstate(r.t, o.id, e)
			est["artifact"] = o.id
			estate = append(estate, est)
		}
	}
	return map[string]any{
		"authKey":  e2e.B64(testAuthKey(r.who.email + "-password")),
		"bundle":   r.bundle(),
		"rotation": r.sign(r.body(), r.nk.seed),
		"keyring":  map[string]any{"rev": r.keyringRev() + 1, "keyring": e2e.B64([]byte("sealed keyring after rotation"))},
		"wraps":    wraps,
		"estate":   estate,
		"records":  records,
	}
}

type rotateAnswer struct {
	Seq    int            `json:"seq"`
	Epochs map[string]int `json:"epochs"`
}

// do sends req as c and returns the status and the decoded error.
func (r *rotation) post(c *testClient, req any) (int, string, *http.Response) {
	r.t.Helper()
	var out map[string]any
	resp := c.do("POST", "/api/me/rotate", req, &out)
	msg, _ := out["error"].(string)
	return resp.StatusCode, msg, resp
}

// commit updates the artifacts a test holds to what the server now has.
func (r *rotation) commit() {
	for _, o := range r.owned {
		o.owner = actor{testClient: r.who.testClient, id: r.who.id, email: r.who.email, keys: r.nk}
		o.latest, o.hash = r.built[o.id], e2e.BodyHash(r.envs[o.id].Body)
	}
}

type rotWorld struct {
	s         *Server
	base      string
	rot, mem  actor
	other     actor
	a, b, c   *owned // rot owns a (private) and b (public, epoch 2); rot is a viewer of c
	apiBearer string
}

func newRotWorld(t *testing.T) *rotWorld {
	t.Helper()
	s, ts := testServer(t)
	w := &rotWorld{s: s, base: ts.URL}
	w.rot = seedKeyedAccount(t, s, ts.URL, "rot@example.com")
	w.mem = seedKeyedAccount(t, s, ts.URL, "mem@example.com")
	w.other = seedKeyedAccount(t, s, ts.URL, "other@example.com")
	w.a = newArtifact(t, w.rot, "a")
	w.a.share("viewer", w.mem)
	w.b = newArtifact(t, w.rot, "b")
	w.b.share("viewer", w.mem)
	w.b.makePublic()
	w.b.apply(w.b.nextEpoch())
	w.c = newArtifact(t, w.other, "c")
	w.c.share("viewer", w.rot)
	w.c.apply(w.c.nextEpoch())
	return w
}

// withAPIKey gives rot a live API key.
func (w *rotWorld) withAPIKey(t *testing.T) {
	t.Helper()
	w.rot.mustDo("POST", "/api/keys", map[string]any{
		"authKey": e2e.B64(testAuthKey(w.rot.email + "-password")), "name": "laptop",
		"keyId": "00112233445566ff", "authSecret": "00112233445566778899aabbccddeeff",
		"mk": e2e.B64(bytes.Repeat([]byte{0x11}, sealedKeyLen)),
	}, nil, http.StatusCreated)
	w.apiBearer = "cairn_00112233445566ff_00112233445566778899aabbccddeeff"
}

func (w *rotWorld) rotation(t *testing.T) *rotation {
	return newRotation(t, w.s, w.base, w.rot, w.a, w.b)
}

// state is everything a refused rotation must leave alone.
func (w *rotWorld) state(t *testing.T) string {
	t.Helper()
	var sb strings.Builder
	get := func(c *testClient, path string) {
		var raw json.RawMessage
		c.mustDo("GET", path, nil, &raw, http.StatusOK)
		fmt.Fprintf(&sb, "%s %s\n", path, raw)
	}
	get(w.rot.testClient, "/api/me/bundle")
	get(w.rot.testClient, "/api/me/keyring")
	get(w.rot.testClient, "/api/users/"+w.rot.id+"/rotations")
	for _, o := range []*owned{w.a, w.b, w.c} {
		get(w.rot.testClient, "/api/artifacts/"+o.id+"/membership")
		get(w.rot.testClient, "/api/artifacts/"+o.id+"/keys")
		get(w.rot.testClient, "/api/artifacts/"+o.id)
	}
	sb.WriteString(wrapDump(t, w.s))
	for _, id := range []string{w.a.id, w.b.id, w.c.id} {
		_, err := w.s.store.OpenOffer(id)
		fmt.Fprintf(&sb, "offer %s %v\n", id, err)
	}
	return sb.String()
}

// stillSignedIn checks the session and the API key both still work.
func (w *rotWorld) stillSignedIn(t *testing.T) {
	t.Helper()
	w.rot.mustDo("GET", "/api/me", nil, nil, http.StatusOK)
	if w.apiBearer != "" {
		(&testClient{t: t, base: w.base, token: w.apiBearer}).mustDo("GET", "/api/me", nil, nil, http.StatusOK)
	}
}

func rotations(t *testing.T, c *testClient, userID string) []e2e.Envelope {
	t.Helper()
	var out struct {
		Records []e2e.Envelope `json:"records"`
	}
	c.mustDo("GET", "/api/users/"+userID+"/rotations", nil, &out, http.StatusOK)
	return out.Records
}

type membershipGot struct {
	Records   []e2e.Envelope            `json:"records"`
	Owners    map[string]e2e.KeyPair    `json:"owners"`
	Rotations map[string][]e2e.Envelope `json:"rotations"`
}

func getMembership(t *testing.T, c *testClient, aid string) membershipGot {
	t.Helper()
	var m membershipGot
	c.mustDo("GET", "/api/artifacts/"+aid+"/membership", nil, &m, http.StatusOK)
	return m
}

func TestRotateKeepingEpochsOfASharedArtifact(t *testing.T) {
	w := newRotWorld(t)
	w.withAPIKey(t)
	oldToken := w.rot.token
	oldSession := w.rot.testClient
	var before struct{ Rev int }
	w.rot.mustDo("GET", "/api/me/keyring", nil, &before, http.StatusOK)

	r := w.rotation(t)
	req := r.request()
	var ans rotateAnswer
	resp := w.rot.do("POST", "/api/me/rotate", req, &ans)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate: %d", resp.StatusCode)
	}
	if ans.Seq != 1 || len(ans.Epochs) != 2 || ans.Epochs[w.a.id] != 1 || ans.Epochs[w.b.id] != 2 {
		t.Errorf("answer = %+v", ans)
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == w.s.sessionCookieName() {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value == "" || cookie.Value == oldToken {
		t.Fatalf("no new session cookie: %+v", resp.Cookies())
	}
	r.commit()

	// The old session and the API key are out; the new cookie works.
	if got, _ := status(oldSession, "GET", "/api/me", nil); got != http.StatusUnauthorized {
		t.Errorf("old session after rotation: %d, want 401", got)
	}
	if got, _ := status(&testClient{t: t, base: w.base, token: w.apiBearer}, "GET", "/api/me", nil); got != http.StatusUnauthorized {
		t.Errorf("old API key after rotation: %d, want 401", got)
	}
	creq, _ := http.NewRequest("GET", w.base+"/api/me/bundle", nil)
	creq.AddCookie(cookie)
	cresp, err := http.DefaultClient.Do(creq)
	if err != nil {
		t.Fatal(err)
	}
	var bundle bundleWire
	json.NewDecoder(cresp.Body).Decode(&bundle)
	cresp.Body.Close()
	if cresp.StatusCode != http.StatusOK || bundle.Ed25519Pub != e2e.B64(r.nk.epub) || bundle.X25519Pub != e2e.B64(r.nk.xpub) || bundle.EK != r.bundle().EK {
		t.Errorf("new cookie: %d, bundle %+v", cresp.StatusCode, bundle)
	}
	rot := r.asNew()

	// Keyring: rev advanced, sealed bytes replaced.
	var k keyringBody
	rot.mustDo("GET", "/api/me/keyring", nil, &k, http.StatusOK)
	if k.Rev != before.Rev+1 || k.Keyring != e2e.B64([]byte("sealed keyring after rotation")) {
		t.Errorf("keyring = %+v", k)
	}

	// The rotation record verifies, and is served to anyone signed in.
	recs := rotations(t, w.mem.testClient, w.rot.id)
	if len(recs) != 1 || recs[0].NewSig == nil {
		t.Fatalf("rotations = %+v", recs)
	}
	var body e2e.RotationBody
	if err := e2e.OpenRotation(recs[0], ed25519.PublicKey(w.rot.keys.epub), &body); err != nil {
		t.Fatal(err)
	}
	if body.Seq != 1 || body.User != w.rot.id || body.New != r.nk.pair() || body.Old != w.rot.keys.pair() {
		t.Errorf("rotation body = %+v", body)
	}

	// Each artifact got a new head record under the new key and fingerprint,
	// the old ones still there, and the estate was replaced.
	for _, o := range []*owned{w.a, w.b} {
		m := getMembership(t, w.mem.testClient, o.id)
		n := len(m.Records)
		head := m.Records[n-1]
		var hb e2e.MembershipBody
		if err := e2e.OpenEnvelope(head, ed25519.PublicKey(r.nk.epub), "membership", &hb); err != nil {
			t.Fatalf("head record does not verify under the new key: %v", err)
		}
		if hb.OwnerFP != r.nk.fp() || hb.Seq != n {
			t.Errorf("head = %+v", hb)
		}
		var prev e2e.MembershipBody
		if err := e2e.OpenEnvelope(m.Records[n-2], ed25519.PublicKey(w.rot.keys.epub), "membership", &prev); err != nil || prev.OwnerFP != w.rot.keys.fp() {
			t.Errorf("the previous record changed: %v %+v", err, prev)
		}
		var keys keysView
		rot.mustDo("GET", "/api/artifacts/"+o.id+"/keys", nil, &keys, http.StatusOK)
		if len(keys.Estate) != hb.Epoch {
			t.Errorf("estate copies = %d, want %d", len(keys.Estate), hb.Epoch)
		}
		for _, e := range req["estate"].([]any) {
			em := e.(map[string]any)
			if em["artifact"] != o.id {
				continue
			}
			found := false
			for _, got := range keys.Estate {
				found = found || (got.Epoch == em["epoch"] && got.Sealed == em["sealed"])
			}
			if !found {
				t.Errorf("estate copy %v of %s not stored", em["epoch"], o.id)
			}
		}
	}
	// The wraps rot holds elsewhere carry the new fingerprint and bytes.
	for _, h := range heldWraps(t, w.s, w.rot.id) {
		if h.fp != r.nk.fp() {
			t.Errorf("wrap %+v still under the old fingerprint", h)
		}
	}
	got, _ := w.s.store.WrapsFor(w.c.id, w.rot.id)
	if len(got) != 2 || !bytes.Equal(got[0].Wrapped, newWrap) {
		t.Errorf("wraps on c = %+v", got)
	}
	// The member's wraps are untouched.
	for _, h := range heldWraps(t, w.s, w.mem.id) {
		if h.fp != w.mem.keys.fp() {
			t.Errorf("member wrap changed: %+v", h)
		}
	}
	// Keeping the epoch and the link hash keeps the public link working.
	wantStatus(t, anonWithLink(t, w.base, testLinkToken(t, w.b.id, 2)), "GET", "/api/artifacts/"+w.b.id, nil, http.StatusOK)
	// The artifacts keep working: the owner signs on under the new key.
	w.a.owner = rot
	w.a.share("editor", w.other)
}

func TestRotateToTheNextEpoch(t *testing.T) {
	w := newRotWorld(t)
	r := w.rotation(t)
	r.next[w.a.id], r.next[w.b.id] = true, true
	var ans rotateAnswer
	w.rot.mustDo("POST", "/api/me/rotate", r.request(), &ans, http.StatusOK)
	if ans.Epochs[w.a.id] != 2 || ans.Epochs[w.b.id] != 3 || ans.Seq != 1 {
		t.Fatalf("answer = %+v", ans)
	}
	r.commit()
	rot := r.asNew()
	got := listIDs(t, rot.testClient)
	if got[w.a.id].Epoch != 2 || got[w.b.id].Epoch != 3 || !got[w.b.id].Public {
		t.Errorf("artifacts = %+v", got)
	}
	// The member holds a wrap for the new epoch.
	mw, _ := w.s.store.WrapsFor(w.b.id, w.mem.id)
	if len(mw) != 3 {
		t.Errorf("member wraps on b = %+v, want epochs 1 to 3", mw)
	}
	// The public link moved with the epoch: the old one is dead.
	wantStatus(t, anonWithLink(t, w.base, testLinkToken(t, w.b.id, 3)), "GET", "/api/artifacts/"+w.b.id, nil, http.StatusOK)
	wantStatus(t, anonWithLink(t, w.base, testLinkToken(t, w.b.id, 2)), "GET", "/api/artifacts/"+w.b.id, nil, http.StatusNotFound)
	// Estate copies for every epoch.
	var keys keysView
	rot.mustDo("GET", "/api/artifacts/"+w.b.id+"/keys", nil, &keys, http.StatusOK)
	if len(keys.Estate) != 3 {
		t.Errorf("estate = %+v", keys.Estate)
	}
	// A public record needs the new hash.
	r2 := newRotation(t, w.s, w.base, rot, w.a, w.b)
	r2.seq, r2.next[w.b.id] = 2, true
	req := r2.request()
	for _, rec := range req["records"].([]any) {
		if rec.(map[string]any)["artifact"] == w.b.id {
			delete(rec.(map[string]any), "linkTokenHash")
		}
	}
	if got, msg, _ := r2.post(rot.testClient, req); got != http.StatusBadRequest || !strings.Contains(msg, w.b.id) {
		t.Errorf("a public next-epoch record with no linkTokenHash: %d %q", got, msg)
	}
}

func TestRotateWithNothingOwned(t *testing.T) {
	w := newRotWorld(t)
	r := newRotation(t, w.s, w.base, w.mem)
	if len(r.wraps) == 0 {
		t.Fatal("the member holds no wraps to rotate")
	}
	var raw json.RawMessage
	w.mem.mustDo("POST", "/api/me/rotate", r.request(), &raw, http.StatusOK)
	if string(raw) != `{"epochs":{},"seq":1}` {
		t.Errorf("answer = %s", raw)
	}
	// Their wraps are under the new fingerprint, and the old session is out.
	for _, h := range heldWraps(t, w.s, w.mem.id) {
		if h.fp != r.nk.fp() {
			t.Errorf("wrap %+v still under the old fingerprint", h)
		}
	}
	wantStatus(t, w.mem.testClient, "GET", "/api/me", nil, http.StatusUnauthorized)
	r.asNew().mustDo("GET", "/api/me", nil, nil, http.StatusOK)
}

func TestRotateWithNoWrapsNoArtifactsAndNoEstate(t *testing.T) {
	w := newRotWorld(t)
	fresh := seedKeyedAccount(t, w.s, w.base, "fresh@example.com")
	r := newRotation(t, w.s, w.base, fresh)
	var raw json.RawMessage
	fresh.mustDo("POST", "/api/me/rotate", r.request(), &raw, http.StatusOK)
	if string(raw) != `{"epochs":{},"seq":1}` {
		t.Errorf("answer = %s", raw)
	}
	if got := heldWraps(t, w.s, fresh.id); len(got) != 0 {
		t.Errorf("wraps = %+v", got)
	}
	r.asNew().mustDo("GET", "/api/me", nil, nil, http.StatusOK)
}

func TestRotationsEndpoint(t *testing.T) {
	w := newRotWorld(t)
	var raw json.RawMessage
	w.mem.mustDo("GET", "/api/users/"+w.rot.id+"/rotations", nil, &raw, http.StatusOK)
	if string(raw) != `{"records":[]}` {
		t.Errorf("no rotations: %s", raw)
	}
	wantStatus(t, w.mem.testClient, "GET", "/api/users/nobody/rotations", nil, http.StatusNotFound)
	(&testClient{t: t, base: w.base}).mustDo("GET", "/api/users/"+w.rot.id+"/rotations", nil, nil, http.StatusUnauthorized)

	r := w.rotation(t)
	w.rot.mustDo("POST", "/api/me/rotate", r.request(), nil, http.StatusOK)
	r.commit()
	rot := r.asNew()
	r2 := newRotation(t, w.s, w.base, rot, w.a, w.b)
	r2.seq = 2
	rot.mustDo("POST", "/api/me/rotate", r2.request(), nil, http.StatusOK)

	recs := rotations(t, w.mem.testClient, w.rot.id)
	if len(recs) != 2 {
		t.Fatalf("rotations = %d", len(recs))
	}
	var b1, b2 e2e.RotationBody
	if err := e2e.OpenRotation(recs[0], ed25519.PublicKey(w.rot.keys.epub), &b1); err != nil {
		t.Fatal(err)
	}
	if err := e2e.OpenRotation(recs[1], ed25519.PublicKey(r.nk.epub), &b2); err != nil {
		t.Fatal(err)
	}
	if b1.Seq != 1 || b2.Seq != 2 || b2.Old != b1.New {
		t.Errorf("chain = %+v %+v", b1, b2)
	}

	// The same accounts the directory lists, and no others.
	if err := w.s.store.SetUserDisabled(w.rot.id, true); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, w.mem.testClient, "GET", "/api/users/"+w.rot.id+"/rotations", nil, http.StatusNotFound)
}

func TestMembershipServesRotationsAndOldOwnerKeys(t *testing.T) {
	w := newRotWorld(t)
	k0 := w.rot.keys
	r := w.rotation(t)
	w.rot.mustDo("POST", "/api/me/rotate", r.request(), nil, http.StatusOK)
	r.commit()
	k1 := r.nk
	rot := r.asNew()
	r2 := newRotation(t, w.s, w.base, rot, w.a, w.b)
	r2.seq = 2
	rot.mustDo("POST", "/api/me/rotate", r2.request(), nil, http.StatusOK)
	k2 := r2.nk
	// A listed member rotates too.
	rm := newRotation(t, w.s, w.base, w.mem)
	w.mem.mustDo("POST", "/api/me/rotate", rm.request(), nil, http.StatusOK)
	// A user who rotated but is neither an owner of the chain nor a member.
	ro := newRotation(t, w.s, w.base, w.other, w.c)
	w.other.mustDo("POST", "/api/me/rotate", ro.request(), nil, http.StatusOK)

	check := func(who string, c *testClient) {
		t.Helper()
		m := getMembership(t, c, w.a.id)
		if len(m.Records) != 4 {
			t.Fatalf("%s: records = %d", who, len(m.Records))
		}
		// The owner, who rotated twice, and the listed member; not other,
		// who is neither.
		if len(m.Rotations) != 2 || len(m.Rotations[w.rot.id]) != 2 || len(m.Rotations[w.mem.id]) != 1 {
			t.Errorf("%s: rotations = %v", who, m.Rotations)
		}
		// Every fingerprint the chain names, including the middle key, which
		// only the rotation bodies carry.
		if len(m.Owners) != 3 {
			t.Errorf("%s: owners = %v", who, m.Owners)
		}
		for _, k := range []userKeys{k0, k1, k2} {
			if m.Owners[k.fp()] != k.pair() {
				t.Errorf("%s: owner %s = %v", who, k.fp(), m.Owners[k.fp()])
			}
		}
	}
	mem := rm.asNew()
	check("member", mem.testClient)
	// The same in link scope: b is public and its chain has the same owners.
	linked := getMembership(t, anonWithLink(t, w.base, testLinkToken(t, w.b.id, 2)), w.b.id)
	if len(linked.Rotations[w.rot.id]) != 2 || linked.Owners[k0.fp()] != k0.pair() || linked.Owners[k2.fp()] != k2.pair() {
		t.Errorf("link scope: rotations %v owners %v", linked.Rotations, linked.Owners)
	}
	// c's owner rotated once, and rot, its listed viewer, twice.
	if m := getMembership(t, r2.asNew().testClient, w.c.id); len(m.Rotations) != 2 || len(m.Rotations[w.other.id]) != 1 || len(m.Rotations[w.rot.id]) != 2 {
		t.Errorf("c rotations = %v", m.Rotations)
	}
}

// Member and team pending states

func TestPendingRotatedMember(t *testing.T) {
	w := newApprovalWorld(t)
	o := w.o
	// A viewer who is listed rotates, keeping the wraps they hold.
	r := newRotation(t, w.s, w.base, w.viewer)
	w.viewer.mustDo("POST", "/api/me/rotate", r.request(), nil, http.StatusOK)
	for _, h := range heldWraps(t, w.s, w.viewer.id) {
		if h.fp != r.nk.fp() {
			t.Errorf("wrap %+v not remade", h)
		}
	}
	got := pendingOf(t, w.owner.testClient, o)
	wantPending(t, got, w.want(map[string]string{w.viewer.id: "rotated", w.team1.id: "new", w.team2.id: "new", w.team3.id: "new"}))
	if got[w.viewer.id].Ed25519Pub != e2e.B64(r.nk.epub) || got[w.viewer.id].Approval != nil {
		t.Errorf("rotated entry: %+v", got[w.viewer.id])
	}
	// An editor cannot ask about a rotated user, as with an approved one.
	wantPending(t, pendingOf(t, w.editor.testClient, o), w.want(map[string]string{w.team1.id: "new", w.team2.id: "new", w.team3.id: "new"}))

	// Listing them under the new key clears it.
	nv := r.asNew()
	b := o.next()
	for i := range b.Members {
		if b.Members[i].User == nv.id {
			b.Members[i].FP = nv.keys.fp()
		}
	}
	o.listWithoutWraps(b)
	wantPending(t, pendingOf(t, w.owner.testClient, o), w.want(map[string]string{w.team1.id: "new", w.team2.id: "new", w.team3.id: "new"}))
}

func TestPendingRotatedTeamApprovedHolder(t *testing.T) {
	w := newApprovalWorld(t)
	o := w.o
	o.approve(w.owner, w.team1)
	o.approve(w.owner, w.team2)
	r := newRotation(t, w.s, w.base, w.team1)
	w.team1.mustDo("POST", "/api/me/rotate", r.request(), nil, http.StatusOK)
	got := pendingOf(t, w.owner.testClient, o)
	wantPending(t, got, w.want(map[string]string{w.team1.id: "rotated", w.team2.id: "approved", w.team3.id: "new"}))
	if got[w.team1.id].Approval != nil {
		t.Error("a rotated entry carries the approval")
	}
	wantPending(t, pendingOf(t, w.editor.testClient, o), w.want(map[string]string{w.team3.id: "new"}))
}

func TestPendingResetBetweenRotationsBreaksTheChain(t *testing.T) {
	w := newApprovalWorld(t)
	o := w.o
	o.approve(w.owner, w.team3)
	r1 := newRotation(t, w.s, w.base, w.team3)
	w.team3.mustDo("POST", "/api/me/rotate", r1.request(), nil, http.StatusOK)
	got := pendingOf(t, w.owner.testClient, o)
	if got[w.team3.id].State != "rotated" {
		t.Fatalf("after one rotation: %+v", got[w.team3.id])
	}
	// A password-only reset changes the keys with no record, then a second
	// rotation: seq order is unbroken, but the chain is not.
	reset := resetKeys(t, w.s, w.base, r1.asNew())
	r2 := newRotation(t, w.s, w.base, reset)
	r2.seq = 2
	reset.mustDo("POST", "/api/me/rotate", r2.request(), nil, http.StatusOK)
	got = pendingOf(t, w.owner.testClient, o)
	if got[w.team3.id].State != "keyChanged" {
		t.Errorf("after a reset between two rotations: %+v, want keyChanged", got[w.team3.id])
	}
}

func TestPendingResetStaysKeyChangedAndResetThenRotateLeavesStaleWraps(t *testing.T) {
	w := newApprovalWorld(t)
	o := w.o
	o.approve(w.owner, w.team1)
	o.approve(w.owner, w.team2)
	reset1 := resetKeys(t, w.s, w.base, w.team1)
	reset2 := resetKeys(t, w.s, w.base, w.team2)
	want := w.want(map[string]string{w.team1.id: "keyChanged", w.team2.id: "keyChanged", w.team3.id: "new"})
	wantPending(t, pendingOf(t, w.owner.testClient, o), want)

	// team1 rotates after the reset; team2 does not. The wraps made for the
	// pre-reset key cannot be opened, so they are neither sent nor touched.
	before := heldWraps(t, w.s, w.team1.id)
	dumpBefore := wrapDump(t, w.s)
	r := newRotation(t, w.s, w.base, reset1)
	if len(r.wraps) != 0 {
		t.Fatalf("wraps under the current key: %+v", r.wraps)
	}
	reset1.mustDo("POST", "/api/me/rotate", r.request(), nil, http.StatusOK)
	if dumpAfter := wrapDump(t, w.s); dumpAfter != dumpBefore {
		t.Errorf("wraps changed:\n%s\nwant\n%s", dumpAfter, dumpBefore)
	}
	for _, h := range before {
		if h.fp != w.team1.keys.fp() {
			t.Errorf("unexpected pre-reset wrap fp: %+v", h)
		}
	}
	// The chain starts at the post-reset key, so it does not explain the
	// pre-reset fingerprint: still keyChanged.
	wantPending(t, pendingOf(t, w.owner.testClient, o), want)

	// Sending a wrap for an artifact and epoch under a stale fingerprint is
	// refused as an extra wrap.
	r2 := newRotation(t, w.s, w.base, reset2)
	req := r2.request()
	req["wraps"] = []any{map[string]any{"artifact": o.id, "epoch": 1, "wrapped": e2e.B64(newWrap)}}
	if got, _, _ := r2.post(reset2.testClient, req); got != http.StatusBadRequest {
		t.Errorf("a wrap under a stale fingerprint: %d, want 400", got)
	}
}

// Refusals

type refusal struct {
	name string
	want int
	// msg, when set, is a part of the message the refusal must carry, to tell
	// one check from the next that answers the same status.
	msg    string
	mutate func(w *rotWorld, r *rotation, req map[string]any)
	// as is the client that sends it: the session by default.
	as func(w *rotWorld) *testClient
}

func records(req map[string]any) []any { return req["records"].([]any) }

// dropRecord removes the i-th record and the estate copies of its artifact, as
// a client does that never heard of the artifact.
func dropRecord(req map[string]any, i int) {
	id := records(req)[i].(map[string]any)["artifact"]
	req["records"] = append(append([]any{}, records(req)[:i]...), records(req)[i+1:]...)
	var keep []any
	for _, e := range req["estate"].([]any) {
		if e.(map[string]any)["artifact"] != id {
			keep = append(keep, e)
		}
	}
	req["estate"] = keep
}

func TestRotateRefusals(t *testing.T) {
	w := newRotWorld(t)
	w.withAPIKey(t)
	// An open offer on c to rot and on a by rot must survive a refusal too.
	if err := w.s.store.WithArtifact(w.c.id, func(tx *store.ArtifactTx) error {
		return tx.PutOffer(store.Offer{To: w.rot.id, By: "admin"})
	}); err != nil {
		t.Fatal(err)
	}
	otherKeys := newUserKeys(t)
	bundleWith := func(req map[string]any, f func(*bundleWire)) {
		b := req["bundle"].(bundleWire)
		f(&b)
		req["bundle"] = b
	}
	flip := func(b []byte) []byte { c := append([]byte{}, b...); c[0] ^= 1; return c }
	resign := func(r *rotation, req map[string]any, b e2e.RotationBody, newSeed []byte) {
		req["rotation"] = r.sign(b, newSeed)
	}
	firstRecord := func(req map[string]any) map[string]any { return records(req)[0].(map[string]any) }
	// signedBy re-signs a record with the given keys, the owner and artifact
	// being those the request already names.
	recordWith := func(w *rotWorld, r *rotation, req map[string]any, i int, f func(b *e2e.MembershipBody), signer actor) {
		rec := records(req)[i].(map[string]any)
		id := rec["artifact"].(string)
		b := r.built[id]
		f(&b)
		rec["membership"] = signRecord(t, signer, b)
	}
	oldActor := w.rot
	newActor := func(r *rotation) actor {
		return actor{testClient: w.rot.testClient, id: w.rot.id, email: w.rot.email, keys: r.nk}
	}

	cases := []refusal{
		{name: "wrong authKey", want: 401, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			req["authKey"] = e2e.B64(testAuthKey("wrong"))
		}},
		{name: "an API key", want: 401, as: func(w *rotWorld) *testClient {
			return &testClient{t: t, base: w.base, token: w.apiBearer}
		}},
		{name: "unknown field", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) { req["extra"] = 1 }},
		{name: "malformed bundle", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			bundleWith(req, func(b *bundleWire) { b.EK = e2e.B64([]byte("short")) })
		}},
		{name: "bundle not base64", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			bundleWith(req, func(b *bundleWire) { b.MKPassword = "!!" })
		}},
		{name: "signer is not the caller", want: 400, msg: "signer is not the caller", mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			env := req["rotation"].(e2e.Envelope)
			env.Signer = w.mem.id
			req["rotation"] = env
		}},
		{name: "bad signature", want: 400, msg: "does not verify", mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			env := req["rotation"].(e2e.Envelope)
			env.Sig = flip(env.Sig)
			req["rotation"] = env
		}},
		{name: "bad newSig", want: 400, msg: "does not verify", mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			env := req["rotation"].(e2e.Envelope)
			env.NewSig = flip(env.NewSig)
			req["rotation"] = env
		}},
		{name: "no newSig", want: 400, msg: "does not verify", mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			env := req["rotation"].(e2e.Envelope)
			env.NewSig = nil
			req["rotation"] = env
		}},
		{name: "signed by the new key only", want: 400, msg: "does not verify", mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			raw, _ := json.Marshal(r.body())
			env, _ := e2e.SignRotation(r.nk.seed, r.nk.seed, raw, w.rot.id)
			req["rotation"] = env
		}},
		{name: "another user's record", want: 400, msg: "for another user", mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			b := r.body()
			b.User = w.mem.id
			resign(r, req, b, r.nk.seed)
		}},
		{name: "stale seq", want: 409, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			b := r.body()
			b.Seq = 2
			resign(r, req, b, r.nk.seed)
		}},
		{name: "seq zero", want: 409, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			b := r.body()
			b.Seq = 0
			resign(r, req, b, r.nk.seed)
		}},
		{name: "wrong old keys", want: 409, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			b := r.body()
			b.Old = otherKeys.pair()
			resign(r, req, b, r.nk.seed)
		}},
		{name: "wrong old x25519 only", want: 409, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			b := r.body()
			b.Old.X25519 = otherKeys.pair().X25519
			resign(r, req, b, r.nk.seed)
		}},
		{name: "new keys are not the bundle's", want: 400, msg: "new is not the bundle's", mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			b := r.body()
			b.New = otherKeys.pair()
			resign(r, req, b, otherKeys.seed)
		}},
		{name: "new x25519 is not the bundle's", want: 400, msg: "new is not the bundle's", mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			bundleWith(req, func(b *bundleWire) { b.X25519Pub = e2e.B64(otherKeys.xpub) })
		}},
		{name: "new fingerprint equals the current one", want: 400, msg: "the new keys are the current keys", mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			b := r.body()
			b.New = w.rot.keys.pair()
			resign(r, req, b, w.rot.keys.seed)
			bundleWith(req, func(bw *bundleWire) {
				bw.X25519Pub, bw.Ed25519Pub = e2e.B64(w.rot.keys.xpub), e2e.B64(w.rot.keys.epub)
			})
		}},
		{name: "another user's fingerprint", want: 409, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			b := r.body()
			b.New = w.mem.keys.pair()
			resign(r, req, b, w.mem.keys.seed)
			bundleWith(req, func(bw *bundleWire) {
				bw.X25519Pub, bw.Ed25519Pub = e2e.B64(w.mem.keys.xpub), e2e.B64(w.mem.keys.epub)
			})
		}},
		{name: "kdf changed", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			bundleWith(req, func(b *bundleWire) {
				b.KDF, _ = json.Marshal(e2e.Params{Alg: "argon2id", Memory: 65536, Time: 3, Threads: 1, Salt: bytes.Repeat([]byte{0x02}, 16)})
			})
		}},
		{name: "stale keyring rev", want: 409, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			req["keyring"] = map[string]any{"rev": r.keyringRev(), "keyring": e2e.B64([]byte("x"))}
		}},
		{name: "empty keyring", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			req["keyring"] = map[string]any{"rev": r.keyringRev() + 1, "keyring": ""}
		}},
		{name: "keyring over 1 MiB", want: 413, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			req["keyring"] = map[string]any{"rev": r.keyringRev() + 1, "keyring": e2e.B64(make([]byte, 1<<20+1))}
		}},
		{name: "a missing wrap", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			req["wraps"] = req["wraps"].([]any)[1:]
		}},
		{name: "no wraps", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) { req["wraps"] = []any{} }},
		{name: "an extra wrap", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			req["wraps"] = append(req["wraps"].([]any), map[string]any{"artifact": w.a.id, "epoch": 1, "wrapped": e2e.B64(newWrap)})
		}},
		{name: "an extra epoch", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			req["wraps"] = append(req["wraps"].([]any), map[string]any{"artifact": w.c.id, "epoch": 3, "wrapped": e2e.B64(newWrap)})
		}},
		{name: "a duplicate wrap", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			ws := req["wraps"].([]any)
			req["wraps"] = []any{ws[0], ws[0]}
		}},
		{name: "a wrong-size wrap", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			ws := req["wraps"].([]any)
			ws[0].(map[string]any)["wrapped"] = e2e.B64(newWrap[:80])
		}},
		{name: "a wrap that is not base64", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			ws := req["wraps"].([]any)
			ws[0].(map[string]any)["wrapped"] = "!!"
		}},
		{name: "a missing record", want: 409, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			dropRecord(req, 0)
		}},
		{name: "no records", want: 409, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			dropRecord(req, 0)
			dropRecord(req, 0)
		}},
		{name: "a record for an artifact the caller does not own", want: 409, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			req["records"] = append(records(req), map[string]any{"artifact": w.c.id, "membership": w.c.change(w.c.next())["membership"], "wraps": []any{}})
		}},
		{name: "a record for an artifact that does not exist", want: 409, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			req["records"] = append(records(req), map[string]any{"artifact": "no-such-artifact", "membership": firstRecord(req)["membership"], "wraps": []any{}})
		}},
		{name: "a record twice", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			req["records"] = append(records(req), records(req)[0])
		}},
		{name: "a head record signed by the old key", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			recordWith(w, r, req, 0, func(*e2e.MembershipBody) {}, oldActor)
		}},
		{name: "the second head record signed by the old key", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			recordWith(w, r, req, 1, func(*e2e.MembershipBody) {}, oldActor)
		}},
		{name: "a head record with the old ownerFp", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			recordWith(w, r, req, 0, func(b *e2e.MembershipBody) { b.OwnerFP = w.rot.keys.fp() }, newActor(r))
		}},
		{name: "the second head record with the old ownerFp", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			recordWith(w, r, req, 1, func(b *e2e.MembershipBody) { b.OwnerFP = w.rot.keys.fp() }, newActor(r))
		}},
		{name: "a head record on a stale prev", want: 409, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			recordWith(w, r, req, 1, func(b *e2e.MembershipBody) { b.Prev = strings.Repeat("0", 64) }, newActor(r))
		}},
		{name: "a record with a bad wrap", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			rec := records(req)[0].(map[string]any)
			rec["wraps"] = []any{map[string]any{"user": w.mem.id, "epoch": 1, "wrapped": e2e.B64(newWrap[:10])}}
		}},
		{name: "a record that is not base64 in its wrap", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			rec := records(req)[0].(map[string]any)
			rec["wraps"] = []any{map[string]any{"user": w.mem.id, "epoch": 1, "wrapped": "!!"}}
		}},
		{name: "an estate copy missing an epoch", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			var keep []any
			for _, e := range req["estate"].([]any) {
				if em := e.(map[string]any); !(em["artifact"] == w.b.id && em["epoch"] == 1) {
					keep = append(keep, e)
				}
			}
			req["estate"] = keep
		}},
		{name: "no estate", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) { req["estate"] = []any{} }},
		{name: "a duplicate estate copy", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			es := req["estate"].([]any)
			req["estate"] = append(es, es[0])
		}},
		{name: "an estate copy past the record's epoch", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			est := testEstate(t, w.a.id, 2)
			est["artifact"] = w.a.id
			req["estate"] = append(req["estate"].([]any), est)
		}},
		{name: "an estate copy of an artifact not owned", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			est := testEstate(t, w.c.id, 1)
			est["artifact"] = w.c.id
			req["estate"] = append(req["estate"].([]any), est)
		}},
		{name: "a wrong-size estate copy", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			est := req["estate"].([]any)[0].(map[string]any)
			est["sealed"] = e2e.B64([]byte("short"))
		}},
		{name: "an estate copy that is not base64", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			req["estate"].([]any)[0].(map[string]any)["sealed"] = "!!"
		}},
		{name: "a public record without its link hash", want: 400, mutate: func(w *rotWorld, r *rotation, req map[string]any) {
			for _, rec := range records(req) {
				delete(rec.(map[string]any), "linkTokenHash")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := w.state(t)
			r := w.rotation(t)
			req := r.request()
			if tc.mutate != nil {
				tc.mutate(w, r, req)
			}
			c := w.rot.testClient
			if tc.as != nil {
				c = tc.as(w)
			}
			got, msg, resp := r.post(c, req)
			if got != tc.want {
				t.Fatalf("status %d %q, want %d", got, msg, tc.want)
			}
			if !strings.Contains(msg, tc.msg) {
				t.Errorf("message %q, want it to contain %q", msg, tc.msg)
			}
			if len(resp.Cookies()) != 0 {
				t.Errorf("a refusal set a cookie: %v", resp.Cookies())
			}
			if after := w.state(t); after != before {
				t.Errorf("a refused rotation changed state:\n%s\nwas\n%s", after, before)
			}
			w.stillSignedIn(t)
		})
	}
}

func TestRotateRefusalNamesTheArtifactAndKeepsTheRule(t *testing.T) {
	w := newRotWorld(t)
	r := w.rotation(t)
	req := r.request()
	dropRecord(req, 0)
	if got, msg, _ := r.post(w.rot.testClient, req); got != 409 || !(strings.Contains(msg, w.a.id) || strings.Contains(msg, w.b.id)) {
		t.Errorf("a missing record: %d %q", got, msg)
	}
	r = w.rotation(t)
	req = r.request()
	req["records"] = append(records(req), map[string]any{"artifact": w.c.id, "membership": w.c.change(w.c.next())["membership"], "wraps": []any{}})
	if got, msg, _ := r.post(w.rot.testClient, req); got != 409 || !strings.Contains(msg, w.c.id) {
		t.Errorf("a record for an artifact not owned: %d %q", got, msg)
	}
	r = w.rotation(t)
	req = r.request()
	rec := records(req)[0].(map[string]any)
	id := rec["artifact"].(string)
	b := r.built[id]
	b.OwnerFP = w.rot.keys.fp()
	rec["membership"] = signRecord(t, actor{id: w.rot.id, keys: r.nk}, b)
	got, msg, _ := r.post(w.rot.testClient, req)
	if got != 400 || !strings.Contains(msg, id) || !strings.Contains(msg, "ownerFp") {
		t.Errorf("a refused record: %d %q, want the artifact and the rule named", got, msg)
	}
}

func TestRotateStaleKeyringAnswersWithTheRev(t *testing.T) {
	w := newRotWorld(t)
	r := w.rotation(t)
	req := r.request()
	req["keyring"] = map[string]any{"rev": 5, "keyring": e2e.B64([]byte("x"))}
	var out map[string]any
	resp := w.rot.do("POST", "/api/me/rotate", req, &out)
	if resp.StatusCode != 409 || out["rev"] != float64(0) {
		t.Errorf("%d %v, want 409 with rev 0", resp.StatusCode, out)
	}
}

func TestRotateRefusedWhenTheOwnedSetMoved(t *testing.T) {
	// A record for every artifact owned is required: an artifact the caller
	// gained since the client read the list is a 409 naming it, a race the
	// client recovers from by reading the list again.
	w := newRotWorld(t)
	extra := newArtifact(t, w.rot, "extra")
	r := w.rotation(t)
	req := r.request()
	got, msg, _ := r.post(w.rot.testClient, req)
	if got != 409 || !strings.Contains(msg, extra.id) {
		t.Errorf("an owned artifact with no record: %d %q", got, msg)
	}
	r.owned = append(r.owned, extra)
	w.rot.mustDo("POST", "/api/me/rotate", r.request(), nil, http.StatusOK)
}

func TestRotateClosesOpenOffers(t *testing.T) {
	w := newRotWorld(t)
	if err := w.s.store.WithArtifact(w.c.id, func(tx *store.ArtifactTx) error {
		return tx.PutOffer(store.Offer{To: w.rot.id, By: "admin"})
	}); err != nil {
		t.Fatal(err)
	}
	// An offer the caller, the owner, made on an artifact they own closes too.
	if err := w.s.store.WithArtifact(w.a.id, func(tx *store.ArtifactTx) error {
		return tx.PutOffer(store.Offer{To: w.mem.id, By: "owner"})
	}); err != nil {
		t.Fatal(err)
	}
	r := w.rotation(t)
	w.rot.mustDo("POST", "/api/me/rotate", r.request(), nil, http.StatusOK)
	for _, id := range []string{w.c.id, w.a.id} {
		if _, err := w.s.store.OpenOffer(id); err == nil {
			t.Errorf("an offer on %s is still open", id)
		}
	}
}

func TestRotationLinked(t *testing.T) {
	row := func(seq int, from, to string) store.Rotation { return store.Rotation{Seq: seq, OldFP: from, NewFP: to} }
	chain := []store.Rotation{row(1, "a", "b"), row(2, "b", "c")}
	// A password-only reset between rotation 2 and 3 changed c to d with no
	// record.
	withReset := append(append([]store.Rotation{}, chain...), row(3, "d", "e"))
	tests := []struct {
		name     string
		rows     []store.Rotation
		from, to string
		want     bool
	}{
		{"one step", chain, "a", "b", true},
		{"two steps", chain, "a", "c", true},
		{"second step", chain, "b", "c", true},
		{"backwards", chain, "c", "a", false},
		{"unknown start", chain, "z", "c", false},
		{"unknown end", chain, "a", "z", false},
		{"no rows", nil, "a", "b", false},
		{"across a reset", withReset, "a", "e", false},
		{"before the reset", withReset, "a", "c", true},
		{"after the reset", withReset, "d", "e", true},
		{"from the reset key", withReset, "c", "e", false},
		{"through a repeated key", []store.Rotation{row(1, "a", "b"), row(2, "b", "a"), row(3, "a", "c")}, "a", "c", true},
		{"a later start", []store.Rotation{row(1, "a", "b"), row(2, "x", "y"), row(3, "a", "c")}, "a", "c", true},
	}
	for _, tc := range tests {
		if got := rotationLinked(tc.rows, tc.from, tc.to); got != tc.want {
			t.Errorf("%s: rotationLinked(%s, %s) = %v, want %v", tc.name, tc.from, tc.to, got, tc.want)
		}
	}
}

func TestRotateKeepingEpochsWithAChangedLinkHash(t *testing.T) {
	// The membership rules accept a new link hash at the same epoch, so an
	// owner can break their own link this way: the old one dies, the new one
	// opens.
	w := newRotWorld(t)
	r := w.rotation(t)
	req := r.request()
	for _, rec := range records(req) {
		if rec := rec.(map[string]any); rec["artifact"] == w.b.id {
			rec["linkTokenHash"] = testLinkHash(t, w.b.id, 3)
		}
	}
	w.rot.mustDo("POST", "/api/me/rotate", req, nil, http.StatusOK)
	wantStatus(t, anonWithLink(t, w.base, testLinkToken(t, w.b.id, 2)), "GET", "/api/artifacts/"+w.b.id, nil, http.StatusNotFound)
	wantStatus(t, anonWithLink(t, w.base, testLinkToken(t, w.b.id, 3)), "GET", "/api/artifacts/"+w.b.id, nil, http.StatusOK)
}

func TestRotateRefusedWhenTheOwnedSetMovesBeforeTheLock(t *testing.T) {
	// The caller gains or loses an artifact after the handler has named the
	// artifacts to lock, so only the check inside the transaction can see it.
	// UnderEpoch holds the lock the rotation needs first, with no database
	// transaction open, so the request can pass its first check and wait on
	// that lock while an artifact changes hands. The pause gives it the time
	// to get there.
	tests := []struct {
		name string
		// moves is the artifact that changes hands, and who gets it.
		moves func(w *rotWorld, second *owned) (*owned, string)
	}{
		{"gained", func(w *rotWorld, second *owned) (*owned, string) { return w.c, w.rot.id }},
		{"lost", func(w *rotWorld, second *owned) (*owned, string) { return second, w.other.id }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newRotWorld(t)
			r := w.rotation(t)
			req := r.request()
			first, second := w.a, w.b
			if second.id < first.id {
				first, second = second, first
			}
			moved, to := tc.moves(w, second)
			inside, release, done := make(chan struct{}), make(chan struct{}), make(chan error)
			go func() {
				done <- w.s.store.UnderEpoch(first.id, first.latest.Epoch, func() {
					close(inside)
					<-release
				})
			}()
			<-inside
			var got int
			var msg string
			sent := make(chan struct{})
			go func() {
				defer close(sent)
				got, msg, _ = r.post(w.rot.testClient, req)
			}()
			time.Sleep(300 * time.Millisecond)
			err := w.s.store.WithArtifact(moved.id, func(tx *store.ArtifactTx) error {
				latest, err := tx.LatestRecord()
				if err != nil {
					return err
				}
				next := *latest
				next.Seq, next.Prev, next.OwnerID = latest.Seq+1, latest.BodyHash, to
				return tx.AppendRecord(&next)
			})
			close(release)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			<-sent
			if got != http.StatusConflict || !strings.Contains(msg, moved.id) {
				t.Errorf("%d %q, want 409 naming %s", got, msg, moved.id)
			}
			if rows := rotations(t, w.rot.testClient, w.rot.id); len(rows) != 0 {
				t.Errorf("a refused rotation left %d rotation records", len(rows))
			}
			w.stillSignedIn(t)
		})
	}
}

func TestRotateRacesTwoRotations(t *testing.T) {
	// Two rotations at seq 1 with different new keys: one wins. The other
	// finds the winner's keys current, so its rotation record does not verify
	// under them (400), or it finds its session gone (401).
	w := newRotWorld(t)
	reqs := [2]map[string]any{}
	rots := [2]*rotation{w.rotation(t), w.rotation(t)}
	for i, r := range rots {
		reqs[i] = r.request()
	}
	before := len(getMembership(t, w.mem.testClient, w.a.id).Records)

	var codes [2]int
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range reqs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes[i], _, _ = rots[i].post(w.rot.testClient, reqs[i])
		}()
	}
	close(start)
	wg.Wait()

	winner := 0
	if codes[1] == http.StatusOK {
		winner = 1
	}
	if codes[winner] != http.StatusOK {
		t.Fatalf("statuses = %v, want one 200", codes)
	}
	switch codes[1-winner] {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusConflict:
	default:
		t.Fatalf("statuses = %v, want the loser refused with 400, 401 or 409", codes)
	}

	// One rotation record, and it is the winner's; the bundle is the winner's.
	recs := rotations(t, w.mem.testClient, w.rot.id)
	if len(recs) != 1 {
		t.Fatalf("rotation records = %d, want 1", len(recs))
	}
	var body e2e.RotationBody
	if err := e2e.OpenRotation(recs[0], ed25519.PublicKey(w.rot.keys.epub), &body); err != nil {
		t.Fatal(err)
	}
	if body.New != rots[winner].nk.pair() {
		t.Errorf("the stored rotation is not request %d's", winner)
	}
	var bundle bundleWire
	rots[winner].asNew().mustDo("GET", "/api/me/bundle", nil, &bundle, http.StatusOK)
	if bundle.Ed25519Pub != e2e.B64(rots[winner].nk.epub) || bundle.X25519Pub != e2e.B64(rots[winner].nk.xpub) {
		t.Errorf("bundle is not request %d's: %+v", winner, bundle)
	}
	// Each artifact gained one head record, the winner's.
	m := getMembership(t, w.mem.testClient, w.a.id)
	if len(m.Records) != before+1 || e2e.BodyHash(m.Records[before].Body) != e2e.BodyHash(rots[winner].envs[w.a.id].Body) {
		t.Errorf("artifact a: %d records, want %d ending in request %d's", len(m.Records), before+1, winner)
	}
}

func TestRotateRacesMembershipPut(t *testing.T) {
	// A rotation and a membership PUT on an owned artifact both follow the
	// same head record, so one of them wins and the other is stale: the PUT is
	// refused with 409, or with 401 once the rotation ended its session; the
	// rotation with 409.
	w := newRotWorld(t)
	r := w.rotation(t)
	req := r.request()
	put := w.a.next()
	put.Members = append(put.Members, e2e.Member{User: w.other.id, Role: "viewer", FP: w.other.keys.fp()})
	sortMembers(put.Members)
	putReq := w.a.change(put)
	path := "/api/artifacts/" + w.a.id + "/membership"
	before := len(getMembership(t, w.mem.testClient, w.a.id).Records)
	bBefore := len(getMembership(t, w.mem.testClient, w.b.id).Records)

	var rotCode, putCode int
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		rotCode, _, _ = r.post(w.rot.testClient, req)
	}()
	go func() {
		defer wg.Done()
		<-start
		putCode, _ = status(w.rot.testClient, "PUT", path, putReq)
	}()
	close(start)
	wg.Wait()

	recs := getMembership(t, w.mem.testClient, w.a.id).Records
	head := e2e.BodyHash(recs[len(recs)-1].Body)
	rows := rotations(t, w.mem.testClient, w.rot.id)
	switch {
	case rotCode == http.StatusOK && (putCode == http.StatusConflict || putCode == http.StatusUnauthorized):
		// The rotation won: its record is the head, and b rotated with it.
		if len(recs) != before+1 || head != e2e.BodyHash(r.envs[w.a.id].Body) || len(rows) != 1 {
			t.Errorf("rotation won: %d records (want %d), head is its own %v, %d rotation records",
				len(recs), before+1, head == e2e.BodyHash(r.envs[w.a.id].Body), len(rows))
		}
		if got := len(getMembership(t, w.mem.testClient, w.b.id).Records); got != bBefore+1 {
			t.Errorf("rotation won, but b has %d records, want %d", got, bBefore+1)
		}
	case rotCode == http.StatusConflict && putCode == http.StatusOK:
		// The PUT won: nothing rotated.
		if len(recs) != before+1 || head != e2e.BodyHash(putReq["membership"].(e2e.Envelope).Body) || len(rows) != 0 {
			t.Errorf("PUT won: %d records (want %d), head is its own %v, %d rotation records",
				len(recs), before+1, head == e2e.BodyHash(putReq["membership"].(e2e.Envelope).Body), len(rows))
		}
		if got := len(getMembership(t, w.mem.testClient, w.b.id).Records); got != bBefore {
			t.Errorf("PUT won, but b has %d records, want %d", got, bBefore)
		}
		w.stillSignedIn(t)
	default:
		t.Fatalf("rotation %d, PUT %d: want 200 with 409 or 401, or 409 with 200", rotCode, putCode)
	}
}

func TestRotateThenAMemberResets(t *testing.T) {
	w := newRotWorld(t)
	r := w.rotation(t)
	w.rot.mustDo("POST", "/api/me/rotate", r.request(), nil, http.StatusOK)
	r.commit()
	owner := r.asNew()
	member := resetKeys(t, w.s, w.base, w.mem)

	// The reset member still reads the owner's chain: both keys, and the record.
	m := getMembership(t, member.testClient, w.a.id)
	if len(m.Rotations[w.rot.id]) != 1 || len(m.Owners) != 2 || m.Owners[w.rot.keys.fp()] != w.rot.keys.pair() || m.Owners[r.nk.fp()] != r.nk.pair() {
		t.Errorf("rotations %v, owners %v", m.Rotations, m.Owners)
	}
	// The owner sees the reset member's listed key is not theirs now.
	if got := pendingOf(t, owner.testClient, w.a); got[w.mem.id].State != "keyChanged" {
		t.Errorf("reset member: %+v, want keyChanged", got[w.mem.id])
	}
}

func TestRotateAcceptsTheAuthKeyOfTheEarlierRotation(t *testing.T) {
	// The password and kdf do not change, so the authKey does not either.
	w := newRotWorld(t)
	r := w.rotation(t)
	req := r.request()
	w.rot.mustDo("POST", "/api/me/rotate", req, nil, http.StatusOK)
	r.commit()
	rot := r.asNew()
	r2 := newRotation(t, w.s, w.base, rot, w.a, w.b)
	r2.seq = 2
	req2 := r2.request()
	req2["authKey"] = req["authKey"]
	var ans rotateAnswer
	rot.mustDo("POST", "/api/me/rotate", req2, &ans, http.StatusOK)
	if ans.Seq != 2 {
		t.Errorf("answer = %+v", ans)
	}
}

func TestRotateBodyLimits(t *testing.T) {
	w := newRotWorld(t)
	r := w.rotation(t)
	send := func(body []byte) (int, string) {
		resp := w.rot.doRaw("POST", "/api/me/rotate", body)
		out := decode[map[string]any](t, resp)
		msg, _ := out["error"].(string)
		return resp.StatusCode, msg
	}

	tooBig := append([]byte(`{"authKey":"`), bytes.Repeat([]byte("a"), maxRotateBodyBytes)...)
	tooBig = append(tooBig, `"}`...)
	if got, msg := send(tooBig); got != http.StatusRequestEntityTooLarge {
		t.Errorf("a body over 16 MiB: %d %q, want 413", got, msg)
	}

	valid, err := json.Marshal(r.request())
	if err != nil {
		t.Fatal(err)
	}
	if got, msg := send(append(valid, " {}"...)); got != http.StatusBadRequest || !strings.Contains(msg, "trailing data") {
		t.Errorf("trailing data after the object: %d %q, want 400", got, msg)
	}
	if rows := rotations(t, w.rot.testClient, w.rot.id); len(rows) != 0 {
		t.Errorf("a refused body left %d rotation records", len(rows))
	}
	w.stillSignedIn(t)
}
