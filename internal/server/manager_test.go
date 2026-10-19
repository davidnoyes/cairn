package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// byManager is the PUT membership body for b as a version 2 record that m
// signs: the owner's wrap of a new epoch in place of its estate copy.
func (o *owned) byManager(m actor, b e2e.MembershipBody) map[string]any {
	b.V, b.Signer, b.SignerFP = 2, m.id, m.keys.fp()
	req := o.change(b)
	req["membership"] = signRecord(o.t, m, b)
	if b.Epoch > o.latest.Epoch {
		req["estate"] = []any{}
		req["wraps"] = append(req["wraps"].([]any), map[string]any{"user": o.owner.id, "epoch": b.Epoch, "wrapped": e2e.B64(fakeWrap)})
	}
	return req
}

// applyByManager PUTs b as m and expects it to land.
func (o *owned) applyByManager(m actor, b e2e.MembershipBody) {
	o.t.Helper()
	req := o.byManager(m, b)
	m.mustDo("PUT", "/api/artifacts/"+o.id+"/membership", req, nil, http.StatusOK)
	// The test keeps the body as an owner's version 1 template for next().
	o.latest, o.hash = b, e2e.BodyHash(req["membership"].(e2e.Envelope).Body)
}

// without is members less the user id.
func without(ms []e2e.Member, id string) []e2e.Member {
	var out []e2e.Member
	for _, m := range ms {
		if m.User != id {
			out = append(out, m)
		}
	}
	return out
}

// memberRole gives the member id role, in place.
func memberRole(ms []e2e.Member, id, role string) {
	for i := range ms {
		if ms[i].User == id {
			ms[i].Role = role
		}
	}
}

type managerWorld struct {
	t                 *testing.T
	s                 *Server
	owner, mgr        actor
	editor, viewer, n actor
	o                 *owned
}

func newManagerWorld(t *testing.T) *managerWorld {
	t.Helper()
	s, ts := testServer(t)
	w := &managerWorld{t: t, s: s}
	w.owner = seedKeyedAccount(t, s, ts.URL, "owner@example.com")
	w.mgr = seedKeyedAccount(t, s, ts.URL, "mgr@example.com")
	w.editor = seedKeyedAccount(t, s, ts.URL, "ed@example.com")
	w.viewer = seedKeyedAccount(t, s, ts.URL, "v@example.com")
	w.n = seedKeyedAccount(t, s, ts.URL, "new@example.com")
	w.o = newArtifact(t, w.owner, "doc")
	w.o.share("manager", w.mgr)
	w.o.share("editor", w.editor)
	w.o.share("viewer", w.viewer)
	return w
}

func (w *managerWorld) base() string { return "/api/artifacts/" + w.o.id }

// removeEditor is the next-epoch change that removes the editor, as b.
func (w *managerWorld) removeEditor() e2e.MembershipBody {
	b := w.o.nextEpoch()
	b.Members = without(b.Members, w.editor.id)
	b.Excluded = []e2e.ExcludedEntry{{User: w.editor.id, FP: w.editor.keys.fp(), Email: w.editor.email}}
	return b
}

func TestManagerSharesAtTheSameEpoch(t *testing.T) {
	w := newManagerWorld(t)
	b := w.o.next()
	b.Members = append(b.Members, e2e.Member{User: w.n.id, Role: "viewer", FP: w.n.keys.fp()})
	sortMembers(b.Members)
	w.o.applyByManager(w.mgr, b)
	w.n.mustDo("GET", w.base(), nil, nil, http.StatusOK)

	// The manager also changes team and public writes, and makes it public.
	b = w.o.next()
	b.Team, b.PublicWrites = "viewer", true
	w.o.applyByManager(w.mgr, b)
	b = w.o.next()
	b.Public = true
	w.o.applyByManager(w.mgr, b)

	var got gotArtifact
	w.mgr.mustDo("GET", w.base(), nil, &got, http.StatusOK)
	if got.Access != "manager" {
		t.Errorf("the manager's access: %q", got.Access)
	}
	// A manager is a writer: it pushes a version, and the owner has nothing
	// to review, as for an editor's.
	pushVersion(t, w.mgr.testClient, w.o.id)
	var review []reviewEntryView
	w.owner.mustDo("GET", w.base()+"/review", nil, &review, http.StatusOK)
	if len(review) != 0 {
		t.Errorf("review list: %+v", review)
	}

	// A public link holder is served the keys of every editor and manager.
	var linked struct {
		Keys map[string]e2e.KeyPair `json:"keys"`
	}
	anonWithLink(t, w.owner.base, w.o.linkToken()).mustDo("GET", w.base()+"/membership", nil, &linked, http.StatusOK)
	if len(linked.Keys) != 2 || linked.Keys[w.mgr.id] != w.mgr.keys.pair() || linked.Keys[w.editor.id] != w.editor.keys.pair() {
		t.Errorf("link keys: %+v", linked.Keys)
	}
}

// A removed manager's rotation records are served as long as a record of
// theirs is in the chain, so a client can follow the key they signed under.
func TestRemovedManagersRotationsAreStillServed(t *testing.T) {
	w := newManagerWorld(t)
	b := w.o.next()
	b.Team = "viewer"
	w.o.applyByManager(w.mgr, b)
	r := newRotation(t, w.s, w.owner.base, w.mgr)
	w.mgr.mustDo("POST", "/api/me/rotate", r.request(), nil, http.StatusOK)

	b = w.o.nextEpoch()
	b.Members = without(b.Members, w.mgr.id)
	b.Excluded = []e2e.ExcludedEntry{{User: w.mgr.id, FP: w.mgr.keys.fp(), Email: w.mgr.email}}
	w.o.apply(b)
	var got struct {
		Owners    map[string]e2e.KeyPair    `json:"owners"`
		Rotations map[string][]e2e.Envelope `json:"rotations"`
	}
	w.owner.mustDo("GET", w.base()+"/membership", nil, &got, http.StatusOK)
	if len(got.Rotations[w.mgr.id]) != 1 || got.Owners[w.mgr.keys.fp()] != w.mgr.keys.pair() {
		t.Errorf("rotations %+v, owners %+v", got.Rotations, got.Owners)
	}
}

func TestManagerStartsAnEpochAndOwnerAddsTheEstate(t *testing.T) {
	w := newManagerWorld(t)
	b := w.removeEditor()
	put := func(req map[string]any) (int, string) {
		return status(w.mgr.testClient, "PUT", w.base()+"/membership", req)
	}

	// The owner's wrap is required, and an estate copy is refused.
	req := w.o.byManager(w.mgr, b)
	wraps := req["wraps"].([]any)
	noOwnerWrap := map[string]any{"membership": req["membership"], "wraps": wraps[:len(wraps)-1], "estate": []any{}}
	if code, msg := put(noOwnerWrap); code != http.StatusBadRequest || !strings.Contains(msg, "missing the wrap for "+w.owner.id) {
		t.Errorf("without the owner's wrap: %d %q", code, msg)
	}
	withEstate := map[string]any{"membership": req["membership"], "wraps": wraps, "estate": []any{testEstate(t, w.o.id, b.Epoch)}}
	if code, msg := put(withEstate); code != http.StatusBadRequest || !strings.Contains(msg, "estate") {
		t.Errorf("with an estate copy: %d %q", code, msg)
	}
	w.mgr.mustDo("PUT", w.base()+"/membership", req, nil, http.StatusOK)
	w.o.latest, w.o.hash = b, e2e.BodyHash(req["membership"].(e2e.Envelope).Body)

	// The removed editor is out; the owner reads the new epoch through the
	// wrap it holds, since the epoch has no estate copy yet.
	wantStatus(t, w.editor.testClient, "GET", w.base(), nil, http.StatusNotFound)
	var keys keysView
	w.owner.mustDo("GET", w.base()+"/keys", nil, &keys, http.StatusOK)
	if len(keys.Wraps) != 1 || keys.Wraps[0].Epoch != 2 || keys.Wraps[0].FP != w.owner.keys.fp() {
		t.Errorf("the owner's wraps: %+v", keys.Wraps)
	}
	if len(keys.Estate) != 1 || keys.Estate[0].Epoch != 1 {
		t.Errorf("the owner's estate copies: %+v", keys.Estate)
	}

	// Only the owner adds the estate copy, once, for an epoch that exists.
	estate := func(epoch string) map[string]any {
		e := testEstate(t, w.o.id, 2)
		return map[string]any{"sealed": e["sealed"]}
	}
	path := func(epoch string) string { return w.base() + "/estate/" + epoch }
	wantStatus(t, w.mgr.testClient, "PUT", path("2"), estate("2"), http.StatusForbidden)
	wantStatus(t, w.viewer.testClient, "PUT", path("2"), estate("2"), http.StatusForbidden)
	wantStatus(t, w.editor.testClient, "PUT", path("2"), estate("2"), http.StatusNotFound)
	tok := &testClient{t: t, base: w.owner.base, token: mintContentToken(t, w.s, w.owner.id, w.o.id)}
	wantStatus(t, tok, "PUT", path("2"), estate("2"), http.StatusNotFound)
	wantStatus(t, w.owner.testClient, "PUT", path("3"), estate("3"), http.StatusNotFound)
	wantStatus(t, w.owner.testClient, "PUT", path("0"), estate("0"), http.StatusNotFound)
	wantStatus(t, w.owner.testClient, "PUT", path("x"), estate("x"), http.StatusNotFound)
	wantStatus(t, w.owner.testClient, "PUT", path("2"), map[string]any{"sealed": "AAAA"}, http.StatusBadRequest)
	wantStatus(t, w.owner.testClient, "PUT", path("2"), map[string]any{"sealed": "!!"}, http.StatusBadRequest)
	wantStatus(t, w.owner.testClient, "PUT", path("1"), estate("1"), http.StatusConflict)
	w.owner.mustDo("PUT", path("2"), estate("2"), nil, http.StatusOK)
	wantStatus(t, w.owner.testClient, "PUT", path("2"), estate("2"), http.StatusConflict)
	w.owner.mustDo("GET", w.base()+"/keys", nil, &keys, http.StatusOK)
	if len(keys.Estate) != 2 || keys.Estate[1].Epoch != 2 {
		t.Errorf("the owner's estate copies after the put: %+v", keys.Estate)
	}
}

func TestOwnersWrapSurvivesTheNextOwnerEpoch(t *testing.T) {
	w := newManagerWorld(t)
	w.o.applyByManager(w.mgr, w.removeEditor())
	// The owner starts epoch 3 before sealing epoch 2: its wrap of epoch 2
	// is still the only way back into it.
	b := w.o.nextEpoch()
	w.o.apply(b)
	var keys keysView
	w.owner.mustDo("GET", w.base()+"/keys", nil, &keys, http.StatusOK)
	if len(keys.Wraps) != 1 || keys.Wraps[0].Epoch != 2 {
		t.Errorf("the owner's wraps: %+v", keys.Wraps)
	}
	if len(keys.Estate) != 2 || keys.Estate[1].Epoch != 3 {
		t.Errorf("the owner's estate copies: %+v", keys.Estate)
	}
}

func TestManagerCannotDoWhatOnlyTheOwnerDoes(t *testing.T) {
	w := newManagerWorld(t)
	put := func(b e2e.MembershipBody, want int) {
		t.Helper()
		code, msg := status(w.mgr.testClient, "PUT", w.base()+"/membership", w.o.byManager(w.mgr, b))
		if code != want || (want == 400 && !strings.Contains(msg, "manager change")) {
			t.Errorf("%d %q, want %d", code, msg, want)
		}
	}
	b := w.o.next()
	memberRole(b.Members, w.viewer.id, "manager") // adds a manager
	put(b, http.StatusBadRequest)
	b = w.o.nextEpoch()
	b.Members = without(b.Members, w.mgr.id) // removes one, themself
	b.Excluded = []e2e.ExcludedEntry{{User: w.mgr.id, FP: w.mgr.keys.fp(), Email: w.mgr.email}}
	put(b, http.StatusBadRequest)
	b = w.o.next()
	memberRole(b.Members, w.mgr.id, "editor") // changes one's role, their own
	put(b, http.StatusBadRequest)

	// No transfer, no handover, no new owner.
	b = w.o.next()
	b.Transfer = e2e.BodyHash([]byte("x"))
	code, msg := status(w.mgr.testClient, "PUT", w.base()+"/membership", w.o.byManager(w.mgr, b))
	if code != http.StatusBadRequest || !strings.Contains(msg, "transfer") {
		t.Errorf("transfer: %d %q", code, msg)
	}

	// Delete, offering ownership, and review stay with the owner.
	wantStatus(t, w.mgr.testClient, "DELETE", w.base(), nil, http.StatusForbidden)
	wantStatus(t, w.mgr.testClient, "GET", w.base()+"/review", nil, http.StatusForbidden)
	offer := e2e.TransferBody{V: 1, Artifact: w.o.id, From: w.mgr.id, To: w.editor.id, ToFP: w.editor.keys.fp(), Prev: w.o.hash}
	wantStatus(t, w.mgr.testClient, "POST", w.base()+"/transfer",
		map[string]any{"to": w.editor.id, "offer": signOffer(t, w.mgr, offer)}, http.StatusForbidden)

	// An editor, though listed, still cannot share.
	wantStatus(t, w.editor.testClient, "PUT", w.base()+"/membership", w.o.byManager(w.editor, w.o.next()), http.StatusForbidden)
}

func TestManagerKeysAreServedWithTheChain(t *testing.T) {
	w := newManagerWorld(t)
	b := w.o.next()
	b.Team = "viewer"
	w.o.applyByManager(w.mgr, b)
	var got struct {
		Records []e2e.Envelope         `json:"records"`
		Owners  map[string]e2e.KeyPair `json:"owners"`
	}
	w.viewer.mustDo("GET", w.base()+"/membership", nil, &got, http.StatusOK)
	if got.Owners[w.mgr.keys.fp()] != w.mgr.keys.pair() || got.Owners[w.owner.keys.fp()] != w.owner.keys.pair() {
		t.Errorf("owners: %+v", got.Owners)
	}
	last := got.Records[len(got.Records)-1]
	if last.Signer != w.mgr.id {
		t.Errorf("the latest record's signer: %q", last.Signer)
	}
	if _, err := e2e.VerifyChain(e2e.ChainInput{Artifact: w.o.id, Records: got.Records, Owners: got.Owners, Anchor: w.owner.keys.fp(),
		CurrentOwnerFP: w.owner.keys.fp()}); err != nil {
		t.Errorf("the served chain does not verify: %v", err)
	}
}

func TestManagerKeysFromARotationAreServed(t *testing.T) {
	w := newManagerWorld(t)
	b := w.o.next()
	b.Team = "viewer"
	w.o.applyByManager(w.mgr, b)

	// The manager rotates their keys. The record names the old key, which
	// the server serves from the rotation records, with the rotation chain
	// that links it to the new one.
	r := newRotation(t, w.s, w.owner.base, w.mgr)
	w.mgr.mustDo("POST", "/api/me/rotate", r.request(), nil, http.StatusOK)
	rotated := r.asNew()
	var got struct {
		Records   []e2e.Envelope            `json:"records"`
		Owners    map[string]e2e.KeyPair    `json:"owners"`
		Rotations map[string][]e2e.Envelope `json:"rotations"`
	}
	w.viewer.mustDo("GET", w.base()+"/membership", nil, &got, http.StatusOK)
	if got.Owners[w.mgr.keys.fp()] != w.mgr.keys.pair() || len(got.Rotations[w.mgr.id]) != 1 {
		t.Errorf("owners %+v, rotations %+v", got.Owners, got.Rotations)
	}
	if _, err := e2e.VerifyChain(e2e.ChainInput{Artifact: w.o.id, Records: got.Records, Owners: got.Owners, Anchor: w.owner.keys.fp(),
		Linked: e2e.RotationLinker(got.Rotations)}); err != nil {
		t.Errorf("the served chain does not verify: %v", err)
	}

	// A manager whose keys changed reads, but cannot write until listed again.
	var view gotArtifact
	rotated.mustDo("GET", w.base(), nil, &view, http.StatusOK)
	if view.Access != "manager" {
		t.Errorf("access after rotating: %q", view.Access)
	}
	wantStatus(t, rotated.testClient, "PUT", w.base()+"/membership", w.o.byManager(rotated, w.o.next()), http.StatusForbidden)
}

func TestOwnerListsAManagerAndOffersOwnership(t *testing.T) {
	w := newManagerWorld(t)
	offer := e2e.TransferBody{V: 1, Artifact: w.o.id, From: w.owner.id, To: w.mgr.id, ToFP: w.mgr.keys.fp(), Prev: w.o.hash}
	w.owner.mustDo("POST", w.base()+"/transfer", map[string]any{"to": w.mgr.id, "offer": signOffer(t, w.owner, offer)}, nil, http.StatusOK)
	// A viewer still cannot be offered it.
	offer.To, offer.ToFP = w.viewer.id, w.viewer.keys.fp()
	wantStatus(t, w.owner.testClient, "POST", w.base()+"/transfer", map[string]any{"to": w.viewer.id, "offer": signOffer(t, w.owner, offer)}, http.StatusConflict)
}

func TestViewerAccountIsNotListedAsManager(t *testing.T) {
	w := newManagerWorld(t)
	if err := w.s.store.SetUserRole(w.n.id, store.RoleViewer); err != nil {
		t.Fatal(err)
	}
	b := w.o.next()
	b.Members = append(b.Members, e2e.Member{User: w.n.id, Role: "manager", FP: w.n.keys.fp()})
	sortMembers(b.Members)
	code, msg := status(w.owner.testClient, "PUT", w.base()+"/membership", w.o.change(b))
	if code != http.StatusBadRequest || !strings.Contains(msg, "viewer account") {
		t.Errorf("%d %q", code, msg)
	}
}

func TestOwnerRemovesAManagerAtTheNextEpoch(t *testing.T) {
	w := newManagerWorld(t)
	b := w.o.next()
	b.Members = without(b.Members, w.mgr.id)
	if code, msg := status(w.owner.testClient, "PUT", w.base()+"/membership", w.o.change(b)); code != http.StatusBadRequest || !strings.Contains(msg, "same epoch") {
		t.Errorf("same-epoch removal: %d %q", code, msg)
	}
	b = w.o.nextEpoch()
	b.Members = without(b.Members, w.mgr.id)
	b.Excluded = []e2e.ExcludedEntry{{User: w.mgr.id, FP: w.mgr.keys.fp(), Email: w.mgr.email}}
	w.o.apply(b)
	wantStatus(t, w.mgr.testClient, "GET", w.base(), nil, http.StatusNotFound)
	// Their records stay in the chain, and so does their key.
	var got struct {
		Owners map[string]e2e.KeyPair `json:"owners"`
	}
	w.owner.mustDo("GET", w.base()+"/membership", nil, &got, http.StatusOK)
	if len(got.Owners) != 1 {
		t.Errorf("owners after the removal: %+v", got.Owners)
	}
}
