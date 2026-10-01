package server

import (
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// Reviewing a removed editor's versions: GET /review and PUT /vouch. See
// "Reviewing a removed editor's versions" in design/e2e-api.md.

type reviewEntry struct {
	ID        string  `json:"id"`
	Seq       int     `json:"seq"`
	PushedBy  *string `json:"pushedBy"`
	CreatedAt string  `json:"createdAt"`
}

func reviewOf(t *testing.T, c *testClient, o *owned) []reviewEntry {
	t.Helper()
	list := []reviewEntry{}
	c.mustDo("GET", "/api/artifacts/"+o.id+"/review", nil, &list, http.StatusOK)
	return list
}

func (o *owned) vouchPath(vid string) string {
	return "/api/artifacts/" + o.id + "/versions/" + vid + "/vouch"
}

func signVouchRaw(t *testing.T, seed []byte, signer, purpose string, raw []byte) e2e.Envelope {
	t.Helper()
	env, err := e2e.NewEnvelope(seed, signer, purpose, raw)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func signVouch(t *testing.T, seed []byte, signer string, b e2e.VouchBody) e2e.Envelope {
	t.Helper()
	return signVouchRaw(t, seed, signer, "vouch", mustJSON(t, b))
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// vouchBy is a well-formed vouch for vid, signed by signer.
func (o *owned) vouchBy(signer actor, vid string) e2e.Envelope {
	o.t.Helper()
	return signVouch(o.t, signer.keys.seed, signer.id, e2e.VouchBody{V: 1, Artifact: o.id, Version: vid})
}

// removeAndExcludeSorted is removeAndExclude for a second exclusion, which
// the excluded list must hold in user ID order.
func (o *owned) removeAndExcludeSorted(u actor) {
	o.t.Helper()
	b := o.nextEpoch()
	b.Members = []e2e.Member{}
	for _, m := range o.latest.Members {
		if m.User != u.id {
			b.Members = append(b.Members, m)
		}
	}
	b.Excluded = append(b.Excluded, e2e.ExcludedEntry{User: u.id, FP: u.keys.fp(), Email: e2e.NormalizeEmail(u.email)})
	sort.Slice(b.Excluded, func(i, j int) bool { return b.Excluded[i].User < b.Excluded[j].User })
	o.apply(b)
}

// reviewWorld is an artifact with an owner, a current editor, and an editor
// who was removed, and a version pushed by each of them.
type reviewWorld struct {
	s                            *Server
	base                         string
	owner, editor, removed       actor
	o                            *owned
	byOwner, byEditor, byRemoved string
}

func newReviewWorld(t *testing.T) *reviewWorld {
	t.Helper()
	s, ts := testServer(t)
	w := &reviewWorld{s: s, base: ts.URL}
	w.owner = seedKeyedAccount(t, s, ts.URL, "owner@example.com")
	w.editor = seedKeyedAccount(t, s, ts.URL, "editor@example.com")
	w.removed = seedKeyedAccount(t, s, ts.URL, "removed@example.com")
	w.o = newArtifact(t, w.owner, "reviewed")
	w.o.share("editor", w.editor, w.removed)
	w.byOwner = pushVersion(t, w.owner.testClient, w.o.id)
	w.byEditor = pushVersion(t, w.editor.testClient, w.o.id)
	w.byRemoved = pushVersion(t, w.removed.testClient, w.o.id)
	w.o.removeAndExclude(w.removed)
	return w
}

func TestReviewListsOnlyUnvouchedVersionsOfNonEditors(t *testing.T) {
	w := newReviewWorld(t)
	got := reviewOf(t, w.owner.testClient, w.o)
	if len(got) != 1 || got[0].ID != w.byRemoved || got[0].Seq != 3 || got[0].PushedBy == nil || *got[0].PushedBy != w.removed.id || got[0].CreatedAt == "" {
		t.Fatalf("review = %+v, want only the removed editor's version %s", got, w.byRemoved)
	}

	// A second removed pusher's version, in seq order.
	w.o.removeAndExcludeSorted(w.editor)
	got = reviewOf(t, w.owner.testClient, w.o)
	if len(got) != 2 || got[0].ID != w.byEditor || got[1].ID != w.byRemoved {
		t.Fatalf("review after removing the editor = %+v, want the editor's then the removed one's", got)
	}

	// A vouch takes a version off the list.
	w.owner.mustDo("PUT", w.o.vouchPath(w.byEditor), map[string]any{"vouch": w.o.vouchBy(w.owner, w.byEditor)}, nil, http.StatusOK)
	got = reviewOf(t, w.owner.testClient, w.o)
	if len(got) != 1 || got[0].ID != w.byRemoved {
		t.Fatalf("review after vouching = %+v, want only %s", got, w.byRemoved)
	}
}

func TestReviewNeverListsAVersionWithNoPusher(t *testing.T) {
	w := newReviewWorld(t)
	if err := w.s.store.DeleteUser(w.removed.id); err != nil {
		t.Fatal(err)
	}
	if got := reviewOf(t, w.owner.testClient, w.o); len(got) != 0 {
		t.Errorf("review = %+v, want none for a deleted pusher", got)
	}
}

func TestReviewAndVouchAreOwnerOnly(t *testing.T) {
	w := newReviewWorld(t)
	outsider := seedKeyedAccount(t, w.s, w.base, "outsider@example.com")
	path := "/api/artifacts/" + w.o.id + "/review"
	wantStatus(t, w.editor.testClient, "GET", path, nil, http.StatusForbidden)
	wantStatus(t, outsider.testClient, "GET", path, nil, http.StatusNotFound)
	wantStatus(t, w.editor.testClient, "PUT", w.o.vouchPath(w.byRemoved), map[string]any{"vouch": w.o.vouchBy(w.editor, w.byRemoved)}, http.StatusForbidden)
	wantStatus(t, outsider.testClient, "PUT", w.o.vouchPath(w.byRemoved), map[string]any{"vouch": w.o.vouchBy(outsider, w.byRemoved)}, http.StatusNotFound)
}

func TestVouchRefusals(t *testing.T) {
	w := newReviewWorld(t)
	o, vid := w.o, w.byRemoved
	other := newArtifact(t, w.owner, "other")
	otherVid := pushVersion(t, w.owner.testClient, other.id)
	good := e2e.VouchBody{V: 1, Artifact: o.id, Version: vid}
	with := func(f func(*e2e.VouchBody)) e2e.VouchBody { b := good; f(&b); return b }
	seed, id := w.owner.keys.seed, w.owner.id

	cases := []struct {
		name string
		env  e2e.Envelope
	}{
		{"signed by another user", o.vouchBy(w.editor, vid)},
		{"the owner's signature under another user's name", signVouch(t, seed, w.editor.id, good)},
		{"signed by an old key of the owner", signVouch(t, newUserKeys(t).seed, id, good)},
		{"another artifact", signVouch(t, seed, id, with(func(b *e2e.VouchBody) { b.Artifact = other.id }))},
		{"another version", signVouch(t, seed, id, with(func(b *e2e.VouchBody) { b.Version = w.byEditor }))},
		{"wrong purpose", signVouchRaw(t, seed, id, "approval", mustJSON(t, good))},
		{"non-empty manifest", signVouch(t, seed, id, with(func(b *e2e.VouchBody) { b.Manifest = "abc" }))},
		{"body version 2", signVouchRaw(t, seed, id, "vouch", []byte(`{"v":2,"artifact":"`+o.id+`","version":"`+vid+`","manifest":""}`))},
	}
	for _, c := range cases {
		if got, msg := status(w.owner.testClient, "PUT", o.vouchPath(vid), map[string]any{"vouch": c.env}); got != http.StatusBadRequest {
			t.Errorf("%s: %d %q, want 400", c.name, got, msg)
		}
	}
	if got := reviewOf(t, w.owner.testClient, o); len(got) != 1 {
		t.Errorf("a refused vouch changed the review list: %+v", got)
	}

	// A version of another artifact is not found under this one.
	wantStatus(t, w.owner.testClient, "PUT", o.vouchPath(otherVid),
		map[string]any{"vouch": signVouch(t, seed, id, e2e.VouchBody{V: 1, Artifact: o.id, Version: otherVid})}, http.StatusNotFound)
}

func TestVouchIsStoredReplacedAndShownOnTheVersion(t *testing.T) {
	w := newReviewWorld(t)
	o := w.o
	type view struct {
		ID       string        `json:"id"`
		PushedBy *string       `json:"pushedBy"`
		Vouch    *e2e.Envelope `json:"vouch"`
	}
	base := "/api/artifacts/" + o.id + "/versions/"
	var v view
	w.owner.mustDo("GET", base+w.byRemoved, nil, &v, http.StatusOK)
	if v.PushedBy == nil || *v.PushedBy != w.removed.id || v.Vouch != nil {
		t.Fatalf("unvouched version = %+v, want pushedBy %s and a null vouch", v, w.removed.id)
	}

	first := o.vouchBy(w.owner, w.byRemoved)
	w.owner.mustDo("PUT", o.vouchPath(w.byRemoved), map[string]any{"vouch": first}, nil, http.StatusOK)
	w.owner.mustDo("GET", base+w.byRemoved, nil, &v, http.StatusOK)
	if v.Vouch == nil || !reflect.DeepEqual(*v.Vouch, first) {
		t.Fatalf("vouch = %+v, want %+v", v.Vouch, first)
	}

	// The same fields in another order sign differently, so a replacement
	// can be told from the first.
	raw := []byte(`{"version":"` + w.byRemoved + `","artifact":"` + o.id + `","manifest":"","v":1}`)
	second := signVouchRaw(t, w.owner.keys.seed, w.owner.id, "vouch", raw)
	w.owner.mustDo("PUT", o.vouchPath(w.byRemoved), map[string]any{"vouch": second}, nil, http.StatusOK)
	w.owner.mustDo("GET", base+w.byRemoved, nil, &v, http.StatusOK)
	if v.Vouch == nil || !reflect.DeepEqual(*v.Vouch, second) {
		t.Fatalf("replaced vouch = %+v, want %+v", v.Vouch, second)
	}

	var list []view
	w.owner.mustDo("GET", "/api/artifacts/"+o.id+"/versions", nil, &list, http.StatusOK)
	if len(list) != 3 {
		t.Fatalf("version list has %d entries, want 3", len(list))
	}
	for _, e := range list {
		if (e.ID == w.byRemoved) != (e.Vouch != nil) || e.PushedBy == nil {
			t.Errorf("list entry %+v", e)
		}
	}
}

func TestDeletingAVersionLeavesNoVouch(t *testing.T) {
	w := newReviewWorld(t)
	w.owner.mustDo("PUT", w.o.vouchPath(w.byRemoved), map[string]any{"vouch": w.o.vouchBy(w.owner, w.byRemoved)}, nil, http.StatusOK)
	w.owner.mustDo("DELETE", "/api/artifacts/"+w.o.id+"/versions/"+w.byRemoved, nil, nil, http.StatusOK)
	vs, err := w.s.store.Vouches(w.o.id)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(vs); n != 0 {
		t.Errorf("%d vouches remain after deleting the version", n)
	}
}
