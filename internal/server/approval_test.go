package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/google/uuid"
)

// Team approval: GET /pending and POST /keys. See "Team approval" in
// design/e2e-api.md.

type pendingEntry struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Email      string        `json:"email"`
	X25519Pub  string        `json:"x25519Pub"`
	Ed25519Pub string        `json:"ed25519Pub"`
	State      string        `json:"state"`
	Approval   *e2e.Envelope `json:"approval"`
}

// pendingOf returns GET /pending as c, keyed by user ID.
func pendingOf(t *testing.T, c *testClient, o *owned) map[string]pendingEntry {
	t.Helper()
	var list []pendingEntry
	c.mustDo("GET", "/api/artifacts/"+o.id+"/pending", nil, &list, http.StatusOK)
	out := map[string]pendingEntry{}
	for _, p := range list {
		out[p.ID] = p
	}
	if len(out) != len(list) {
		t.Fatalf("pending lists a user twice: %+v", list)
	}
	return out
}

func wantPending(t *testing.T, got map[string]pendingEntry, want map[string]string) {
	t.Helper()
	have := map[string]string{}
	for id, p := range got {
		have[id] = p.State
	}
	if len(have) != len(want) {
		t.Errorf("pending: %v, want %v", have, want)
		return
	}
	for id, state := range want {
		if have[id] != state {
			t.Errorf("pending: %v, want %v", have, want)
			return
		}
	}
}

func signApproval(t *testing.T, signer actor, b e2e.ApprovalBody) e2e.Envelope {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return signApprovalRaw(t, signer, raw)
}

func signApprovalRaw(t *testing.T, signer actor, raw []byte) e2e.Envelope {
	t.Helper()
	env, err := e2e.NewEnvelope(signer.keys.seed, signer.id, "approval", raw)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// approveReq is the POST /keys body that signer sends to approve user at
// the artifact's current epoch, with a wrap for every epoch.
func approveReq(t *testing.T, o *owned, signer, user actor) map[string]any {
	t.Helper()
	wraps := []any{}
	for e := 1; e <= o.latest.Epoch; e++ {
		wraps = append(wraps, map[string]any{"epoch": e, "wrapped": e2e.B64(fakeWrap)})
	}
	return map[string]any{
		"user": user.id, "fp": user.keys.fp(), "wraps": wraps,
		"approval": signApproval(t, signer, e2e.ApprovalBody{V: 1, Artifact: o.id, Epoch: o.latest.Epoch, User: user.id, FP: user.keys.fp()}),
	}
}

func (o *owned) approvePath() string { return "/api/artifacts/" + o.id + "/keys" }

// approve POSTs signer's approval of user and expects it to land.
func (o *owned) approve(signer, user actor) {
	o.t.Helper()
	signer.mustDo("POST", o.approvePath(), approveReq(o.t, o, signer, user), nil, http.StatusOK)
}

func (o *owned) setTeam(team string) {
	o.t.Helper()
	b := o.next()
	b.Team = team
	o.apply(b)
}

// listWithoutWraps applies b, which lists only members who already hold
// wraps under their current keys, so the change carries none.
func (o *owned) listWithoutWraps(b e2e.MembershipBody) {
	o.t.Helper()
	req := map[string]any{"membership": signRecord(o.t, o.owner, b), "wraps": []any{}, "estate": []any{}}
	o.owner.mustDo("PUT", "/api/artifacts/"+o.id+"/membership", req, nil, http.StatusOK)
	o.latest, o.hash = b, e2e.BodyHash(req["membership"].(e2e.Envelope).Body)
}

// removeAndExclude drops u from the members at the next epoch and excludes
// them, as an owner's client does.
func (o *owned) removeAndExclude(u actor) {
	o.t.Helper()
	b := o.nextEpoch()
	var kept []e2e.Member
	for _, m := range b.Members {
		if m.User != u.id {
			kept = append(kept, m)
		}
	}
	b.Members = append([]e2e.Member{}, kept...)
	b.Excluded = append(b.Excluded, e2e.ExcludedEntry{User: u.id, FP: u.keys.fp(), Email: e2e.NormalizeEmail(u.email)})
	o.apply(b)
}

// resetKeys gives a an account with new keys, as a reset without the
// recovery code does, and returns it signed in.
func resetKeys(t *testing.T, s *Server, base string, a actor) actor {
	t.Helper()
	keys := newUserKeys(t)
	hash, err := auth.HashPassword(string(testAuthKey(a.email + "-password")))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.ResetAccount(a.id, hash, bundleFor(t, keys), time.Now()); err != nil {
		t.Fatal(err)
	}
	return actor{testClient: login(t, base, a.email, a.email+"-password"), id: a.id, email: a.email, keys: keys}
}

// approvalWorld is an artifact at epoch 2 shared with the team as viewers:
// owner, an editor, and a viewer are listed, and team1 to team3 are users
// the owner has not listed.
type approvalWorld struct {
	admin                 string // the seeded administrator: a verified user with no access, so always new under a team
	s                     *Server
	base                  string
	owner, editor, viewer actor
	team1, team2, team3   actor
	o                     *owned
}

func newApprovalWorld(t *testing.T) *approvalWorld {
	t.Helper()
	s, ts := testServer(t)
	w := &approvalWorld{s: s, base: ts.URL}
	admin, err := s.store.UserByEmail("admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	w.admin = admin.ID
	w.owner = seedKeyedAccount(t, s, ts.URL, "owner@example.com")
	w.editor = seedKeyedAccount(t, s, ts.URL, "editor@example.com")
	w.viewer = seedKeyedAccount(t, s, ts.URL, "viewer@example.com")
	w.team1 = seedKeyedAccount(t, s, ts.URL, "team1@example.com")
	w.team2 = seedKeyedAccount(t, s, ts.URL, "team2@example.com")
	w.team3 = seedKeyedAccount(t, s, ts.URL, "team3@example.com")
	w.o = newArtifact(t, w.owner, "team doc")
	w.o.share("editor", w.editor)
	w.o.share("viewer", w.viewer)
	b := w.o.nextEpoch()
	b.Team = "viewer"
	w.o.apply(b)
	return w
}

// want adds the administrator, who is waiting under any team share, to the
// states a test expects.
func (w *approvalWorld) want(states map[string]string) map[string]string {
	states[w.admin] = "new"
	return states
}

func TestPendingStates(t *testing.T) {
	w := newApprovalWorld(t)
	o := w.o

	// An unverified account and a disabled one are never waiting.
	unverified := newUserKeys(t)
	hash, err := auth.HashPassword(string(testAuthKey("unverified-password")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.store.CreateAccount("unverified@example.com", "Unverified", hash, bundleFor(t, unverified), false); err != nil {
		t.Fatal(err)
	}
	disabled := seedKeyedAccount(t, w.s, w.base, "disabled@example.com")
	if err := w.s.store.SetUserDisabled(disabled.id, true); err != nil {
		t.Fatal(err)
	}

	// Team none: nobody is waiting.
	none := newArtifact(t, w.owner, "private")
	if got := pendingOf(t, w.owner.testClient, none); len(got) != 0 {
		t.Errorf("pending under team none: %+v", got)
	}

	// Team viewer: every verified user with no access is new. The owner, the
	// listed editor and viewer, and the caller are not.
	got := pendingOf(t, w.owner.testClient, o)
	wantPending(t, got, w.want(map[string]string{w.team1.id: "new", w.team2.id: "new", w.team3.id: "new"}))
	p := got[w.team1.id]
	if p.Name != "Test User" || p.Email != w.team1.email || p.Approval != nil ||
		p.X25519Pub != e2e.B64(w.team1.keys.xpub) || p.Ed25519Pub != e2e.B64(w.team1.keys.epub) {
		t.Errorf("a new user's entry: %+v", p)
	}
	wantPending(t, pendingOf(t, w.editor.testClient, o), w.want(map[string]string{w.team1.id: "new", w.team2.id: "new", w.team3.id: "new"}))

	// A viewer cannot ask, and a user with no access cannot tell it exists.
	wantStatus(t, w.viewer.testClient, "GET", "/api/artifacts/"+o.id+"/pending", nil, http.StatusForbidden)
	wantStatus(t, w.team1.testClient, "GET", "/api/artifacts/"+o.id+"/pending", nil, http.StatusNotFound)

	// Approved: the owner sees the stored envelope; the editor does not see
	// the user at all.
	req := approveReq(t, o, w.editor, w.team1)
	w.editor.mustDo("POST", o.approvePath(), req, nil, http.StatusOK)
	got = pendingOf(t, w.owner.testClient, o)
	wantPending(t, got, w.want(map[string]string{w.team1.id: "approved", w.team2.id: "new", w.team3.id: "new"}))
	if a := got[w.team1.id].Approval; a == nil || !bytes.Equal(a.Body, req["approval"].(e2e.Envelope).Body) ||
		!bytes.Equal(a.Sig, req["approval"].(e2e.Envelope).Sig) || a.Signer != w.editor.id {
		t.Errorf("the approved user's approval: %+v", a)
	}
	wantPending(t, pendingOf(t, w.editor.testClient, o), w.want(map[string]string{w.team2.id: "new", w.team3.id: "new"}))

	// Listed, the approved user is no longer waiting.
	b := o.next()
	b.Members = append(b.Members, e2e.Member{User: w.team1.id, Role: "viewer", FP: w.team1.keys.fp()})
	sortMembers(b.Members)
	o.listWithoutWraps(b)
	wantPending(t, pendingOf(t, w.owner.testClient, o), w.want(map[string]string{w.team2.id: "new", w.team3.id: "new"}))

	// A key that changed after a wrap or a listing is keyChanged, to the
	// editor as well as the owner, and never new or approved.
	o.approve(w.owner, w.team2)
	team2 := resetKeys(t, w.s, w.base, w.team2)
	viewer := resetKeys(t, w.s, w.base, w.viewer)
	team1 := resetKeys(t, w.s, w.base, w.team1)
	want := w.want(map[string]string{w.team2.id: "keyChanged", w.viewer.id: "keyChanged", w.team1.id: "keyChanged", w.team3.id: "new"})
	got = pendingOf(t, w.owner.testClient, o)
	wantPending(t, got, want)
	wantPending(t, pendingOf(t, w.editor.testClient, o), want)
	if got[w.team2.id].Approval != nil {
		t.Error("a keyChanged entry carries an approval")
	}
	if got[w.team2.id].Ed25519Pub != e2e.B64(team2.keys.epub) || got[w.viewer.id].X25519Pub != e2e.B64(viewer.keys.xpub) ||
		got[w.team1.id].Email != team1.email {
		t.Errorf("keyChanged entries show the user's current keys: %+v", got)
	}
}

// A listed member whose key changed is keyChanged on the listing alone, not
// only through a wrap made for the old key: a member the owner kept without
// a wrap, such as a previous owner, holds none.
func TestPendingListedMemberWithNoWrapWhoseKeyChanged(t *testing.T) {
	w := newApprovalWorld(t)
	if err := w.s.store.WithArtifact(w.o.id, func(tx *store.ArtifactTx) error {
		return tx.DeleteWraps(w.viewer.id)
	}); err != nil {
		t.Fatal(err)
	}
	wantPending(t, pendingOf(t, w.owner.testClient, w.o), w.want(map[string]string{
		w.team1.id: "new", w.team2.id: "new", w.team3.id: "new"}))
	resetKeys(t, w.s, w.base, w.viewer)
	got := pendingOf(t, w.owner.testClient, w.o)
	if got[w.viewer.id].State != "keyChanged" {
		t.Errorf("a listed member with no wrap whose key changed: %+v, want keyChanged", got[w.viewer.id])
	}
}

// An artifact with no membership record yet has no team: nobody is waiting.
func TestPendingOfAnArtifactWithNoRecord(t *testing.T) {
	w := newApprovalWorld(t)
	id := uuid.NewString()
	if _, err := w.s.store.CreateOwnedArtifact(id, "bare", "", w.owner.id, nil); err != nil {
		t.Fatal(err)
	}
	var list []pendingEntry
	w.owner.mustDo("GET", "/api/artifacts/"+id+"/pending", nil, &list, http.StatusOK)
	if len(list) != 0 {
		t.Errorf("pending = %+v, want none", list)
	}
}

// Approving into an artifact with no membership record is a 409, as it is
// for any artifact with no team, not a server error. The access check
// refuses it first, on the artifact's team of none.
func TestApproveOnAnArtifactWithNoRecord(t *testing.T) {
	w := newApprovalWorld(t)
	id := uuid.NewString()
	if _, err := w.s.store.CreateOwnedArtifact(id, "bare", "", w.owner.id, nil); err != nil {
		t.Fatal(err)
	}
	got, msg := status(w.owner.testClient, "POST", "/api/artifacts/"+id+"/keys", map[string]any{"user": w.team1.id, "fp": w.team1.keys.fp()})
	if got != http.StatusConflict {
		t.Errorf("approve with no record: %d %q, want 409", got, msg)
	}
}

func TestPendingOmitsExcludedUsers(t *testing.T) {
	w := newApprovalWorld(t)
	o := w.o
	o.approve(w.owner, w.team1)
	// The owner moves to a new epoch that drops team1 and the viewer.
	b := o.nextEpoch()
	b.Members = []e2e.Member{{User: w.editor.id, Role: "editor", FP: w.editor.keys.fp()}}
	b.Excluded = []e2e.ExcludedEntry{
		{User: w.team1.id, FP: w.team1.keys.fp(), Email: e2e.NormalizeEmail(w.team1.email)},
		{User: w.viewer.id, FP: w.viewer.keys.fp(), Email: e2e.NormalizeEmail(w.viewer.email)},
	}
	if b.Excluded[0].User > b.Excluded[1].User {
		b.Excluded[0], b.Excluded[1] = b.Excluded[1], b.Excluded[0]
	}
	o.apply(b)
	wantPending(t, pendingOf(t, w.owner.testClient, o), w.want(map[string]string{w.team2.id: "new", w.team3.id: "new"}))

	// By user ID, even after the excluded user's key changed.
	resetKeys(t, w.s, w.base, w.viewer)
	wantPending(t, pendingOf(t, w.owner.testClient, o), w.want(map[string]string{w.team2.id: "new", w.team3.id: "new"}))

	// By fingerprint: another account that holds the viewer's old keys.
	if err := w.s.store.DeleteUser(w.team3.id); err != nil {
		t.Fatal(err)
	}
	clone := seedAccountWith(t, w.s, "clone@example.com", "clone-password", false, bundleFor(t, w.viewer.keys))
	// By normalized email: team1's account is gone and someone signs up again.
	if err := w.s.store.DeleteUser(w.team1.id); err != nil {
		t.Fatal(err)
	}
	again := seedKeyedAccount(t, w.s, w.base, w.team1.email)
	wantPending(t, pendingOf(t, w.owner.testClient, o), w.want(map[string]string{w.team2.id: "new"}))
	if _, ok := pendingOf(t, w.owner.testClient, o)[clone.ID]; ok {
		t.Error("pending lists a user whose fingerprint is excluded")
	}
	if _, ok := pendingOf(t, w.owner.testClient, o)[again.id]; ok {
		t.Error("pending lists a user whose normalized email is excluded")
	}
}

func TestApproveRefusals(t *testing.T) {
	type refusal struct {
		name   string
		status int
		msg    string
		// run sets up and returns who sends what.
		run func(t *testing.T, w *approvalWorld) (actor, map[string]any)
	}
	post := func(name string, status int, msg string, run func(t *testing.T, w *approvalWorld) (actor, map[string]any)) refusal {
		return refusal{name, status, msg, run}
	}
	// editedApproval re-signs the owner's approval of team1 with edit applied.
	editedApproval := func(edit func(b *e2e.ApprovalBody)) func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
		return func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			req := approveReq(t, w.o, w.owner, w.team1)
			b := e2e.ApprovalBody{V: 1, Artifact: w.o.id, Epoch: 2, User: w.team1.id, FP: w.team1.keys.fp()}
			edit(&b)
			req["approval"] = signApproval(t, w.owner, b)
			return w.owner, req
		}
	}
	editedWraps := func(edit func(wraps []any) []any) func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
		return func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			req := approveReq(t, w.o, w.owner, w.team1)
			req["wraps"] = edit(req["wraps"].([]any))
			return w.owner, req
		}
	}
	wrap := func(epoch int) map[string]any {
		return map[string]any{"epoch": epoch, "wrapped": e2e.B64(fakeWrap)}
	}
	cases := []refusal{
		post("a viewer", 403, "access does not allow", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			return w.viewer, approveReq(t, w.o, w.viewer, w.team1)
		}),
		post("an approved team member", 403, "access does not allow", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			w.o.approve(w.owner, w.team2)
			return w.team2, approveReq(t, w.o, w.team2, w.team1)
		}),
		post("a user with no access", 404, "not found", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			return w.team3, approveReq(t, w.o, w.team3, w.team1)
		}),
		post("team none", 409, "state refuses", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			w.o.setTeam("none")
			return w.owner, approveReq(t, w.o, w.owner, w.team1)
		}),
		post("a user who holds a wrap", 409, "holds a wrap", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			w.o.approve(w.owner, w.team1)
			return w.owner, approveReq(t, w.o, w.owner, w.team1)
		}),
		post("a listed user", 409, "listed", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			return w.owner, approveReq(t, w.o, w.owner, w.viewer)
		}),
		post("a listed user whose key changed", 409, "listed", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			viewer := resetKeys(t, w.s, w.base, w.viewer)
			return w.owner, approveReq(t, w.o, w.owner, viewer)
		}),
		post("a wrapped user whose key changed", 409, "holds a wrap", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			w.o.approve(w.owner, w.team1)
			team1 := resetKeys(t, w.s, w.base, w.team1)
			return w.owner, approveReq(t, w.o, w.owner, team1)
		}),
		post("the owner", 409, "owner", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			return w.editor, approveReq(t, w.o, w.editor, w.owner)
		}),
		post("an excluded user ID", 409, "excluded", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			w.o.removeAndExclude(w.viewer)
			return w.owner, approveReq(t, w.o, w.owner, w.viewer)
		}),
		post("an excluded fingerprint", 409, "excluded", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			w.o.removeAndExclude(w.viewer)
			if err := w.s.store.DeleteUser(w.viewer.id); err != nil {
				t.Fatal(err)
			}
			clone := seedAccountWith(t, w.s, "clone@example.com", "clone-password", false, bundleFor(t, w.viewer.keys))
			return w.owner, approveReq(t, w.o, w.owner, actor{id: clone.ID, email: clone.Email, keys: w.viewer.keys})
		}),
		post("an excluded normalized email", 409, "excluded", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			w.o.removeAndExclude(w.viewer)
			if err := w.s.store.DeleteUser(w.viewer.id); err != nil {
				t.Fatal(err)
			}
			again := seedKeyedAccount(t, w.s, w.base, "VIEWER@example.com")
			return w.owner, approveReq(t, w.o, w.owner, again)
		}),
		post("a fingerprint another user ID shares", 409, "shares", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			seedAccountWith(t, w.s, "twin@example.com", "twin-password", false, bundleFor(t, w.team1.keys))
			return w.owner, approveReq(t, w.o, w.owner, w.team1)
		}),
		// No case for another user ID sharing the email: users.email is
		// UNIQUE COLLATE NOCASE, so CreateAccount refuses a second account
		// with the same normalized email and the directory cannot hold one.
		// e2e.ValidateApproval's email check is covered only at that level.
		post("a fingerprint that is not the user's current one", 409, "current fingerprint", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			req := approveReq(t, w.o, w.owner, w.team1)
			req["fp"] = w.team2.keys.fp()
			req["approval"] = signApproval(t, w.owner, e2e.ApprovalBody{V: 1, Artifact: w.o.id, Epoch: 2, User: w.team1.id, FP: w.team2.keys.fp()})
			return w.owner, req
		}),
		post("a user who does not exist", 404, "not a user", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			req := approveReq(t, w.o, w.owner, w.team1)
			req["user"] = "no-such-user"
			return w.owner, req
		}),
		post("an approval signed by a key that is not the caller's", 400, "does not verify", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			req := approveReq(t, w.o, w.owner, w.team1)
			forged := signApproval(t, w.team3, e2e.ApprovalBody{V: 1, Artifact: w.o.id, Epoch: 2, User: w.team1.id, FP: w.team1.keys.fp()})
			forged.Signer = w.owner.id
			req["approval"] = forged
			return w.owner, req
		}),
		post("an approval signed by someone else", 400, "not signed by the caller", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			req := approveReq(t, w.o, w.owner, w.team1)
			return w.editor, req
		}),
		post("an approval for another artifact", 400, "artifact", editedApproval(func(b *e2e.ApprovalBody) {
			b.Artifact = "22222222-2222-4222-8222-222222222222"
		})),
		post("an approval for an old epoch", 400, "epoch", editedApproval(func(b *e2e.ApprovalBody) { b.Epoch = 1 })),
		post("an approval for another user", 400, "user", editedApproval(func(b *e2e.ApprovalBody) { b.User = "someone-else" })),
		post("an approval for another fingerprint", 400, "fp", editedApproval(func(b *e2e.ApprovalBody) { b.FP = strings.Repeat("a", 64) })),
		post("an approval with an unknown field", 400, "unknown field", func(t *testing.T, w *approvalWorld) (actor, map[string]any) {
			req := approveReq(t, w.o, w.owner, w.team1)
			req["approval"] = signApprovalRaw(t, w.owner, []byte(`{"v":1,"artifact":"`+w.o.id+`","epoch":2,"user":"`+w.team1.id+`","fp":"`+w.team1.keys.fp()+`","role":"editor"}`))
			return w.owner, req
		}),
		post("no wraps", 400, "missing the wrap for epoch 1", editedWraps(func([]any) []any { return []any{} })),
		post("a wrap missing for the current epoch", 400, "missing the wrap for epoch 2", editedWraps(func(w []any) []any { return w[:1] })),
		post("a wrap missing for an earlier epoch", 400, "missing the wrap for epoch 1", editedWraps(func(w []any) []any { return w[1:] })),
		post("a wrap for a future epoch", 400, "epoch 3", editedWraps(func(w []any) []any { return append(w, wrap(3)) })),
		post("a wrap given twice", 400, "twice", editedWraps(func(w []any) []any { return append(w, w[0]) })),
		post("a wrap of the wrong size", 400, "81 bytes", editedWraps(func(w []any) []any {
			return []any{wrap(1), map[string]any{"epoch": 2, "wrapped": e2e.B64(fakeWrap[:80])}}
		})),
		post("a wrap that is not base64", 400, "base64", editedWraps(func(w []any) []any {
			return []any{wrap(1), map[string]any{"epoch": 2, "wrapped": "!!"}}
		})),
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newApprovalWorld(t)
			caller, req := c.run(t, w)
			wrapsBefore, err := w.s.store.WrapsFor(w.o.id, w.team1.id)
			if err != nil {
				t.Fatal(err)
			}
			before := pendingOf(t, w.owner.testClient, w.o)
			got, msg := status(caller.testClient, "POST", w.o.approvePath(), req)
			if got != c.status || !strings.Contains(msg, c.msg) {
				t.Fatalf("POST keys: %d %q, want %d containing %q", got, msg, c.status, c.msg)
			}
			// A refused approval stores nothing: no wrap, no approval.
			wrapsAfter, err := w.s.store.WrapsFor(w.o.id, w.team1.id)
			if err != nil || len(wrapsAfter) != len(wrapsBefore) {
				t.Errorf("wraps for the user went from %d to %d after a refusal (%v)", len(wrapsBefore), len(wrapsAfter), err)
			}
			after := pendingOf(t, w.owner.testClient, w.o)
			if len(after) != len(before) {
				t.Errorf("pending went from %d to %d entries after a refusal", len(before), len(after))
			}
			for id, p := range before {
				if after[id].State != p.State {
					t.Errorf("%s went from %s to %s after a refusal", id, p.State, after[id].State)
				}
			}
		})
	}
}

func TestApproveStoresWrapsAndLetsTheUserRead(t *testing.T) {
	w := newApprovalWorld(t)
	vid := pushVersion(t, w.owner.testClient, w.o.id)
	base := "/api/artifacts/" + w.o.id
	vbase := base + "/versions/" + vid

	// Before approval, team1 sees nothing.
	wantStatus(t, w.team1.testClient, "GET", base, nil, http.StatusNotFound)

	w.o.approve(w.editor, w.team1)
	var keys struct {
		Wraps []struct {
			Epoch   int    `json:"epoch"`
			Wrapped string `json:"wrapped"`
			FP      string `json:"fp"`
		} `json:"wraps"`
	}
	w.team1.mustDo("GET", base+"/keys", nil, &keys, http.StatusOK)
	if len(keys.Wraps) != 2 || keys.Wraps[0].Epoch != 1 || keys.Wraps[1].Epoch != 2 ||
		keys.Wraps[0].FP != w.team1.keys.fp() || keys.Wraps[0].Wrapped != e2e.B64(fakeWrap) {
		t.Errorf("the approved user's wraps: %+v", keys.Wraps)
	}
	var view gotArtifact
	w.team1.mustDo("GET", base, nil, &view, http.StatusOK)
	if view.Access != "team" {
		t.Errorf("access after approval: %q", view.Access)
	}
	w.team1.mustDo("POST", vbase+"/db/query", map[string]any{"sql": "SELECT 1"}, nil, http.StatusOK)

	// An approved team member reads but cannot write, share, or approve.
	wantStatus(t, w.team1.testClient, "POST", vbase+"/db/batch", map[string]any{"statements": []map[string]any{{"sql": "CREATE TABLE t (x)"}}}, http.StatusForbidden)
	if r := w.team1.upload("POST", base+"/versions", map[string]string{"index.html": "x"}, nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("approved team member push: %d", r.StatusCode)
	}
	wantStatus(t, w.team1.testClient, "PATCH", base, map[string]any{"name": "x"}, http.StatusForbidden)
	wantStatus(t, w.team1.testClient, "GET", base+"/pending", nil, http.StatusForbidden)

	// Listed as an editor, with no new wrap, they write.
	b := w.o.next()
	b.Members = append(b.Members, e2e.Member{User: w.team1.id, Role: "editor", FP: w.team1.keys.fp()})
	sortMembers(b.Members)
	w.o.listWithoutWraps(b)
	w.team1.mustDo("GET", base, nil, &view, http.StatusOK)
	if view.Access != "editor" {
		t.Errorf("access once listed: %q", view.Access)
	}
	w.team1.mustDo("POST", vbase+"/db/batch", map[string]any{"statements": []map[string]any{{"sql": "CREATE TABLE t (x)"}}}, nil, http.StatusOK)
}

// An approval that races a next-epoch record loses: the record lands first
// and the approval no longer names the current epoch or covers every one.
func TestApprovalRacingANextEpochRecord(t *testing.T) {
	w := newApprovalWorld(t)
	stale := approveReq(t, w.o, w.owner, w.team1)
	b := w.o.nextEpoch()
	w.o.apply(b)
	if got, msg := status(w.owner.testClient, "POST", w.o.approvePath(), stale); got != http.StatusBadRequest || !strings.Contains(msg, "epoch") {
		t.Fatalf("an approval for epoch 2 after epoch 3 began: %d %q, want 400 naming the epoch", got, msg)
	}
	// The same approval of epoch 3 with wraps for epochs 1 and 2 only.
	short := approveReq(t, w.o, w.owner, w.team1)
	short["wraps"] = short["wraps"].([]any)[:2]
	if got, msg := status(w.owner.testClient, "POST", w.o.approvePath(), short); got != http.StatusBadRequest || !strings.Contains(msg, "epoch 3") {
		t.Fatalf("wraps that stop at epoch 2: %d %q, want 400 naming epoch 3", got, msg)
	}
	w.o.approve(w.owner, w.team1)
}

// An editor's approval and the owner's next-epoch record race. The artifact
// row lock lets one in first, and that one wins: an approval that lands
// first makes the record refuse a team member who holds a wrap and is
// neither listed nor excluded, and a record that lands first makes the
// approval name a past epoch. Either way the approved user ends with a wrap
// for every epoch up to the latest or with none, and a stored approval only
// beside the wraps it came with.
func TestApprovalRacingANextEpochRecordConcurrently(t *testing.T) {
	w := newApprovalWorld(t)
	for i := 0; i < 20; i++ {
		o := newArtifact(t, w.owner, "race")
		o.share("editor", w.editor)
		o.setTeam("viewer")
		approval := approveReq(t, o, w.editor, w.team1)
		b := o.nextEpoch()
		record := o.change(b)

		var approveStatus, recordStatus int
		var approveMsg, recordMsg string
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			approveStatus, approveMsg = status(w.editor.testClient, "POST", o.approvePath(), approval)
		}()
		go func() {
			defer wg.Done()
			<-start
			recordStatus, recordMsg = status(w.owner.testClient, "PUT", "/api/artifacts/"+o.id+"/membership", record)
		}()
		close(start)
		wg.Wait()

		if (approveStatus == http.StatusOK) == (recordStatus == http.StatusOK) {
			t.Fatalf("round %d: the approval answered %d %q and the record %d %q, want exactly one to land", i, approveStatus, approveMsg, recordStatus, recordMsg)
		}
		if approveStatus != http.StatusOK && approveStatus != http.StatusBadRequest ||
			recordStatus != http.StatusOK && recordStatus != http.StatusBadRequest {
			t.Fatalf("round %d: the approval answered %d %q and the record %d %q, want 200 or 400", i, approveStatus, approveMsg, recordStatus, recordMsg)
		}
		art, err := w.s.store.ArtifactByID(o.id)
		if err != nil {
			t.Fatal(err)
		}
		var wraps []store.Wrap
		var approvals []store.Approval
		if err := w.s.store.WithArtifact(o.id, func(tx *store.ArtifactTx) (err error) {
			if wraps, err = tx.Wraps(); err != nil {
				return err
			}
			approvals, err = tx.Approvals()
			return err
		}); err != nil {
			t.Fatal(err)
		}
		epochs := []int{}
		for _, wr := range wraps {
			if wr.UserID == w.team1.id {
				epochs = append(epochs, wr.Epoch)
			}
		}
		if len(epochs) != 0 && len(epochs) != art.Epoch {
			t.Fatalf("round %d: the approved user holds wraps for epochs %v at epoch %d, want every epoch or none (approval: %d %q)", i, epochs, art.Epoch, approveStatus, approveMsg)
		}
		stored := false
		for _, a := range approvals {
			stored = stored || a.UserID == w.team1.id
		}
		if stored != (len(epochs) != 0) {
			t.Fatalf("round %d: approval stored = %v with wraps for epochs %v", i, stored, epochs)
		}
	}
}

// An editor whose keys changed holds a wrap and a listing for keys that are
// no longer theirs. access.Check refuses their approval with a 403 before
// the transaction starts; the check inside it, against the latest record, is
// exercised by the membership package's tests.
func TestApprovalFromAnEditorWhoseKeysChanged(t *testing.T) {
	w := newApprovalWorld(t)
	editor := resetKeys(t, w.s, w.base, w.editor)
	// The editor reads, but access.Check already refuses their approval.
	wantStatus(t, editor.testClient, "POST", w.o.approvePath(), approveReq(t, w.o, editor, w.team1), http.StatusForbidden)
}
