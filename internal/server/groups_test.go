package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/google/uuid"
)

// gotGroup is a group as the endpoints answer.
type gotGroup struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Seq     int            `json:"seq"`
	Members int            `json:"members"`
	Role    string         `json:"role"`
	Records []e2e.Envelope `json:"records"`
}

func gm(a actor, role string) e2e.GroupMember {
	return e2e.GroupMember{User: a.id, FP: a.keys.fp(), Role: role}
}

func sortGroupMembers(ms []e2e.GroupMember) []e2e.GroupMember {
	sort.Slice(ms, func(i, j int) bool { return ms[i].User < ms[j].User })
	return ms
}

// groupMembers is the members sorted by user ID.
func groupMembers(ms ...e2e.GroupMember) []e2e.GroupMember { return sortGroupMembers(ms) }

func signGroup(t *testing.T, signer actor, b e2e.GroupBody) e2e.Envelope {
	t.Helper()
	body, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(signer.keys.seed, signer.id, "group", body)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// groupOf is a group a test created, with its latest body and its hash.
type groupOf struct {
	t      *testing.T
	id     string
	latest e2e.GroupBody
	hash   string
}

// firstGroupBody is the first record of a new group that creator signs.
func firstGroupBody(creator actor, name string, members ...e2e.GroupMember) e2e.GroupBody {
	return e2e.GroupBody{V: 1, Group: uuid.NewString(), Seq: 1, Name: name, Members: groupMembers(members...),
		Signer: creator.id, SignerFP: creator.keys.fp()}
}

// newGroup creates a group as creator and expects it to land.
func newGroup(t *testing.T, creator actor, name string, members ...e2e.GroupMember) *groupOf {
	t.Helper()
	b := firstGroupBody(creator, name, members...)
	env := signGroup(t, creator, b)
	var got gotGroup
	creator.mustDo("POST", "/api/groups", map[string]any{"record": env}, &got, http.StatusCreated)
	return &groupOf{t: t, id: b.Group, latest: b, hash: e2e.BodyHash(env.Body)}
}

// next is the record after the latest, signed by signer, before edit.
func (g *groupOf) next(signer actor, edit func(*e2e.GroupBody)) e2e.GroupBody {
	b := g.latest
	b.Seq++
	b.Prev = g.hash
	b.Signer, b.SignerFP = signer.id, signer.keys.fp()
	b.Members = append([]e2e.GroupMember(nil), b.Members...)
	if edit != nil {
		edit(&b)
	}
	return b
}

// put PUTs b signed by signer, and expects want.
func (g *groupOf) put(signer actor, b e2e.GroupBody, want int) {
	g.t.Helper()
	env := signGroup(g.t, signer, b)
	wantStatus(g.t, signer.testClient, "PUT", "/api/groups/"+g.id, map[string]any{"record": env}, want)
	if want == http.StatusOK {
		g.latest, g.hash = b, e2e.BodyHash(env.Body)
	}
}

// apply is put for a record that must land.
func (g *groupOf) apply(signer actor, edit func(*e2e.GroupBody)) {
	g.t.Helper()
	g.put(signer, g.next(signer, edit), http.StatusOK)
}

type groupWorld struct {
	t                      *testing.T
	s                      *Server
	url                    string
	alice, bob, carol      actor
	dave                   actor // a second member-role account
	admin                  *testClient
	viewerAccount, mallory actor
}

func newGroupWorld(t *testing.T) *groupWorld {
	t.Helper()
	s, ts := testServer(t)
	w := &groupWorld{t: t, s: s, url: ts.URL}
	w.alice = seedKeyedAccount(t, s, ts.URL, "alice@example.com")
	w.bob = seedKeyedAccount(t, s, ts.URL, "bob@example.com")
	w.carol = seedKeyedAccount(t, s, ts.URL, "carol@example.com")
	w.dave = seedKeyedAccount(t, s, ts.URL, "dave@example.com")
	w.viewerAccount = seedKeyedAccount(t, s, ts.URL, "viewer@example.com")
	setRole(t, s, w.viewerAccount.id, store.RoleViewer)
	w.mallory = seedKeyedAccount(t, s, ts.URL, "mallory@example.com")
	w.admin = login(t, ts.URL, "admin@example.com", "admin-password")
	return w
}

func TestCreateAndReadAGroup(t *testing.T) {
	w := newGroupWorld(t)
	var empty []gotGroup
	w.alice.mustDo("GET", "/api/groups", nil, &empty, http.StatusOK)
	if empty == nil || len(empty) != 0 {
		t.Errorf("list with no groups = %#v, want []", empty)
	}

	b := firstGroupBody(w.alice, "Reviewers", gm(w.alice, "manager"), gm(w.bob, "member"))
	env := signGroup(t, w.alice, b)
	var created gotGroup
	w.alice.mustDo("POST", "/api/groups", map[string]any{"record": env}, &created, http.StatusCreated)
	if created.ID != b.Group || created.Name != "Reviewers" || created.Seq != 1 || created.Members != 2 || created.Role != "manager" || len(created.Records) != 1 {
		t.Errorf("POST answered %+v", created)
	}
	if e2e.BodyHash(created.Records[0].Body) != e2e.BodyHash(env.Body) || created.Records[0].Signer != w.alice.id {
		t.Errorf("POST's record is not the stored one: %+v", created.Records[0])
	}

	// Every signed-in user reads the group, each with their own role.
	for _, c := range []struct {
		who  actor
		role string
	}{{w.alice, "manager"}, {w.bob, "member"}, {w.carol, ""}, {w.viewerAccount, ""}} {
		who, role := c.who, c.role
		var got gotGroup
		who.mustDo("GET", "/api/groups/"+b.Group, nil, &got, http.StatusOK)
		if got.Role != role || got.Name != "Reviewers" || got.Members != 2 || len(got.Records) != 1 {
			t.Errorf("%s reads %+v, want role %q", who.email, got, role)
		}
		var list []gotGroup
		who.mustDo("GET", "/api/groups", nil, &list, http.StatusOK)
		if len(list) != 1 || list[0].ID != b.Group || list[0].Role != role || list[0].Records != nil || list[0].Seq != 1 || list[0].Members != 2 {
			t.Errorf("%s lists %+v, want one group, role %q, no records", who.email, list, role)
		}
	}
	wantStatus(t, w.alice.testClient, "GET", "/api/groups/"+uuid.NewString(), nil, http.StatusNotFound)
	wantStatus(t, &testClient{t: t, base: w.url}, "GET", "/api/groups", nil, http.StatusUnauthorized)
	wantStatus(t, &testClient{t: t, base: w.url}, "GET", "/api/groups/"+b.Group, nil, http.StatusUnauthorized)
}

func TestCreateGroupRefusals(t *testing.T) {
	w := newGroupWorld(t)
	other := w.mallory
	good := func() e2e.GroupBody {
		return firstGroupBody(w.alice, "Reviewers", gm(w.alice, "manager"), gm(w.bob, "member"))
	}
	// unverified and deactivated accounts, made through the store.
	unverifiedKeys := newUserKeys(t)
	unverified, err := w.s.store.CreateAccount("new@example.com", "New", "hash", bundleFor(t, unverifiedKeys), store.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	disabled := w.dave
	if err := w.s.store.SetUserDisabled(disabled.id, true); err != nil {
		t.Fatal(err)
	}
	newKeyed := func(a actor, fp string) e2e.GroupMember { return e2e.GroupMember{User: a.id, FP: fp, Role: "member"} }

	cases := []struct {
		name string
		body func() (e2e.GroupBody, actor) // the body, and who signs it
		want int
	}{
		{"valid", func() (e2e.GroupBody, actor) { return good(), w.alice }, http.StatusCreated},
		{"signed by another user", func() (e2e.GroupBody, actor) { return good(), other }, http.StatusBadRequest},
		{"body signer is another user", func() (e2e.GroupBody, actor) {
			b := good()
			b.Signer = w.bob.id
			return b, w.alice
		}, http.StatusBadRequest},
		{"signerFp is not the current fingerprint", func() (e2e.GroupBody, actor) {
			b := good()
			b.SignerFP = w.bob.keys.fp()
			return b, w.alice
		}, http.StatusBadRequest},
		{"group is not a UUID", func() (e2e.GroupBody, actor) {
			b := good()
			b.Group = "reviewers"
			return b, w.alice
		}, http.StatusBadRequest},
		{"group is an uppercase UUID", func() (e2e.GroupBody, actor) {
			b := good()
			b.Group = strings.ToUpper(b.Group)
			return b, w.alice
		}, http.StatusBadRequest},
		{"seq 2", func() (e2e.GroupBody, actor) {
			b := good()
			b.Seq = 2
			return b, w.alice
		}, http.StatusBadRequest},
		{"has a prev", func() (e2e.GroupBody, actor) {
			b := good()
			b.Prev = strings.Repeat("0", 64)
			return b, w.alice
		}, http.StatusBadRequest},
		{"creator listed as a member", func() (e2e.GroupBody, actor) {
			return firstGroupBody(w.alice, "Reviewers", gm(w.alice, "member"), gm(w.bob, "manager")), w.alice
		}, http.StatusBadRequest},
		{"creator not listed", func() (e2e.GroupBody, actor) {
			return firstGroupBody(w.alice, "Reviewers", gm(w.bob, "manager")), w.alice
		}, http.StatusBadRequest},
		{"creator listed under another fp", func() (e2e.GroupBody, actor) {
			return firstGroupBody(w.alice, "Reviewers", e2e.GroupMember{User: w.alice.id, FP: w.bob.keys.fp(), Role: "manager"}), w.alice
		}, http.StatusBadRequest},
		{"member is not a user", func() (e2e.GroupBody, actor) {
			return firstGroupBody(w.alice, "Reviewers", gm(w.alice, "manager"),
				e2e.GroupMember{User: "u-nobody", FP: w.bob.keys.fp(), Role: "member"}), w.alice
		}, http.StatusBadRequest},
		{"member is unverified", func() (e2e.GroupBody, actor) {
			return firstGroupBody(w.alice, "Reviewers", gm(w.alice, "manager"), newKeyed(actor{id: unverified.ID}, unverifiedKeys.fp())), w.alice
		}, http.StatusBadRequest},
		{"member is deactivated", func() (e2e.GroupBody, actor) {
			return firstGroupBody(w.alice, "Reviewers", gm(w.alice, "manager"), gm(disabled, "member")), w.alice
		}, http.StatusBadRequest},
		{"member's fp is not current", func() (e2e.GroupBody, actor) {
			return firstGroupBody(w.alice, "Reviewers", gm(w.alice, "manager"), newKeyed(w.bob, w.carol.keys.fp())), w.alice
		}, http.StatusBadRequest},
		{"viewer account made a manager", func() (e2e.GroupBody, actor) {
			return firstGroupBody(w.alice, "Reviewers", gm(w.alice, "manager"), gm(w.viewerAccount, "manager")), w.alice
		}, http.StatusBadRequest},
		{"empty name", func() (e2e.GroupBody, actor) {
			b := good()
			b.Name = ""
			return b, w.alice
		}, http.StatusBadRequest},
		{"name with a control character", func() (e2e.GroupBody, actor) {
			b := good()
			b.Name = "Review\ners"
			return b, w.alice
		}, http.StatusBadRequest},
		{"members not sorted", func() (e2e.GroupBody, actor) {
			b := good()
			b.Members = []e2e.GroupMember{b.Members[1], b.Members[0]}
			return b, w.alice
		}, http.StatusBadRequest},
		{"duplicate member", func() (e2e.GroupBody, actor) {
			b := good()
			b.Members = []e2e.GroupMember{gm(w.alice, "manager"), gm(w.alice, "manager")}
			return b, w.alice
		}, http.StatusBadRequest},
		{"bad role", func() (e2e.GroupBody, actor) {
			return firstGroupBody(w.alice, "Reviewers", gm(w.alice, "manager"), gm(w.bob, "owner")), w.alice
		}, http.StatusBadRequest},
	}
	for _, c := range cases {
		b, signer := c.body()
		env := signGroup(t, signer, b)
		if code, msg := status(w.alice.testClient, "POST", "/api/groups", map[string]any{"record": env}); code != c.want {
			t.Errorf("%s: %d %q, want %d", c.name, code, msg, c.want)
		}
	}
	// The directory check would also refuse a creator listed under another
	// fingerprint, so the first-record rule is told apart by what it says.
	elsewhere := firstGroupBody(w.alice, "Reviewers", e2e.GroupMember{User: w.alice.id, FP: w.bob.keys.fp(), Role: "manager"})
	if code, msg := status(w.alice.testClient, "POST", "/api/groups", map[string]any{"record": signGroup(t, w.alice, elsewhere)}); code != http.StatusBadRequest || !strings.Contains(msg, "under your current fingerprint") {
		t.Errorf("a creator listed under another fp: %d %q, want 400 and the first-record rule", code, msg)
	}

	// A body with a key the format does not have, and a record that does not
	// verify under the caller's key.
	raw := strings.Replace(string(mustJSONBytes(t, good())), `"name":`, `"extra":1,"name":`, 1)
	env, err := e2e.NewEnvelope(w.alice.keys.seed, w.alice.id, "group", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, w.alice.testClient, "POST", "/api/groups", map[string]any{"record": env}, http.StatusBadRequest)
	// Signed with alice's key, under another user's name on the envelope.
	named, err := e2e.NewEnvelope(w.alice.keys.seed, w.bob.id, "group", mustJSONBytes(t, good()))
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, w.alice.testClient, "POST", "/api/groups", map[string]any{"record": named}, http.StatusBadRequest)
	forged := signGroup(t, w.alice, good())
	forged.Sig[0] ^= 1
	wantStatus(t, w.alice.testClient, "POST", "/api/groups", map[string]any{"record": forged}, http.StatusBadRequest)
	envFor := signGroup(t, w.alice, good())
	envFor.Body = append([]byte(nil), envFor.Body...)
	envFor.Body[len(envFor.Body)-3] ^= 1
	wantStatus(t, w.alice.testClient, "POST", "/api/groups", map[string]any{"record": envFor}, http.StatusBadRequest)
	// Signed as a different purpose.
	body := mustJSONBytes(t, good())
	wrongPurpose, err := e2e.NewEnvelope(w.alice.keys.seed, w.alice.id, "membership", body)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, w.alice.testClient, "POST", "/api/groups", map[string]any{"record": wrongPurpose}, http.StatusBadRequest)

	// Only the one valid group landed.
	var list []gotGroup
	w.alice.mustDo("GET", "/api/groups", nil, &list, http.StatusOK)
	if len(list) != 1 {
		t.Errorf("%d groups stored, want 1", len(list))
	}
}

func mustJSONBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAGroupIDCannotBeUsedTwice(t *testing.T) {
	w := newGroupWorld(t)
	g := newGroup(t, w.alice, "Reviewers", gm(w.alice, "manager"))
	again := firstGroupBody(w.bob, "Mine", gm(w.bob, "manager"))
	again.Group = g.id
	if code, msg := status(w.bob.testClient, "POST", "/api/groups", map[string]any{"record": signGroup(t, w.bob, again)}); code != http.StatusConflict || !strings.Contains(msg, "already exists") {
		t.Errorf("a second creation: %d %q, want 409 and \"already exists\"", code, msg)
	}
	var got gotGroup
	w.alice.mustDo("GET", "/api/groups/"+g.id, nil, &got, http.StatusOK)
	if got.Name != "Reviewers" || len(got.Records) != 1 {
		t.Errorf("the group after the refused second creation: %+v", got)
	}
}

func TestViewerAccountsSignNoGroupRecord(t *testing.T) {
	w := newGroupWorld(t)
	v := w.viewerAccount
	b := firstGroupBody(v, "Mine", gm(v, "manager"))
	wantViewerRefused(t, v, "POST", "/api/groups", map[string]any{"record": signGroup(t, v, b)})

	// A viewer account that was made a manager, then demoted, may not
	// change or delete the group either.
	g := newGroup(t, w.alice, "Reviewers", gm(w.alice, "manager"), gm(w.bob, "manager"))
	setRole(t, w.s, w.bob.id, store.RoleViewer)
	wantViewerRefused(t, w.bob, "PUT", "/api/groups/"+g.id, map[string]any{"record": signGroup(t, w.bob, g.next(w.bob, nil))})
	wantViewerRefused(t, w.bob, "DELETE", "/api/groups/"+g.id, nil)
	w.alice.mustDo("GET", "/api/groups/"+g.id, nil, nil, http.StatusOK)
	// It reads, as every signed-in user does.
	w.bob.mustDo("GET", "/api/groups/"+g.id, nil, nil, http.StatusOK)
}

func TestGroupLaterRecordRules(t *testing.T) {
	w := newGroupWorld(t)
	g := newGroup(t, w.alice, "Reviewers", gm(w.alice, "manager"), gm(w.bob, "member"))
	put := func(name string, signer actor, edit func(*e2e.GroupBody), want int, why ...string) {
		t.Helper()
		b := g.next(signer, edit)
		env := signGroup(t, signer, b)
		code, msg := status(signer.testClient, "PUT", "/api/groups/"+g.id, map[string]any{"record": env})
		if code != want {
			t.Errorf("%s: %d %q, want %d", name, code, msg, want)
		}
		// The store refuses a stale seq as well, so the handler's own
		// refusal is told apart by what it says.
		for _, w := range why {
			if !strings.Contains(msg, w) {
				t.Errorf("%s: %q does not mention %q", name, msg, w)
			}
		}
	}
	put("seq skips one", w.alice, func(b *e2e.GroupBody) { b.Seq += 1 }, http.StatusConflict, "seq 3, want 2")
	put("seq repeats", w.alice, func(b *e2e.GroupBody) { b.Seq = 1 }, http.StatusConflict, "seq 1, want 2")
	put("prev is another hash", w.alice, func(b *e2e.GroupBody) { b.Prev = strings.Repeat("0", 64) }, http.StatusConflict, "prev")
	put("group changes", w.alice, func(b *e2e.GroupBody) { b.Group = uuid.NewString() }, http.StatusBadRequest)
	put("a member signs", w.bob, nil, http.StatusForbidden)
	put("a stranger signs", w.carol, nil, http.StatusForbidden)
	put("signed as another user", w.alice, func(b *e2e.GroupBody) { b.Signer, b.SignerFP = w.carol.id, w.carol.keys.fp() }, http.StatusBadRequest)
	put("no manager left", w.alice, func(b *e2e.GroupBody) { b.Members = []e2e.GroupMember{gm(w.bob, "member")} }, http.StatusBadRequest)
	put("the name is empty", w.alice, func(b *e2e.GroupBody) { b.Name = "" }, http.StatusBadRequest)
	put("a new member is not a user", w.alice, func(b *e2e.GroupBody) {
		b.Members = groupMembers(append(b.Members, e2e.GroupMember{User: "u-nobody", FP: w.carol.keys.fp(), Role: "member"})...)
	}, http.StatusBadRequest)
	put("a new member is listed under another fp", w.alice, func(b *e2e.GroupBody) {
		b.Members = groupMembers(append(b.Members, e2e.GroupMember{User: w.carol.id, FP: w.bob.keys.fp(), Role: "member"})...)
	}, http.StatusBadRequest)

	// Nothing above landed.
	var got gotGroup
	w.alice.mustDo("GET", "/api/groups/"+g.id, nil, &got, http.StatusOK)
	if got.Seq != 1 || len(got.Records) != 1 {
		t.Fatalf("after the refusals: %+v", got)
	}
	// Unknown group, and a record for a group that does not exist.
	wantStatus(t, w.alice.testClient, "PUT", "/api/groups/"+uuid.NewString(), map[string]any{"record": signGroup(t, w.alice, g.next(w.alice, nil))}, http.StatusNotFound)

	// The valid record lands, and the group reads back with both records.
	g.apply(w.alice, func(b *e2e.GroupBody) {
		b.Name = "Release reviewers"
		b.Members = groupMembers(append(b.Members, gm(w.carol, "member"))...)
	})
	w.bob.mustDo("GET", "/api/groups/"+g.id, nil, &got, http.StatusOK)
	if got.Seq != 2 || got.Name != "Release reviewers" || got.Members != 3 || got.Role != "member" || len(got.Records) != 2 {
		t.Errorf("after the change: %+v", got)
	}
	if members, _ := w.s.store.GroupMembers(g.id); len(members) != 3 {
		t.Errorf("stored members = %+v, want 3", members)
	}
}

func TestGroupManagerAddedByAManagerSigns(t *testing.T) {
	w := newGroupWorld(t)
	g := newGroup(t, w.alice, "Reviewers", gm(w.alice, "manager"))
	g.apply(w.alice, func(b *e2e.GroupBody) { b.Members = groupMembers(gm(w.alice, "manager"), gm(w.bob, "manager")) })
	g.apply(w.bob, func(b *e2e.GroupBody) {
		b.Members = groupMembers(gm(w.alice, "manager"), gm(w.bob, "manager"), gm(w.carol, "member"))
	})
	// A manager removes themselves while another remains, and then is not one.
	g.apply(w.alice, func(b *e2e.GroupBody) { b.Members = groupMembers(gm(w.bob, "manager"), gm(w.carol, "member")) })
	g.put(w.alice, g.next(w.alice, nil), http.StatusForbidden)
}

func TestGroupManagerWhoRotatedSignsUnderTheNewKey(t *testing.T) {
	w := newGroupWorld(t)
	g := newGroup(t, w.alice, "Reviewers", gm(w.alice, "manager"), gm(w.bob, "manager"))
	r := newRotation(t, w.s, w.alice.base, w.bob)
	w.bob.mustDo("POST", "/api/me/rotate", r.request(), nil, http.StatusOK)
	bob2 := r.asNew()

	// The record before lists bob under his old fp, which his rotation record
	// links to the new one.
	g.apply(bob2, func(b *e2e.GroupBody) { b.Name = "Release reviewers" })

	// His old key no longer signs: signerFp is not his current fingerprint.
	old := w.bob
	b := g.next(old, nil)
	wantStatus(t, bob2.testClient, "PUT", "/api/groups/"+g.id, map[string]any{"record": signGroup(t, old, b)}, http.StatusBadRequest)

	// Without his rotation records, nothing leads from the fp the record
	// lists to his current one.
	if _, err := w.s.store.DB().Exec(`DELETE FROM user_rotations WHERE user_id = ?`, bob2.id); err != nil {
		t.Fatal(err)
	}
	g.put(bob2, g.next(bob2, nil), http.StatusForbidden)
}

func TestGroupChangedEntriesAreCheckedAndCarriedOnesAreNot(t *testing.T) {
	w := newGroupWorld(t)
	g := newGroup(t, w.alice, "Reviewers", gm(w.alice, "manager"), gm(w.bob, "member"), gm(w.carol, "member"))
	if err := w.s.store.SetUserDisabled(w.bob.id, true); err != nil {
		t.Fatal(err)
	}
	// bob is deactivated: his entry carried over unchanged is accepted.
	g.apply(w.alice, func(b *e2e.GroupBody) { b.Name = "Release reviewers" })
	// A change to his entry is a changed entry, which is checked.
	g.put(w.alice, g.next(w.alice, func(b *e2e.GroupBody) {
		for i := range b.Members {
			if b.Members[i].User == w.bob.id {
				b.Members[i].Role = "manager"
			}
		}
	}), http.StatusBadRequest)
	// He leaves, and cannot be added back while deactivated.
	g.apply(w.alice, func(b *e2e.GroupBody) { b.Members = groupMembers(gm(w.alice, "manager"), gm(w.carol, "member")) })
	g.put(w.alice, g.next(w.alice, func(b *e2e.GroupBody) {
		b.Members = groupMembers(append(b.Members, gm(w.bob, "member"))...)
	}), http.StatusBadRequest)
	if err := w.s.store.SetUserDisabled(w.bob.id, false); err != nil {
		t.Fatal(err)
	}
	g.apply(w.alice, func(b *e2e.GroupBody) { b.Members = groupMembers(append(b.Members, gm(w.bob, "member"))...) })

	// An entry changed to a fingerprint that is not the user's current one
	// is refused.
	g.put(w.alice, g.next(w.alice, func(b *e2e.GroupBody) {
		for i := range b.Members {
			if b.Members[i].User == w.carol.id {
				b.Members[i].FP = w.bob.keys.fp()
			}
		}
	}), http.StatusBadRequest)
}

func TestGroupViewerAccountsAreMembersAndNeverNewManagers(t *testing.T) {
	w := newGroupWorld(t)
	v := w.viewerAccount
	g := newGroup(t, w.alice, "Reviewers", gm(w.alice, "manager"), gm(w.bob, "manager"))
	// A viewer account is a member, and is not made a manager.
	g.apply(w.alice, func(b *e2e.GroupBody) { b.Members = groupMembers(append(b.Members, gm(v, "member"))...) })
	g.put(w.alice, g.next(w.alice, func(b *e2e.GroupBody) {
		for i := range b.Members {
			if b.Members[i].User == v.id {
				b.Members[i].Role = "manager"
			}
		}
	}), http.StatusBadRequest)

	// bob becomes a viewer account: his manager entry stays when carried
	// over, and so does he as a manager in a record carol cannot change.
	setRole(t, w.s, w.bob.id, store.RoleViewer)
	g.apply(w.alice, func(b *e2e.GroupBody) { b.Name = "Release reviewers" })

	// His entry changes when he rotates his keys, and he stays a manager:
	// he is not newly made one.
	r := newRotation(t, w.s, w.alice.base, w.bob)
	w.bob.mustDo("POST", "/api/me/rotate", r.request(), nil, http.StatusOK)
	bob2 := r.asNew()
	g.apply(w.alice, func(b *e2e.GroupBody) {
		for i := range b.Members {
			if b.Members[i].User == bob2.id {
				b.Members[i].FP = bob2.keys.fp()
			}
		}
	})
}

func TestConcurrentGroupRecordsOnOnePrev(t *testing.T) {
	w := newGroupWorld(t)
	g := newGroup(t, w.alice, "Reviewers", gm(w.alice, "manager"))
	var envs [2]e2e.Envelope
	for i, name := range []string{"One", "Two"} {
		envs[i] = signGroup(t, w.alice, g.next(w.alice, func(b *e2e.GroupBody) { b.Name = name }))
	}
	var codes [2]int
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range envs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes[i], _ = status(w.alice.testClient, "PUT", "/api/groups/"+g.id, map[string]any{"record": envs[i]})
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
	var got gotGroup
	w.alice.mustDo("GET", "/api/groups/"+g.id, nil, &got, http.StatusOK)
	if len(got.Records) != 2 || e2e.BodyHash(got.Records[1].Body) != e2e.BodyHash(envs[winner].Body) {
		t.Errorf("stored chain is not the winner's (request %d): %d records", winner, len(got.Records))
	}
}

func TestDeletingAGroup(t *testing.T) {
	w := newGroupWorld(t)
	g := newGroup(t, w.alice, "Reviewers", gm(w.alice, "manager"), gm(w.bob, "member"))
	wantStatus(t, w.bob.testClient, "DELETE", "/api/groups/"+g.id, nil, http.StatusForbidden)
	wantStatus(t, w.carol.testClient, "DELETE", "/api/groups/"+g.id, nil, http.StatusForbidden)
	wantStatus(t, w.alice.testClient, "DELETE", "/api/groups/"+uuid.NewString(), nil, http.StatusNotFound)
	w.alice.mustDo("GET", "/api/groups/"+g.id, nil, nil, http.StatusOK)

	w.alice.mustDo("DELETE", "/api/groups/"+g.id, nil, nil, http.StatusOK)
	w.alice.mustDo("GET", "/api/groups/"+g.id, nil, nil, http.StatusNotFound)
	if recs, err := w.s.store.GroupRecords(g.id); err == nil {
		t.Errorf("records survive the delete: %d", len(recs))
	}
	if ms, _ := w.s.store.GroupMembers(g.id); len(ms) != 0 {
		t.Errorf("members survive the delete: %+v", ms)
	}

	// An administrator, who is not a member, deletes any group.
	h := newGroup(t, w.alice, "Another", gm(w.alice, "manager"))
	w.admin.mustDo("DELETE", "/api/groups/"+h.id, nil, nil, http.StatusOK)
	w.alice.mustDo("GET", "/api/groups/"+h.id, nil, nil, http.StatusNotFound)
}

// The group routes are not on a content-origin token's allowlist.
func TestGroupRoutesAreNotForContentTokens(t *testing.T) {
	for _, p := range []string{"GET /api/groups", "POST /api/groups", "GET /api/groups/{id}", "PUT /api/groups/{id}", "DELETE /api/groups/{id}"} {
		if contentTokenRoutes[p] {
			t.Errorf("%s is allowed to a content token", p)
		}
	}
}

// gotSigners is the signers of a group as the endpoints answer.
type gotSigners struct {
	Signers map[string]struct {
		X25519    string         `json:"x25519"`
		Ed25519   string         `json:"ed25519"`
		Rotations []e2e.Envelope `json:"rotations"`
	} `json:"signers"`
}

// The group view carries the current keys and rotation records of everyone who
// signed a record, a deactivated account too, and of no one else.
func TestGroupServesItsSignersKeys(t *testing.T) {
	w := newGroupWorld(t)
	g := newGroup(t, w.alice, "Reviewers", gm(w.alice, "manager"), gm(w.bob, "manager"), gm(w.carol, "member"))
	r := newRotation(t, w.s, w.alice.base, w.bob)
	w.bob.mustDo("POST", "/api/me/rotate", r.request(), nil, http.StatusOK)
	bob2 := r.asNew()
	g.apply(bob2, func(b *e2e.GroupBody) { b.Name = "Release reviewers" })
	bobRotations := rotations(t, w.alice.testClient, w.bob.id)
	if len(bobRotations) != 1 {
		t.Fatalf("bob has %d rotation records, want 1", len(bobRotations))
	}
	if err := w.s.store.SetUserDisabled(w.bob.id, true); err != nil {
		t.Fatal(err)
	}

	check := func(what string, got gotSigners) {
		t.Helper()
		if len(got.Signers) != 2 {
			t.Fatalf("%s: signers = %+v, want alice and bob only", what, got.Signers)
		}
		a, ok := got.Signers[w.alice.id]
		if !ok || a.X25519 != w.alice.keys.pair().X25519 || a.Ed25519 != w.alice.keys.pair().Ed25519 || len(a.Rotations) != 0 {
			t.Errorf("%s: alice's entry = %+v", what, a)
		}
		b, ok := got.Signers[w.bob.id]
		if !ok || b.X25519 != bob2.keys.pair().X25519 || b.Ed25519 != bob2.keys.pair().Ed25519 {
			t.Errorf("%s: bob's entry = %+v, want his current keys", what, b)
		}
		if len(b.Rotations) != 1 || e2e.BodyHash(b.Rotations[0].Body) != e2e.BodyHash(bobRotations[0].Body) {
			t.Errorf("%s: bob's rotations = %+v, want his one record", what, b.Rotations)
		}
	}
	var got gotSigners
	w.alice.mustDo("GET", "/api/groups/"+g.id, nil, &got, http.StatusOK)
	check("GET", got)
	// A signer with no rotation records has an empty list, not null.
	var raw struct {
		Signers map[string]map[string]json.RawMessage `json:"signers"`
	}
	w.alice.mustDo("GET", "/api/groups/"+g.id, nil, &raw, http.StatusOK)
	if got := string(raw.Signers[w.alice.id]["rotations"]); got != "[]" {
		t.Errorf("alice's rotations = %s, want []", got)
	}

	// POST and PUT answer with the same view; the list does not carry it.
	var put gotSigners
	env := signGroup(t, w.alice, g.next(w.alice, nil))
	w.alice.mustDo("PUT", "/api/groups/"+g.id, map[string]any{"record": env}, &put, http.StatusOK)
	check("PUT", put)
	var created gotSigners
	other := firstGroupBody(w.alice, "Other", gm(w.alice, "manager"))
	w.alice.mustDo("POST", "/api/groups", map[string]any{"record": signGroup(t, w.alice, other)}, &created, http.StatusCreated)
	if len(created.Signers) != 1 || created.Signers[w.alice.id].Ed25519 != w.alice.keys.pair().Ed25519 {
		t.Errorf("POST: signers = %+v, want alice", created.Signers)
	}
	var list []map[string]json.RawMessage
	w.alice.mustDo("GET", "/api/groups", nil, &list, http.StatusOK)
	for _, g := range list {
		if _, ok := g["signers"]; ok {
			t.Errorf("the list carries signers: %v", g)
		}
	}
}

// A group ID is never reused: after the group is deleted, a first record
// under its ID is a 409, as for a group that exists.
func TestAGroupIDCannotBeReusedAfterTheGroupIsDeleted(t *testing.T) {
	w := newGroupWorld(t)
	first := firstGroupBody(w.alice, "Reviewers", gm(w.alice, "manager"))
	env := signGroup(t, w.alice, first)
	w.alice.mustDo("POST", "/api/groups", map[string]any{"record": env}, nil, http.StatusCreated)
	w.alice.mustDo("DELETE", "/api/groups/"+first.Group, nil, nil, http.StatusOK)

	code, msg := status(w.alice.testClient, "POST", "/api/groups", map[string]any{"record": env})
	if code != http.StatusConflict || !strings.Contains(msg, "deleted") {
		t.Errorf("re-creating a deleted group: %d %q, want 409 and a mention of the deletion", code, msg)
	}
	// Another signer, another content, the same ID: refused all the same.
	again := firstGroupBody(w.bob, "Mine", gm(w.bob, "manager"))
	again.Group = first.Group
	wantStatus(t, w.bob.testClient, "POST", "/api/groups", map[string]any{"record": signGroup(t, w.bob, again)}, http.StatusConflict)
	w.alice.mustDo("GET", "/api/groups/"+first.Group, nil, nil, http.StatusNotFound)
}

// An account that signed a record of a group that still exists is not
// deleted: 409, as for one that owns artifacts. A member who signed nothing
// is, and so is the signer once the group is gone.
func TestAnAccountThatSignedAGroupRecordCannotBeDeleted(t *testing.T) {
	w := newGroupWorld(t)
	g := newGroup(t, w.alice, "Reviewers", gm(w.alice, "manager"), gm(w.bob, "member"))

	code, msg := status(w.admin, "DELETE", "/api/admin/users/"+w.alice.id, nil)
	if code != http.StatusConflict || !strings.Contains(msg, "group") {
		t.Errorf("deleting a signer: %d %q, want 409 naming the group", code, msg)
	}
	if _, err := w.s.store.UserByID(w.alice.id); err != nil {
		t.Errorf("the signer was deleted anyway: %v", err)
	}
	// Deactivating is the way out, and the group stays readable.
	if err := w.s.store.SetUserDisabled(w.alice.id, true); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Signers map[string]json.RawMessage `json:"signers"`
	}
	w.carol.mustDo("GET", "/api/groups/"+g.id, nil, &got, http.StatusOK)
	if _, ok := got.Signers[w.alice.id]; !ok {
		t.Errorf("the deactivated signer's keys are not served: %v", got.Signers)
	}

	wantStatus(t, w.admin, "DELETE", "/api/admin/users/"+w.bob.id, nil, http.StatusOK)
	w.admin.mustDo("DELETE", "/api/groups/"+g.id, nil, nil, http.StatusOK)
	wantStatus(t, w.admin, "DELETE", "/api/admin/users/"+w.alice.id, nil, http.StatusOK)
}

// A member who was deactivated and carried over unchanged can be re-listed
// once reactivated, and a changed fingerprint is checked again.
func TestAReactivatedGroupMemberCanBeListedAgain(t *testing.T) {
	w := newGroupWorld(t)
	g := newGroup(t, w.alice, "Reviewers", gm(w.alice, "manager"), gm(w.bob, "member"))
	if err := w.s.store.SetUserDisabled(w.bob.id, true); err != nil {
		t.Fatal(err)
	}
	g.apply(w.alice, func(b *e2e.GroupBody) { b.Name = "Release reviewers" }) // carried over unchanged
	if err := w.s.store.SetUserDisabled(w.bob.id, false); err != nil {
		t.Fatal(err)
	}
	promote := func(b *e2e.GroupBody) {
		for i := range b.Members {
			if b.Members[i].User == w.bob.id {
				b.Members[i].Role = "manager"
			}
		}
	}
	g.apply(w.alice, promote) // listed again, now a changed entry, and active
	g.put(w.alice, g.next(w.alice, func(b *e2e.GroupBody) {
		for i := range b.Members {
			if b.Members[i].User == w.bob.id {
				b.Members[i].FP = w.carol.keys.fp()
			}
		}
	}), http.StatusBadRequest)
}
