package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/server"
)

// withCarol signs carol up on s's server and returns her keyed client.
func (s *sharing) withCarol(t *testing.T) *Client {
	t.Helper()
	signupVerify(t, s.host, s.m, "carol@example.com", testPassword)
	out, err := New(s.host, "").Login("carol@example.com", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	return keyedFor(t, s.host, out.APIKey)
}

// groupRows is the members of a verified group by email.
func groupRows(t *testing.T, c *Client, id string) (*GroupView, map[string]GroupMemberView) {
	t.Helper()
	v, err := c.ShowGroup(id, false)
	if err != nil {
		t.Fatalf("ShowGroup: %v", err)
	}
	rows := map[string]GroupMemberView{}
	for _, m := range v.Members {
		rows[m.Email] = m
	}
	return v, rows
}

func TestGroupLifecycle(t *testing.T) {
	s := newSharing(t)
	carol := s.withCarol(t)
	bobID, carolID := s.userID(t, s.bob), s.userID(t, carol)

	v, err := s.ada.CreateGroup("Reviewers", []string{"bob@example.com"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if v.Name != "Reviewers" || v.Seq != 1 || v.Role != "manager" || len(v.Members) != 2 {
		t.Fatalf("created group = %+v", v)
	}
	rows := map[string]GroupMemberView{}
	for _, m := range v.Members {
		rows[m.Email] = m
	}
	if rows["ada@example.com"].Role != "manager" || rows["ada@example.com"].State != "self" ||
		rows["bob@example.com"].Role != "member" || rows["bob@example.com"].State != e2e.PinUnverified || rows["bob@example.com"].FP == "" {
		t.Errorf("rows = %+v", rows)
	}

	// The keyring holds the group's seq and head; bob, who is no manager,
	// reads the group and stores his own.
	adaKeys := mustUnlock(t, s.ada)
	kr, err := s.ada.ReadKeyring(adaKeys)
	if err != nil {
		t.Fatal(err)
	}
	var w groupWire
	if err := s.ada.doJSON("GET", "/api/groups/"+v.ID, nil, &w); err != nil {
		t.Fatal(err)
	}
	if got := kr.Groups[v.ID]; got != (e2e.GroupPin{Seq: 1, Head: e2e.BodyHash(w.Records[0].Body)}) {
		t.Errorf("ada's keyring groups entry = %+v", got)
	}
	bv, _ := groupRows(t, s.bob, v.ID)
	if bv.Role != "member" || bv.Seq != 1 {
		t.Errorf("bob's view = %+v", bv)
	}

	// A member changes nothing.
	if _, err := s.bob.AddGroupMember(v.ID, "carol@example.com", false, false); !errors.Is(err, ErrNotGroupManager) {
		t.Errorf("a member adding: %v, want ErrNotGroupManager", err)
	}
	if err := s.bob.RenameGroup(v.ID, "Mine", false); !errors.Is(err, ErrNotGroupManager) {
		t.Errorf("a member renaming: %v, want ErrNotGroupManager", err)
	}
	if _, err := s.bob.RemoveGroupMember(v.ID, "ada@example.com", false); !errors.Is(err, ErrNotGroupManager) {
		t.Errorf("a member removing: %v, want ErrNotGroupManager", err)
	}

	// Ada makes bob a manager; bob adds carol under a record he signs.
	res, err := s.ada.AddGroupMember(v.ID, "bob@example.com", true, false)
	if err != nil || res.Unchanged || res.Role != "manager" {
		t.Fatalf("make bob a manager: %+v, %v", res, err)
	}
	if res, err := s.ada.AddGroupMember(v.ID, "bob@example.com", true, false); err != nil || !res.Unchanged {
		t.Errorf("the same again: %+v, %v, want unchanged", res, err)
	}
	if res, err := s.bob.AddGroupMember(v.ID, "carol@example.com", false, false); err != nil || res.Prior != e2e.PinNew {
		t.Fatalf("bob adds carol: %+v, %v", res, err)
	}
	v, rows = groupRows(t, s.ada, v.ID)
	if v.Seq != 3 || len(v.Members) != 3 || rows["bob@example.com"].Role != "manager" || rows["carol@example.com"].Role != "member" {
		t.Errorf("after the changes: %+v", v)
	}
	if rows["carol@example.com"].State != e2e.PinNew {
		t.Errorf("carol's pin state = %q, want new: bob added her, so ada never pinned her", rows["carol@example.com"].State)
	}

	// Rename, remove, and the guards on them.
	if err := s.ada.RenameGroup(v.ID, "Release reviewers", false); err != nil {
		t.Fatal(err)
	}
	if err := s.ada.RenameGroup(v.ID, "", false); err == nil {
		t.Error("an empty name was accepted")
	}
	if got, err := s.ada.RemoveGroupMember(v.ID, "carol@example.com", false); err != nil || got != carolID {
		t.Errorf("remove carol: %q, %v", got, err)
	}
	if _, err := s.ada.RemoveGroupMember(v.ID, "carol@example.com", false); !errors.Is(err, ErrNotGroupMember) {
		t.Errorf("remove carol again: %v, want ErrNotGroupMember", err)
	}
	if _, err := s.ada.RemoveGroupMember(v.ID, bobID, false); err != nil {
		t.Errorf("remove bob by user ID: %v", err)
	}
	if _, err := s.ada.RemoveGroupMember(v.ID, "ada@example.com", false); !errors.Is(err, ErrLastManager) {
		t.Errorf("remove the last manager: %v, want ErrLastManager", err)
	}
	v, _ = groupRows(t, s.ada, v.ID)
	if v.Seq != 6 || v.Name != "Release reviewers" || len(v.Members) != 1 {
		t.Errorf("final group = %+v", v)
	}

	// Only a manager deletes, and a deleted group is gone.
	var apiErr *APIError
	if err := carol.DeleteGroup(v.ID); !errors.As(err, &apiErr) || apiErr.Status != http.StatusForbidden {
		t.Errorf("a non-manager deleting: %v, want 403", err)
	}
	if err := s.ada.DeleteGroup(v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.ShowGroup(v.ID, false); !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound {
		t.Errorf("show after delete: %v, want 404", err)
	}
}

func TestResolveGroup(t *testing.T) {
	s := newSharing(t)
	one, err := s.ada.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	two, err := s.bob.CreateGroup("Writers", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{one.ID, "Reviewers"} {
		if g, err := s.ada.ResolveGroup(ref); err != nil || g.ID != one.ID || g.Name != "Reviewers" || g.Role != "manager" {
			t.Errorf("ResolveGroup(%q) = %+v, %v", ref, g, err)
		}
	}
	if g, err := s.ada.ResolveGroup("Writers"); err != nil || g.ID != two.ID || g.Role != "" {
		t.Errorf("ResolveGroup(Writers) = %+v, %v", g, err)
	}
	if _, err := s.ada.ResolveGroup("reviewers"); !errors.Is(err, ErrNoGroup) {
		t.Errorf("a name in another case: %v, want ErrNoGroup", err)
	}
	if _, err := s.ada.ResolveGroup("nothing"); !errors.Is(err, ErrNoGroup) {
		t.Errorf("an unknown name: %v, want ErrNoGroup", err)
	}
	three, err := s.bob.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.ResolveGroup("Reviewers"); !errors.Is(err, ErrAmbiguousGroup) {
		t.Errorf("a shared name: %v, want ErrAmbiguousGroup", err)
	}
	// An ID is never ambiguous.
	if g, err := s.ada.ResolveGroup(three.ID); err != nil || g.ID != three.ID {
		t.Errorf("ResolveGroup(id) = %+v, %v", g, err)
	}
}

func TestAShorterGroupChainIsRefused(t *testing.T) {
	s := newSharing(t)
	v, err := s.ada.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.AddGroupMember(v.ID, "bob@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	// Ada's keyring holds seq 2 after that. The server now serves one record.
	proxy := tamperingProxy(t, s.host, "/api/groups/"+v.ID, func(m map[string]json.RawMessage) {
		var recs []json.RawMessage
		json.Unmarshal(m["records"], &recs)
		m["records"] = mustJSON(t, recs[:1])
	})
	ada := viaProxy(proxy, s.ada)
	if _, err := ada.ShowGroup(v.ID, false); !errors.Is(err, e2e.ErrRollback) {
		t.Errorf("ShowGroup on a shorter chain: %v, want ErrRollback", err)
	}
	if _, err := ada.AddGroupMember(v.ID, "bob@example.com", true, false); !errors.Is(err, e2e.ErrRollback) {
		t.Errorf("AddGroupMember on a shorter chain: %v, want ErrRollback", err)
	}
	// Nothing was signed.
	if _, rows := groupRows(t, s.ada, v.ID); rows["bob@example.com"].Role != "member" {
		t.Errorf("rows = %+v", rows)
	}
}

func TestAForkedGroupChainIsRefused(t *testing.T) {
	s := newSharing(t)
	v, err := s.ada.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.AddGroupMember(v.ID, "bob@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	// Ada's keyring says the record at seq 2 hashed to another head.
	k := mustUnlock(t, s.ada)
	if _, err := s.ada.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Groups[v.ID] = e2e.GroupPin{Seq: 2, Head: e2e.BodyHash([]byte("another record"))}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.ShowGroup(v.ID, false); !errors.Is(err, e2e.ErrFork) {
		t.Errorf("ShowGroup on a forked chain: %v, want ErrFork", err)
	}
	if err := s.ada.RenameGroup(v.ID, "Other", false); !errors.Is(err, e2e.ErrFork) {
		t.Errorf("RenameGroup on a forked chain: %v, want ErrFork", err)
	}
}

// swapSigner is a rewrite of a group's answer that serves pair as the current
// keys of user.
func swapSigner(t *testing.T, user string, pair e2e.KeyPair) func(map[string]json.RawMessage) {
	return func(m map[string]json.RawMessage) {
		var signers map[string]map[string]json.RawMessage
		if err := json.Unmarshal(m["signers"], &signers); err != nil {
			t.Fatal(err)
		}
		signers[user]["x25519"] = mustJSON(t, pair.X25519)
		signers[user]["ed25519"] = mustJSON(t, pair.Ed25519)
		m["signers"] = mustJSON(t, signers)
	}
}

// A chain whose records were not signed by the keys the group serves for its
// signers is refused, so a server cannot invent a manager.
func TestAGroupChainFromAnotherKeyIsRefused(t *testing.T) {
	s := newSharing(t)
	v, err := s.ada.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, pair, _ := strangerKeys(t)
	proxy := tamperingProxy(t, s.host, "/api/groups/"+v.ID, swapSigner(t, mustUnlock(t, s.ada).UserID, pair))
	if _, err := viaProxy(proxy, s.bob).ShowGroup(v.ID, false); err == nil || !errors.Is(err, e2e.ErrChain) {
		t.Errorf("ShowGroup with ada's served key swapped: %v, want ErrChain", err)
	}
}

// A signer's served key is anchored at the caller's pin: a key that differs
// from it with no rotation is refused, naming the signer, even when the chain
// was signed by that key, and accepting it does not make a chain it did not
// sign verify.
func TestAGroupSignersKeyIsAnchoredAtThePin(t *testing.T) {
	s := newSharing(t)
	adaID := mustUnlock(t, s.ada).UserID
	v, err := s.ada.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.bob.Pin("ada@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	_, pair, fp := strangerKeys(t)
	proxy := tamperingProxy(t, s.host, "/api/groups/"+v.ID, swapSigner(t, adaID, pair))
	bob := viaProxy(proxy, s.bob)
	var changed *KeyChangedError
	if _, err := bob.ShowGroup(v.ID, false); !errors.As(err, &changed) || changed.User != adaID || changed.Email != "ada@example.com" || changed.CurrentFP != fp {
		t.Fatalf("ShowGroup with ada's served key changed: %v, want a KeyChangedError for ada", err)
	}
	if _, err := bob.ShowGroup(v.ID, true); !errors.Is(err, e2e.ErrChain) {
		t.Errorf("ShowGroup accepting a key that did not sign the chain: %v, want ErrChain", err)
	}
	if got := pinOf(t, s.bob, adaID).FP; got != mustUnlock(t, s.ada).FP {
		t.Errorf("ada's pin is %q after the refusals, want it unchanged", got)
	}
}

// A signer not pinned yet is pinned unverified.
func TestAGroupSignerNotPinnedIsPinnedUnverified(t *testing.T) {
	s := newSharing(t)
	adaID := mustUnlock(t, s.ada).UserID
	v, err := s.ada.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p := pinOf(t, s.bob, adaID); p.FP != "" {
		t.Fatalf("bob already pins ada: %+v", p)
	}
	view, err := s.bob.ShowGroup(v.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if p := pinOf(t, s.bob, adaID); p.FP != mustUnlock(t, s.ada).FP || p.State != e2e.PinUnverified {
		t.Errorf("ada's pin = %+v, want her keys, unverified", p)
	}
	// The members are shown against the pins as they are now.
	if got := view.Members[0]; got.User != adaID || got.State != e2e.PinUnverified {
		t.Errorf("ada's row = %+v, want unverified", got)
	}
	// The caller's own key is not pinned.
	if _, err := s.ada.ShowGroup(v.ID, false); err != nil {
		t.Fatal(err)
	}
	if p := pinOf(t, s.ada, adaID); p.FP != "" {
		t.Errorf("ada pins herself: %+v", p)
	}
	// With the chain already in the keyring, a signer pinned in the meantime
	// is still shown by the pin.
	k := mustUnlock(t, s.bob)
	if _, err := s.bob.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		delete(kr.Pins, adaID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	view, err = s.bob.ShowGroup(v.ID, false)
	if err != nil || view.Members[0].State != e2e.PinUnverified {
		t.Errorf("ada's row after her pin was lost and taken again = %+v, %v, want unverified", view, err)
	}
}

// A signer whose keys rotated from the pinned ones is accepted, the pin
// follows, and the records signed under the earlier key still verify.
func TestAGroupSignerWhoRotatedFollowsThePin(t *testing.T) {
	s := newSharing(t)
	bobID := s.userID(t, s.bob)
	v, err := s.ada.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.AddGroupMember(v.ID, "bob@example.com", true, false); err != nil {
		t.Fatal(err)
	}
	oldFP := mustUnlock(t, s.bob).FP
	if err := s.bob.RenameGroup(v.ID, "Under the old key", false); err != nil {
		t.Fatal(err)
	}
	rotateOK(t, s.bob, false)
	newFP := mustUnlock(t, s.bob).FP
	if newFP == oldFP {
		t.Fatal("bob's fingerprint did not change")
	}
	if err := s.bob.RenameGroup(v.ID, "Under the new key", false); err != nil {
		t.Fatal(err)
	}
	if p := pinOf(t, s.ada, bobID); p.FP != oldFP {
		t.Fatalf("ada pins %q before reading, want bob's old keys %q", p.FP, oldFP)
	}
	view, err := s.ada.ShowGroup(v.ID, false)
	if err != nil || view.Name != "Under the new key" || view.Seq != 4 {
		t.Fatalf("ShowGroup after bob rotated: %+v, %v", view, err)
	}
	if p := pinOf(t, s.ada, bobID); p.FP != newFP || p.State != e2e.PinUnverified || p.RotSeq != 1 {
		t.Errorf("bob's pin = %+v, want the new keys, unverified, at rotation 1", p)
	}
}

// A signer whose key changed with no rotation is refused until accepted, and
// accepting it moves the pin.
func TestAGroupSignerWhoseKeyChangedNeedsAccepting(t *testing.T) {
	s := newSharing(t)
	bobID := s.userID(t, s.bob)
	if _, err := s.ada.Pin("bob@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	s.resetBob(t) // bob's keys change with no rotation record
	v, err := s.bob.CreateGroup("Mine", nil)
	if err != nil {
		t.Fatal(err)
	}

	var changed *KeyChangedError
	if _, err := s.ada.ShowGroup(v.ID, false); !errors.As(err, &changed) || changed.User != bobID || changed.Email != "bob@example.com" {
		t.Fatalf("ShowGroup under bob's new key: %v, want a KeyChangedError for bob", err)
	}
	if err := s.ada.RenameGroup(v.ID, "Other", true); !errors.Is(err, ErrNotGroupManager) {
		t.Errorf("RenameGroup accepting bob's key: %v, want ErrNotGroupManager, so the chain verified", err)
	}
	if p := pinOf(t, s.ada, bobID); p.FP != mustUnlock(t, s.bob).FP || p.State != e2e.PinUnverified {
		t.Errorf("bob's pin = %+v, want his new keys, unverified", p)
	}
	if _, err := s.ada.ShowGroup(v.ID, false); err != nil {
		t.Errorf("ShowGroup once pinned: %v", err)
	}
}

// A group whose manager was deactivated is still read: the directory no
// longer lists them, and the group serves their keys.
func TestAGroupOfADeactivatedManagerStillVerifies(t *testing.T) {
	s := newSharing(t)
	carol := s.withCarol(t)
	bobID := s.userID(t, s.bob)
	v, err := s.ada.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.AddGroupMember(v.ID, "bob@example.com", true, false); err != nil {
		t.Fatal(err)
	}
	if err := s.bob.RenameGroup(v.ID, "Bob was here", false); err != nil {
		t.Fatal(err)
	}
	signupVerify(t, s.host, s.m, "admin@example.com", testPassword)
	admin := New(s.host, "")
	if _, err := admin.Login("admin@example.com", testPassword); err != nil {
		t.Fatal(err)
	}
	if err := admin.doJSON("PATCH", "/api/admin/users/"+bobID, map[string]any{"disabled": true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.DirectoryUser(bobID); !isNotFound(err) {
		t.Fatalf("the directory still serves bob: %v", err)
	}
	for name, c := range map[string]*Client{"ada, who pins bob": s.ada, "carol, who does not": carol} {
		view, err := c.ShowGroup(v.ID, false)
		if err != nil || view.Name != "Bob was here" {
			t.Errorf("%s: ShowGroup = %+v, %v", name, view, err)
		}
	}
}

func TestGroupAddingAMemberChecksThePin(t *testing.T) {
	s := newSharing(t)
	v, err := s.ada.CreateGroup("Reviewers", []string{"bob@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	s.resetBob(t) // bob's keys change with no rotation record

	var changed *KeyChangedError
	if _, err := s.ada.AddGroupMember(v.ID, "bob@example.com", false, false); !errors.As(err, &changed) {
		t.Fatalf("adding bob under new keys: %v, want KeyChangedError", err)
	}
	// Nothing was signed, and the pin stands.
	if _, rows := groupRows(t, s.ada, v.ID); len(rows) != 2 {
		t.Errorf("rows = %+v", rows)
	}
	if v2, _ := groupRows(t, s.ada, v.ID); v2.Seq != 1 {
		t.Errorf("seq = %d, want 1", v2.Seq)
	}
	if _, err := s.ada.CreateGroup("Other", []string{"bob@example.com"}); !errors.As(err, &changed) {
		t.Errorf("creating a group with bob under new keys: %v, want KeyChangedError", err)
	}

	res, err := s.ada.AddGroupMember(v.ID, "bob@example.com", true, true)
	if err != nil || res.Prior != e2e.PinChanged {
		t.Fatalf("accepting the new key: %+v, %v", res, err)
	}
	k := mustUnlock(t, s.ada)
	kr, err := s.ada.ReadKeyring(k)
	if err != nil {
		t.Fatal(err)
	}
	var bobFP string
	if _, rows := groupRows(t, s.ada, v.ID); true {
		bobFP = rows["bob@example.com"].FP
	}
	if kr.Pins[s.userID(t, s.bob)].FP != bobFP {
		t.Errorf("the pin %q is not the fp the record lists %q", kr.Pins[s.userID(t, s.bob)].FP, bobFP)
	}
}

func TestAViewerAccountIsNeverMadeAGroupManager(t *testing.T) {
	host, m := newTestServerWith(t, func(c *server.Config) {
		c.SignupDomains = []string{"example.com"}
		c.ViewerDomains = []string{"viewers.test"}
	})
	clients := map[string]*Client{}
	for _, email := range []string{"ada@example.com", "carol@viewers.test"} {
		signupVerify(t, host, m, email, testPassword)
		out, err := New(host, "").Login(email, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		clients[email] = keyedFor(t, host, out.APIKey)
	}
	ada, carol := clients["ada@example.com"], clients["carol@viewers.test"]
	v, err := ada.CreateGroup("Reviewers", []string{"carol@viewers.test"})
	if err != nil {
		t.Fatalf("a viewer account as a member: %v", err)
	}
	// The client refuses it before it signs anything: the server would too.
	_, err = ada.AddGroupMember(v.ID, "carol@viewers.test", true, false)
	var refused *APIError
	if err == nil || errors.As(err, &refused) || !strings.Contains(err.Error(), "viewer account") {
		t.Errorf("making a viewer account a manager: %v, want the client's own refusal", err)
	}
	if _, rows := groupRows(t, ada, v.ID); rows["carol@viewers.test"].Role != "member" {
		t.Errorf("rows = %+v", rows)
	}
	var apiErr *APIError
	if _, err := carol.CreateGroup("Mine", nil); !errors.As(err, &apiErr) || apiErr.Status != http.StatusForbidden {
		t.Errorf("a viewer account creating: %v, want 403", err)
	}
	// It reads the group it is in.
	if cv, err := carol.ShowGroup(v.ID, false); err != nil || cv.Role != "member" {
		t.Errorf("a viewer account reading: %+v, %v", cv, err)
	}
}

func TestCreateGroupRefusesABadName(t *testing.T) {
	s := newSharing(t)
	for _, name := range []string{"", "Review\ners"} {
		if _, err := s.ada.CreateGroup(name, nil); !errors.Is(err, e2e.ErrChain) {
			t.Errorf("CreateGroup(%q): %v, want ErrChain", name, err)
		}
	}
	if gs, err := s.ada.Groups(); err != nil || len(gs) != 0 {
		t.Errorf("groups after the refusals: %+v, %v", gs, err)
	}
}

// A creator listed as a member of their own group is listed once, as the
// manager.
func TestGroupCreateIgnoresTheCreatorAsAMember(t *testing.T) {
	s := newSharing(t)
	v, err := s.ada.CreateGroup("Solo", []string{"ada@example.com", "bob@example.com", "bob@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Members) != 2 || v.Role != "manager" {
		t.Errorf("members = %+v, role %q, want ada and bob once each, ada a manager", v.Members, v.Role)
	}
}

// recordGroup keeps the entry another device stored when it holds a higher
// seq, and refuses the same seq at another head.
func TestGroupRecordKeepsTheHigherSeqAndRefusesAFork(t *testing.T) {
	s := newSharing(t)
	v, err := s.ada.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	k := mustUnlock(t, s.ada)
	vg, err := s.ada.VerifyGroup(k, v.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	stale := e2e.NewKeyring() // what a read before the other device wrote held

	other := e2e.GroupPin{Seq: 5, Head: e2e.BodyHash([]byte("later"))}
	if _, err := s.ada.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Groups[v.ID] = other
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	kr, err := s.ada.recordGroup(k, stale, v.ID, vg.Chain)
	if err != nil || kr.Groups[v.ID] != other {
		t.Errorf("recordGroup over a higher seq: %+v, %v, want the entry kept", kr.Groups[v.ID], err)
	}

	forked := e2e.GroupPin{Seq: 1, Head: e2e.BodyHash([]byte("forked"))}
	if _, err := s.ada.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Groups[v.ID] = forked
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.recordGroup(k, stale, v.ID, vg.Chain); !errors.Is(err, e2e.ErrFork) {
		t.Errorf("recordGroup over the same seq at another head: %v, want ErrFork", err)
	}
}

// groupAnswer reads GET /api/groups/{id} as c, for a test to build a tampered
// answer from.
func groupAnswer(t *testing.T, c *Client, id string) groupWire {
	t.Helper()
	var w groupWire
	if err := c.doJSON("GET", "/api/groups/"+id, nil, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

// answeringWith serves w as the answer for group id, and the real server's
// for everything else.
func answeringWith(t *testing.T, host, id string, w groupWire) string {
	t.Helper()
	return tamperingProxy(t, host, "/api/groups/"+id, func(m map[string]json.RawMessage) {
		for k, v := range mustJSONMap(t, w) {
			m[k] = v
		}
	})
}

func mustJSONMap(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(mustJSON(t, v), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// A group answer with no keys for a signer is refused.
func TestAGroupAnswerWithoutAKeyForASignerIsRefused(t *testing.T) {
	s := newSharing(t)
	v, err := s.ada.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := tamperingProxy(t, s.host, "/api/groups/"+v.ID, func(m map[string]json.RawMessage) {
		m["signers"] = json.RawMessage("{}")
	})
	if _, err := viaProxy(proxy, s.bob).ShowGroup(v.ID, false); err == nil || !strings.Contains(err.Error(), "did not serve the keys of") {
		t.Errorf("ShowGroup with no signers: %v, want the keys not served", err)
	}
}

// The caller's own key is the one their keyring holds, so a server cannot
// serve other keys for the caller.
func TestAGroupSignerEntryForTheCallerIsTheirOwnKey(t *testing.T) {
	s := newSharing(t)
	v, err := s.ada.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, pair, _ := strangerKeys(t)
	proxy := tamperingProxy(t, s.host, "/api/groups/"+v.ID, swapSigner(t, mustUnlock(t, s.ada).UserID, pair))
	if _, err := viaProxy(proxy, s.ada).ShowGroup(v.ID, false); err != nil {
		t.Errorf("ShowGroup for ada with her own entry swapped: %v", err)
	}
}

// A record claims a signer but is signed under another user's key, which the
// other user's own record puts among the keys. The claimed signer's key does
// not lead to it, so the chain is refused.
func TestAGroupRecordSignedUnderAnotherUsersKeyIsRefused(t *testing.T) {
	s := newSharing(t)
	v, err := s.ada.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	adaID, bob := mustUnlock(t, s.ada).UserID, mustUnlock(t, s.bob)
	w := groupAnswer(t, s.bob, v.ID)
	members := []e2e.GroupMember{{User: adaID, FP: bob.FP, Role: "manager"}, {User: bob.UserID, FP: bob.FP, Role: "manager"}}
	slices.SortFunc(members, func(a, b e2e.GroupMember) int { return strings.Compare(a.User, b.User) })
	sign := func(seq int, prev, signer string) e2e.Envelope {
		body, err := json.Marshal(e2e.GroupBody{V: 1, Group: v.ID, Seq: seq, Prev: prev, Name: "Reviewers", Members: members, Signer: signer, SignerFP: bob.FP})
		if err != nil {
			t.Fatal(err)
		}
		env, err := e2e.NewEnvelope(bob.Ed25519Seed, signer, "group", body)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	first := sign(1, "", adaID)
	second := sign(2, e2e.BodyHash(first.Body), bob.UserID)
	w.Records = []e2e.Envelope{first, second}
	w.Signers[bob.UserID] = groupSignerWire{X25519: e2e.B64(bob.X25519Pub), Ed25519: e2e.B64(bob.Ed25519Pub)}
	proxy := answeringWith(t, s.host, v.ID, w)
	if _, err := viaProxy(proxy, s.bob).ShowGroup(v.ID, false); !errors.Is(err, e2e.ErrChain) || !strings.Contains(err.Error(), "does not lead to") {
		t.Errorf("ShowGroup of a record signed under bob's key, claiming ada: %v, want ErrChain, not lead to", err)
	}
}

// Rotation records that do not lead to a signer's current key add no key
// that may sign for them.
func TestSignerKeysTakeOnlyRotationsThatLeadToTheCurrentKey(t *testing.T) {
	s := newSharing(t)
	v, err := s.ada.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	adaID := mustUnlock(t, s.ada).UserID
	bobID := s.userID(t, s.bob)
	rotateOK(t, s.bob, false)
	bobRotations, err := s.bob.Rotations(bobID)
	if err != nil || len(bobRotations) != 1 {
		t.Fatalf("bob's rotations = %v, %v", bobRotations, err)
	}
	w := groupAnswer(t, s.bob, v.ID)
	served := w.Signers[adaID]
	served.Rotations = bobRotations // none of them is ada's
	w.Signers[adaID] = served
	k := mustUnlock(t, s.bob)
	kr, err := s.bob.ReadKeyring(k)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.bob.anchorSigners(k, kr, w, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.keys) != 1 || len(got.mayBe[adaID]) != 1 {
		t.Errorf("ada's keys = %v, %v, want her current key only", got.keys, got.mayBe)
	}
}
