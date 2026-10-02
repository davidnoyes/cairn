package client

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// ownWraps opens every AK wrap c holds for the artifact, by epoch. A user
// the server no longer lets read has none.
func ownWraps(t *testing.T, c *Client, artifact string) map[int][]byte {
	t.Helper()
	k := mustUnlock(t, c)
	keys, err := c.Keys(artifact)
	if err != nil {
		return map[int][]byte{}
	}
	out := map[int][]byte{}
	for _, w := range keys.Wraps {
		ak, err := e2e.Unwrap(k.X25519Priv, e2e.WrapContext{
			Purpose: "ak", Artifact: artifact, Epoch: uint64(w.Epoch), RecipientID: k.UserID, RecipientPub: k.X25519Pub,
		}, w.Wrapped)
		if err != nil {
			t.Fatalf("Unwrap epoch %d: %v", w.Epoch, err)
		}
		out[w.Epoch] = ak
	}
	return out
}

func latestRecord(t *testing.T, c *Client, artifact string) e2e.MembershipBody {
	t.Helper()
	return publicChain(t, c, artifact).Latest
}

func excludedEmails(b e2e.MembershipBody) []string {
	var out []string
	for _, x := range b.Excluded {
		out = append(out, x.Email)
	}
	slices.Sort(out)
	return out
}

func recordCount(t *testing.T, c *Client, artifact string) int {
	t.Helper()
	m, err := c.Membership(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return len(m.Records)
}

func TestUnshareEndsAMembersAccess(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	oldAK := ownWraps(t, s.bob, s.artifact)[1]
	if oldAK == nil {
		t.Fatal("bob holds no epoch 1 wrap")
	}
	res, err := s.ada.Unshare(s.artifact, "bob@example.com")
	if err != nil {
		t.Fatalf("Unshare: %v", err)
	}
	if !res.NewEpoch || res.Epoch != 2 || res.Link != "" {
		t.Errorf("Unshare = %+v, want epoch 2, no link", res)
	}
	if len(res.Excluded) != 1 || res.Excluded[0].User.Email != "bob@example.com" {
		t.Errorf("Excluded = %+v, want bob", res.Excluded)
	}
	// B holds no wrap, so cannot read epoch 2 or any other.
	if got := ownWraps(t, s.bob, s.artifact); len(got) != 0 {
		t.Errorf("bob still holds wraps for epochs %v", got)
	}
	// The new epoch has an AK bob never held.
	k := mustUnlock(t, s.ada)
	va, err := s.ada.VerifyArtifact(k, s.artifact, k.FP)
	if err != nil {
		t.Fatal(err)
	}
	aks, err := s.ada.epochAKs(k, s.artifact, va.Chain)
	if err != nil {
		t.Fatal(err)
	}
	if string(aks[1]) != string(oldAK) || string(aks[2]) == string(oldAK) {
		t.Errorf("epoch 1 AK matches bob's: %v, epoch 2 AK matches bob's: %v; want true, false",
			string(aks[1]) == string(oldAK), string(aks[2]) == string(oldAK))
	}
	latest := va.Chain.Latest
	if latest.Epoch != 2 || len(latest.Members) != 0 || !slices.Equal(excludedEmails(latest), []string{"bob@example.com"}) {
		t.Errorf("latest record = epoch %d, members %v, excluded %v", latest.Epoch, latest.Members, excludedEmails(latest))
	}
	if x := latest.Excluded[0]; x.User != s.userID(t, s.bob) || x.FP != mustUnlock(t, s.bob).FP {
		t.Errorf("excluded entry = %+v, want bob's id and fingerprint", x)
	}
}

func TestUnshareRefusals(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Unshare(s.artifact, "bob@example.com"); !errors.Is(err, ErrNotMember) {
		t.Errorf("unsharing a non-member: %v, want ErrNotMember", err)
	}
	if _, err := s.ada.Unshare(s.artifact, "nobody@example.com"); !errors.Is(err, ErrUnknownUser) {
		t.Errorf("unsharing an unknown user: %v, want ErrUnknownUser", err)
	}
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.bob.Unshare(s.artifact, "ada@example.com"); !errors.Is(err, ErrNotOwner) {
		t.Errorf("a non-owner unsharing: %v, want ErrNotOwner", err)
	}
	if got := recordCount(t, s.ada, s.artifact); got != 2 {
		t.Errorf("%d records, want 2: a refused unshare must write nothing", got)
	}
}

func TestShareByNameReadmitsAnExcludedUser(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.Unshare(s.artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	res, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false)
	if err != nil {
		t.Fatalf("sharing again with an excluded user: %v", err)
	}
	if len(res.Dropped) != 1 || res.Dropped[0].Email != "bob@example.com" {
		t.Errorf("Dropped = %+v, want bob's entry", res.Dropped)
	}
	latest := latestRecord(t, s.ada, s.artifact)
	if len(latest.Excluded) != 0 || latest.Epoch != 2 {
		t.Errorf("latest = epoch %d, excluded %v, want epoch 2, none", latest.Epoch, latest.Excluded)
	}
	if r := memberRows(t, s.ada, s.artifact)["bob@example.com"]; r.Role != "viewer" {
		t.Errorf("bob's row = %+v, want a viewer", r)
	}
	// He holds every epoch's wrap again.
	if got := ownWraps(t, s.bob, s.artifact); len(got) != 2 {
		t.Errorf("bob holds wraps for %d epochs, want 2", len(got))
	}
}

func TestApproveRefusesAUserAnUnshareExcluded(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	if _, err := w.ada.Unshare(w.artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Approve(w.artifact, "bob@example.com", false); !errors.Is(err, ErrExcluded) {
		t.Errorf("Approve of an excluded user: %v, want ErrExcluded", err)
	}
}

func TestShareDemotionStartsANewEpoch(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	res, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false)
	if err != nil {
		t.Fatalf("demoting: %v", err)
	}
	if !res.NewEpoch || res.Epoch != 2 || res.Unchanged || res.Promoted || len(res.Excluded) != 0 {
		t.Errorf("Share = %+v, want a new epoch 2 and no exclusion", res)
	}
	latest := latestRecord(t, s.ada, s.artifact)
	if latest.Epoch != 2 || len(latest.Members) != 1 || latest.Members[0].Role != "viewer" {
		t.Errorf("latest = epoch %d, members %+v, want bob a viewer at epoch 2", latest.Epoch, latest.Members)
	}
	// Still a member: he reads both epochs, and the new one is not the old one.
	got := ownWraps(t, s.bob, s.artifact)
	if len(got) != 2 || string(got[1]) == string(got[2]) {
		t.Errorf("bob's wraps cover %d epochs, want 2 different AKs", len(got))
	}
	// A viewer's client never approves.
	if _, err := s.bob.Approve(s.artifact, "ada@example.com", false); !errors.Is(err, ErrNotApprover) {
		t.Errorf("a demoted editor approving: %v, want ErrNotApprover", err)
	}
}

// A demoted editor whose keys changed is listed under the new ones, and wrapped
// to every epoch: the wraps they held were made for keys that are gone.
func TestShareDemotionAcceptingANewKeyWrapsEveryEpoch(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	s.resetBob(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err == nil {
		t.Fatal("demoting a user whose key changed succeeded without --accept-new-key")
	}
	res, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", true)
	if err != nil || !res.NewEpoch || !res.Demoted {
		t.Fatalf("Share = %+v, %v, want a demotion in a new epoch", res, err)
	}
	if got := ownWraps(t, s.bob, s.artifact); len(got) != 2 {
		t.Errorf("bob holds wraps for %d epochs, want 2", len(got))
	}
	if m := latestRecord(t, s.ada, s.artifact).Members; len(m) != 1 || m[0].FP != mustUnlock(t, s.bob).FP {
		t.Errorf("members = %+v, want bob under his new fingerprint", m)
	}
}

func TestTeamNoneStartsANewEpochAndExcludesAHolder(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	if err := approve(t, w.bob, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	res, err := w.ada.Team(w.artifact, "none")
	if err != nil {
		t.Fatalf("Team none with cat holding a wrap: %v", err)
	}
	if !res.NewEpoch || res.Epoch != 2 || len(res.Excluded) != 1 || res.Excluded[0].User.Email != "cat@example.com" {
		t.Errorf("Team = %+v, want epoch 2 with cat excluded", res)
	}
	if got := ownWraps(t, w.cat, w.artifact); len(got) != 0 {
		t.Errorf("cat still holds wraps for %d epochs", len(got))
	}
	latest := latestRecord(t, w.ada, w.artifact)
	if latest.Team != "none" || !slices.Equal(excludedEmails(latest), []string{"cat@example.com"}) {
		t.Errorf("latest = team %s, excluded %v", latest.Team, excludedEmails(latest))
	}
	// Bob stays an editor and reads the new epoch.
	if got := ownWraps(t, w.bob, w.artifact); len(got) != 2 {
		t.Errorf("bob holds %d wraps, want 2", len(got))
	}
	wantStates(t, pendingStates(t, w.ada, w.artifact), map[string]string{})
}

func TestUnshareOnATeamArtifactListsAnApprovedMember(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	if _, err := w.ada.Share(w.artifact, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if err := approve(t, w.bob, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	res, err := w.ada.Unshare(w.artifact, "dan@example.com")
	if err != nil {
		t.Fatalf("Unshare: %v", err)
	}
	if len(res.Listed) != 1 || res.Listed[0].Email != "cat@example.com" {
		t.Errorf("Listed = %+v, want cat", res.Listed)
	}
	if len(res.Excluded) != 1 || res.Excluded[0].User.Email != "dan@example.com" {
		t.Errorf("Excluded = %+v, want only dan", res.Excluded)
	}
	rows := memberRows(t, w.ada, w.artifact)
	if rows["cat@example.com"].Role != "viewer" || rows["dan@example.com"].Role != "" {
		t.Errorf("rows = %+v, want cat a viewer and dan gone", rows)
	}
	got := ownWraps(t, w.cat, w.artifact)
	if len(got) != 2 {
		t.Errorf("cat holds %d wraps, want epochs 1 and 2", len(got))
	}
	if got := ownWraps(t, w.dan, w.artifact); len(got) != 0 {
		t.Errorf("dan still holds wraps for %d epochs", len(got))
	}
}

// An approved member whose approval fails a check is excluded and reported:
// the record cannot leave them out of both lists, and the client never lists
// a user on the server's word alone.
func TestUnshareExcludesAnApprovedMemberWhoseApprovalFails(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	if _, err := w.ada.Share(w.artifact, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if err := approve(t, w.bob, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	owner := rewritingList(t, w.ada, "/api/artifacts/"+w.artifact+"/pending", func(list []map[string]any) []map[string]any {
		catEntry(list)["approval"] = nil
		return list
	})
	res, err := owner.Unshare(w.artifact, "dan@example.com")
	if err != nil {
		t.Fatalf("Unshare: %v", err)
	}
	if len(res.Listed) != 0 || len(res.Excluded) != 2 {
		t.Fatalf("Listed %+v, Excluded %+v, want cat and dan excluded", res.Listed, res.Excluded)
	}
	for _, x := range res.Excluded {
		if x.User.Email == "cat@example.com" && !strings.Contains(x.Reason, "approval") {
			t.Errorf("cat's reason %q does not name the approval", x.Reason)
		}
	}
	latest := latestRecord(t, w.ada, w.artifact)
	if !slices.Equal(excludedEmails(latest), []string{"cat@example.com", "dan@example.com"}) {
		t.Errorf("excluded = %v, want cat and dan", excludedEmails(latest))
	}
	if r := memberRows(t, w.ada, w.artifact)["cat@example.com"]; r.Role != "" {
		t.Errorf("cat is listed as %+v, want never listed", r)
	}
	if got := ownWraps(t, w.cat, w.artifact); len(got) != 0 {
		t.Errorf("cat still holds wraps for %d epochs", len(got))
	}
}

// Unshare also takes a team member who holds a wrap but is not listed.
func TestUnshareExcludesAnApprovedUserByName(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	if err := approve(t, w.bob, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	res, err := w.ada.Unshare(w.artifact, "cat@example.com")
	if err != nil {
		t.Fatalf("Unshare: %v", err)
	}
	if len(res.Listed) != 0 || len(res.Excluded) != 1 || res.Excluded[0].User.Email != "cat@example.com" {
		t.Errorf("Listed %+v, Excluded %+v, want cat excluded though the approval checks out", res.Listed, res.Excluded)
	}
	if got := ownWraps(t, w.cat, w.artifact); len(got) != 0 {
		t.Errorf("cat still holds wraps for %d epochs", len(got))
	}
}

func TestPublicOffStartsANewEpoch(t *testing.T) {
	s := newSharing(t)
	on, err := s.ada.Public(s.artifact, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLink(on.Link); err != nil {
		t.Fatalf("OpenLink before off: %v", err)
	}
	res, err := s.ada.Public(s.artifact, false, nil)
	if err != nil {
		t.Fatalf("Public off: %v", err)
	}
	if res.Public || !res.NewEpoch || res.Epoch != 2 || res.Unchanged || res.Link != "" {
		t.Errorf("Public off = %+v, want private, a new epoch 2, no link", res)
	}
	if got := latestRecord(t, s.ada, s.artifact); got.Public || got.Epoch != 2 {
		t.Errorf("latest = public %v, epoch %d", got.Public, got.Epoch)
	}
	if _, err := OpenLink(on.Link); err == nil {
		t.Error("the old link still opens the artifact")
	}
}

func TestUnshareOnAPublicArtifactReturnsANewLink(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	on, err := s.ada.Public(s.artifact, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ada.Unshare(s.artifact, "bob@example.com")
	if err != nil {
		t.Fatalf("Unshare: %v", err)
	}
	if res.Link == "" || res.Link == on.Link {
		t.Fatalf("Unshare link = %q, want a new link", res.Link)
	}
	if l := mustParseLink(t, res.Link); l.Epoch != 2 {
		t.Errorf("new link epoch = %d, want 2", l.Epoch)
	}
	if _, err := OpenLink(res.Link); err != nil {
		t.Errorf("the new link does not open: %v", err)
	}
	if _, err := OpenLink(on.Link); err == nil {
		t.Error("the old link still opens the artifact")
	}
	if !latestRecord(t, s.ada, s.artifact).Public {
		t.Error("the artifact is no longer public")
	}
}

func TestShareDemotionOnAPublicArtifactReturnsANewLink(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	on, err := s.ada.Public(s.artifact, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false)
	if err != nil {
		t.Fatalf("demoting: %v", err)
	}
	if res.Link == "" || res.Link == on.Link {
		t.Errorf("Share link = %q, want a new link", res.Link)
	}
	if _, err := OpenLink(res.Link); err != nil {
		t.Errorf("the new link does not open: %v", err)
	}
}

func TestNextEpochRefusesAMemberWhoseKeyChanged(t *testing.T) {
	w := newTeam(t)
	for _, who := range []string{"bob@example.com", "cat@example.com"} {
		if _, err := w.ada.Share(w.artifact, who, "viewer", false); err != nil {
			t.Fatal(err)
		}
	}
	w.sharing.resetBob(t)
	before := recordCount(t, w.ada, w.artifact)
	_, err := w.ada.Unshare(w.artifact, "cat@example.com")
	if !errors.Is(err, ErrMemberKeyChanged) {
		t.Fatalf("Unshare with bob's key changed: %v, want ErrMemberKeyChanged", err)
	}
	for _, want := range []string{"bob@example.com", "--accept-new-key", "unshare"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q does not mention %s", err, want)
		}
	}
	if got := recordCount(t, w.ada, w.artifact); got != before {
		t.Errorf("a refused change wrote a record: %d records, was %d", got, before)
	}
	// The owner can unshare bob himself: a removed member needs no fresh key.
	if _, err := w.ada.Unshare(w.artifact, "bob@example.com"); err != nil {
		t.Errorf("Unshare of bob: %v", err)
	}
}

func TestNextEpochRefusesAPinnedMemberWhoseKeyChanged(t *testing.T) {
	w := newTeam(t)
	for _, who := range []string{"bob@example.com", "cat@example.com"} {
		if _, err := w.ada.Share(w.artifact, who, "viewer", false); err != nil {
			t.Fatal(err)
		}
	}
	// The record lists bob under his current key, but the owner's pin for him
	// is another one.
	k := mustUnlock(t, w.ada)
	dir, _ := w.ada.Directory()
	bob, _ := FindUser(dir, "bob@example.com")
	if _, err := w.ada.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Pins[bob.ID] = e2e.Pin{FP: strings.Repeat("ab", 32), State: e2e.PinVerified}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var changed *KeyChangedError
	if _, err := w.ada.Unshare(w.artifact, "cat@example.com"); !errors.As(err, &changed) || changed.User != bob.ID {
		t.Errorf("Unshare = %v, want a KeyChangedError for bob", err)
	}
}

func TestNextEpochRefusesAReusedAK(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	k := mustUnlock(t, s.ada)
	va, err := s.ada.VerifyArtifact(k, s.artifact, k.FP)
	if err != nil {
		t.Fatal(err)
	}
	aks, err := s.ada.epochAKs(k, s.artifact, va.Chain)
	if err != nil {
		t.Fatal(err)
	}
	old := newAK
	t.Cleanup(func() { newAK = old })
	newAK = func() ([]byte, error) { return slices.Clone(aks[1]), nil }
	if _, err := s.ada.Unshare(s.artifact, "bob@example.com"); !errors.Is(err, e2e.ErrReusedAK) {
		t.Errorf("Unshare with a reused AK: %v, want ErrReusedAK", err)
	}
	if got := recordCount(t, s.ada, s.artifact); got != 2 {
		t.Errorf("%d records, want 2", got)
	}
}

func TestNextEpochRefusesAStaleEpoch(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	k := mustUnlock(t, s.ada)
	m, _ := s.ada.Membership(s.artifact)
	if _, err := s.ada.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Epochs[s.artifact] = e2e.KeyringEpoch{Epoch: 3, Seq: 1, Head: e2e.BodyHash(m.Records[0].Body)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.Unshare(s.artifact, "bob@example.com"); !errors.Is(err, e2e.ErrStaleEpoch) {
		t.Errorf("Unshare to an epoch below the pin: %v, want ErrStaleEpoch", err)
	}
}

// An exclusion stays through later epochs: the server refuses a record that
// drops an entry without listing the user.
func TestNextEpochKeepsExistingExclusions(t *testing.T) {
	w := newTeam(t)
	for _, who := range []string{"bob@example.com", "cat@example.com"} {
		if _, err := w.ada.Share(w.artifact, who, "viewer", false); err != nil {
			t.Fatal(err)
		}
	}
	for _, who := range []string{"bob@example.com", "cat@example.com"} {
		if _, err := w.ada.Unshare(w.artifact, who); err != nil {
			t.Fatalf("Unshare %s: %v", who, err)
		}
	}
	latest := latestRecord(t, w.ada, w.artifact)
	if latest.Epoch != 3 || !slices.Equal(excludedEmails(latest), []string{"bob@example.com", "cat@example.com"}) {
		t.Errorf("latest = epoch %d, excluded %v, want epoch 3 with bob and cat", latest.Epoch, excludedEmails(latest))
	}
}
