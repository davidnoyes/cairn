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

// groupWorld is the team world plus a group that ada manages.
type groupWorld struct {
	*team
	group string // the group's ID
}

// newGroupWorld makes a group named Reviewers, managed by ada, with the
// members whose emails are given, and shares nothing yet.
func newGroupWorld(t *testing.T, members ...string) *groupWorld {
	t.Helper()
	w := &groupWorld{team: newTeam(t)}
	v, err := w.ada.CreateGroup("Reviewers", members)
	if err != nil {
		t.Fatal(err)
	}
	w.group = v.ID
	return w
}

// status is the HTTP status c's request for the artifact's membership gets:
// 200 for someone who may read it, 404 for anyone else.
func status(t *testing.T, c *Client, artifact string) int {
	t.Helper()
	err := c.doJSON("GET", "/api/artifacts/"+artifact+"/membership", nil, nil)
	var api *APIError
	switch {
	case err == nil:
		return http.StatusOK
	case errors.As(err, &api):
		return api.Status
	}
	t.Fatalf("membership: %v", err)
	return 0
}

// latestBody is the artifact's latest membership record, as ada reads it.
func latestBody(t *testing.T, c *Client, artifact string) e2e.MembershipBody {
	t.Helper()
	m, err := c.Membership(artifact)
	if err != nil {
		t.Fatal(err)
	}
	var b e2e.MembershipBody
	if err := json.Unmarshal(m.Records[len(m.Records)-1].Body, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

// wrapEpochs opens every wrap c holds for the artifact and checks each against
// the akCommit the chain lists for its epoch, returning the epochs.
func wrapEpochs(t *testing.T, c *Client, artifact string) []int {
	t.Helper()
	k := mustUnlock(t, c)
	va, err := c.VerifyArtifact(k, artifact, "")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := c.Keys(artifact)
	if err != nil {
		t.Fatal(err)
	}
	var epochs []int
	for _, w := range keys.Wraps {
		if _, err := openWrap(k, artifact, epochCommits(va.Chain), w); err != nil {
			t.Fatal(err)
		}
		epochs = append(epochs, w.Epoch)
	}
	return epochs
}

func emails(users []DirectoryUser) []string {
	var out []string
	for _, u := range users {
		out = append(out, u.Email)
	}
	slices.Sort(out)
	return out
}

func pendingEmails(list []UnlistedUser) []string {
	var out []string
	for _, u := range list {
		out = append(out, u.User.Email)
	}
	slices.Sort(out)
	return out
}

func TestShareGroupApprovesItsCurrentMembers(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com", "dan@example.com")
	// Nobody in the group reads before the artifact is shared with it.
	if got := status(t, w.cat, w.artifact); got != http.StatusNotFound {
		t.Fatalf("cat before the share: %d", got)
	}
	res, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false)
	if err != nil {
		t.Fatalf("ShareGroup: %v", err)
	}
	if res.Group.ID != w.group || res.Group.Name != "Reviewers" || res.Role != "viewer" || res.Unchanged || res.Epoch != 1 {
		t.Errorf("result = %+v", res)
	}
	if got := emails(res.Approved); !slices.Equal(got, []string{"cat@example.com", "dan@example.com"}) || len(res.Pending) != 0 {
		t.Errorf("approved %v, pending %v", got, pendingEmails(res.Pending))
	}
	b := latestBody(t, w.ada, w.artifact)
	if b.Seq != 2 || b.Epoch != 1 || !slices.Equal(b.Groups, []e2e.GroupShare{{Group: w.group, Role: "viewer"}}) {
		t.Errorf("latest record = seq %d epoch %d groups %v", b.Seq, b.Epoch, b.Groups)
	}
	// They read now, and their wraps open.
	for _, c := range []*Client{w.cat, w.dan} {
		if got := status(t, c, w.artifact); got != http.StatusOK {
			t.Errorf("a member after the share: %d", got)
		}
		if got := openWraps(t, c, w.artifact); !slices.Equal(got, []int{1}) {
			t.Errorf("wraps = %v", got)
		}
	}
	// The owner sees them as approved, held by the group.
	list, err := w.ada.Pending(w.artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range list {
		if p.State != PendingApproved || !slices.Equal(p.Groups, []string{w.group}) {
			t.Errorf("pending entry %s = %s, groups %v", p.User.Email, p.State, p.Groups)
		}
	}

	// The next record lists them under the group's role, so the same share
	// again is not unchanged.
	again, err := w.ada.ShareGroup(w.artifact, w.group, "viewer", false)
	if err != nil {
		t.Fatal(err)
	}
	if again.Unchanged || !slices.Equal(emails(again.Listed), []string{"cat@example.com", "dan@example.com"}) {
		t.Errorf("share again = %+v, want both listed", again)
	}
	// Nobody is waiting any more, so nobody is approved or left pending.
	if len(again.Approved) != 0 || len(again.Pending) != 0 {
		t.Errorf("share again approved %v, left %v pending", emails(again.Approved), pendingEmails(again.Pending))
	}
	rows := memberRows(t, w.ada, w.artifact)
	if rows["cat@example.com"].Role != "viewer" || rows["dan@example.com"].Role != "viewer" {
		t.Errorf("member rows = %+v", rows)
	}
	third, err := w.ada.ShareGroup(w.artifact, w.group, "viewer", false)
	if err != nil || !third.Unchanged {
		t.Errorf("a third time = %+v, %v, want unchanged", third, err)
	}
}

func TestShareGroupLeavesAMemberWhoseKeyDiffersPending(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com", "dan@example.com")
	// Cat resets her account: her keys change, and the group record still
	// lists the old fingerprint.
	if err := New(w.host, "").Forgot("cat@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(w.host, "").ResetNew(verifyLink(t, w.m, "cat@example.com"), "a brand new password"); err != nil {
		t.Fatal(err)
	}
	out, err := New(w.host, "").Login("cat@example.com", "a brand new password")
	if err != nil {
		t.Fatal(err)
	}
	w.cat = keyedFor(t, w.host, out.APIKey)

	res, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false)
	if err != nil {
		t.Fatalf("ShareGroup: %v", err)
	}
	if got := emails(res.Approved); !slices.Equal(got, []string{"dan@example.com"}) {
		t.Errorf("approved %v, want dan alone", got)
	}
	if len(res.Pending) != 1 || res.Pending[0].User.Email != "cat@example.com" || !errors.Is(res.Pending[0].Err, ErrGroupKeyChanged) {
		t.Fatalf("pending = %+v, want cat with a group key change", res.Pending)
	}
	var changed *GroupKeyChangedError
	if !errors.As(res.Pending[0].Err, &changed) || changed.GroupFP == changed.User.FP || changed.Group != w.group {
		t.Errorf("warning = %+v", changed)
	}
	if got := status(t, w.cat, w.artifact); got != http.StatusNotFound {
		t.Errorf("cat reads before approval: %d", got)
	}
	// Accepting a new key for the group's signers does not approve a member
	// whose key differs from the group record's: she stays pending.
	again, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Pending) != 1 || again.Pending[0].User.Email != "cat@example.com" {
		t.Errorf("share with acceptNewKey: pending %v", pendingEmails(again.Pending))
	}
	// Approving by name is the key-change warning, refused until accepted.
	if _, err := w.ada.Approve(w.artifact, "cat@example.com", false); !errors.Is(err, ErrGroupKeyChanged) {
		t.Fatalf("Approve: %v, want ErrGroupKeyChanged", err)
	}
	if _, err := w.ada.Approve(w.artifact, "cat@example.com", true); err != nil {
		t.Fatalf("Approve with --accept-new-key: %v", err)
	}
	if got := status(t, w.cat, w.artifact); got != http.StatusOK {
		t.Errorf("cat after approval: %d", got)
	}
}

func TestApproveALaterJoinerOfAListedGroup(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.AddGroupMember(w.group, "dan@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	// Dan waits, held by the group; an editor approves him by name.
	list, err := w.bob.Pending(w.artifact)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].User.Email != "dan@example.com" || list[0].State != PendingNew || !slices.Equal(list[0].Groups, []string{w.group}) {
		t.Fatalf("bob's pending = %+v", list)
	}
	if got := status(t, w.dan, w.artifact); got != http.StatusNotFound {
		t.Errorf("dan before approval: %d", got)
	}
	if _, err := w.bob.Approve(w.artifact, "dan@example.com", false); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if got := status(t, w.dan, w.artifact); got != http.StatusOK {
		t.Errorf("dan after approval: %d", got)
	}
	// A user in no listed group is not waiting.
	if _, err := w.bob.Approve(w.artifact, "ada@example.com", false); !errors.Is(err, ErrAlreadyListed) {
		t.Errorf("approving the owner: %v", err)
	}
}

func TestApproveRefusesAUserWhoseGroupChainDoesNotListThem(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	dir, err := w.ada.Directory()
	if err != nil {
		t.Fatal(err)
	}
	dan, err := FindUser(dir, "dan@example.com")
	if err != nil {
		t.Fatal(err)
	}
	// The server names a group that holds dan; the group's chain does not.
	lying := func(c *Client) *Client {
		return rewritingList(t, c, "/api/artifacts/"+w.artifact+"/pending", func(list []map[string]any) []map[string]any {
			return append(list, map[string]any{"id": dan.ID, "name": dan.Name, "email": dan.Email,
				"x25519Pub": e2e.B64(dan.X25519Pub), "ed25519Pub": e2e.B64(dan.Ed25519Pub),
				"state": "new", "approval": nil, "group": []string{w.group}})
		})
	}
	if _, err := lying(w.ada).Approve(w.artifact, "dan@example.com", false); !errors.Is(err, ErrNotInGroup) {
		t.Fatalf("Approve: %v, want ErrNotInGroup", err)
	}
	if got := status(t, w.dan, w.artifact); got != http.StatusNotFound {
		t.Errorf("dan reads: %d", got)
	}
}

func TestListingDoesNotListAUserWhoseGroupChainDoesNotHoldThem(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	dir, err := w.ada.Directory()
	if err != nil {
		t.Fatal(err)
	}
	dan, err := FindUser(dir, "dan@example.com")
	if err != nil {
		t.Fatal(err)
	}
	// The server calls dan approved, held by a group whose chain does not list him.
	lying := rewritingList(t, w.ada, "/api/artifacts/"+w.artifact+"/pending", func(list []map[string]any) []map[string]any {
		return append(list, map[string]any{"id": dan.ID, "name": dan.Name, "email": dan.Email,
			"x25519Pub": e2e.B64(dan.X25519Pub), "ed25519Pub": e2e.B64(dan.Ed25519Pub),
			"state": "approved", "approval": nil, "group": []string{w.group}})
	})
	res, err := lying.ShareGroup(w.artifact, w.group, "viewer", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := emails(res.Listed); !slices.Equal(got, []string{"cat@example.com"}) {
		t.Errorf("listed %v, want cat alone", got)
	}
	if len(res.Unlisted) != 1 || res.Unlisted[0].User.Email != "dan@example.com" || !errors.Is(res.Unlisted[0].Err, ErrNotInGroup) {
		t.Errorf("unlisted = %+v, want dan with ErrNotInGroup", res.Unlisted)
	}
	if rows := memberRows(t, w.ada, w.artifact); rows["dan@example.com"].Role != "" {
		t.Errorf("dan is listed: %+v", rows["dan@example.com"])
	}
}

func TestLeavingEveryGroupCutsAccessAtOnce(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com", "dan@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.RemoveGroupMember(w.group, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	// At once: 404 for cat, and dan reads on.
	if got := status(t, w.cat, w.artifact); got != http.StatusNotFound {
		t.Errorf("cat after leaving: %d", got)
	}
	if got := status(t, w.dan, w.artifact); got != http.StatusOK {
		t.Errorf("dan: %d", got)
	}
	// Cat shows as left, with no group; dan is still approved.
	list, err := w.ada.Pending(w.artifact)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, p := range list {
		states[p.User.Email] = p.State
		if p.State == PendingLeft && len(p.Groups) != 0 {
			t.Errorf("a user who left is held by %v", p.Groups)
		}
	}
	wantStates(t, states, map[string]string{"cat@example.com": "left", "dan@example.com": "approved"})
	// The approver (an editor) is not shown a left entry either, as with approved ones.
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	wantStates(t, pendingStates(t, w.bob, w.artifact), map[string]string{})

	// Approving cat is not possible: nothing covers them.
	if _, err := w.ada.Approve(w.artifact, "cat@example.com", false); !errors.Is(err, ErrNotWaiting) {
		t.Errorf("Approve a user who left: %v, want ErrNotWaiting", err)
	}
}

func TestAUserWhoLeftIsExcludedInTheNextEpoch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason string
		run    func(w *groupWorld) (*UnshareResult, error)
	}{
		{"unshare them", "removed", func(w *groupWorld) (*UnshareResult, error) { return w.ada.Unshare(w.artifact, "cat@example.com") }},
		{"any other next epoch", "left the group", func(w *groupWorld) (*UnshareResult, error) {
			if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
				return nil, err
			}
			return w.ada.Unshare(w.artifact, "bob@example.com")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newGroupWorld(t, "cat@example.com", "dan@example.com")
			if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
				t.Fatal(err)
			}
			if _, err := w.ada.RemoveGroupMember(w.group, "cat@example.com", false); err != nil {
				t.Fatal(err)
			}
			res, err := tc.run(w)
			if err != nil {
				t.Fatalf("unshare: %v", err)
			}
			if !res.NewEpoch || res.Epoch != 2 {
				t.Fatalf("result = %+v, want a new epoch", res)
			}
			var reasons = map[string]string{}
			for _, x := range res.Excluded {
				reasons[x.User.Email] = x.Reason
			}
			if reasons["cat@example.com"] != tc.reason {
				t.Errorf("excluded = %v, want cat: %s", reasons, tc.reason)
			}
			// Dan is still in the group, so the new epoch lists him.
			if _, ok := reasons["dan@example.com"]; ok {
				t.Errorf("dan was excluded: %v", reasons)
			}
			if rows := memberRows(t, w.ada, w.artifact); rows["dan@example.com"].Role != "viewer" {
				t.Errorf("rows = %+v, want dan listed as a viewer", rows)
			}
			if got := status(t, w.dan, w.artifact); got != http.StatusOK {
				t.Errorf("dan: %d", got)
			}
			if got := wrapEpochs(t, w.dan, w.artifact); !slices.Equal(got, []int{1, 2}) {
				t.Errorf("dan's wraps = %v", got)
			}
			if got := status(t, w.cat, w.artifact); got != http.StatusNotFound {
				t.Errorf("cat: %d", got)
			}
			b := latestBody(t, w.ada, w.artifact)
			if !slices.ContainsFunc(b.Excluded, func(x e2e.ExcludedEntry) bool { return x.User == res.Excluded[0].User.ID }) {
				t.Errorf("excluded = %v", b.Excluded)
			}
			// Not a holder any more: cat is no longer pending.
			if got := pendingStates(t, w.ada, w.artifact); len(got) != 0 {
				t.Errorf("pending = %v", got)
			}
		})
	}
}

func TestUnshareGroupWithAndWithoutHolders(t *testing.T) {
	t.Run("nobody holds the key through it", func(t *testing.T) {
		w := newGroupWorld(t, "cat@example.com")
		if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
			t.Fatal(err)
		}
		// Cat is approved by ShareGroup; make her leave first, so no holder is covered.
		if _, err := w.ada.RemoveGroupMember(w.group, "cat@example.com", false); err != nil {
			t.Fatal(err)
		}
		res, err := w.ada.UnshareGroup(w.artifact, "Reviewers")
		if err != nil {
			t.Fatal(err)
		}
		if res.NewEpoch || res.Epoch != 1 {
			t.Errorf("result = %+v, want the same epoch", res)
		}
		if b := latestBody(t, w.ada, w.artifact); len(b.Groups) != 0 || b.Epoch != 1 || b.Seq != 3 {
			t.Errorf("record = %+v", b)
		}
	})
	t.Run("a holder covered only by it", func(t *testing.T) {
		w := newGroupWorld(t, "cat@example.com", "dan@example.com")
		if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
			t.Fatal(err)
		}
		res, err := w.ada.UnshareGroup(w.artifact, w.group)
		if err != nil {
			t.Fatal(err)
		}
		if !res.NewEpoch || res.Epoch != 2 || len(res.Excluded) != 2 {
			t.Fatalf("result = %+v, want a new epoch that excludes both", res)
		}
		for _, x := range res.Excluded {
			if !strings.Contains(x.Reason, "no group") {
				t.Errorf("reason for %s: %q", x.User.Email, x.Reason)
			}
		}
		for _, c := range []*Client{w.cat, w.dan} {
			if got := status(t, c, w.artifact); got != http.StatusNotFound {
				t.Errorf("a former member: %d", got)
			}
		}
		if b := latestBody(t, w.ada, w.artifact); len(b.Groups) != 0 || b.Epoch != 2 {
			t.Errorf("record = %+v", b)
		}
	})
	t.Run("a holder another group still covers", func(t *testing.T) {
		w := newGroupWorld(t, "cat@example.com")
		other, err := w.ada.CreateGroup("Others", []string{"cat@example.com", "dan@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range []string{w.group, other.ID} {
			if _, err := w.ada.ShareGroup(w.artifact, g, "viewer", false); err != nil {
				t.Fatal(err)
			}
		}
		res, err := w.ada.UnshareGroup(w.artifact, "Reviewers")
		if err != nil {
			t.Fatal(err)
		}
		if res.NewEpoch {
			t.Errorf("result = %+v, want the same epoch: Others still covers cat", res)
		}
		if got := status(t, w.cat, w.artifact); got != http.StatusOK {
			t.Errorf("cat: %d", got)
		}
		// Dropping the last group is a new epoch.
		// Cat is listed as a member by now, so only dan is excluded.
		res, err = w.ada.UnshareGroup(w.artifact, "Others")
		if err != nil || !res.NewEpoch || len(res.Excluded) != 1 || res.Excluded[0].User.Email != "dan@example.com" {
			t.Errorf("last group: %+v, %v", res, err)
		}
	})
	t.Run("a holder only the dropped group holds", func(t *testing.T) {
		w := newGroupWorld(t, "cat@example.com")
		other, err := w.ada.CreateGroup("Others", []string{"dan@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		// Sharing Reviewers last leaves cat approved and not yet listed.
		for _, g := range []string{other.ID, w.group} {
			if _, err := w.ada.ShareGroup(w.artifact, g, "viewer", false); err != nil {
				t.Fatal(err)
			}
		}
		// The remaining group holds dan, not cat, so cat is cut off in a new epoch.
		res, err := w.ada.UnshareGroup(w.artifact, "Reviewers")
		if err != nil || !res.NewEpoch || len(res.Excluded) != 1 || res.Excluded[0].User.Email != "cat@example.com" {
			t.Fatalf("UnshareGroup: %+v, %v", res, err)
		}
		if got := status(t, w.dan, w.artifact); got != http.StatusOK {
			t.Errorf("dan: %d", got)
		}
	})
	t.Run("a group the artifact is not shared with", func(t *testing.T) {
		w := newGroupWorld(t, "cat@example.com")
		if _, err := w.ada.UnshareGroup(w.artifact, "Reviewers"); !errors.Is(err, ErrNotSharedWithGroup) {
			t.Errorf("UnshareGroup: %v", err)
		}
		if _, err := w.ada.UnshareGroup(w.artifact, "No such group"); !errors.Is(err, ErrNoGroup) {
			t.Errorf("UnshareGroup: %v", err)
		}
	})
}

func TestTeamNoneKeepsAGroupsMembers(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Team(w.artifact, "viewer"); err != nil {
		t.Fatal(err)
	}
	// Dan is approved through the team; cat through the group.
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Approve(w.artifact, "dan@example.com", false); err != nil {
		t.Fatal(err)
	}
	res, err := w.ada.Team(w.artifact, "none")
	if err != nil {
		t.Fatal(err)
	}
	// Dan held the key only through the team, so a new epoch excludes him.
	if !res.NewEpoch || len(res.Excluded) != 1 || res.Excluded[0].User.Email != "dan@example.com" {
		t.Fatalf("result = %+v, want a new epoch that excludes dan", res)
	}
	if got := status(t, w.cat, w.artifact); got != http.StatusOK {
		t.Errorf("cat: %d", got)
	}
	if rows := memberRows(t, w.ada, w.artifact); rows["cat@example.com"].Role != "viewer" {
		t.Errorf("rows = %+v, want cat listed through the group", rows)
	}
}

func TestListingTakesTheHighestRole(t *testing.T) {
	for _, tc := range []struct {
		name, team, group, want string
	}{
		{"a group editor over a team viewer", "viewer", "editor", "editor"},
		{"a team editor over a group viewer", "editor", "viewer", "editor"},
		{"a group viewer alone", "none", "viewer", "viewer"},
		{"a group editor alone", "none", "editor", "editor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newGroupWorld(t, "cat@example.com")
			if _, err := w.ada.Team(w.artifact, tc.team); err != nil {
				t.Fatal(err)
			}
			if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", tc.group, false); err != nil {
				t.Fatal(err)
			}
			// The next record lists cat, approved by ShareGroup.
			if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", tc.group, false); err != nil {
				t.Fatal(err)
			}
			if got := memberRows(t, w.ada, w.artifact)["cat@example.com"].Role; got != tc.want {
				t.Errorf("cat is listed as %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAViewerAccountIsListedAsAViewer(t *testing.T) {
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
	g, err := ada.CreateGroup("Readers", []string{"carol@viewers.test"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := ada.CreateArtifact("shared", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.ShareGroup(a.ID, g.ID, "editor", false); err != nil {
		t.Fatal(err)
	}
	if got := status(t, carol, a.ID); got != http.StatusOK {
		t.Fatalf("carol: %d", got)
	}
	if _, err := ada.ShareGroup(a.ID, g.ID, "editor", false); err != nil {
		t.Fatal(err)
	}
	if got := memberRows(t, ada, a.ID)["carol@viewers.test"].Role; got != "viewer" {
		t.Errorf("a viewer account is listed as %q, want viewer", got)
	}
}

func TestADeletedGroupGrantsNothingAndIsDropped(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if got := status(t, w.cat, w.artifact); got != http.StatusOK {
		t.Fatalf("cat: %d", got)
	}
	if err := w.ada.DeleteGroup(w.group); err != nil {
		t.Fatal(err)
	}
	if got := status(t, w.cat, w.artifact); got != http.StatusNotFound {
		t.Errorf("cat after the group was deleted: %d", got)
	}
	// The record still lists it, and members shows it as deleted.
	if b := latestBody(t, w.ada, w.artifact); len(b.Groups) != 1 {
		t.Fatalf("record = %+v", b)
	}
	_, _, err := w.ada.Members(w.artifact)
	if err != nil {
		t.Fatal(err)
	}
	k := mustUnlock(t, w.ada)
	va, err := w.ada.VerifyArtifact(k, w.artifact, "")
	if err != nil {
		t.Fatal(err)
	}
	listed, err := w.ada.ListedGroups(va)
	if err != nil || len(listed) != 1 || !listed[0].Deleted || listed[0].ID != w.group {
		t.Errorf("listed = %+v, %v", listed, err)
	}
	// The next change drops it, and says so.
	res, err := w.ada.Share(w.artifact, "bob@example.com", "viewer", false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.DroppedGroups, []string{w.group}) {
		t.Errorf("dropped = %v", res.DroppedGroups)
	}
	if b := latestBody(t, w.ada, w.artifact); len(b.Groups) != 0 {
		t.Errorf("record = %+v, want no groups", b)
	}
}

func TestANextEpochReportsTheDeletedGroupItDrops(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if err := w.ada.DeleteGroup(w.group); err != nil {
		t.Fatal(err)
	}
	res, err := w.ada.Unshare(w.artifact, "cat@example.com")
	if err != nil || !res.NewEpoch {
		t.Fatalf("Unshare: %+v, %v", res, err)
	}
	if !slices.Equal(res.DroppedGroups, []string{w.group}) {
		t.Errorf("dropped = %v, want the deleted group", res.DroppedGroups)
	}
}

func TestShareGroupLeavesAnApprovedMemberTheOwnerCannotListToTheListing(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com", "dan@example.com")
	dir, err := w.ada.Directory()
	if err != nil {
		t.Fatal(err)
	}
	dan, err := FindUser(dir, "dan@example.com")
	if err != nil {
		t.Fatal(err)
	}
	// The server calls dan approved, with no approval to check, and held by
	// the group: the client cannot list him, and he is no one to approve.
	lying := rewritingList(t, w.ada, "/api/artifacts/"+w.artifact+"/pending", func(list []map[string]any) []map[string]any {
		out := []map[string]any{}
		for _, e := range list {
			if e["id"] != dan.ID {
				out = append(out, e)
			}
		}
		return append(out, map[string]any{"id": dan.ID, "name": dan.Name, "email": dan.Email,
			"x25519Pub": e2e.B64(dan.X25519Pub), "ed25519Pub": e2e.B64(dan.Ed25519Pub),
			"state": "approved", "approval": nil, "group": []string{w.group}})
	})
	res, err := lying.ShareGroup(w.artifact, w.group, "viewer", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pending) != 0 {
		t.Errorf("pending %v: an approved user is not one to approve again", pendingEmails(res.Pending))
	}
	if got := pendingEmails(res.Unlisted); !slices.Equal(got, []string{"dan@example.com"}) {
		t.Errorf("unlisted %v, want dan, whose approval does not check out", got)
	}
	if got := emails(res.Approved); !slices.Equal(got, []string{"cat@example.com"}) {
		t.Errorf("approved %v, want cat", got)
	}
}

func TestADeletedGroupCanBeUnsharedByID(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if err := w.ada.DeleteGroup(w.group); err != nil {
		t.Fatal(err)
	}
	// Cat holds the key, and nothing covers her now: a next epoch excludes her.
	res, err := w.ada.UnshareGroup(w.artifact, w.group)
	if err != nil {
		t.Fatalf("UnshareGroup: %v", err)
	}
	if b := latestBody(t, w.ada, w.artifact); len(b.Groups) != 0 {
		t.Errorf("record = %+v", b)
	}
	if res.Group.ID != w.group {
		t.Errorf("result = %+v", res)
	}
}

func TestShareGroupRefusals(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "No such group", "viewer", false); !errors.Is(err, ErrNoGroup) {
		t.Errorf("an unknown group: %v", err)
	}
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "manager", false); err == nil || !strings.Contains(err.Error(), "viewer or editor") {
		t.Errorf("a manager role: %v", err)
	}
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.ShareGroup(w.artifact, "Reviewers", "viewer", false); !errors.Is(err, ErrNotOwner) {
		t.Errorf("a viewer sharing: %v", err)
	}
	// A name two groups share is ambiguous.
	if _, err := w.ada.CreateGroup("Reviewers", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); !errors.Is(err, ErrAmbiguousGroup) {
		t.Errorf("an ambiguous name: %v", err)
	}
}

func TestAManagerSharesWithAGroup(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "manager", false); err != nil {
		t.Fatal(err)
	}
	res, err := w.bob.ShareGroup(w.artifact, "Reviewers", "viewer", false)
	if err != nil {
		t.Fatalf("a manager sharing with a group: %v", err)
	}
	if got := emails(res.Approved); !slices.Equal(got, []string{"cat@example.com"}) {
		t.Errorf("approved %v", got)
	}
	if b := latestBody(t, w.ada, w.artifact); b.V != 2 || len(b.Groups) != 1 {
		t.Errorf("record = %+v, want a version 2 record that lists the group", b)
	}
	if got := status(t, w.cat, w.artifact); got != http.StatusOK {
		t.Errorf("cat: %d", got)
	}
	// The owner's unshare of the group excludes cat in a new epoch.
	res2, err := w.bob.UnshareGroup(w.artifact, "Reviewers")
	if err != nil || !res2.NewEpoch {
		t.Errorf("manager unshare: %+v, %v", res2, err)
	}
}

func TestShareUnlistedHolderWhoLeft(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.RemoveGroupMember(w.group, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	// The owner lists her by name: she holds wraps already, so none are sent.
	if _, err := w.ada.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatalf("Share: %v", err)
	}
	if got := status(t, w.cat, w.artifact); got != http.StatusOK {
		t.Errorf("cat after being listed: %d", got)
	}
}
