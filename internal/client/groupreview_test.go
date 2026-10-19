package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// labelledLeft is ada's client, served a pending list that calls every entry
// left.
func labelledLeft(t *testing.T, w *groupWorld) *Client {
	return rewritingList(t, w.ada, "/api/artifacts/"+w.artifact+"/pending", func(list []map[string]any) []map[string]any {
		for _, e := range list {
			e["state"] = "left"
		}
		return list
	})
}

// A server that calls an approved user left skips the approval check for them
// and nothing else: they hold their wraps, so none are sent, and the others
// are still listed after their checks.
func TestAServerLabellingAnApprovedUserLeftChangesNothingElse(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com", "dan@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	before := openWraps(t, w.dan, w.artifact)
	rec := latestBody(t, w.ada, w.artifact)
	res, err := labelledLeft(t, w).Share(w.artifact, "dan@example.com", "viewer", false)
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if got := openWraps(t, w.dan, w.artifact); !slices.Equal(got, before) {
		t.Errorf("dan's wraps = %v, were %v: wraps were sent", got, before)
	}
	if res.Unchanged || res.Epoch != rec.Epoch {
		t.Errorf("result = %+v", res)
	}
	rows := memberRows(t, w.ada, w.artifact)
	if rows["dan@example.com"].Role != "viewer" {
		t.Errorf("dan's row = %+v", rows["dan@example.com"])
	}
	if got := status(t, w.dan, w.artifact); got != http.StatusOK {
		t.Errorf("dan reads: %d", got)
	}
}

func TestAUserInTwoListedGroupsReadsUntilTheyLeaveBoth(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com", "dan@example.com")
	two, err := w.ada.CreateGroup("Writers", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Writers is listed first and empty, so approving Reviewers' members
	// lists nobody yet; cat then joins Writers too.
	for _, g := range []string{two.ID, w.group} {
		if _, err := w.ada.ShareGroup(w.artifact, g, "viewer", false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.ada.AddGroupMember(two.ID, "cat@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	if got := status(t, w.cat, w.artifact); got != http.StatusOK {
		t.Fatalf("cat before leaving: %d", got)
	}
	if _, err := w.ada.RemoveGroupMember(w.group, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	if got := status(t, w.cat, w.artifact); got != http.StatusOK {
		t.Errorf("cat after leaving one group: %d, want 200", got)
	}
	wantStates(t, pendingStates(t, w.ada, w.artifact), map[string]string{"cat@example.com": "approved", "dan@example.com": "approved"})
	list, err := w.ada.Pending(w.artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range list {
		if p.User.Email == "cat@example.com" && !slices.Equal(p.Groups, []string{two.ID}) {
			t.Errorf("cat is held by %v, want Writers alone", p.Groups)
		}
	}
	if _, err := w.ada.RemoveGroupMember(two.ID, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	if got := status(t, w.cat, w.artifact); got != http.StatusNotFound {
		t.Errorf("cat after leaving both: %d, want 404", got)
	}
	wantStates(t, pendingStates(t, w.ada, w.artifact), map[string]string{"cat@example.com": "left", "dan@example.com": "approved"})
}

func TestADroppedGroupSharedAgainMakesItsHoldersNewcomers(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com", "dan@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	// Nothing else covers them, so dropping the group starts epoch 2 and
	// excludes both.
	res, err := w.ada.UnshareGroup(w.artifact, "Reviewers")
	if err != nil {
		t.Fatal(err)
	}
	if res.Epoch != 2 {
		t.Fatalf("unshare epoch = %d, want 2", res.Epoch)
	}
	if b := latestBody(t, w.ada, w.artifact); len(b.Groups) != 0 || len(b.Excluded) != 2 {
		t.Fatalf("record after the drop = %+v", b)
	}
	for _, c := range []*Client{w.cat, w.dan} {
		if got := status(t, c, w.artifact); got != http.StatusNotFound {
			t.Errorf("a holder after the drop: %d, want 404", got)
		}
	}
	wantStates(t, pendingStates(t, w.ada, w.artifact), map[string]string{})
	// Shared again, the excluded holders stay excluded: only the owner lists
	// one again, by name, and no approval state survived the drop.
	again, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false)
	if err != nil {
		t.Fatalf("ShareGroup again: %v", err)
	}
	if len(again.Approved) != 0 || len(again.Pending) != 0 {
		t.Errorf("approved %v, pending %v: an excluded holder came back", emails(again.Approved), pendingEmails(again.Pending))
	}
	if _, err := w.ada.Approve(w.artifact, "cat@example.com", false); !errors.Is(err, ErrExcluded) {
		t.Errorf("Approve an excluded holder: %v, want ErrExcluded", err)
	}
	if got := status(t, w.cat, w.artifact); got != http.StatusNotFound {
		t.Errorf("an excluded holder after sharing again: %d, want 404", got)
	}
	if _, err := w.ada.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if got := status(t, w.cat, w.artifact); got != http.StatusOK {
		t.Errorf("cat listed again by name: %d, want 200", got)
	}
}

// A group dropped while nobody holds the key through it, and shared again,
// treats its members as newcomers: no approval state or group row is left.
func TestADroppedGroupSharedAgainHasNewcomers(t *testing.T) {
	w := newGroupWorld(t)
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.AddGroupMember(w.group, "cat@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	wantStates(t, pendingStates(t, w.ada, w.artifact), map[string]string{"cat@example.com": "new"})
	res, err := w.ada.UnshareGroup(w.artifact, "Reviewers")
	if err != nil {
		t.Fatal(err)
	}
	if res.Epoch != 1 {
		t.Fatalf("unshare epoch = %d, want a same-epoch record", res.Epoch)
	}
	wantStates(t, pendingStates(t, w.ada, w.artifact), map[string]string{})
	if _, err := w.ada.Approve(w.artifact, "cat@example.com", false); err == nil {
		t.Error("Approve with no group or team listed succeeded")
	}
	again, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := emails(again.Approved); !slices.Equal(got, []string{"cat@example.com"}) {
		t.Errorf("approved %v, want cat", got)
	}
	if got := status(t, w.cat, w.artifact); got != http.StatusOK {
		t.Errorf("cat after sharing again: %d, want 200", got)
	}
	if got := openWraps(t, w.cat, w.artifact); !slices.Equal(got, []int{1}) {
		t.Errorf("wraps = %v", got)
	}
}

// badGroupSig serves a group's chain with the last record's signature
// changed.
func badGroupSig(t *testing.T, w *groupWorld, c *Client) *Client {
	t.Helper()
	proxy := tamperingProxy(t, w.host, "/api/groups/"+w.group, func(m map[string]json.RawMessage) {
		var recs []map[string]any
		if err := json.Unmarshal(m["records"], &recs); err != nil {
			t.Error(err)
			return
		}
		last := recs[len(recs)-1]
		sig, _ := last["sig"].(string)
		flip := "A"
		if strings.HasPrefix(sig, "A") {
			flip = "B"
		}
		last["sig"] = flip + sig[1:]
		m["records"] = mustJSON(t, recs)
	})
	return viaProxy(proxy, c)
}

// brokenGroupLink serves a group's chain with its first record gone, so the
// second names a predecessor that is not there.
func brokenGroupLink(t *testing.T, w *groupWorld, c *Client) *Client {
	t.Helper()
	proxy := tamperingProxy(t, w.host, "/api/groups/"+w.group, func(m map[string]json.RawMessage) {
		var recs []json.RawMessage
		if err := json.Unmarshal(m["records"], &recs); err != nil {
			t.Error(err)
			return
		}
		m["records"] = mustJSON(t, recs[1:])
	})
	return viaProxy(proxy, c)
}

func TestAGroupChainThatFailsVerificationIsNeverTrusted(t *testing.T) {
	for name, corrupt := range map[string]func(*testing.T, *groupWorld, *Client) *Client{
		"a bad signature": badGroupSig,
		"a broken link":   brokenGroupLink,
	} {
		t.Run(name, func(t *testing.T) {
			w := newGroupWorld(t, "cat@example.com")
			// A second record, so the chain has a link to break.
			if _, err := w.ada.AddGroupMember(w.group, "dan@example.com", false, false); err != nil {
				t.Fatal(err)
			}
			if _, err := w.ada.RemoveGroupMember(w.group, "dan@example.com", false); err != nil {
				t.Fatal(err)
			}
			bad := corrupt(t, w, w.ada)

			// ShareGroup refuses, and lists nothing.
			if _, err := bad.ShareGroup(w.artifact, "Reviewers", "viewer", false); err == nil || !strings.Contains(err.Error(), "do not verify") {
				t.Fatalf("ShareGroup: %v, want a verification refusal", err)
			}
			if b := latestBody(t, w.ada, w.artifact); len(b.Groups) != 0 {
				t.Fatalf("a group was listed on the server's word: %+v", b.Groups)
			}

			// The same group, listed by a clean client, with cat waiting.
			if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
				t.Fatal(err)
			}
			if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
				t.Fatal(err)
			}
			wantStates(t, pendingStates(t, w.ada, w.artifact), map[string]string{"cat@example.com": "approved"})

			// Dan joins; approving him on a chain that fails refuses him.
			if _, err := w.ada.AddGroupMember(w.group, "dan@example.com", false, false); err != nil {
				t.Fatal(err)
			}
			if _, err := bad.Approve(w.artifact, "dan@example.com", false); err == nil {
				t.Error("Approve on a chain that fails verification succeeded")
			}
			if got := status(t, w.dan, w.artifact); got != http.StatusNotFound {
				t.Errorf("dan after the refused approval: %d, want 404", got)
			}

			// A next epoch lists nobody on that chain's word: it is refused,
			// and cat, approved and held by the group, stays unlisted.
			epoch := latestBody(t, w.ada, w.artifact).Epoch
			res, err := bad.Unshare(w.artifact, "bob@example.com")
			if err == nil || !strings.Contains(err.Error(), "do not verify") {
				t.Fatalf("Unshare: %+v, %v, want a verification refusal", res, err)
			}
			if got := latestBody(t, w.ada, w.artifact).Epoch; got != epoch {
				t.Errorf("epoch = %d, was %d: a record was signed", got, epoch)
			}
			if rows := memberRows(t, w.ada, w.artifact); rows["cat@example.com"].Role != "" {
				t.Errorf("cat is listed: %+v", rows["cat@example.com"])
			}
			// Control: the same step on the real chain lists her.
			res, err = w.ada.Unshare(w.artifact, "bob@example.com")
			if err != nil || !slices.Equal(emails(res.Listed), []string{"cat@example.com"}) {
				t.Errorf("control: listed %v, %v, want cat", emails(res.Listed), err)
			}
		})
	}
}
