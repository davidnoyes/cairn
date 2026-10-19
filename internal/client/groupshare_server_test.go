package client

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// apiStatus is the HTTP status and message of err, an *APIError, or 0.
func apiStatus(err error) (int, string) {
	var api *APIError
	if errors.As(err, &api) {
		return api.Status, api.Message
	}
	return 0, ""
}

// rawApprove sends the request Approve sends, for who, without any of the
// client's checks: the artifact's owner signs the approval, and every epoch's
// AK is wrapped to the user, which the server cannot tell from a good one.
func rawApprove(t *testing.T, w *groupWorld, who string) error {
	t.Helper()
	k := mustUnlock(t, w.ada)
	va, err := w.ada.VerifyArtifact(k, w.artifact, "")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := w.ada.Directory()
	if err != nil {
		t.Fatal(err)
	}
	u, err := FindUser(dir, who)
	if err != nil {
		t.Fatal(err)
	}
	latest := va.Chain.Latest
	var wraps []map[string]any
	for epoch := 1; epoch <= latest.Epoch; epoch++ {
		wrapped, err := e2e.Wrap(rand.Reader, e2e.WrapContext{
			Purpose: "ak", Artifact: w.artifact, Epoch: uint64(epoch), RecipientID: u.ID, RecipientPub: u.X25519Pub,
		}, bytes.Repeat([]byte{1}, 32))
		if err != nil {
			t.Fatal(err)
		}
		wraps = append(wraps, map[string]any{"epoch": epoch, "wrapped": e2e.B64(wrapped)})
	}
	body := mustJSON(t, e2e.ApprovalBody{V: 1, Artifact: w.artifact, Epoch: latest.Epoch, User: u.ID, FP: u.FP})
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "approval", body)
	if err != nil {
		t.Fatal(err)
	}
	return w.ada.doJSON("POST", "/api/artifacts/"+w.artifact+"/keys", map[string]any{
		"user": u.ID, "fp": u.FP, "approval": env, "wraps": wraps,
	}, nil)
}

// putSameEpoch signs and sends a same-epoch record that edits the latest one,
// as ada, without the client's own rules.
func putSameEpoch(t *testing.T, w *groupWorld, edit func(next *e2e.MembershipBody)) error {
	t.Helper()
	k := mustUnlock(t, w.ada)
	va, err := w.ada.VerifyArtifact(k, w.artifact, "")
	if err != nil {
		t.Fatal(err)
	}
	next := va.Chain.Latest
	edit(&next)
	next, env, err := signNext(k.Ed25519Seed, k.UserID, va, next)
	if err != nil {
		t.Fatal(err)
	}
	_ = next
	return w.ada.doJSON("PUT", "/api/artifacts/"+w.artifact+"/membership", map[string]any{
		"membership": env, "wraps": []any{}, "estate": []any{}, "linkTokenHash": "",
	}, nil)
}

func TestServerRefusesToApproveAUserInNoListedGroup(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	// Dan is in no listed group, and the team share is off: 409.
	err := rawApprove(t, w, "dan@example.com")
	if status, msg := apiStatus(err); status != http.StatusConflict || !strings.Contains(msg, "team") {
		t.Errorf("approving dan: %v, want 409", err)
	}
	if got := status(t, w.dan, w.artifact); got != http.StatusNotFound {
		t.Errorf("dan reads: %d", got)
	}
	// Once dan joins the group, the same request lands.
	if _, err := w.ada.AddGroupMember(w.group, "dan@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	if err := rawApprove(t, w, "dan@example.com"); err != nil {
		t.Errorf("approving a member of the group: %v", err)
	}
}

func TestServerRefusesApprovalWhenTheRecordListsNoGroupAndNoTeam(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	err := rawApprove(t, w, "cat@example.com")
	if status, _ := apiStatus(err); status != http.StatusConflict {
		t.Errorf("approving with no team and no group: %v, want 409", err)
	}
}

func TestServerRefusesARecordThatAddsAGroupThatDoesNotExist(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	err := putSameEpoch(t, w, func(next *e2e.MembershipBody) {
		next.Groups = []e2e.GroupShare{{Group: "11111111-1111-4111-8111-111111111111", Role: "viewer"}}
	})
	if status, msg := apiStatus(err); status != http.StatusBadRequest || !strings.Contains(msg, "does not exist") {
		t.Errorf("adding a group that does not exist: %v", err)
	}
	// A group that exists is accepted, and one the record already lists may
	// be deleted and stay listed.
	if err := putSameEpoch(t, w, func(next *e2e.MembershipBody) {
		next.Groups = []e2e.GroupShare{{Group: w.group, Role: "viewer"}}
	}); err != nil {
		t.Fatalf("adding a group that exists: %v", err)
	}
	if err := w.ada.DeleteGroup(w.group); err != nil {
		t.Fatal(err)
	}
	if err := putSameEpoch(t, w, func(next *e2e.MembershipBody) { next.Public = false }); err != nil {
		t.Errorf("a record that keeps listing a deleted group: %v", err)
	}
}

func TestServerRefusesMalformedGroupsInARecord(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	other, err := w.ada.CreateGroup("Others", nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{w.group, other.ID}
	slices.Sort(ids)
	for name, groups := range map[string][]e2e.GroupShare{
		"unsorted":   {{Group: ids[1], Role: "viewer"}, {Group: ids[0], Role: "viewer"}},
		"duplicate":  {{Group: ids[0], Role: "viewer"}, {Group: ids[0], Role: "editor"}},
		"a manager":  {{Group: ids[0], Role: "manager"}},
		"not a UUID": {{Group: "ABC", Role: "viewer"}},
	} {
		err := putSameEpoch(t, w, func(next *e2e.MembershipBody) { next.Groups = groups })
		if status, _ := apiStatus(err); status != http.StatusBadRequest {
			t.Errorf("%s: %v, want 400", name, err)
		}
	}
}

func TestServerRefusesToDropAGroupThatLeavesAHolderUncovered(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com", "dan@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	drop := func(next *e2e.MembershipBody) { next.Groups = nil }
	err := putSameEpoch(t, w, drop)
	if status, msg := apiStatus(err); status != http.StatusBadRequest || !strings.Contains(msg, "same epoch") {
		t.Fatalf("dropping the group with two holders: %v, want 400 same epoch", err)
	}
	// Cat leaves the group, so the record changes nothing for her; dan still
	// qualifies before it and not after.
	if _, err := w.ada.RemoveGroupMember(w.group, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	if err := putSameEpoch(t, w, drop); err == nil {
		t.Fatal("dropping the group while dan holds the key through it landed")
	}
}

func TestServerAllowsDroppingAGroupWhenNoHolderIsUncovered(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	// Cat leaves the group before the record drops it: no holder who
	// qualified before the record is left uncovered by it.
	if _, err := w.ada.RemoveGroupMember(w.group, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	if err := putSameEpoch(t, w, func(next *e2e.MembershipBody) { next.Groups = nil }); err != nil {
		t.Errorf("dropping a group no holder reads through: %v", err)
	}
}

func TestServerAllowsDroppingAGroupWithNoHolder(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	// Listed, but nobody approved: no holder at all.
	if err := putSameEpoch(t, w, func(next *e2e.MembershipBody) {
		next.Groups = []e2e.GroupShare{{Group: w.group, Role: "viewer"}}
	}); err != nil {
		t.Fatal(err)
	}
	if err := putSameEpoch(t, w, func(next *e2e.MembershipBody) { next.Groups = nil }); err != nil {
		t.Errorf("dropping a group with no holder: %v", err)
	}
}

func TestServerRequiresANextEpochToCoverAUserWhoLeft(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com", "dan@example.com")
	if _, err := w.ada.ShareGroup(w.artifact, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.RemoveGroupMember(w.group, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	// A next epoch that neither lists nor excludes cat is refused, as it is
	// for any unlisted holder.
	k := mustUnlock(t, w.ada)
	va, err := w.ada.VerifyArtifact(k, w.artifact, "")
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := w.ada.Directory()
	dan, _ := FindUser(dir, "dan@example.com")
	ak := bytes.Repeat([]byte{9}, 32)
	next := va.Chain.Latest
	next.Epoch, next.AKCommit = 2, ""
	next.AKCommit, _ = e2e.AKCommit(ak, w.artifact, 2)
	next.Members = []e2e.Member{{User: dan.ID, Role: "viewer", FP: dan.FP}}
	next, env, err := signNext(k.Ed25519Seed, k.UserID, va, next)
	if err != nil {
		t.Fatal(err)
	}
	_ = next
	ekKey, _ := e2e.EKSealKey(k.EK)
	sealed, err := e2e.Seal(rand.Reader, ekKey, estateFields(w.artifact, 2), ak)
	if err != nil {
		t.Fatal(err)
	}
	var wraps []map[string]any
	for epoch := 1; epoch <= 2; epoch++ {
		wr, err := e2e.Wrap(rand.Reader, e2e.WrapContext{Purpose: "ak", Artifact: w.artifact, Epoch: uint64(epoch), RecipientID: dan.ID, RecipientPub: dan.X25519Pub}, ak)
		if err != nil {
			t.Fatal(err)
		}
		if epoch == 2 {
			wraps = append(wraps, map[string]any{"user": dan.ID, "epoch": epoch, "wrapped": e2e.B64(wr)})
		}
	}
	err = w.ada.doJSON("PUT", "/api/artifacts/"+w.artifact+"/membership", map[string]any{
		"membership": env, "wraps": wraps, "linkTokenHash": "",
		"estate": []map[string]any{{"epoch": 2, "sealed": e2e.B64(sealed)}},
	}, nil)
	if status, msg := apiStatus(err); status != http.StatusBadRequest || !strings.Contains(msg, "neither listed nor excluded") {
		t.Errorf("a next epoch that leaves cat out of both lists: %v", err)
	}
}
