package client

import (
	"net/http"
	"testing"
)

// Applying the inheritance alone signs what is pending and approves no one:
// a newcomer to a group stays waiting until the explicit Apply, as the Approve
// button and cairn apply are the decision.
func TestApplyInheritedSignsPendingRecordsAndApprovesNoOne(t *testing.T) {
	w := &othersTree{team: newTeam(t)}
	w.work = mustFolder(t, w.ada, "Work", "")
	if _, err := w.ada.Share(w.work, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)
	w.theirs = mustCreate(t, w.bob, "theirs", InFolder(w.work)).ID
	g, err := w.ada.CreateGroup("Reviewers", []string{"cat@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.ShareGroup(w.work, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)
	if _, err := w.ada.AddGroupMember(g.ID, "dan@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	// A new manager of the folder leaves bob's item pending: only he signs it.
	if _, err := w.ada.Share(w.work, "cat@example.com", "manager", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)

	res, err := w.bob.ApplyInherited()
	if err != nil {
		t.Fatalf("ApplyInherited: %v", err)
	}
	if it := itemResult(&res.FanOut, w.theirs); it == nil || it.State != FanOutUpdated {
		t.Fatalf("bob's item = %+v, want it updated", res.FanOut.Items)
	}
	if len(res.Approvals) != 0 {
		t.Errorf("ApplyInherited approved: %+v", res.Approvals)
	}
	wantStatus(t, w.dan, w.theirs, http.StatusNotFound)
	// The explicit Apply still approves.
	res = applyOK(t, w.bob)
	if len(res.Approvals) == 0 {
		t.Fatalf("Apply approved no one: %+v", res)
	}
	wantStatus(t, w.dan, w.theirs, http.StatusOK)
}

// With nothing pending, ApplyInherited does no more than list the artifacts.
func TestApplyInheritedWithNothingPendingReturnsAnEmptyResult(t *testing.T) {
	w := newOthersTree(t)
	res, err := w.bob.ApplyInherited()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.FanOut.Items) != 0 || len(res.Waiting) != 0 || len(res.Approvals) != 0 {
		t.Errorf("ApplyInherited = %+v, want nothing", res)
	}
	// It does not even unlock: a client that holds no key gets the same.
	keyless := *w.bob
	keyless.Key = nil
	if _, err := keyless.ApplyInherited(); err != nil {
		t.Errorf("ApplyInherited with nothing pending and no key: %v", err)
	}
}
