package main

import (
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
)

// applyOut is the JSON cairn apply prints.
type applyOut struct {
	Applied struct {
		Total     int
		Updated   int
		NewEpoch  int
		Waiting   int
		NeedsMove int
		Failed    []map[string]string
		Items     []struct{ ID, State string }
	}
	Waiting []struct{ ID, Kind, Owner, OwnerEmail string }
	Approve []struct {
		ID       string
		Approved []map[string]string
	} `json:"approvals"`
}

// newOthersWorld is the team world with ada's folder Work, which bob edits,
// holding bob's artifact theirs. Ada is signed in.
func newOthersWorld(t *testing.T) (w *teamWorld, work, theirs string) {
	t.Helper()
	w = newTeamWorld(t)
	w.as(t, "ada")
	work = runJSON[client.Artifact](t, runFolder, "create", "Work", "--json").ID
	if _, err := runQuiet(t, runShare, "Work", "bob@example.com", "--role", "editor"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "bob")
	theirs = runJSON[client.Artifact](t, runArtifact, "create", "theirs", "--in", work, "--json").ID
	w.as(t, "ada")
	return w, work, theirs
}

// shareManagerOfOthersItems shares Work with email as a manager. That changes
// the managers of bob's item, which only bob signs, so ada's fan-out leaves it
// pending, and the share says it waits on bob and does not fail.
func shareManagerOfOthersItems(t *testing.T, email string) string {
	t.Helper()
	text, err := runQuiet(t, runShare, "Work", email, "--role", "manager")
	if err != nil {
		t.Fatalf("share: %v, want the item to wait on its owner and the share to succeed", err)
	}
	return text
}

// An item whose record lacks the folder's owner is one the owner cannot read,
// so a stub: bob's folder Inner, with cat's item in it, is moved into ada's
// folder Work, and the item has not been brought in step with Work yet. Ada
// signs Inner herself, as a manager, and the item waits on cat.
func TestShareAFolderReportsItemsThatWaitOnTheirOwners(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")
	runJSON[client.Artifact](t, runFolder, "create", "Work", "--json")
	if _, err := runQuiet(t, runShare, "Work", "bob@example.com", "--role", "editor"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "bob")
	inner := runJSON[client.Artifact](t, runFolder, "create", "Inner", "--json").ID
	if _, err := runQuiet(t, runShare, "Inner", "cat@example.com", "--role", "editor"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "cat")
	theirs := runJSON[client.Artifact](t, runArtifact, "create", "theirs", "--in", inner, "--json").ID
	w.as(t, "bob")
	// Bob manages the item as the folder's owner, but only cat lists a manager.
	if _, err := runQuiet(t, runMove, inner, "--to", "Work"); err != nil && !strings.Contains(err.Error(), "not up to date with their folder yet") {
		t.Fatal(err)
	}
	w.as(t, "ada")
	text, err := runQuiet(t, runShare, "Work", "dan@example.com", "--role", "viewer")
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	if !strings.Contains(text, "1 wait on their owners") || !strings.Contains(text, theirs+": waits on cat@example.com") {
		t.Errorf("share printed %q", text)
	}
	// Sharing it again resumes, and prints it as JSON.
	res := runJSON[struct {
		FanOut struct {
			Waiting int
			Failed  []map[string]string
			Items   []struct{ ID, State, Owner, OwnerEmail string }
		}
	}](t, runShare, "Work", "dan@example.com", "--role", "viewer", "--json")
	if f := res.FanOut; f.Waiting != 1 || len(f.Failed) != 0 || len(f.Items) != 2 || f.Items[1].State != "waits" || f.Items[1].OwnerEmail != "cat@example.com" || f.Items[1].Owner == "" {
		t.Errorf("fanOut = %+v", res.FanOut)
	}
}

func TestShareAFolderAsManagerLeavesOthersItemsPendingForTheirOwners(t *testing.T) {
	_, _, theirs := newOthersWorld(t)
	text := shareManagerOfOthersItems(t, "cat@example.com")
	if !strings.Contains(text, "0 still pending, 1 wait on their owners") || !strings.Contains(text, theirs+": waits on bob@example.com") || strings.Contains(text, ": still pending:") {
		t.Errorf("share printed %q", text)
	}
}

func TestFolderListShowsAStubForAnItemNotSharedYet(t *testing.T) {
	w, work, theirs := newOthersWorld(t)
	shareManagerOfOthersItems(t, "cat@example.com")
	w.as(t, "cat")
	text, err := runQuiet(t, runFolder, "list", "Work")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "(not shared with you yet, owned by bob@example.com)  "+theirs) || strings.Contains(text, "theirs") {
		t.Errorf("folder list printed %q", text)
	}
	nodes := runJSON[[]struct {
		ID    string
		Stub  bool
		Name  string
		Owner string
	}](t, runFolder, "list", work, "--json")
	if len(nodes) != 1 || !nodes[0].Stub || nodes[0].Name != "" || nodes[0].ID != theirs || nodes[0].Owner == "" {
		t.Errorf("folder list --json = %+v", nodes)
	}
}

func TestApplyPrintsWhatItDidAndWhatWaits(t *testing.T) {
	w, _, theirs := newOthersWorld(t)
	shareManagerOfOthersItems(t, "cat@example.com")
	// Ada owns none of what is pending: it waits on bob.
	text, err := runQuiet(t, runApply)
	if err != nil || !strings.Contains(text, "1 item still waits on someone else:\n") || !strings.Contains(text, theirs+": waits on bob@example.com") {
		t.Errorf("ada's apply printed %q, %v", text, err)
	}
	if res := runJSON[applyOut](t, runApply, "--json"); len(res.Waiting) != 1 || res.Waiting[0].ID != theirs || res.Waiting[0].OwnerEmail != "bob@example.com" || res.Applied.Total != 0 {
		t.Errorf("ada's apply --json = %+v", res)
	}

	w.as(t, "bob")
	text, err = runQuiet(t, runApply)
	if err != nil || !strings.Contains(text, "1 item: 1 updated") {
		t.Errorf("bob's apply printed %q, %v", text, err)
	}
	w.as(t, "cat")
	if _, err := runQuiet(t, runMembers, theirs); err != nil {
		t.Errorf("cat reads the item after the apply: %v", err)
	}
	// Idempotent, in both forms.
	w.as(t, "bob")
	if text, err = runQuiet(t, runApply); err != nil || !strings.Contains(text, "nothing to apply") {
		t.Errorf("the second apply printed %q, %v", text, err)
	}
	res := runJSON[applyOut](t, runApply, "--json")
	if res.Applied.Total != 0 || len(res.Waiting) != 0 || len(res.Approve) != 0 || res.Applied.Items == nil || res.Waiting == nil {
		t.Errorf("the second apply --json = %+v", res)
	}
}

func TestApplyCountsSeveralItemsThatWait(t *testing.T) {
	w, work, _ := newOthersWorld(t)
	w.as(t, "bob")
	runJSON[client.Artifact](t, runArtifact, "create", "more", "--in", work, "--json")
	w.as(t, "ada")
	shareManagerOfOthersItems(t, "cat@example.com")
	text, err := runQuiet(t, runApply)
	if err != nil || !strings.Contains(text, "2 items still wait on someone else:\n") {
		t.Errorf("ada's apply printed %q, %v", text, err)
	}
}

func TestApplyApprovesGroupNewcomers(t *testing.T) {
	w, _, theirs := newOthersWorld(t)
	if _, err := runQuiet(t, runGroup, "create", "Reviewers", "--member", "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runShare, "Work", "Reviewers", "--role", "viewer"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "bob")
	if _, err := runQuiet(t, runApply); err != nil {
		t.Fatal(err)
	}
	w.as(t, "ada")
	if _, err := runQuiet(t, runGroup, "add", "Reviewers", "dan@example.com"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "bob")
	text, err := runQuiet(t, runApply)
	if err != nil || !strings.Contains(text, theirs+": approved dan@example.com") {
		t.Errorf("bob's apply printed %q, %v", text, err)
	}
	if text, err = runQuiet(t, runApply); err != nil || !strings.Contains(text, "nothing to apply") {
		t.Errorf("a repeat printed %q, %v", text, err)
	}
}

func TestFolderDeleteShowsWhatBecomesOfOtherPeoplesItems(t *testing.T) {
	w, work, theirs := newOthersWorld(t)
	mine := runJSON[client.Artifact](t, runArtifact, "create", "mine", "--in", "Work", "--json").ID
	done := captureStderr(t)
	got := runJSON[struct {
		Folder  string
		Deleted struct{ Folders, Artifacts int }
		Moved   []struct{ ID, Kind, Owner string }
	}](t, runFolder, "delete", "Work", "--yes", "--json")
	plan := done()
	if got.Folder != work || got.Deleted.Folders != 1 || got.Deleted.Artifacts != 1 || len(got.Moved) != 1 || got.Moved[0].ID != theirs || got.Moved[0].Owner == "" {
		t.Errorf("JSON: %+v", got)
	}
	if !strings.Contains(plan, "removes 1 folder, itself included, and 1 artifact") ||
		!strings.Contains(plan, "1 item someone else owns move to their owners' top levels") ||
		!strings.Contains(plan, theirs+"  artifact, owned by bob@example.com") {
		t.Errorf("the plan on stderr: %q", plan)
	}
	if _, err := runQuiet(t, runArtifact, "show", mine); err == nil {
		t.Errorf("ada's own item was not deleted")
	}
	// Bob's item is at his top level and pending until he applies.
	w.as(t, "bob")
	item := runJSON[client.Artifact](t, runArtifact, "show", theirs, "--json")
	if item.ParentID != "" {
		t.Errorf("bob's item after the delete sits in %q", item.ParentID)
	}
	res := runJSON[applyOut](t, runApply, "--json")
	// Ada, the folder's owner, read it through the folder, so her entry lapses
	// and the apply starts a new epoch.
	if res.Applied.Total != 1 || res.Applied.NewEpoch != 1 || res.Applied.Items[0].ID != theirs {
		t.Errorf("bob's apply --json = %+v", res.Applied)
	}
	if text, err := runQuiet(t, runApply); err != nil || !strings.Contains(text, "nothing to apply") {
		t.Errorf("a second apply printed %q, %v", text, err)
	}
}

func TestApplyLeavesAMovedItemToItsOwner(t *testing.T) {
	w, _, theirs := newOthersWorld(t)
	w.as(t, "bob")
	other := runJSON[client.Artifact](t, runFolder, "create", "Other", "--json").ID
	// Another client moved the item, so its record names Work.
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Move(theirs, other); err != nil {
		t.Fatal(err)
	}
	text, err := runQuiet(t, runApply)
	if err != nil || !strings.Contains(text, "1 need a move") || !strings.Contains(text, theirs+": needs a move:") || !strings.Contains(text, "cairn move "+theirs+" --to "+other) {
		t.Errorf("apply printed %q, %v", text, err)
	}
	res := runJSON[applyOut](t, runApply, "--json")
	if a := res.Applied; a.NeedsMove != 1 || len(a.Failed) != 0 || len(a.Items) != 1 || a.Items[0].State != "needsMove" {
		t.Errorf("apply --json = %+v", a)
	}
	// The remedy it names settles it.
	if _, err := runQuiet(t, runMove, theirs, "--to", other); err != nil {
		t.Fatal(err)
	}
	if text, err = runQuiet(t, runApply); err != nil || !strings.Contains(text, "nothing to apply") {
		t.Errorf("after the move, apply printed %q, %v", text, err)
	}
}

func TestFolderDeleteTextReportsWhatMoved(t *testing.T) {
	newOthersWorld(t)
	text, err := runQuiet(t, runFolder, "delete", "Work", "--yes")
	if err != nil || !strings.Contains(text, "1 item of other owners moved to their owners' top levels") {
		t.Errorf("delete printed %q, %v", text, err)
	}
}

func TestFolderDeleteByAnEditorIsRefused(t *testing.T) {
	w, _, _ := newOthersWorld(t)
	w.as(t, "bob")
	if err := runFolder([]string{"delete", "Work", "--yes"}); err == nil || !strings.Contains(err.Error(), "only the folder's owner deletes it") {
		t.Errorf("an editor deletes the folder: %v", err)
	}
}
