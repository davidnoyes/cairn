package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
)

// fanOutOut is the fanOut key of a command's JSON.
type fanOutOut struct {
	FanOut struct {
		Total    int
		Current  int
		Updated  int
		NewEpoch int
		Failed   []map[string]string
		Items    []struct {
			ID       string
			Kind     string
			State    string
			Excluded []string
		}
	}
}

// folderShareWorld is the team world with ada's folder Work holding the
// artifact notes and the folder Plans, which holds the artifact deep. Ada is
// signed in.
func folderShareWorld(t *testing.T) (w *teamWorld, work, plans, notes, deep string) {
	t.Helper()
	w = newTeamWorld(t)
	w.as(t, "ada")
	work = runJSON[client.Artifact](t, runFolder, "create", "Work", "--json").ID
	plans = runJSON[client.Artifact](t, runFolder, "create", "Plans", "--in", "Work", "--json").ID
	notes = runJSON[client.Artifact](t, runArtifact, "create", "notes", "--in", "Work", "--json").ID
	deep = runJSON[client.Artifact](t, runArtifact, "create", "deep", "--in", "Plans", "--json").ID
	return w, work, plans, notes, deep
}

// membersOf is the members JSON rows of an artifact, by email.
func membersOf(t *testing.T, artifact string) map[string]map[string]string {
	t.Helper()
	out := runJSON[struct{ Members []map[string]string }](t, runMembers, artifact, "--json")
	rows := map[string]map[string]string{}
	for _, r := range out.Members {
		rows[r["email"]] = r
	}
	return rows
}

func TestShareAFolderFansOutAndPrintsProgress(t *testing.T) {
	w, work, plans, notes, deep := folderShareWorld(t)
	done := captureStderr(t)
	res := runJSON[fanOutOut](t, runShare, "Work", "cat@example.com", "--role", "editor", "--json")
	progress := done()
	if f := res.FanOut; f.Total != 3 || f.Updated != 3 || f.Current != 0 || f.NewEpoch != 0 || len(f.Failed) != 0 || len(f.Items) != 3 {
		t.Errorf("fanOut = %+v", f)
	}
	if !strings.Contains(progress, "1 of 3 items") || !strings.Contains(progress, "3 of 3 items") {
		t.Errorf("progress on stderr: %q", progress)
	}
	// Every item lists cat with the marks, and cat reads each one.
	for _, id := range []string{plans, notes, deep} {
		row := membersOf(t, id)["cat@example.com"]
		if row["via"] != work || row["viaName"] != "Work" || row["role"] != "editor" {
			t.Errorf("%s lists cat as %v", id, row)
		}
	}
	if row := membersOf(t, work)["cat@example.com"]; row["via"] != "" {
		t.Errorf("the folder's own entry names a folder: %v", row)
	}
	text, err := runQuiet(t, runMembers, deep)
	if err != nil || !strings.Contains(text, "via Work ("+work+")") {
		t.Errorf("members printed %q, %v", text, err)
	}
	w.as(t, "cat")
	if _, err := runQuiet(t, runMembers, deep); err != nil {
		t.Errorf("cat reads deep: %v", err)
	}
	w.as(t, "ada")

	// The same command again has nothing left to do.
	again := runJSON[fanOutOut](t, runShare, "Work", "cat@example.com", "--role", "editor", "--json")
	if f := again.FanOut; f.Total != 3 || f.Current != 3 || f.Updated != 0 {
		t.Errorf("fanOut on a second run = %+v", f)
	}
	out, err := runQuiet(t, runShare, "Work", "cat@example.com", "--role", "editor")
	if err != nil || !strings.Contains(out, "3 items: 0 updated, 0 at a new epoch, 3 already up to date, 0 still pending") {
		t.Errorf("share printed %q, %v", out, err)
	}
	// An artifact is shared as before, with no fan-out in its JSON.
	plain := runJSON[map[string]any](t, runShare, notes, "dan@example.com", "--json")
	if _, ok := plain["fanOut"]; ok {
		t.Errorf("an artifact's share carries a fan-out: %v", plain)
	}
}

func TestUnshareAFolderStartsAnEpochForEachItemAndResumes(t *testing.T) {
	w, _, plans, notes, deep := folderShareWorld(t)
	if _, err := runQuiet(t, runShare, "Work", "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	res := runJSON[fanOutOut](t, runUnshare, "Work", "cat@example.com", "--json")
	if f := res.FanOut; f.Total != 3 || f.NewEpoch != 3 || len(f.Failed) != 0 {
		t.Fatalf("fanOut = %+v", f)
	}
	for _, it := range res.FanOut.Items {
		if it.State != "newEpoch" || len(it.Excluded) != 1 {
			t.Errorf("item %+v", it)
		}
	}
	for _, id := range []string{plans, notes, deep} {
		if _, ok := membersOf(t, id)["cat@example.com"]; ok {
			t.Errorf("%s still lists cat", id)
		}
	}
	w.as(t, "cat")
	if _, err := runQuiet(t, runMembers, deep); err == nil {
		t.Errorf("cat still reads deep")
	}
	w.as(t, "ada")

	// Running it again finds the folder done, says so, and works through the
	// items, which are all current.
	out, err := runQuiet(t, runUnshare, "Work", "cat@example.com")
	if err != nil || !strings.Contains(out, "Work no longer lists cat@example.com") || !strings.Contains(out, "3 already up to date") {
		t.Errorf("unshare again printed %q, %v", out, err)
	}
	// The text of the first run names who each item excluded.
	if _, err := runQuiet(t, runShare, "Work", "dan@example.com"); err != nil {
		t.Fatal(err)
	}
	out, err = runQuiet(t, runUnshare, "Work", "dan@example.com")
	if err != nil || strings.Count(out, "new epoch, excluded dan@example.com") != 3 {
		t.Errorf("unshare printed %q, %v", out, err)
	}
}

func TestMoveFansOutAfterTheMove(t *testing.T) {
	w, work, _, _, _ := folderShareWorld(t)
	if _, err := runQuiet(t, runShare, "Work", "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	loose := runJSON[client.Artifact](t, runArtifact, "create", "loose", "--json").ID

	into := runJSON[map[string]any](t, runMove, loose, "--to", "Work", "--json")
	fo, _ := into["fanOut"].(map[string]any)
	if into["id"] != loose || into["parent"] != work || fo["updated"] != float64(1) || fo["total"] != float64(1) {
		t.Errorf("move --to --json = %v", into)
	}
	if row := membersOf(t, loose)["cat@example.com"]; row["via"] != work {
		t.Errorf("after the move into Work: %v", row)
	}
	w.as(t, "cat")
	if _, err := runQuiet(t, runMembers, loose); err != nil {
		t.Errorf("cat reads the item in Work: %v", err)
	}
	w.as(t, "ada")

	out, err := runQuiet(t, runMove, loose, "--top")
	if err != nil || !strings.Contains(out, "to the top level") || !strings.Contains(out, "new epoch, excluded cat@example.com") {
		t.Errorf("move --top printed %q, %v", out, err)
	}
	w.as(t, "cat")
	if _, err := runQuiet(t, runMembers, loose); err == nil {
		t.Errorf("cat still reads the item after it left Work")
	}
}

func TestGroupSharedFolderShowsTheGroupViaTheFolder(t *testing.T) {
	w, work, _, _, deep := folderShareWorld(t)
	g := runJSON[groupOut](t, runGroup, "create", "Reviewers", "--member", "cat@example.com", "--json")
	res := runJSON[fanOutOut](t, runShare, "Work", "Reviewers", "--json")
	if f := res.FanOut; f.Total != 3 || f.Updated != 3 {
		t.Fatalf("fanOut = %+v", f)
	}
	members := runJSON[struct {
		Groups []map[string]any
	}](t, runMembers, deep, "--json")
	if len(members.Groups) != 1 || members.Groups[0]["id"] != g.ID || members.Groups[0]["via"] != work || members.Groups[0]["viaName"] != "Work" {
		t.Errorf("groups = %v", members.Groups)
	}
	text, err := runQuiet(t, runMembers, deep)
	if err != nil || !strings.Contains(text, "group "+g.ID+" via Work ("+work+")") {
		t.Errorf("members printed %q, %v", text, err)
	}
	w.as(t, "cat")
	if _, err := runQuiet(t, runMembers, deep); err != nil {
		t.Errorf("a member of the group reads deep: %v", err)
	}
}

func TestUnshareAGroupFromAFolderResumes(t *testing.T) {
	w, _, _, _, deep := folderShareWorld(t)
	runJSON[groupOut](t, runGroup, "create", "Reviewers", "--member", "cat@example.com", "--json")
	if _, err := runQuiet(t, runShare, "Work", "Reviewers"); err != nil {
		t.Fatal(err)
	}
	res := runJSON[fanOutOut](t, runUnshare, "Work", "Reviewers", "--json")
	if f := res.FanOut; f.Total != 3 || f.NewEpoch != 3 {
		t.Fatalf("fanOut = %+v", f)
	}
	out, err := runQuiet(t, runUnshare, "Work", "Reviewers")
	if err != nil || !strings.Contains(out, "Work no longer lists Reviewers") || !strings.Contains(out, "3 already up to date") {
		t.Errorf("unshare again printed %q, %v", out, err)
	}
	w.as(t, "cat")
	if _, err := runQuiet(t, runMembers, deep); err == nil {
		t.Errorf("a member of the dropped group still reads deep")
	}
}

func TestUnshareOfANonMemberOfAnArtifactIsStillAnError(t *testing.T) {
	_, _, _, notes, _ := folderShareWorld(t)
	if _, err := runQuiet(t, runUnshare, notes, "dan@example.com"); !errors.Is(err, client.ErrNotMember) {
		t.Errorf("unshare of a non-member: %v", err)
	}
}

func TestMembersNameAFolderTheReaderCannotReadByItsID(t *testing.T) {
	w, work, _, _, deep := folderShareWorld(t)
	if _, err := runQuiet(t, runShare, "Work", "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	// Bob reads deep by a direct grant, and not the folder the entry of cat
	// comes from.
	if _, err := runQuiet(t, runShare, deep, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "bob")
	out, err := runQuiet(t, runMembers, deep)
	if err != nil || !strings.Contains(out, " via "+work+"\n") || strings.Contains(out, "Work (") {
		t.Errorf("members printed %q, %v", out, err)
	}
	rows := membersOf(t, deep)
	if rows["cat@example.com"]["via"] != work || rows["cat@example.com"]["viaName"] != work {
		t.Errorf("cat's row as bob reads it: %v", rows["cat@example.com"])
	}
	if _, ok := rows["bob@example.com"]["via"]; ok {
		t.Errorf("bob's direct row names a folder: %v", rows["bob@example.com"])
	}
}
