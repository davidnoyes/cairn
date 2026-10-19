package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
)

// groupShareWorld is the team world with the team share turned off and a group
// Reviewers that ada manages, with cat and dan as members.
func groupShareWorld(t *testing.T) (*teamWorld, string) {
	t.Helper()
	w := newTeamWorld(t)
	w.as(t, "ada")
	if _, err := runQuiet(t, runTeam, w.artifact, "none"); err != nil {
		t.Fatal(err)
	}
	g := runJSON[groupOut](t, runGroup, "create", "Reviewers", "--member", "cat@example.com", "--member", "dan@example.com", "--json")
	return w, g.ID
}

func TestShareWithAGroupByName(t *testing.T) {
	w, gid := groupShareWorld(t)
	res := runJSON[map[string]any](t, runShare, w.artifact, "Reviewers", "--role", "editor", "--json")
	group, _ := res["group"].(map[string]any)
	if res["artifact"] != w.artifact || group["id"] != gid || group["name"] != "Reviewers" || res["role"] != "editor" ||
		res["epoch"] != float64(1) || res["unchanged"] != false {
		t.Errorf("share --json = %v", res)
	}
	approved, _ := res["approved"].([]any)
	if len(approved) != 2 {
		t.Fatalf("approved = %v, want cat and dan", res["approved"])
	}
	for _, a := range approved {
		row := a.(map[string]any)
		if row["email"] == "" || len(row["fp"].(string)) != 64 || row["user"] == "" {
			t.Errorf("an approved row = %v", row)
		}
	}
	for _, key := range []string{"pending", "listed", "unlisted"} {
		if l, ok := res[key].([]any); !ok || len(l) != 0 {
			t.Errorf("%s = %v, want an empty array", key, res[key])
		}
	}

	// The owner sees them approved, held by the group.
	pending := runJSON[struct {
		Pending []struct {
			Email  string
			State  string
			Groups []map[string]any
		}
	}](t, runApprove, w.artifact, "--json")
	if len(pending.Pending) != 2 {
		t.Fatalf("pending = %+v", pending)
	}
	for _, p := range pending.Pending {
		if p.State != "approved" || len(p.Groups) != 1 || p.Groups[0]["id"] != gid || p.Groups[0]["name"] != "Reviewers" || p.Groups[0]["deleted"] != false {
			t.Errorf("pending row = %+v", p)
		}
		if _, ok := p.Groups[0]["role"]; ok {
			t.Errorf("a pending row's group names a role: %v", p.Groups[0])
		}
	}
	text, err := runQuiet(t, runApprove, w.artifact)
	if err != nil || !strings.Contains(text, "groups: Reviewers") {
		t.Errorf("approve printed %q, %v", text, err)
	}

	// members shows the group, with its name and role.
	members := runJSON[struct {
		Groups []struct {
			ID, Name, Role string
			Deleted        bool
		}
	}](t, runMembers, w.artifact, "--json")
	if len(members.Groups) != 1 || members.Groups[0].ID != gid || members.Groups[0].Name != "Reviewers" || members.Groups[0].Role != "editor" || members.Groups[0].Deleted {
		t.Errorf("members groups = %+v", members.Groups)
	}
	text, err = runQuiet(t, runMembers, w.artifact)
	if err != nil || !strings.Contains(text, "editor  Reviewers") || !strings.Contains(text, "group "+gid) {
		t.Errorf("members printed %q, %v", text, err)
	}
	// With no group, members shows an empty list.
	w.as(t, "bob")
	if _, err := runQuiet(t, runMembers, w.artifact); err != nil {
		t.Errorf("a member reading members: %v", err)
	}
}

func TestShareWithAGroupPrintsWhatItDid(t *testing.T) {
	w, _ := groupShareWorld(t)
	out, err := runQuiet(t, runShare, w.artifact, "Reviewers", "--role", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"with group Reviewers as viewer", "approved cat@example.com", "approved dan@example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("share printed %q, want %q", out, want)
		}
	}
	out, err = runQuiet(t, runShare, w.artifact, "Reviewers", "--role", "viewer")
	if err != nil || !strings.Contains(out, "listed approved team member") {
		t.Errorf("share again printed %q, %v", out, err)
	}
	out, err = runQuiet(t, runShare, w.artifact, "Reviewers", "--role", "viewer")
	if err != nil || !strings.Contains(out, "already shared with Reviewers as viewer; nothing changed") {
		t.Errorf("a third share printed %q, %v", out, err)
	}
}

func TestADeletedGroupIsNamedAsDeletedAndDropped(t *testing.T) {
	w, gid := groupShareWorld(t)
	if _, err := runQuiet(t, runShare, w.artifact, "Reviewers", "--role", "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runGroup, "delete", gid); err != nil {
		t.Fatal(err)
	}
	text, err := runQuiet(t, runMembers, w.artifact)
	if err != nil || !strings.Contains(text, "(deleted group)") || !strings.Contains(text, "group "+gid) {
		t.Errorf("members printed %q, %v", text, err)
	}
	members := runJSON[struct {
		Groups []struct {
			ID      string
			Name    string
			Deleted bool
		}
	}](t, runMembers, w.artifact, "--json")
	if len(members.Groups) != 1 || members.Groups[0].ID != gid || members.Groups[0].Name != "" || !members.Groups[0].Deleted {
		t.Errorf("members groups = %+v", members.Groups)
	}
	// The next record drops it, and says so.
	res := runJSON[map[string]any](t, runShare, w.artifact, "bob@example.com", "--role", "viewer", "--json")
	if got, _ := res["droppedGroups"].([]any); len(got) != 1 || got[0] != gid {
		t.Errorf("share --json = %v, want droppedGroups [%s]", res, gid)
	}
	if res := runJSON[map[string]any](t, runTeam, w.artifact, "none", "--json"); res["droppedGroups"] != nil {
		t.Errorf("a record that drops nothing names droppedGroups: %v", res)
	}
}

func TestPublicAndUnshareSayWhichDeletedGroupTheyDrop(t *testing.T) {
	for name, run := range map[string]func(w *teamWorld) (string, error){
		"public": func(w *teamWorld) (string, error) { return runQuiet(t, runPublic, w.artifact, "on") },
		"a next epoch": func(w *teamWorld) (string, error) {
			return runQuiet(t, runUnshare, w.artifact, "cat@example.com")
		},
	} {
		t.Run(name, func(t *testing.T) {
			w, gid := groupShareWorld(t)
			if _, err := runQuiet(t, runShare, w.artifact, "Reviewers", "--role", "viewer"); err != nil {
				t.Fatal(err)
			}
			if _, err := runQuiet(t, runGroup, "delete", gid); err != nil {
				t.Fatal(err)
			}
			out, err := run(w)
			if err != nil || !strings.Contains(out, "dropped group "+gid) {
				t.Errorf("printed %q, %v, want the dropped group", out, err)
			}
		})
	}
}

func TestApproveSaysWhenNoGroupMemberIsWaiting(t *testing.T) {
	w, _ := groupShareWorld(t)
	if _, err := runQuiet(t, runShare, w.artifact, "Reviewers", "--role", "viewer"); err != nil {
		t.Fatal(err)
	}
	// Bob is an editor, so he is shown only the users waiting for approval.
	w.as(t, "bob")
	out, err := runQuiet(t, runApprove, w.artifact)
	if err != nil || !strings.Contains(out, "no group members waiting") || strings.Contains(out, "no team members waiting") {
		t.Errorf("approve printed %q, %v", out, err)
	}
}

func TestApproveListsALaterJoinerWithTheirGroup(t *testing.T) {
	w, gid := groupShareWorld(t)
	if _, err := runQuiet(t, runGroup, "remove", gid, "dan@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runShare, w.artifact, "Reviewers", "--role", "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runGroup, "add", gid, "dan@example.com"); err != nil {
		t.Fatal(err)
	}
	text, err := runQuiet(t, runApprove, w.artifact)
	if err != nil || !strings.Contains(text, "dan@example.com") || !strings.Contains(text, "groups: Reviewers") ||
		!strings.Contains(text, "cairn approve "+w.artifact+" USER") {
		t.Fatalf("approve printed %q, %v", text, err)
	}
	if rows := w.pending(t); rows["dan@example.com"].State != "new" || rows["cat@example.com"].State != "approved" {
		t.Fatalf("pending = %+v", rows)
	}
	out, err := runQuiet(t, runApprove, w.artifact, "dan@example.com")
	if err != nil || !strings.Contains(out, "approved for shared") {
		t.Errorf("approve dan printed %q, %v", out, err)
	}
}

func TestLeftUsersAreListedWithTheHintToUnshareThem(t *testing.T) {
	w, gid := groupShareWorld(t)
	if _, err := runQuiet(t, runShare, w.artifact, "Reviewers", "--role", "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runGroup, "remove", gid, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	text, err := runQuiet(t, runApprove, w.artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"left ", "cat@example.com", "cairn unshare " + w.artifact + " cat@example.com", "left every group"} {
		if !strings.Contains(text, want) {
			t.Errorf("approve printed %q, want %q", text, want)
		}
	}
	rows := w.pending(t)
	if rows["cat@example.com"].State != "left" || rows["dan@example.com"].State != "approved" {
		t.Errorf("pending = %+v", rows)
	}
	// Unshare excludes them in a new epoch, as for any unlisted holder.
	res := runJSON[map[string]any](t, runUnshare, w.artifact, "cat@example.com", "--json")
	excluded, _ := res["excluded"].([]any)
	if res["newEpoch"] != true || len(excluded) != 1 || excluded[0].(map[string]any)["email"] != "cat@example.com" {
		t.Errorf("unshare --json = %v", res)
	}
}

func TestUnshareAGroup(t *testing.T) {
	w, gid := groupShareWorld(t)
	if _, err := runQuiet(t, runShare, w.artifact, "Reviewers", "--role", "viewer"); err != nil {
		t.Fatal(err)
	}
	res := runJSON[map[string]any](t, runUnshare, w.artifact, gid, "--json")
	group, _ := res["group"].(map[string]any)
	excluded, _ := res["excluded"].([]any)
	if group["id"] != gid || group["name"] != "Reviewers" || res["newEpoch"] != true || res["epoch"] != float64(2) || len(excluded) != 2 {
		t.Errorf("unshare --json = %v", res)
	}
	if _, err := runQuiet(t, runUnshare, w.artifact, "Reviewers"); !errors.Is(err, client.ErrNotSharedWithGroup) {
		t.Errorf("unshare again: %v, want ErrNotSharedWithGroup", err)
	}
	// Both were excluded, so nobody holds the key through the group now, and
	// dropping it again needs no new epoch.
	if _, err := runQuiet(t, runShare, w.artifact, "Reviewers", "--role", "viewer"); err != nil {
		t.Fatal(err)
	}
	out, err := runQuiet(t, runUnshare, w.artifact, "Reviewers")
	if err != nil || !strings.Contains(out, "removed group Reviewers ("+gid+")") || strings.Contains(out, "started epoch") {
		t.Errorf("unshare printed %q, %v", out, err)
	}
}

func TestEveryoneIsTheTeamShare(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")
	res := runJSON[map[string]any](t, runUnshare, w.artifact, "everyone", "--json")
	if res["team"] != "none" || res["unchanged"] != false {
		t.Errorf("unshare everyone --json = %v", res)
	}
	res = runJSON[map[string]any](t, runShare, w.artifact, "everyone", "--role", "editor", "--json")
	if res["team"] != "editor" || res["unchanged"] != false {
		t.Errorf("share everyone --json = %v", res)
	}
	out, err := runQuiet(t, runShare, w.artifact, "everyone", "--role", "editor")
	if err != nil || !strings.Contains(out, "team is already editor") {
		t.Errorf("share everyone again printed %q, %v", out, err)
	}
	if _, err := runQuiet(t, runShare, w.artifact, "everyone", "--role", "manager"); err == nil || !strings.Contains(err.Error(), "viewer or editor") {
		t.Errorf("share everyone as manager: %v", err)
	}
	// cairn team keeps working, and agrees.
	res = runJSON[map[string]any](t, runTeam, w.artifact, "viewer", "--json")
	if res["team"] != "viewer" {
		t.Errorf("team viewer --json = %v", res)
	}
	// A team member is approved, so turning the team off needs a new epoch.
	w.as(t, "bob")
	if _, err := runQuiet(t, runApprove, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "ada")
	res = runJSON[map[string]any](t, runUnshare, w.artifact, "everyone", "--json")
	if res["newEpoch"] != true {
		t.Errorf("unshare everyone with an approved member = %v", res)
	}
}

func TestShareAndUnshareTakeAUserAGroupOrEveryone(t *testing.T) {
	w, _ := groupShareWorld(t)
	// An email is a user, and a user ID, which has no @, is one too when no
	// group has that name.
	res := runJSON[map[string]any](t, runShare, w.artifact, "cat@example.com", "--role", "viewer", "--json")
	if res["email"] != "cat@example.com" || res["group"] != nil {
		t.Errorf("share a user --json = %v", res)
	}
	id := res["user"].(string)
	if res := runJSON[map[string]any](t, runUnshare, w.artifact, id, "--json"); res["email"] != "cat@example.com" || res["user"] != id {
		t.Errorf("unshare a user by ID --json = %v", res)
	}
	// A name that is no group and no user is the user lookup's error.
	if _, err := runQuiet(t, runShare, w.artifact, "No such name"); !errors.Is(err, client.ErrUnknownUser) {
		t.Errorf("share an unknown name: %v, want ErrUnknownUser", err)
	}
	if _, err := runQuiet(t, runUnshare, w.artifact, "No such name"); !errors.Is(err, client.ErrUnknownUser) {
		t.Errorf("unshare an unknown name: %v, want ErrUnknownUser", err)
	}
	// A group takes viewer or editor.
	if _, err := runQuiet(t, runShare, w.artifact, "Reviewers", "--role", "manager"); err == nil || !strings.Contains(err.Error(), "viewer or editor") {
		t.Errorf("share a group as manager: %v", err)
	}
	// A name two groups share is ambiguous.
	if _, err := runQuiet(t, runGroup, "create", "Reviewers"); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runShare, w.artifact, "Reviewers"); !errors.Is(err, client.ErrAmbiguousGroup) {
		t.Errorf("share an ambiguous name: %v, want ErrAmbiguousGroup", err)
	}
	if _, err := runQuiet(t, runUnshare, w.artifact, "Reviewers"); !errors.Is(err, client.ErrAmbiguousGroup) {
		t.Errorf("unshare an ambiguous name: %v, want ErrAmbiguousGroup", err)
	}
}

func TestShareWithAGroupLeavesAMemberWhoseKeyChangedPending(t *testing.T) {
	w, _ := groupShareWorld(t)
	resetCLIUser(t, w, "cat@example.com")
	res := runJSON[map[string]any](t, runShare, w.artifact, "Reviewers", "--json")
	pending, _ := res["pending"].([]any)
	approved, _ := res["approved"].([]any)
	if len(pending) != 1 || len(approved) != 1 {
		t.Fatalf("share --json = %v, want dan approved and cat pending", res)
	}
	row := pending[0].(map[string]any)
	if row["email"] != "cat@example.com" || !strings.Contains(row["reason"].(string), "directory") {
		t.Errorf("pending row = %v", row)
	}
	// Text says who is pending and what to run once the fingerprint is checked.
	if _, err := runQuiet(t, runUnshare, w.artifact, "Reviewers"); err != nil {
		t.Fatal(err)
	}
	out, err := runQuiet(t, runShare, w.artifact, "Reviewers")
	if err != nil || !strings.Contains(out, "pending: ") || !strings.Contains(out, "cairn approve "+w.artifact+" cat@example.com") {
		t.Errorf("share printed %q, %v", out, err)
	}
}
