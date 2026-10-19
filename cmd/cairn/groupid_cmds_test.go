package main

import (
	"strings"
	"testing"
)

// A group's name is chosen by its managers, so one named after a user's ID
// must not take a share or an unshare meant for that user.
func TestAGroupNamedAfterAUserIDNeverStandsInForTheUser(t *testing.T) {
	w, gid := groupShareWorld(t)
	res := runJSON[map[string]any](t, runShare, w.artifact, "cat@example.com", "--role", "viewer", "--json")
	id := res["user"].(string)
	if _, err := runQuiet(t, runGroup, "create", id, "--member", "dan@example.com"); err != nil {
		t.Fatal(err)
	}
	// Cat is listed already; unshare by ID acts on cat, not on the group.
	res = runJSON[map[string]any](t, runUnshare, w.artifact, id, "--json")
	if res["email"] != "cat@example.com" || res["user"] != id || res["group"] != nil {
		t.Errorf("unshare by user ID --json = %v", res)
	}
	res = runJSON[map[string]any](t, runShare, w.artifact, id, "--role", "viewer", "--json")
	if res["email"] != "cat@example.com" || res["user"] != id || res["group"] != nil {
		t.Errorf("share by user ID --json = %v", res)
	}
	// A real group ID still takes the group, and the text names its ID.
	out, err := runQuiet(t, runShare, w.artifact, gid, "--role", "viewer")
	if err != nil || !strings.Contains(out, "with group Reviewers ("+gid+") as viewer") {
		t.Errorf("share by group ID printed %q, %v", out, err)
	}
}
