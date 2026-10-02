package main

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

func TestUnshareCommand(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")
	if _, err := runQuiet(t, runTeam, w.artifact, "none"); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runShare, w.artifact, "dan@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runUnshare); err == nil || !strings.Contains(err.Error(), "usage: cairn unshare ARTIFACT USER") {
		t.Errorf("unshare with no user: %v", err)
	}
	out, err := runQuiet(t, runUnshare, w.artifact, "dan@example.com")
	if err != nil {
		t.Fatalf("cairn unshare: %v", err)
	}
	for _, want := range []string{"started epoch 2", "excluded dan@example.com", "removed", "cairn share " + w.artifact + " USER"} {
		if !strings.Contains(out, want) {
			t.Errorf("cairn unshare printed %q, want %q", out, want)
		}
	}
	if strings.Contains(out, "cairn review") {
		t.Errorf("cairn unshare printed %q, want no review hint: dan pushed nothing", out)
	}
	if _, ok := membersByEmail(t, w.artifact)["dan@example.com"]; ok {
		t.Error("dan is still a member")
	}
	if _, err := runQuiet(t, runUnshare, w.artifact, "dan@example.com"); !errors.Is(err, client.ErrNotMember) {
		t.Errorf("unsharing a non-member: %v, want ErrNotMember", err)
	}

	res := runJSON[map[string]any](t, runUnshare, w.artifact, "bob@example.com", "--json")
	ex, _ := res["excluded"].([]any)
	if res["artifact"] != w.artifact || res["epoch"] != float64(3) || res["newEpoch"] != true || res["link"] != "" || len(ex) != 1 {
		t.Fatalf("cairn unshare --json = %v, want epoch 3, a new epoch, no link, bob excluded", res)
	}
	if e := ex[0].(map[string]any); e["email"] != "bob@example.com" || e["user"] == "" || len(e["fp"].(string)) != 64 || e["reason"] != "removed" {
		t.Errorf("excluded entry = %v", e)
	}
}

func TestUnsharePrintsTheNewLinkOfAPublicArtifact(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")
	old := runJSON[map[string]any](t, runPublic, w.artifact, "on", "--json")["link"].(string)
	out, err := runQuiet(t, runUnshare, w.artifact, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, old) || !strings.Contains(out, "/shared/"+w.artifact+"#k=") || !strings.Contains(out, "old link") {
		t.Errorf("cairn unshare printed %q, want the new link only, and a note that the old one stops working", out)
	}
}

func TestShareDemotionCommand(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "bob")
	if _, err := runQuiet(t, runPush, siteDir(t), "--artifact", w.artifact); err != nil {
		t.Fatalf("bob's push: %v", err)
	}
	w.as(t, "ada")
	out, err := runQuiet(t, runShare, w.artifact, "bob@example.com", "--role", "viewer")
	if err != nil {
		t.Fatalf("demotion: %v", err)
	}
	for _, want := range []string{"demoted to viewer", "started epoch 2", "1 version needs review", "cairn review " + w.artifact} {
		if !strings.Contains(out, want) {
			t.Errorf("cairn share printed %q, want %q", out, want)
		}
	}
	if r := membersByEmail(t, w.artifact)["bob@example.com"]; r.Role != "viewer" {
		t.Errorf("bob's row = %+v, want a viewer", r)
	}
}

func TestTeamNoneStartsANewEpochWhileAMemberHoldsAWrap(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "bob")
	if _, err := runQuiet(t, runApprove, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "ada")
	out, err := runQuiet(t, runTeam, w.artifact, "none")
	if err != nil {
		t.Fatalf("team none with cat holding a wrap: %v", err)
	}
	for _, want := range []string{"team set to none", "started epoch 2", "excluded cat@example.com", "cairn share " + w.artifact + " USER"} {
		if !strings.Contains(out, want) {
			t.Errorf("cairn team none printed %q, want %q", out, want)
		}
	}
}

func TestPublicOffCommandStartsANewEpoch(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")
	if _, err := runQuiet(t, runPublic, w.artifact, "on"); err != nil {
		t.Fatal(err)
	}
	out, err := runQuiet(t, runPublic, w.artifact, "off")
	if err != nil || !strings.Contains(out, "is private") || !strings.Contains(out, "started epoch 2") {
		t.Errorf("cairn public off printed %q, %v, want it private in epoch 2", out, err)
	}
	if strings.Contains(out, "already private") {
		t.Errorf("cairn public off printed %q: it changed the artifact", out)
	}
	res := runJSON[map[string]any](t, runPublic, w.artifact, "on", "--json")
	if res["epoch"] != float64(2) {
		t.Errorf("cairn public on after off = %v, want epoch 2", res)
	}
	res = runJSON[map[string]any](t, runPublic, w.artifact, "off", "--json")
	if res["public"] != false || res["link"] != "" || res["unchanged"] != false || res["newEpoch"] != true || res["epoch"] != float64(3) {
		t.Errorf("cairn public off --json = %v", res)
	}
}

// A member whose account was deleted is unshared by user ID, and the output
// names them by it.
func TestUnshareCommandOnADeletedAccount(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")
	if _, err := runQuiet(t, runShare, w.artifact, "dan@example.com"); err != nil {
		t.Fatal(err)
	}
	dan := membersByEmail(t, w.artifact)["dan@example.com"].User
	signupVerify(t, w.host, w.m, "admin@example.com", sharePassword)
	out, err := client.New(w.host, "").Login("admin@example.com", sharePassword)
	if err != nil {
		t.Fatal(err)
	}
	key, err := e2e.ParseAPIKey(out.APIKey)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("DELETE", w.host+"/api/admin/users/"+dan, nil)
	req.Header.Set("Authorization", "Bearer "+client.NewWithKey(w.host, key).Token)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Fatalf("deleting dan: %v %v", resp, err)
	}

	got, err := runQuiet(t, runUnshare, w.artifact, dan)
	if err != nil {
		t.Fatalf("cairn unshare of a deleted account: %v", err)
	}
	for _, want := range []string{"removed deleted account " + dan, "excluded deleted account " + dan} {
		if !strings.Contains(got, want) {
			t.Errorf("cairn unshare printed %q, want %q", got, want)
		}
	}
}

// Making a team artifact private lists an approved team member who held a
// wrap, and says so.
func TestPublicOffCommandReportsTheTeamMembersItLists(t *testing.T) {
	for _, jsonOut := range []bool{false, true} {
		w := newTeamWorld(t)
		w.as(t, "bob")
		if _, err := runQuiet(t, runApprove, w.artifact, "cat@example.com"); err != nil {
			t.Fatal(err)
		}
		w.as(t, "ada")
		if _, err := runQuiet(t, runPublic, w.artifact, "on"); err != nil {
			t.Fatal(err)
		}
		if jsonOut {
			res := runJSON[map[string]any](t, runPublic, w.artifact, "off", "--json")
			if l, _ := res["listed"].([]any); len(l) != 1 || l[0].(map[string]any)["email"] != "cat@example.com" {
				t.Errorf("cairn public off --json = %v, want cat listed", res)
			}
			continue
		}
		out, err := runQuiet(t, runPublic, w.artifact, "off")
		if err != nil || !strings.Contains(out, "listed approved team member cat@example.com") {
			t.Errorf("cairn public off printed %q, %v, want cat listed", out, err)
		}
	}
}
