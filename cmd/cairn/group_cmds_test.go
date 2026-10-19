package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

type groupRowJSON struct {
	User, Name, Email, Role, FP, State string
	WasVerified                        *bool
}

type groupOut struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Seq     int            `json:"seq"`
	Role    string         `json:"role"`
	Members []groupRowJSON `json:"members"`
}

func TestGroupCommands(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")

	// create, with two members.
	g := runJSON[groupOut](t, runGroup, "create", "Reviewers", "--member", "bob@example.com", "--member", "cat@example.com", "--json")
	if g.ID == "" || g.Name != "Reviewers" || g.Seq != 1 || g.Role != "manager" || len(g.Members) != 3 {
		t.Fatalf("group create --json = %+v", g)
	}
	rows := map[string]groupRowJSON{}
	for _, m := range g.Members {
		rows[m.Email] = m
	}
	if r := rows["ada@example.com"]; r.Role != "manager" || r.State != "self" || r.User == "" || r.Name == "" || len(r.FP) != 64 {
		t.Errorf("ada's row = %+v", r)
	}
	if r := rows["bob@example.com"]; r.Role != "member" || r.State != e2e.PinUnverified || len(r.FP) != 64 || r.WasVerified != nil {
		t.Errorf("bob's row = %+v", r)
	}

	// list, by ID and by name for the other commands.
	list := runJSON[[]map[string]any](t, runGroup, "list", "--json")
	if len(list) != 1 || list[0]["id"] != g.ID || list[0]["name"] != "Reviewers" || list[0]["seq"] != float64(1) || list[0]["members"] != float64(3) || list[0]["role"] != "manager" {
		t.Errorf("group list --json = %v", list)
	}
	text, err := runQuiet(t, runGroup, "list")
	if err != nil || !strings.Contains(text, "Reviewers") || !strings.Contains(text, g.ID) || !strings.Contains(text, "manager") {
		t.Errorf("group list printed %q, %v", text, err)
	}

	// show, as json and text.
	shown := runJSON[groupOut](t, runGroup, "show", "Reviewers", "--json")
	if shown.ID != g.ID || len(shown.Members) != 3 || shown.Role != "manager" {
		t.Errorf("group show --json = %+v", shown)
	}
	text, err = runQuiet(t, runGroup, "show", g.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Reviewers (" + g.ID + "), record 1", "manager", "bob@example.com", "unverified", showFP(rows["bob@example.com"].FP)} {
		if !strings.Contains(text, want) {
			t.Errorf("group show printed %q, want %q", text, want)
		}
	}

	// add: a manager, then the same again, then dan as a member.
	add := runJSON[map[string]any](t, runGroup, "add", "Reviewers", "bob@example.com", "--manager", "--json")
	if add["group"] != g.ID || add["email"] != "bob@example.com" || add["role"] != "manager" || add["unchanged"] != false ||
		add["prior"] != e2e.PinUnverified || add["user"] != rows["bob@example.com"].User || add["fp"] != rows["bob@example.com"].FP {
		t.Errorf("group add --json = %v", add)
	}
	same := runJSON[map[string]any](t, runGroup, "add", g.ID, "bob@example.com", "--manager", "--json")
	if same["unchanged"] != true {
		t.Errorf("group add again --json = %v, want unchanged", same)
	}
	out, err := runQuiet(t, runGroup, "add", "Reviewers", "dan@example.com")
	if err != nil || !strings.Contains(out, "dan@example.com is now a member of Reviewers") || !strings.Contains(out, "cairn pin dan@example.com --verified") {
		t.Errorf("group add printed %q, %v", out, err)
	}

	// bob, a manager now, renames it; a member could not.
	w.as(t, "bob")
	ren := runJSON[map[string]any](t, runGroup, "rename", "Reviewers", "Release reviewers", "--json")
	if ren["group"] != g.ID || ren["name"] != "Release reviewers" {
		t.Errorf("group rename --json = %v", ren)
	}
	w.as(t, "cat")
	if _, err := runQuiet(t, runGroup, "rename", "Release reviewers", "Mine"); !errors.Is(err, client.ErrNotGroupManager) {
		t.Errorf("a member renaming: %v, want ErrNotGroupManager", err)
	}
	if _, err := runQuiet(t, runGroup, "delete", "Release reviewers"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("a member deleting: %v, want a 403", err)
	}

	// remove, as ada.
	w.as(t, "ada")
	rm := runJSON[map[string]any](t, runGroup, "remove", "Release reviewers", "dan@example.com", "--json")
	if rm["group"] != g.ID || rm["removed"] != true || rm["user"] == "" {
		t.Errorf("group remove --json = %v", rm)
	}
	shown = runJSON[groupOut](t, runGroup, "show", g.ID, "--json")
	if shown.Name != "Release reviewers" || shown.Seq != 5 || len(shown.Members) != 3 {
		t.Errorf("group show --json after the changes = %+v", shown)
	}

	// delete.
	del := runJSON[map[string]any](t, runGroup, "delete", g.ID, "--json")
	if del["group"] != g.ID || del["deleted"] != true {
		t.Errorf("group delete --json = %v", del)
	}
	if _, err := runQuiet(t, runGroup, "show", g.ID); !errors.Is(err, client.ErrNoGroup) {
		t.Errorf("show after delete: %v, want ErrNoGroup", err)
	}
	if out, err := runQuiet(t, runGroup, "list"); err != nil || !strings.Contains(out, "no groups") {
		t.Errorf("group list after delete printed %q, %v", out, err)
	}
	if list := runJSON[[]map[string]any](t, runGroup, "list", "--json"); list == nil || len(list) != 0 {
		t.Errorf("group list --json after delete = %#v, want []", list)
	}
}

func TestGroupCommandUsageAndErrors(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")
	if err := runGroup(nil); err == nil || !strings.Contains(err.Error(), "cairn group create NAME") {
		t.Errorf("group with no subcommand: %v", err)
	}
	if err := runGroup([]string{"bogus"}); err == nil || !strings.Contains(err.Error(), `unknown group subcommand "bogus"`) {
		t.Errorf("group bogus: %v", err)
	}
	for sub, want := range map[string]string{
		"create": "usage: cairn group create NAME", "show": "usage: cairn group show GROUP", "add": "usage: cairn group add GROUP USER",
		"remove": "usage: cairn group remove GROUP USER", "rename": "usage: cairn group rename GROUP NAME", "delete": "usage: cairn group delete GROUP",
	} {
		if _, err := runQuiet(t, runGroup, sub); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("group %s with no arguments: %v, want %q", sub, err, want)
		}
	}
	if _, err := runQuiet(t, runGroup, "show", "nothing"); !errors.Is(err, client.ErrNoGroup) {
		t.Errorf("show of an unknown group: %v, want ErrNoGroup", err)
	}
	if _, err := runQuiet(t, runGroup, "create", ""); err == nil {
		t.Error("group create with an empty name succeeded")
	}
	if _, err := runQuiet(t, runGroup, "create", "Reviewers", "--member", "nobody@example.com"); !errors.Is(err, client.ErrUnknownUser) {
		t.Errorf("create with an unknown member: %v, want ErrUnknownUser", err)
	}

	// A name two groups share is refused as ambiguous, and an ID works.
	one := runJSON[groupOut](t, runGroup, "create", "Same", "--json")
	w.as(t, "bob")
	runJSON[groupOut](t, runGroup, "create", "Same", "--json")
	if _, err := runQuiet(t, runGroup, "show", "Same"); !errors.Is(err, client.ErrAmbiguousGroup) {
		t.Errorf("show of an ambiguous name: %v, want ErrAmbiguousGroup", err)
	}
	if got := runJSON[groupOut](t, runGroup, "show", one.ID, "--json"); got.ID != one.ID || got.Role != "" {
		t.Errorf("show by id as a stranger = %+v, want no role", got)
	}
}

func TestGroupAddRefusesAChangedKeyUntilAccepted(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")
	g := runJSON[groupOut](t, runGroup, "create", "Reviewers", "--member", "bob@example.com", "--json")
	// ada pinned bob on creating the group. Her pin is replaced by one for
	// other keys, as if bob's keys had changed since.
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var bobID string
	for _, m := range g.Members {
		if m.Email == "bob@example.com" {
			bobID = m.User
		}
	}
	if _, err := c.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Pins[bobID] = e2e.Pin{FP: strings.Repeat("a", 64), State: e2e.PinVerified}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err = runQuiet(t, runGroup, "add", "Reviewers", "bob@example.com", "--manager")
	var changed *client.KeyChangedError
	if !errors.As(err, &changed) || !strings.Contains(err.Error(), "--accept-new-key") {
		t.Fatalf("group add with a changed key: %v, want KeyChangedError naming --accept-new-key", err)
	}
	add := runJSON[map[string]any](t, runGroup, "add", "Reviewers", "bob@example.com", "--manager", "--accept-new-key", "--json")
	if add["prior"] != e2e.PinChanged || add["role"] != "manager" {
		t.Errorf("group add --accept-new-key --json = %v", add)
	}
}
