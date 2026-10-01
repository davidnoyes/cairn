package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

func TestPublicCommand(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")

	out, err := runQuiet(t, runPublic, w.artifact, "on")
	if err != nil {
		t.Fatalf("cairn public on: %v", err)
	}
	var link string
	for _, line := range strings.Fields(out) {
		if strings.Contains(line, "/shared/") {
			link = line
		}
	}
	if _, perr := e2e.ParseLink(link); perr != nil {
		t.Fatalf("cairn public on printed no link: %q (%v)", out, perr)
	}
	for _, want := range []string{"Anyone who holds this link can read the artifact", "part after the #", "writes are off"} {
		if !strings.Contains(out, want) {
			t.Errorf("cairn public on printed %q, want it to say %q", out, want)
		}
	}
	if opened, err := client.OpenLink(link); err != nil || !opened.Chain.Latest.Public {
		t.Errorf("OpenLink(%q) = %v", link, err)
	}

	again, err := runQuiet(t, runPublic, w.artifact, "on")
	if err != nil || !strings.Contains(again, "already public; nothing changed") || !strings.Contains(again, link) {
		t.Errorf("cairn public on again printed %q, %v", again, err)
	}

	on, err := runQuiet(t, runPublic, w.artifact, "on", "--writes", "on")
	if err != nil || !strings.Contains(on, link) || !strings.Contains(on, "writes are on") {
		t.Errorf("cairn public on --writes on printed %q, %v", on, err)
	}
	res := runJSON[map[string]any](t, runPublic, w.artifact, "on", "--writes", "off", "--json")
	if res["artifact"] != w.artifact || res["public"] != true || res["publicWrites"] != false || res["epoch"] != float64(1) ||
		res["link"] != link || res["unchanged"] != false || len(res) != 6 {
		t.Errorf("cairn public --json = %v", res)
	}
	res = runJSON[map[string]any](t, runPublic, w.artifact, "on", "--json")
	if res["unchanged"] != true || res["publicWrites"] != false {
		t.Errorf("cairn public on --json again = %v", res)
	}
}

func TestPublicOffCommand(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")

	out, err := runQuiet(t, runPublic, w.artifact, "off")
	if err != nil || !strings.Contains(out, "already private; nothing changed") {
		t.Errorf("cairn public off on a private artifact printed %q, %v", out, err)
	}
	res := runJSON[map[string]any](t, runPublic, w.artifact, "off", "--json")
	if res["public"] != false || res["link"] != "" || res["unchanged"] != true {
		t.Errorf("cairn public off --json = %v", res)
	}
	if _, err := runQuiet(t, runPublic, w.artifact, "on"); err != nil {
		t.Fatal(err)
	}
	_, err = runQuiet(t, runPublic, w.artifact, "off")
	if !errors.Is(err, client.ErrPublicOffNeedsNextEpoch) || !strings.Contains(err.Error(), "new epoch") {
		t.Errorf("cairn public off on a public artifact = %v, want ErrPublicOffNeedsNextEpoch", err)
	}
}

func TestPublicCommandRefusals(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")
	const usage = "usage: cairn public ARTIFACT on|off [--writes on|off] [--json]"
	if _, err := runQuiet(t, runPublic, w.artifact); err == nil || !strings.Contains(err.Error(), usage) {
		t.Errorf("public with no value: %v", err)
	}
	// A typo is refused before any request, so a missing artifact is not
	// looked up.
	for _, args := range [][]string{
		{"no-such-artifact", "maybe"},
		{"no-such-artifact", "on", "--writes", "maybe"},
	} {
		if _, err := runQuiet(t, runPublic, args...); err == nil || !strings.Contains(err.Error(), "on or off") {
			t.Errorf("public %v: %v, want the on or off message", args, err)
		}
	}
	if _, err := runQuiet(t, runPublic, "no-such-artifact", "off", "--writes", "on"); !errors.Is(err, client.ErrPublicWritesWithOff) {
		t.Errorf("public off --writes on: %v, want ErrPublicWritesWithOff", err)
	}
	w.as(t, "bob")
	if _, err := runQuiet(t, runPublic, w.artifact, "on"); !errors.Is(err, client.ErrNotOwner) {
		t.Errorf("public by an editor: %v, want ErrNotOwner", err)
	}
}
