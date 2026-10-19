package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
)

// managerWorld is a server with ada, who owns an artifact, bob, whom she made
// a manager through the CLI, and cat and dan, each with a CLI config of
// their own.
func managerWorld(t *testing.T) *teamWorld {
	t.Helper()
	host, m := newTestServer(t)
	w := &teamWorld{m: m, host: host, configs: map[string]string{}}
	for _, who := range []string{"ada", "bob", "cat", "dan"} {
		signupVerify(t, host, m, who+"@example.com", sharePassword)
		w.configs[who] = filepath.Join(t.TempDir(), who+".json")
		w.as(t, who)
		cliLogin(t, host, who+"@example.com", sharePassword)
	}
	w.as(t, "ada")
	a := runJSON[map[string]any](t, artifactCreate, "shared", "--json")
	w.artifact = a["id"].(string)
	out, err := runQuiet(t, runShare, w.artifact, "bob@example.com", "--role", "manager")
	if err != nil || !strings.Contains(out, "added as manager of shared") {
		t.Fatalf("cairn share --role manager: %q, %v", out, err)
	}
	return w
}

type membersOut struct {
	Seq      int `json:"seq"`
	Epoch    int `json:"epoch"`
	Members  []memberRow
	SignedBy *struct {
		User  string `json:"user"`
		Email string `json:"email"`
	} `json:"signedBy"`
}

func membersJSON(t *testing.T, artifact string) membersOut {
	t.Helper()
	return runJSON[membersOut](t, runMembers, artifact, "--json")
}

func TestMembersShowsAManagerAndWhoSignedTheRecord(t *testing.T) {
	w := managerWorld(t)
	got := membersJSON(t, w.artifact)
	if got.SignedBy != nil {
		t.Errorf("signedBy = %+v after the owner's record, want none", got.SignedBy)
	}
	rows := map[string]memberRow{}
	for _, r := range got.Members {
		rows[r.Email] = r
	}
	if rows["bob@example.com"].Role != "manager" || rows["ada@example.com"].Role != "owner" {
		t.Errorf("rows = %+v, want bob manager and ada owner", rows)
	}
	text, err := runQuiet(t, runMembers, w.artifact)
	if err != nil || !strings.Contains(text, "manager  bob@example.com") || strings.Contains(text, "signed by") {
		t.Errorf("cairn members printed %q, %v", text, err)
	}

	// bob signs the next record, and the owner's members shows it.
	w.as(t, "bob")
	if _, err := runQuiet(t, runShare, w.artifact, "cat@example.com"); err != nil {
		t.Fatalf("manager's cairn share: %v", err)
	}
	for _, who := range []string{"bob", "ada", "cat"} {
		w.as(t, who)
		got := membersJSON(t, w.artifact)
		bobRow := ""
		for _, r := range got.Members {
			if r.Email == "bob@example.com" {
				bobRow = r.User
			}
		}
		if got.SignedBy == nil || got.SignedBy.Email != "bob@example.com" || got.SignedBy.User != bobRow {
			t.Errorf("as %s: signedBy = %+v, want bob (%s)", who, got.SignedBy, bobRow)
		}
		text, err := runQuiet(t, runMembers, w.artifact)
		if err != nil || !strings.Contains(text, "was signed by manager bob@example.com") {
			t.Errorf("as %s: cairn members printed %q, %v", who, text, err)
		}
	}
	// The owner's record after it names no signer.
	w.as(t, "ada")
	if _, err := runQuiet(t, runShare, w.artifact, "dan@example.com"); err != nil {
		t.Fatal(err)
	}
	if got := membersJSON(t, w.artifact); got.SignedBy != nil {
		t.Errorf("signedBy = %+v after the owner's record, want none", got.SignedBy)
	}
}

func TestManagerRunsTheMemberCommands(t *testing.T) {
	w := managerWorld(t)
	w.as(t, "bob")
	for _, args := range [][]string{
		{"share", w.artifact, "cat@example.com", "--role", "editor"},
		{"share", w.artifact, "dan@example.com"},
		{"team", w.artifact, "viewer"},
		{"public", w.artifact, "on"},
		{"public", w.artifact, "off"},
		{"unshare", w.artifact, "dan@example.com"},
		{"team", w.artifact, "none"},
	} {
		run := map[string]func([]string) error{"share": runShare, "team": runTeam, "public": runPublic, "unshare": runUnshare}[args[0]]
		if out, err := runQuiet(t, run, args[1:]...); err != nil {
			t.Fatalf("as a manager, cairn %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	// The owner reads what a manager's epochs wrote.
	w.as(t, "ada")
	got := membersJSON(t, w.artifact)
	if got.Epoch < 2 {
		t.Errorf("epoch = %d, want a manager's new epoch", got.Epoch)
	}
	if _, err := runQuiet(t, runShare, w.artifact, "dan@example.com"); err != nil {
		t.Errorf("the owner shares after a manager's epochs: %v", err)
	}
}

// A change that left an epoch unreadable says so, in text and in JSON.
func TestEpochChangeReportsAnUnreadableEpoch(t *testing.T) {
	ch := client.EpochChange{NewEpoch: true, Unreadable: []int{2}}
	// The review hint at the end needs a server, and a failed lookup there is
	// not an error, so a client with none will do.
	c := client.New("http://127.0.0.1:1", "")
	out, _ := runQuiet(t, func([]string) error { printEpochChange(c, "art", 3, ch); return nil })
	if !strings.Contains(out, "warning: epoch 2 is unreadable to you") {
		t.Errorf("printEpochChange printed %q, want a warning naming epoch 2", out)
	}
	got := map[string]any{}
	epochChangeJSON(got, ch)
	if u, _ := got["unreadableEpochs"].([]int); len(u) != 1 || u[0] != 2 {
		t.Errorf("unreadableEpochs = %v, want [2]", got["unreadableEpochs"])
	}
}

// A rotation that left an epoch out says so.
func TestRotationReportsAnUnreadableEpoch(t *testing.T) {
	res := &client.RotateResult{Seq: 1, Epochs: map[string]int{"art": 2}, Unreadable: map[string][]int{"art": {2}}}
	out, _ := runQuiet(t, func([]string) error { printRotation(res, true, true); return nil })
	if !strings.Contains(out, "artifact art: epoch 2") || !strings.Contains(out, "warning: epoch 2 is unreadable to you") {
		t.Errorf("printRotation printed %q, want a warning naming epoch 2 under the artifact", out)
	}
}

func TestOwnerOnlyActionsAreRefusedForAManager(t *testing.T) {
	w := managerWorld(t)
	w.as(t, "bob")
	seq := membersJSON(t, w.artifact).Seq

	_, err := runQuiet(t, runShare, w.artifact, "dan@example.com", "--role", "manager")
	if !errors.Is(err, client.ErrManagerOwnerOnly) || !strings.Contains(err.Error(), "only the artifact's owner can add or change a manager") {
		t.Errorf("share --role manager as a manager: %v", err)
	}
	if _, err := runQuiet(t, runUnshare, w.artifact, "bob@example.com"); !errors.Is(err, client.ErrManagerOwnerOnly) {
		t.Errorf("a manager unshares himself: %v", err)
	}
	if _, err := runQuiet(t, runTransfer, w.artifact, "cat@example.com"); !errors.Is(err, client.ErrTransferNotOwner) {
		t.Errorf("a manager offers ownership: %v", err)
	}
	if _, err := runQuiet(t, artifactDelete, w.artifact); !errors.Is(err, client.ErrDeleteNotOwner) {
		t.Errorf("a manager deletes: %v", err)
	}
	if got := membersJSON(t, w.artifact).Seq; got != seq {
		t.Errorf("record %d after the refusals, was %d", got, seq)
	}
	// The artifact is still there, for the owner.
	w.as(t, "ada")
	if _, err := runQuiet(t, runMembers, w.artifact); err != nil {
		t.Errorf("the owner reads it after the refused delete: %v", err)
	}
}
