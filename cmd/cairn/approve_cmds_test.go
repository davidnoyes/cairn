package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
)

// teamWorld is a server with ada (who owns an artifact), bob, cat, and dan,
// each with a CLI config of their own, so a test switches who runs a command.
type teamWorld struct {
	m        *mail.Capture
	host     string
	artifact string
	configs  map[string]string
}

// newTeamWorld signs everyone up, and has ada create an artifact, make bob
// an editor, and share it with the team as viewers.
func newTeamWorld(t *testing.T) *teamWorld {
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
	if _, err := runQuiet(t, runShare, w.artifact, "bob@example.com", "--role", "editor"); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runTeam, w.artifact, "viewer"); err != nil {
		t.Fatalf("cairn team viewer: %v", err)
	}
	return w
}

// as makes who the user the next commands run as.
func (w *teamWorld) as(t *testing.T, who string) {
	t.Helper()
	t.Setenv("CAIRN_CONFIG", w.configs[who])
}

type pendingRow struct {
	User, Name, Email, FP, State string
}

func (w *teamWorld) pending(t *testing.T) map[string]pendingRow {
	t.Helper()
	out := runJSON[struct {
		Artifact string       `json:"artifact"`
		Pending  []pendingRow `json:"pending"`
	}](t, runApprove, w.artifact, "--json")
	if out.Artifact != w.artifact {
		t.Errorf("approve --json artifact = %q, want %q", out.Artifact, w.artifact)
	}
	rows := map[string]pendingRow{}
	for _, r := range out.Pending {
		rows[r.Email] = r
	}
	return rows
}

func TestTeamCommand(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")

	out, err := runQuiet(t, runTeam, w.artifact, "editor")
	if err != nil || !strings.Contains(out, "team set to editor for shared") {
		t.Errorf("cairn team editor printed %q, %v", out, err)
	}
	again, err := runQuiet(t, runTeam, w.artifact, "editor")
	if err != nil || !strings.Contains(again, "already editor; nothing changed") {
		t.Errorf("cairn team editor again printed %q, %v", again, err)
	}
	res := runJSON[map[string]any](t, runTeam, w.artifact, "viewer", "--json")
	if res["artifact"] != w.artifact || res["team"] != "viewer" || res["epoch"] != float64(1) || res["unchanged"] != false ||
		len(res["listed"].([]any)) != 0 || len(res["unlisted"].([]any)) != 0 {
		t.Errorf("cairn team --json = %v", res)
	}
	if res := runJSON[map[string]any](t, runTeam, w.artifact, "none", "--json"); res["team"] != "none" {
		t.Errorf("cairn team none --json = %v", res)
	}
}

func TestTeamCommandRefusals(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")
	if _, err := runQuiet(t, runTeam, w.artifact); err == nil || !strings.Contains(err.Error(), "usage: cairn team ARTIFACT none|viewer|editor") {
		t.Errorf("team with no value: %v", err)
	}
	if _, err := runQuiet(t, runTeam, w.artifact, "everyone"); err == nil || !strings.Contains(err.Error(), "none, viewer, or editor") {
		t.Errorf("team everyone: %v", err)
	}
	w.as(t, "bob")
	if _, err := runQuiet(t, runTeam, w.artifact, "none"); !errors.Is(err, client.ErrNotOwner) {
		t.Errorf("team by an editor: %v, want ErrNotOwner", err)
	}
}

func TestTeamNoneNeedsANewEpochWhileAMemberHoldsAWrap(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "bob")
	if _, err := runQuiet(t, runApprove, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "ada")
	_, err := runQuiet(t, runTeam, w.artifact, "none")
	if !errors.Is(err, client.ErrTeamNeedsNextEpoch) || !strings.Contains(err.Error(), "new epoch") {
		t.Errorf("team none with cat holding a wrap: %v, want ErrTeamNeedsNextEpoch naming a new epoch", err)
	}
	if got := runJSON[map[string]any](t, runTeam, w.artifact, "viewer", "--json"); got["team"] != "viewer" {
		t.Errorf("a refused change must leave the team as it was: %v", got)
	}
}

func TestApproveCommandListsAndApproves(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "bob")

	rows := w.pending(t)
	if len(rows) != 2 || rows["cat@example.com"].State != "new" || rows["dan@example.com"].State != "new" {
		t.Fatalf("pending = %+v, want cat and dan, new", rows)
	}
	cat := rows["cat@example.com"]
	if cat.Name != "Ada" || cat.User == "" || len(cat.FP) != 64 {
		t.Errorf("cat's row = %+v, want a name, an id, and a hex fingerprint", cat)
	}
	text, err := runQuiet(t, runApprove, w.artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"new", "cat@example.com", showFP(cat.FP), "cairn approve " + w.artifact + " USER"} {
		if !strings.Contains(text, want) {
			t.Errorf("cairn approve printed %q, want %q", text, want)
		}
	}

	out, err := runQuiet(t, runApprove, w.artifact, "cat@example.com")
	if err != nil {
		t.Fatalf("cairn approve cat: %v", err)
	}
	for _, want := range []string{"cat@example.com", showFP(cat.FP), "new; pinned unverified", "approved for shared", "cairn pin cat@example.com --verified"} {
		if !strings.Contains(out, want) {
			t.Errorf("cairn approve printed %q, want %q", out, want)
		}
	}
	// The editor no longer sees cat; the owner sees them as approved.
	if rows := w.pending(t); len(rows) != 1 || rows["dan@example.com"].State != "new" {
		t.Errorf("bob's pending after approving = %+v, want only dan", rows)
	}
	w.as(t, "ada")
	if rows := w.pending(t); rows["cat@example.com"].State != "approved" || rows["dan@example.com"].State != "new" {
		t.Errorf("ada's pending = %+v, want cat approved and dan new", rows)
	}
	if text, _ := runQuiet(t, runApprove, w.artifact); !strings.Contains(text, "approved") {
		t.Errorf("cairn approve as the owner printed %q, want cat as approved", text)
	}

	w.as(t, "bob")
	res := runJSON[map[string]any](t, runApprove, w.artifact, "dan@example.com", "--json")
	if res["artifact"] != w.artifact || res["email"] != "dan@example.com" || res["prior"] != e2e.PinNew ||
		res["epoch"] != float64(1) || res["approved"] != true || len(res["fp"].(string)) != 64 || res["user"] == "" {
		t.Errorf("cairn approve --json = %v", res)
	}
}

func TestApproveCommandWithNoTeamWaiting(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")
	if _, err := runQuiet(t, runTeam, w.artifact, "none"); err != nil {
		t.Fatal(err)
	}
	out, err := runQuiet(t, runApprove, w.artifact)
	if err != nil || !strings.Contains(out, "no team members waiting") {
		t.Errorf("cairn approve under team none printed %q, %v", out, err)
	}
	if _, err := runQuiet(t, runApprove, w.artifact, "cat@example.com"); !errors.Is(err, client.ErrNoTeam) {
		t.Errorf("approve under team none: %v, want ErrNoTeam", err)
	}
}

func TestApproveCommandRefusals(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "bob")
	if _, err := runQuiet(t, runApprove); err == nil || !strings.Contains(err.Error(), "usage: cairn approve ARTIFACT [USER]") {
		t.Errorf("approve with no artifact: %v", err)
	}
	if _, err := runQuiet(t, runApprove, w.artifact, "cat@example.com", "extra"); err == nil || !strings.Contains(err.Error(), "usage: cairn approve ARTIFACT [USER]") {
		t.Errorf("approve with too many arguments: %v", err)
	}
	if _, err := runQuiet(t, runApprove, w.artifact, "nobody@example.com"); !errors.Is(err, client.ErrUnknownUser) {
		t.Errorf("approve an unknown user: %v, want ErrUnknownUser", err)
	}
	if _, err := runQuiet(t, runApprove, w.artifact, "ada@example.com"); !errors.Is(err, client.ErrAlreadyListed) {
		t.Errorf("approve the owner: %v, want ErrAlreadyListed", err)
	}
	// A team member's client never wraps.
	if _, err := runQuiet(t, runApprove, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "cat")
	if _, err := runQuiet(t, runApprove, w.artifact, "dan@example.com"); !errors.Is(err, client.ErrNotApprover) {
		t.Errorf("approve by a team member: %v, want ErrNotApprover", err)
	}
	var refused *client.APIError
	if _, err := runQuiet(t, runApprove, w.artifact); !errors.As(err, &refused) || refused.Status != http.StatusForbidden {
		t.Errorf("listing pending as a team member: %v, want the server's 403", err)
	}
}

func TestApproveCommandChangedKey(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "bob")
	pinned := runJSON[map[string]string](t, runPin, "cat@example.com", "--verified", "--json")["fp"]
	// Cat resets without the recovery code, so their keys change.
	if err := client.New(w.host, "").Forgot("cat@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.New(w.host, "").ResetNew(verifyLink(t, w.m, "cat@example.com"), "a brand new password"); err != nil {
		t.Fatal(err)
	}
	_, err := runQuiet(t, runApprove, w.artifact, "cat@example.com")
	var changed *client.KeyChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("approve a changed key: %v, want a KeyChangedError", err)
	}
	for _, want := range []string{showFP(pinned), showFP(changed.CurrentFP), "reset at", "--accept-new-key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err, want)
		}
	}
	if rows := w.pending(t); rows["cat@example.com"].State != "new" {
		t.Errorf("cat after the refusal = %+v, want still new: nothing was wrapped", rows["cat@example.com"])
	}
	res := runJSON[map[string]any](t, runApprove, w.artifact, "cat@example.com", "--accept-new-key", "--json")
	if res["prior"] != e2e.PinChanged || res["fp"] != changed.CurrentFP {
		t.Errorf("approve --accept-new-key = %v", res)
	}
}

// putNextEpoch has ada's CLI login write the next epoch's record by hand,
// after edit: the CLI has no command to remove a member yet.
func putNextEpoch(t *testing.T, w *teamWorld, edit func(next *e2e.MembershipBody)) {
	t.Helper()
	w.as(t, "ada")
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	va, err := c.VerifyArtifact(k, w.artifact, k.FP)
	if err != nil {
		t.Fatal(err)
	}
	ak := bytes.Repeat([]byte{9}, 32)
	next := va.Chain.Latest
	next.Epoch, next.Seq, next.Prev = next.Epoch+1, next.Seq+1, va.Chain.Head
	next.AKCommit, _ = e2e.AKCommit(ak, w.artifact, uint64(next.Epoch))
	edit(&next)
	body, _ := json.Marshal(next)
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "membership", body)
	if err != nil {
		t.Fatal(err)
	}
	ekKey, _ := e2e.EKSealKey(k.EK)
	sealed, err := e2e.Seal(bytes.NewReader(bytes.Repeat([]byte{3}, 64)), ekKey,
		[][]byte{[]byte("estate"), []byte(w.artifact), []byte("2")}, ak)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(map[string]any{
		"membership": env, "wraps": []any{}, "linkTokenHash": "",
		"estate": []map[string]any{{"epoch": next.Epoch, "sealed": e2e.B64(sealed)}},
	})
	r, err := http.NewRequest("PUT", w.host+"/api/artifacts/"+w.artifact+"/membership", bytes.NewReader(req))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer cairn_"+c.Key.KeyID+"_"+c.Key.AuthSecret)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("writing the next epoch: %d", resp.StatusCode)
	}
}

func TestApproveCommandRefusesAnExcludedUser(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")
	dir := runJSON[struct {
		Members []memberRow `json:"members"`
	}](t, runMembers, w.artifact, "--json")
	var bob memberRow
	for _, r := range dir.Members {
		if r.Email == "bob@example.com" {
			bob = r
		}
	}
	putNextEpoch(t, w, func(next *e2e.MembershipBody) {
		next.Members = []e2e.Member{}
		next.Excluded = []e2e.ExcludedEntry{{User: bob.User, FP: bob.FP, Email: bob.Email}}
	})
	_, err := runQuiet(t, runApprove, w.artifact, "bob@example.com")
	if !errors.Is(err, client.ErrExcluded) || !strings.Contains(err.Error(), "bob@example.com") {
		t.Errorf("approve an excluded user: %v, want ErrExcluded naming bob", err)
	}
}

// The owner's next record lists an approved team member, and share and team
// both say so.
func TestShareAndTeamReportTheApprovedMembersTheyList(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "bob")
	if _, err := runQuiet(t, runApprove, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "ada")
	out, err := runQuiet(t, runShare, w.artifact, "dan@example.com")
	if err != nil || !strings.Contains(out, "listed approved team member cat@example.com") {
		t.Errorf("cairn share printed %q, %v, want cat listed", out, err)
	}
	if rows := membersByEmail(t, w.artifact); rows["cat@example.com"].Role != "viewer" || rows["dan@example.com"].Role != "viewer" {
		t.Errorf("members = %+v, want cat and dan as viewers", rows)
	}
	// Listed, cat is no longer waiting, and team says nothing more about them.
	if rows := w.pending(t); len(rows) != 0 {
		t.Errorf("pending after listing = %+v, want none", rows)
	}
	res := runJSON[map[string]any](t, runTeam, w.artifact, "editor", "--json")
	if res["unchanged"] != false || len(res["listed"].([]any)) != 0 || len(res["unlisted"].([]any)) != 0 {
		t.Errorf("cairn team editor --json = %v, want a change that lists nobody new", res)
	}
}
