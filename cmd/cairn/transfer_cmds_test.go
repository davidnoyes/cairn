package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
)

// xferWorld is a server with ada, who owns an artifact, bob and cat as
// editors, dan as a viewer, and an administrator, each with a CLI config of
// their own. Each member has opened the artifact once, so each has the owner
// pinned.
type xferWorld struct {
	m        *mail.Capture
	host     string
	artifact string
	configs  map[string]string
}

func newXferWorld(t *testing.T) *xferWorld {
	t.Helper()
	host, m := newTestServer(t)
	w := &xferWorld{m: m, host: host, configs: map[string]string{}}
	for _, who := range []string{"ada", "bob", "cat", "dan", "admin"} {
		signupVerify(t, host, m, who+"@example.com", sharePassword)
		w.configs[who] = filepath.Join(t.TempDir(), who+".json")
		w.as(t, who)
		cliLogin(t, host, who+"@example.com", sharePassword)
	}
	w.as(t, "ada")
	w.artifact = runJSON[map[string]any](t, artifactCreate, "shared", "--json")["id"].(string)
	for _, s := range [][2]string{{"bob", "editor"}, {"cat", "editor"}, {"dan", "viewer"}} {
		if _, err := runQuiet(t, runShare, w.artifact, s[0]+"@example.com", "--role", s[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, who := range []string{"bob", "cat", "dan"} {
		w.as(t, who)
		if _, err := runQuiet(t, runMembers, w.artifact); err != nil {
			t.Fatal(err)
		}
	}
	w.as(t, "ada")
	return w
}

func (w *xferWorld) as(t *testing.T, who string) {
	t.Helper()
	t.Setenv("CAIRN_CONFIG", w.configs[who])
}

// adminDo sends an administrator's request.
func (w *xferWorld) adminDo(t *testing.T, method, path string, body any) {
	t.Helper()
	w.as(t, "admin")
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(method, w.host+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	key, err := e2e.ParseAPIKey(loadConfig().APIKey)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearerOf(key))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s: %d", method, path, resp.StatusCode)
	}
}

// handOver deactivates ada and has the administrator offer the artifact to
// who, who accepts it.
func (w *xferWorld) handOver(t *testing.T, who string) {
	t.Helper()
	w.as(t, "ada")
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	me, err := c.Me()
	if err != nil {
		t.Fatal(err)
	}
	w.as(t, who)
	c, err = apiClient()
	if err != nil {
		t.Fatal(err)
	}
	them, err := c.Me()
	if err != nil {
		t.Fatal(err)
	}
	w.adminDo(t, "PATCH", "/api/admin/users/"+me.ID, map[string]any{"disabled": true})
	w.adminDo(t, "POST", "/api/admin/artifacts/"+w.artifact+"/transfer", map[string]any{"to": them.ID})
	w.as(t, who)
	got := runJSON[map[string]any](t, runTransfer, "accept", w.artifact, "--drop-previous-owner", "--json")
	if got["byAdministrator"] != true {
		t.Errorf("cairn transfer accept --json after an administrator's offer: %v", got)
	}
	// The person who accepted needs no notice: it is acknowledged already.
	if h, ok := got["handover"].(map[string]any); !ok || h["acked"] != true {
		t.Errorf("the accepting user's handover = %v, want acknowledged", got["handover"])
	}
}

func TestTransferOfferAndAcceptCommands(t *testing.T) {
	w := newXferWorld(t)
	out, err := runQuiet(t, runTransfer, w.artifact, "bob@example.com")
	if err != nil {
		t.Fatalf("cairn transfer: %v", err)
	}
	for _, want := range []string{"bob@example.com", "offered ownership of shared to bob@example.com", "cairn transfer accept " + w.artifact} {
		if !strings.Contains(out, want) {
			t.Errorf("cairn transfer printed %q, want %q", out, want)
		}
	}

	w.as(t, "bob")
	out, err = runQuiet(t, runTransfer, "accept", w.artifact)
	if err != nil {
		t.Fatalf("cairn transfer accept: %v", err)
	}
	for _, want := range []string{"you own shared now, at epoch 1", "ada@example.com stays as an editor"} {
		if !strings.Contains(out, want) {
			t.Errorf("cairn transfer accept printed %q, want %q", out, want)
		}
	}
	rows := membersByEmail(t, w.artifact)
	if r := rows["bob@example.com"]; r.Role != "owner" || r.State != "self" {
		t.Errorf("bob's row: %+v", r)
	}
	if r := rows["ada@example.com"]; r.Role != "editor" {
		t.Errorf("ada's row: %+v", r)
	}
}

func TestTransferJSONOutput(t *testing.T) {
	w := newXferWorld(t)
	offered := runJSON[map[string]any](t, runTransfer, w.artifact, "bob@example.com", "--json")
	if offered["artifact"] != w.artifact || offered["email"] != "bob@example.com" || offered["replaced"] != false || offered["prior"] == "" || offered["fp"] == "" {
		t.Errorf("offer --json = %v", offered)
	}
	if _, present := offered["handover"]; present {
		t.Errorf("an artifact with no handover has a handover key: %v", offered)
	}
	again := runJSON[map[string]any](t, runTransfer, w.artifact, "cat@example.com", "--json")
	if again["replaced"] != true {
		t.Errorf("a second offer --json = %v, want replaced", again)
	}

	w.as(t, "bob")
	if _, err := runQuiet(t, runTransfer, "accept", w.artifact); !errors.Is(err, client.ErrNoOfferToYou) {
		t.Errorf("bob accepted an offer that was closed: %v", err)
	}
}

func TestTransferAnswersJSON(t *testing.T) {
	w := newXferWorld(t)
	runJSON[map[string]any](t, runTransfer, w.artifact, "bob@example.com", "--json")
	w.as(t, "bob")
	if got := runJSON[map[string]any](t, runTransfer, "decline", w.artifact, "--json"); got["artifact"] != w.artifact || got["declined"] != true {
		t.Errorf("decline --json = %v", got)
	}
	w.as(t, "ada")
	runJSON[map[string]any](t, runTransfer, w.artifact, "bob@example.com", "--json")
	if got := runJSON[map[string]any](t, runTransfer, "withdraw", w.artifact, "--json"); got["artifact"] != w.artifact || got["withdrawn"] != true {
		t.Errorf("withdraw --json = %v", got)
	}
	runJSON[map[string]any](t, runTransfer, w.artifact, "bob@example.com", "--json")
	w.as(t, "bob")
	got := runJSON[map[string]any](t, runTransfer, "accept", w.artifact, "--drop-previous-owner", "--json")
	if got["artifact"] != w.artifact || got["epoch"] != float64(2) || got["keptPreviousOwner"] != false || got["byAdministrator"] != false ||
		got["previousOwnerEmail"] != "ada@example.com" || got["newEpoch"] != true || len(got["excluded"].([]any)) != 1 {
		t.Errorf("accept --json = %v", got)
	}

	// Without the flag the previous owner stays.
	w = newXferWorld(t)
	runJSON[map[string]any](t, runTransfer, w.artifact, "bob@example.com", "--json")
	w.as(t, "bob")
	got = runJSON[map[string]any](t, runTransfer, "--json", "accept", w.artifact)
	if got["epoch"] != float64(1) || got["keptPreviousOwner"] != true || got["newEpoch"] != false {
		t.Errorf("accept --json = %v", got)
	}
}

func TestMembersShowsAnOpenOffer(t *testing.T) {
	w := newXferWorld(t)
	today := time.Now().UTC().Format("2006-01-02")
	line := "ownership offered to bob@example.com on " + today + "; they accept with: cairn transfer accept " + w.artifact
	youLine := "ownership offered to you on " + today + "; accept with: cairn transfer accept " + w.artifact

	// No offer, no line and no key.
	if out, err := runQuiet(t, runMembers, w.artifact); err != nil || strings.Contains(out, "ownership offered") {
		t.Errorf("members with no offer: %q, %v", out, err)
	}
	if got := runJSON[map[string]any](t, runMembers, w.artifact, "--json"); got["transfer"] != nil {
		t.Errorf("members --json with no offer: %v", got["transfer"])
	}

	if _, err := runQuiet(t, runTransfer, w.artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	// The owner sees who it was offered to.
	out, err := runQuiet(t, runMembers, w.artifact)
	if err != nil || !strings.Contains(out, line) {
		t.Errorf("the owner's members: %q, %v, want %q", out, err, line)
	}
	got := runJSON[map[string]any](t, runMembers, w.artifact, "--json")
	tr, _ := got["transfer"].(map[string]any)
	if tr == nil || tr["email"] != "bob@example.com" || tr["at"] != today || tr["by"] != "owner" || tr["to"] == "" {
		t.Errorf("the owner's members --json transfer = %v", got["transfer"])
	}

	// The offered user sees it as an offer to them.
	w.as(t, "bob")
	out, err = runQuiet(t, runMembers, w.artifact)
	if err != nil || !strings.Contains(out, youLine) {
		t.Errorf("the offered user's members: %q, %v, want %q", out, err, youLine)
	}
	if got := runJSON[map[string]any](t, runMembers, w.artifact, "--json"); got["transfer"] == nil {
		t.Errorf("the offered user's members --json has no transfer")
	}

	// Another member sees nothing of it.
	w.as(t, "cat")
	if out, err := runQuiet(t, runMembers, w.artifact); err != nil || strings.Contains(out, "ownership offered") {
		t.Errorf("another member's members: %q, %v", out, err)
	}
	if got := runJSON[map[string]any](t, runMembers, w.artifact, "--json"); got["transfer"] != nil {
		t.Errorf("another member's members --json: %v", got["transfer"])
	}
}

func TestMembersNamesAnAdministratorsOffer(t *testing.T) {
	w := newXferWorld(t)
	w.as(t, "ada")
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	ada, err := c.Me()
	if err != nil {
		t.Fatal(err)
	}
	w.as(t, "bob")
	c, err = apiClient()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := c.Me()
	if err != nil {
		t.Fatal(err)
	}
	w.adminDo(t, "PATCH", "/api/admin/users/"+ada.ID, map[string]any{"disabled": true})
	w.adminDo(t, "POST", "/api/admin/artifacts/"+w.artifact+"/transfer", map[string]any{"to": bob.ID})
	w.as(t, "bob")
	out, err := runQuiet(t, runMembers, w.artifact)
	if want := "ownership offered to you on " + time.Now().UTC().Format("2006-01-02") + " by an administrator; accept with: cairn transfer accept " + w.artifact; err != nil || !strings.Contains(out, want) {
		t.Errorf("members: %q, %v, want %q", out, err, want)
	}
	// An administrator's offer drops the previous owner without the flag.
	got := runJSON[map[string]any](t, runTransfer, "accept", w.artifact, "--json")
	if got["keptPreviousOwner"] != false || got["byAdministrator"] != true {
		t.Errorf("accept --json = %v", got)
	}
}

func TestDeclineNeedsNoHandoverAcknowledgement(t *testing.T) {
	w := newXferWorld(t)
	w.handOver(t, "bob")
	w.as(t, "bob")
	if _, err := runQuiet(t, runTransfer, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "cat")
	if out, err := runQuiet(t, runTransfer, "decline", w.artifact); err != nil || !strings.Contains(out, "declined the offer") {
		t.Errorf("cairn transfer decline with an unacknowledged handover: %q, %v", out, err)
	}
}

func TestTransferTextOutputOfTheAnswers(t *testing.T) {
	w := newXferWorld(t)
	if _, err := runQuiet(t, runTransfer, w.artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if out, err := runQuiet(t, runTransfer, w.artifact, "cat@example.com"); err != nil || !strings.Contains(out, "closed the earlier offer") {
		t.Errorf("a second offer printed %q, %v", out, err)
	}
	if out, err := runQuiet(t, runTransfer, "withdraw", w.artifact); err != nil || !strings.Contains(out, "withdrew the offer of ownership of shared") {
		t.Errorf("withdraw printed %q, %v", out, err)
	}
	if _, err := runQuiet(t, runTransfer, w.artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "bob")
	if out, err := runQuiet(t, runTransfer, "decline", w.artifact); err != nil || !strings.Contains(out, "declined the offer of ownership of shared") {
		t.Errorf("decline printed %q, %v", out, err)
	}
	w.as(t, "ada")
	if _, err := runQuiet(t, runTransfer, w.artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "bob")
	out, err := runQuiet(t, runTransfer, "accept", w.artifact, "--drop-previous-owner")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"you own shared now, at epoch 2", "started epoch 2", "excluded ada@example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("accept --drop-previous-owner printed %q, want %q", out, want)
		}
	}
	if strings.Contains(out, "stays as an editor") {
		t.Errorf("a dropped previous owner stays: %q", out)
	}
}

func TestTransferUsageAndRefusals(t *testing.T) {
	w := newXferWorld(t)
	for _, args := range [][]string{
		{},
		{w.artifact},
		{"accept"},
		{"decline"},
		{"withdraw"},
		{w.artifact, "bob@example.com", "extra"},
		{"accept", w.artifact, "extra"},
		{"--json"},
	} {
		if _, err := runQuiet(t, runTransfer, args...); err == nil || !strings.Contains(err.Error(), "usage: cairn transfer ARTIFACT USER") {
			t.Errorf("cairn transfer %v: %v, want the usage", args, err)
		}
	}
	// accept with another word than a subcommand is an offer to a user.
	if _, err := runQuiet(t, runTransfer, "accept", "bob@example.com"); err == nil || !strings.Contains(err.Error(), "no artifact") {
		t.Errorf("cairn transfer accept bob@example.com: %v, want an artifact lookup failure", err)
	}
	for _, c := range []struct {
		args []string
		want error
	}{
		{[]string{w.artifact, "dan@example.com"}, client.ErrTransferNotEditor},
		{[]string{w.artifact, "nobody@example.com"}, client.ErrUnknownUser},
		{[]string{"accept", w.artifact}, client.ErrNoOfferToYou},
		{[]string{"decline", w.artifact}, client.ErrNoOfferToYou},
		{[]string{"withdraw", w.artifact}, client.ErrNoOffer},
	} {
		if _, err := runQuiet(t, runTransfer, c.args...); !errors.Is(err, c.want) {
			t.Errorf("cairn transfer %v: %v, want %v", c.args, err, c.want)
		}
	}
	w.as(t, "bob")
	if _, err := runQuiet(t, runTransfer, w.artifact, "cat@example.com"); !errors.Is(err, client.ErrTransferNotOwner) {
		t.Errorf("an editor's cairn transfer: %v, want ErrTransferNotOwner", err)
	}
	if _, err := runQuiet(t, runTransfer, "no-such-artifact", "cat@example.com"); err == nil {
		t.Error("cairn transfer of a missing artifact succeeded")
	}
	if _, err := runQuiet(t, runTransfer, "accept", "no-such-artifact"); err == nil {
		t.Error("cairn transfer accept of a missing artifact succeeded")
	}
}

func TestTransferNeedsALogin(t *testing.T) {
	t.Setenv("CAIRN_HOST", "")
	t.Setenv("CAIRN_API_KEY", "")
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	for _, args := range [][]string{{"x", "bob@example.com"}, {"accept", "x"}, {"decline", "x"}, {"withdraw", "x"}} {
		if _, err := runQuiet(t, runTransfer, args...); err == nil || !strings.Contains(err.Error(), "not logged in") {
			t.Errorf("cairn transfer %v: %v, want the not-logged-in error", args, err)
		}
	}
}

func TestTransferAcceptDropAdvice(t *testing.T) {
	w := newXferWorld(t)
	w.as(t, "ada")
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	me, err := c.Me()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runTransfer, w.artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	w.adminDo(t, "PATCH", "/api/admin/users/"+me.ID, map[string]any{"disabled": true})
	w.as(t, "bob")
	if _, err := runQuiet(t, runTransfer, "accept", w.artifact); !errors.Is(err, client.ErrPreviousOwnerGone) || !strings.Contains(err.Error(), "--drop-previous-owner") {
		t.Errorf("accept with the previous owner gone: %v", err)
	}
}

func TestHandoverNoticeAndAcceptNewOwner(t *testing.T) {
	w := newXferWorld(t)
	w.handOver(t, "bob")
	today := time.Now().UTC().Format("2006-01-02")
	notice := "ownership was handed over by an administrator on " + today
	seq := ownerChangeSeq(t, w.artifact)

	// Read-only commands print the notice to stderr each time, never refuse,
	// and keep stdout JSON.
	w.as(t, "cat")
	for i := 0; i < 2; i++ {
		done := captureStderr(t)
		got := runJSON[map[string]any](t, runMembers, w.artifact, "--json")
		if errText := done(); !strings.Contains(errText, notice) || strings.Count(errText, notice) != 1 {
			t.Errorf("run %d: stderr %q, want the notice once", i+1, errText)
		}
		h, ok := got["handover"].(map[string]any)
		if !ok || h["date"] != today || h["acked"] != false {
			t.Errorf("members --json handover = %v", got["handover"])
		}
	}
	done := captureStderr(t)
	if _, err := runQuiet(t, runMembers, w.artifact); err != nil {
		t.Fatal(err)
	}
	if errText := done(); !strings.Contains(errText, notice) {
		t.Errorf("members printed %q on stderr", errText)
	}

	// Every write refuses, with the notice and what to do about it.
	site := siteDir(t)
	writes := map[string][]string{
		"share":    {w.artifact, "dan@example.com"},
		"unshare":  {w.artifact, "dan@example.com"},
		"team":     {w.artifact, "viewer"},
		"approve":  {w.artifact, "dan@example.com"},
		"public":   {w.artifact, "on"},
		"vouch":    {w.artifact, "nope"},
		"push":     {site, "--artifact", w.artifact},
		"transfer": {w.artifact, "bob@example.com"},
		"accept":   {"accept", w.artifact},
		"withdraw": {"withdraw", w.artifact},
	}
	runs := map[string]func([]string) error{
		"share": runShare, "unshare": runUnshare, "team": runTeam, "approve": runApprove, "public": runPublic,
		"vouch": runVouch, "push": runPush, "transfer": runTransfer, "accept": runTransfer, "withdraw": runTransfer,
	}
	for name, args := range writes {
		done := captureStderr(t)
		_, err := runQuiet(t, runs[name], args...)
		errText := done()
		var refused *client.HandoverNotAckedError
		if !errors.As(err, &refused) || !strings.Contains(err.Error(), "--accept-new-owner") || !strings.Contains(err.Error(), "confirm the handover with the people involved") {
			t.Errorf("cairn %s: %v, want the refusal with the advice", name, err)
		}
		if !strings.Contains(errText, notice) {
			t.Errorf("cairn %s printed %q on stderr, want the notice", name, errText)
		}
		// Every command takes the flag, and it records the acknowledgement,
		// whatever else the command then does. Forget it for the next one.
		_, err = runQuiet(t, runs[name], append(slices.Clone(args), "--accept-new-owner")...)
		if errors.As(err, &refused) {
			t.Errorf("cairn %s --accept-new-owner: %v", name, err)
		}
		if got := ackOf(t, w.artifact); got != seq {
			t.Errorf("cairn %s --accept-new-owner left the ack at %d, want %d", name, got, seq)
		}
		setAck(t, w.artifact, 0)
	}

	// With the flag, the write goes ahead, once; the notice still shows after.
	out := runJSON[map[string]any](t, runPush, site, "--artifact", w.artifact, "--accept-new-owner", "--json")
	if h, ok := out["handover"].(map[string]any); !ok || h["acked"] != true || h["date"] != today {
		t.Errorf("push --json after accepting: handover = %v", out["handover"])
	}
	done = captureStderr(t)
	got := runJSON[map[string]any](t, runMembers, w.artifact, "--json")
	if errText := done(); !strings.Contains(errText, notice) {
		t.Errorf("stderr after accepting: %q", errText)
	}
	if h := got["handover"].(map[string]any); h["acked"] != true {
		t.Errorf("members --json after accepting: %v", h)
	}
	if _, err := runQuiet(t, runPush, site, "--artifact", w.artifact); err != nil {
		t.Errorf("push after accepting, with no flag: %v", err)
	}

	// The new owner accepted it with the handover, so no refusal and no flag.
	w.as(t, "bob")
	if _, err := runQuiet(t, runShare, w.artifact, "dan@example.com", "--role", "editor"); err != nil {
		t.Errorf("the new owner's share: %v", err)
	}
	// Someone else who never accepted is still refused.
	w.as(t, "dan")
	var refused *client.HandoverNotAckedError
	if _, err := runQuiet(t, runPush, site, "--artifact", w.artifact); !errors.As(err, &refused) {
		t.Errorf("another member's push: %v, want a refusal", err)
	}
}

// ownerChangeSeq is the number of records of the artifact, which is the seq
// of the handover when it is the latest.
func ownerChangeSeq(t *testing.T, artifact string) int {
	t.Helper()
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	m, err := c.Membership(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return len(m.Records)
}

// ackOf is the handover the current user's keyring acknowledges.
func ackOf(t *testing.T, artifact string) int {
	t.Helper()
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := c.ReadKeyring(mustUnlock(t, c))
	if err != nil {
		t.Fatal(err)
	}
	return kr.Epochs[artifact].Ack
}

// setAck sets the acknowledged handover in the current user's keyring.
func setAck(t *testing.T, artifact string, seq int) {
	t.Helper()
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpdateKeyring(mustUnlock(t, c), func(kr *e2e.Keyring) error {
		e := kr.Epochs[artifact]
		e.Ack = seq
		kr.Epochs[artifact] = e
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func mustUnlock(t *testing.T, c *client.Client) *client.UnlockedKeys {
	t.Helper()
	k, err := c.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRotateKeysPrintsTransferWarnings(t *testing.T) {
	w := newXferWorld(t)
	if _, err := runQuiet(t, runTransfer, w.artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "bob")
	if _, err := runQuiet(t, runTransfer, "accept", w.artifact); err != nil {
		t.Fatal(err)
	}
	w.as(t, "ada")
	withStdin(t, sharePassword+"\n")
	out, err := runQuiet(t, runRotateKeys, "--password-stdin")
	if err != nil {
		t.Fatalf("cairn rotate-keys: %v", err)
	}
	if want := "warning: you handed ownership of artifact " + w.artifact + " to bob@example.com on " + time.Now().UTC().Format("2006-01-02"); !strings.Contains(out, want) {
		t.Errorf("cairn rotate-keys printed %q, want %q", out, want)
	}

	w.as(t, "bob")
	withStdin(t, sharePassword+"\n")
	res := runJSON[struct {
		Warnings []string `json:"warnings"`
	}](t, runRotateKeys, "--password-stdin", "--json")
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "took ownership of artifact "+w.artifact+" from ada@example.com") {
		t.Errorf("cairn rotate-keys --json warnings = %q", res.Warnings)
	}

	w.as(t, "dan")
	withStdin(t, sharePassword+"\n")
	res = runJSON[struct {
		Warnings []string `json:"warnings"`
	}](t, runRotateKeys, "--password-stdin", "--json")
	if res.Warnings == nil || len(res.Warnings) != 0 {
		t.Errorf("another member's warnings = %#v, want an empty array", res.Warnings)
	}
}
