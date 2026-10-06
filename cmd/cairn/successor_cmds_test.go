package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/clock"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

const day14 = 14*24*time.Hour + time.Hour

// succWorld is a server on a fake clock with ada, who owns an artifact with a
// stored file; bob, whom she can nominate; cat, who owns an artifact shared
// with ada; and an administrator, each with a CLI config of their own.
type succWorld struct {
	*xferWorld
	clk *clock.Fake
	// owned is ada's artifact, and shared is cat's, which she can read.
	owned, shared string
}

const succFile = "the estate of ada"

func newSuccWorld(t *testing.T) *succWorld {
	t.Helper()
	clk := clock.NewFake(time.Now())
	host, m := newTestServerAt(t, clk)
	w := &succWorld{xferWorld: &xferWorld{m: m, host: host, configs: map[string]string{}}, clk: clk}
	for _, who := range []string{"ada", "bob", "cat", "admin"} {
		signupVerify(t, host, m, who+"@example.com", sharePassword)
		w.configs[who] = filepath.Join(t.TempDir(), who+".json")
		w.as(t, who)
		cliLogin(t, host, who+"@example.com", sharePassword)
	}
	w.as(t, "cat")
	w.shared = runJSON[map[string]any](t, artifactCreate, "theirs", "--json")["id"].(string)
	if _, err := runQuiet(t, runShare, w.shared, "ada@example.com"); err != nil {
		t.Fatal(err)
	}
	w.as(t, "ada")
	w.owned = runJSON[map[string]any](t, artifactCreate, "estate", "--json")["id"].(string)
	site := siteDir(t)
	pushed := runJSON[struct {
		Version client.Version `json:"version"`
	}](t, runPush, site, "--artifact", w.owned, "--json")
	file := filepath.Join(t.TempDir(), "will.txt")
	if err := os.WriteFile(file, []byte(succFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runFiles, "put", file, "--artifact", w.owned, "--version", pushed.Version.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runMembers, w.shared); err != nil {
		t.Fatal(err)
	}
	return w
}

// run runs a command as who, with password on stdin, and returns what it
// printed to stdout and stderr.
func (w *succWorld) run(t *testing.T, who string, fn func([]string) error, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	w.as(t, who)
	withStdin(t, sharePassword+"\n")
	doneErr, doneOut := captureStderr(t), captureStdout(t)
	err = fn(args)
	stdout, stderr = doneOut(), doneErr()
	return
}

func (w *succWorld) mustRun(t *testing.T, who string, fn func([]string) error, args ...string) string {
	t.Helper()
	out, _, err := w.run(t, who, fn, args...)
	if err != nil {
		t.Fatalf("%s: %v", strings.Join(args, " "), err)
	}
	return out
}

// codeOf is who's own successor code.
func (w *succWorld) codeOf(t *testing.T, who string) string {
	return strings.TrimSpace(w.mustRun(t, who, runSuccessor, "code"))
}

// nominate has ada nominate bob.
func (w *succWorld) nominate(t *testing.T) {
	t.Helper()
	w.mustRun(t, "ada", runSuccessor, "nominate", "bob@example.com", "--code", w.codeOf(t, "bob"), "--password-stdin")
}

// request has bob ask for access to ada's artifacts, and returns what he saw.
func (w *succWorld) request(t *testing.T) string {
	t.Helper()
	return w.mustRun(t, "bob", runSuccessor, "request", "ada@example.com")
}

// release has ada nominate bob, and bob ask, then lets the 14 days pass.
func (w *succWorld) release(t *testing.T) {
	t.Helper()
	w.nominate(t)
	w.request(t)
	w.clk.Advance(day14)
}

func (w *succWorld) status(t *testing.T, who string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(w.mustRun(t, who, runSuccessor, "status", "--json")), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSuccessorCodeIsComputedFromTheOwnKeys(t *testing.T) {
	w := newSuccWorld(t)
	code := w.codeOf(t, "bob")
	w.as(t, "ada")
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := c.Directory()
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range dir {
		if u.Email == "bob@example.com" {
			got, err := c.CheckSuccessorCode(u.Email, code)
			if err != nil || got.ID != u.ID {
				t.Errorf("bob's own code against the directory: %v, %v", got, err)
			}
		}
	}
	if code == w.codeOf(t, "cat") {
		t.Error("two users have the same code")
	}
}

func TestSuccessorNominateNeedsTheRightCode(t *testing.T) {
	w := newSuccWorld(t)
	catCode := w.codeOf(t, "cat")
	for _, tc := range []struct {
		name string
		args []string
		want error
	}{
		{"another user's code", []string{"bob@example.com", "--code", catCode}, client.ErrSuccessorCode},
		{"a code of nobody", []string{"bob@example.com", "--code", "AAAA-AAAA-AAAA-AAAA"}, client.ErrSuccessorCode},
		{"not a code", []string{"bob@example.com", "--code", "nonsense"}, e2e.ErrFormat},
		{"no code", []string{"bob@example.com"}, nil},
		{"no user", []string{"--code", catCode}, nil},
		{"unknown user", []string{"nobody@example.com", "--code", catCode}, client.ErrUnknownUser},
	} {
		_, _, err := w.run(t, "ada", runSuccessor, append([]string{"nominate"}, append(tc.args, "--password-stdin")...)...)
		if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	// A mismatch says what to do about it.
	_, _, err := w.run(t, "ada", runSuccessor, "nominate", "bob@example.com", "--code", catCode, "--password-stdin")
	if err == nil || !strings.Contains(err.Error(), "ask them to run cairn successor code again") || !strings.Contains(err.Error(), "wrong keys") {
		t.Errorf("a code mismatch: %v, want it to say how to go on", err)
	}
	// No code is a usage error, not a malformed code.
	_, _, err = w.run(t, "ada", runSuccessor, "nominate", "bob@example.com", "--password-stdin")
	if err == nil || !strings.HasPrefix(err.Error(), "usage: cairn successor nominate USER --code CODE") {
		t.Errorf("nominate without --code: %v, want the usage line", err)
	}
	// Nothing was sent.
	if st := w.status(t, "ada"); st["successor"] != nil || st["nominatedAt"] != "" {
		t.Errorf("after the refusals, ada's successor is %v", st)
	}

	out := w.mustRun(t, "ada", runSuccessor, "nominate", "bob@example.com", "--code", w.codeOf(t, "bob"), "--password-stdin")
	if !strings.Contains(out, "bob@example.com") || !strings.Contains(out, "record 1") {
		t.Errorf("nominate printed %q", out)
	}
	if wait := fmt.Sprintf(" %d days after they ask", int(store.SuccessionWait/(24*time.Hour))); !strings.Contains(out, wait) {
		t.Errorf("nominate printed %q, want the wait%q", out, wait)
	}
	st := w.status(t, "ada")
	if s, _ := st["successor"].(map[string]any); s == nil || s["email"] != "bob@example.com" {
		t.Errorf("ada's successor = %v", st["successor"])
	}
	if from := w.status(t, "bob")["nominatedYou"].([]any); len(from) != 1 {
		t.Errorf("bob's nominators = %v", from)
	}

	// A wrong password sends nothing either.
	w.as(t, "ada")
	withStdin(t, "not the password\n")
	if err := runSuccessor([]string{"nominate", "cat@example.com", "--code", catCode, "--password-stdin"}); err == nil {
		t.Error("nominate with a wrong password succeeded")
	}
	if s, _ := w.status(t, "ada")["successor"].(map[string]any); s["email"] != "bob@example.com" {
		t.Errorf("a wrong password changed the successor to %v", s)
	}
}

func TestSuccessorRemoveAndNominateAgain(t *testing.T) {
	w := newSuccWorld(t)
	if _, _, err := w.run(t, "ada", runSuccessor, "remove"); !errors.Is(err, client.ErrNoSuccessor) {
		t.Errorf("remove with no successor: %v", err)
	}
	w.nominate(t)
	if out := w.mustRun(t, "ada", runSuccessor, "remove"); !strings.Contains(out, "bob@example.com is no longer your successor") {
		t.Errorf("remove printed %q", out)
	}
	if st := w.status(t, "ada"); st["successor"] != nil {
		t.Errorf("after remove, the successor is %v", st["successor"])
	}
	// The remove record took seq 2, so the next nomination is 3.
	out := w.mustRun(t, "ada", runSuccessor, "nominate", "bob@example.com", "--code", w.codeOf(t, "bob"), "--password-stdin")
	if !strings.Contains(out, "record 3") {
		t.Errorf("nominate after remove printed %q, want record 3", out)
	}
	// Bob asks for what is no longer his.
	if _, _, err := w.run(t, "cat", runSuccessor, "request", "ada@example.com"); !errors.Is(err, client.ErrNotSuccessor) {
		t.Errorf("a stranger's request: %v", err)
	}
}

func TestSuccessorRequestWarnsTheUserOnStderr(t *testing.T) {
	w := newSuccWorld(t)
	w.nominate(t)
	if out := w.request(t); !strings.Contains(out, "access starts on "+w.clk.Now().AddDate(0, 0, 14).UTC().Format("2006-01-02")) {
		t.Errorf("request printed %q", out)
	}
	if _, _, err := w.run(t, "bob", runSuccessor, "request", "ada@example.com"); err == nil {
		t.Error("a second request succeeded")
	}

	const warning = "your successor asked for access"
	out, errOut, err := w.run(t, "ada", runArtifact, "list", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(errOut, warning) != 1 || !strings.Contains(errOut, "cairn successor refuse") {
		t.Errorf("stderr = %q, want the warning once", errOut)
	}
	if strings.Contains(out, "successor") || !json.Valid([]byte(out)) {
		t.Errorf("stdout = %q, want clean JSON", out)
	}
	// Once per command, however many requests it makes.
	_, errOut, err = w.run(t, "ada", runMembers, w.owned)
	if err != nil || strings.Count(errOut, warning) != 1 {
		t.Errorf("members: %v, stderr %q", err, errOut)
	}
	// Bob has nothing to be warned of.
	if _, errOut, _ := w.run(t, "bob", runArtifact, "list"); strings.Contains(errOut, "warning") {
		t.Errorf("bob's stderr = %q", errOut)
	}
	status := w.mustRun(t, "ada", runSuccessor, "status")
	if !strings.Contains(status, "bob@example.com") || !strings.Contains(status, "unless you run cairn successor refuse") {
		t.Errorf("status printed %q", status)
	}
	if got := w.mustRun(t, "bob", runSuccessor, "status"); !strings.Contains(got, "ada@example.com") || !strings.Contains(got, "you asked on") {
		t.Errorf("bob's status printed %q", got)
	}
}

func TestSuccessorRefusalOnDay13BlocksAccess(t *testing.T) {
	w := newSuccWorld(t)
	w.nominate(t)
	if _, _, err := w.run(t, "ada", runSuccessor, "refuse"); err == nil {
		t.Error("refusing with no request succeeded")
	}
	w.request(t)
	w.clk.Advance(13 * 24 * time.Hour)
	if out := w.mustRun(t, "ada", runSuccessor, "refuse"); !strings.Contains(out, "refused the request") {
		t.Errorf("refuse printed %q", out)
	}
	w.clk.Advance(2 * 24 * time.Hour)

	if _, _, err := w.run(t, "bob", runArtifact, "show", w.owned); err == nil {
		t.Error("bob opened ada's artifact after the refusal")
	}
	if _, _, err := w.run(t, "bob", runFiles, "get", "will.txt", "--artifact", w.owned); err == nil {
		t.Error("bob read ada's file after the refusal")
	}
	if _, errOut, err := w.run(t, "ada", runArtifact, "list"); err != nil || strings.Contains(errOut, "warning") {
		t.Errorf("after the refusal ada's list: %v, stderr %q", err, errOut)
	}
	// The nomination stays, and bob may ask again.
	if st := w.status(t, "ada"); st["successor"] == nil || st["request"] != nil {
		t.Errorf("after the refusal: %v", st)
	}
}

// Silence for 14 days releases the successor, whether or not the user was
// deactivated meanwhile, and they read the user's own artifacts only.
func TestSuccessorReleaseReadsTheEstate(t *testing.T) {
	for _, deactivated := range []bool{false, true} {
		name := "active"
		if deactivated {
			name = "deactivated"
		}
		t.Run(name, func(t *testing.T) {
			w := newSuccWorld(t)
			w.nominate(t)
			w.request(t)
			w.clk.Advance(14*24*time.Hour - time.Hour)
			if _, _, err := w.run(t, "bob", runFiles, "get", "will.txt", "--artifact", w.owned); err == nil {
				t.Error("bob read ada's file the hour before the release")
			}
			if deactivated {
				ada := w.userID(t, "ada")
				w.adminDo(t, "PATCH", "/api/admin/users/"+ada, map[string]any{"disabled": true})
			}
			w.clk.Advance(2 * time.Hour)

			if got := w.mustRun(t, "bob", runFiles, "get", "will.txt", "--artifact", w.owned); got != succFile {
				t.Errorf("bob read %q, want %q", got, succFile)
			}
			if got := w.mustRun(t, "bob", runArtifact, "show", w.owned); !strings.Contains(got, "estate (") {
				t.Errorf("artifact show printed %q", got)
			}
			if got := w.mustRun(t, "bob", runFiles, "list", "--artifact", w.owned); !strings.Contains(got, "will.txt") {
				t.Errorf("files list printed %q", got)
			}
			if got := w.mustRun(t, "bob", runSuccessor, "status"); !strings.Contains(got, "released on") {
				t.Errorf("status printed %q", got)
			}
			// Not an artifact that was merely shared with ada.
			for _, args := range [][]string{{"show", w.shared}, {"show", "theirs"}} {
				if _, _, err := w.run(t, "bob", runArtifact, args...); err == nil {
					t.Errorf("artifact %v: bob opened what was shared with ada", args)
				}
			}
			if _, _, err := w.run(t, "bob", runMembers, w.shared); err == nil {
				t.Error("bob listed the members of what was shared with ada")
			}

			// Reading only: a write says so.
			dir := siteDir(t)
			batch := filepath.Join(t.TempDir(), "batch.json")
			if err := os.WriteFile(batch, []byte(`[{"sql": "CREATE TABLE t (n INTEGER)"}]`), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				fn   func([]string) error
				args []string
			}{
				{runPush, []string{dir, "--artifact", w.owned}},
				{runFiles, []string{"put", filepath.Join(dir, "index.html"), "--artifact", w.owned}},
				{runFiles, []string{"delete", "will.txt", "--artifact", w.owned}},
				{runDB, []string{"batch", "--artifact", w.owned, "--file", batch}},
				{runArtifact, []string{"update", w.owned, "--name", "mine"}},
				{runShare, []string{w.owned, "cat@example.com"}},
			} {
				_, _, err := w.run(t, "bob", tc.fn, tc.args...)
				if err == nil {
					t.Errorf("%v: a successor wrote", tc.args)
				} else if !strings.Contains(err.Error(), "successor") {
					t.Errorf("%v: %v, want the error to say the successor only reads", tc.args, err)
				}
			}
			if got := w.mustRun(t, "bob", runFiles, "get", "will.txt", "--artifact", w.owned); got != succFile {
				t.Errorf("after the refused writes bob read %q", got)
			}
		})
	}
}

func (w *succWorld) userID(t *testing.T, who string) string {
	t.Helper()
	w.as(t, who)
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	me, err := c.Me()
	if err != nil {
		t.Fatal(err)
	}
	return me.ID
}

func TestSuccessorReleaseBlocksTheUserUntilTheyRotate(t *testing.T) {
	w := newSuccWorld(t)
	w.release(t)

	_, errOut, err := w.run(t, "ada", runArtifact, "create", "another")
	if err == nil || !strings.Contains(err.Error(), "rotate your keys first") {
		t.Fatalf("a write after the release: %v", err)
	}
	if !strings.Contains(errOut, "your successor was released") || !strings.Contains(errOut, "cairn rotate-keys") {
		t.Errorf("stderr = %q, want the rotate warning", errOut)
	}
	if _, errOut, err := w.run(t, "ada", runArtifact, "list"); err != nil || strings.Count(errOut, "cairn rotate-keys") != 1 {
		t.Errorf("a read after the release: %v, stderr %q", err, errOut)
	}
	// A release cannot be refused or undone.
	if _, _, err := w.run(t, "ada", runSuccessor, "refuse"); err == nil {
		t.Error("refused a release")
	}
	if _, _, err := w.run(t, "ada", runSuccessor, "remove"); err == nil {
		t.Error("removed a released successor")
	}
	if got := w.mustRun(t, "bob", runFiles, "get", "will.txt", "--artifact", w.owned); got != succFile {
		t.Errorf("bob read %q", got)
	}

	w.as(t, "ada")
	t.Setenv("CAIRN_HOST", "")
	t.Setenv("CAIRN_API_KEY", "")
	out, _, err := w.run(t, "ada", runRotateKeys, "--password-stdin")
	if err != nil || !strings.Contains(out, "Keys rotated") {
		t.Fatalf("rotate-keys: %q, %v", out, err)
	}
	// The rotation ended the successor's access.
	if _, _, err := w.run(t, "bob", runFiles, "get", "will.txt", "--artifact", w.owned); err == nil {
		t.Error("bob still reads after ada rotated her keys")
	}
	if from := w.status(t, "bob")["nominatedYou"].([]any); len(from) != 0 {
		t.Errorf("bob's nominators after the rotation = %v", from)
	}
	if _, _, err := w.run(t, "ada", runArtifact, "create", "another"); err != nil {
		t.Errorf("a write after rotating: %v", err)
	}
}

// An administrator's handover to the released successor is silent: the chain
// check finds the previous owner's successor record, so no member sees the
// notice.
func TestSuccessorAdminHandoverIsSilent(t *testing.T) {
	w := newSuccWorld(t)
	// Ada's artifact is public, so a link holder's chain check must find the
	// successor record too.
	w.mustRun(t, "ada", runPublic, w.owned, "on")
	w.release(t)
	ada, bob := w.userID(t, "ada"), w.userID(t, "bob")
	w.adminDo(t, "PATCH", "/api/admin/users/"+ada, map[string]any{"disabled": true})
	w.adminDo(t, "POST", "/api/admin/artifacts/"+w.owned+"/transfer", map[string]any{"to": bob})

	out, errOut, err := w.run(t, "bob", runTransfer, "accept", w.owned, "--json")
	if err != nil {
		t.Fatalf("transfer accept: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got["byAdministrator"] != true {
		t.Errorf("accept printed %v", got)
	}
	if _, has := got["handover"]; has || strings.Contains(errOut, "handed over") {
		t.Errorf("the successor's handover shows a notice: %v, stderr %q", got["handover"], errOut)
	}
	out, errOut, err = w.run(t, "bob", runMembers, w.owned, "--json")
	if err != nil || strings.Contains(out, "handover") || strings.Contains(errOut, "handed over") {
		t.Errorf("members after the handover: %v, %q, stderr %q", err, out, errOut)
	}
	// Dropping ada started a new epoch, and so a new link.
	if link, _ := got["link"].(string); link == "" {
		t.Errorf("accept printed no new link: %v", got)
	} else if _, err := client.OpenLink(link); err != nil {
		t.Errorf("the public link after the handover: %v", err)
	}
	// Bob now owns it, and writes.
	if got := w.mustRun(t, "bob", runFiles, "get", "will.txt", "--artifact", w.owned); got != succFile {
		t.Errorf("bob read %q", got)
	}
	if _, _, err := w.run(t, "bob", runArtifact, "update", w.owned, "--name", "mine"); err != nil {
		t.Errorf("the new owner's rename: %v", err)
	}
}

func TestSuccessorNoticeEmail(t *testing.T) {
	w := newSuccWorld(t)
	out := w.mustRun(t, "ada", runSuccessor, "notice-email", "ada.home@example.org", "--password-stdin")
	if !strings.Contains(out, "check ada.home@example.org") {
		t.Errorf("notice-email printed %q", out)
	}
	if _, ok := w.m.Last("ada.home@example.org"); !ok {
		t.Error("no verification mail was sent to the notice address")
	}
	if out := w.mustRun(t, "ada", runSuccessor, "notice-email", "", "--password-stdin"); !strings.Contains(out, "cleared") {
		t.Errorf("clearing printed %q", out)
	}
	if _, _, err := w.run(t, "ada", runSuccessor, "notice-email", "not an address", "--password-stdin"); err == nil {
		t.Error("a malformed address was accepted")
	}
}

// The user whose successor was released is told how to end it, in words.
func TestSuccessorStatusSaysHowToEndAReleasedAccess(t *testing.T) {
	w := newSuccWorld(t)
	w.nominate(t)
	w.request(t)
	released := w.clk.Now().AddDate(0, 0, 14).UTC().Format("2006-01-02")
	w.clk.Advance(day14)
	got := w.mustRun(t, "ada", runSuccessor, "status")
	if !strings.Contains(got, "were released on "+released+"; run cairn rotate-keys to end their access") {
		t.Errorf("status printed %q, want the release date and the rotate-keys instruction", got)
	}
}

func TestSuccessorAdviceNeedsASuccessorRun(t *testing.T) {
	forbidden := &client.APIError{Status: http.StatusForbidden, Message: "forbidden"}
	t.Cleanup(func() { successorOnly = false })

	successorOnly = false
	for _, err := range []error{forbidden, client.ErrCannotPush, client.ErrNotOwner} {
		if got := successorAdvice(err); got != "" {
			t.Errorf("an owner's or editor's refusal %v got the advice %q", err, got)
		}
	}
	successorOnly = true
	for _, err := range []error{forbidden, client.ErrCannotPush, client.ErrNotOwner} {
		if got := successorAdvice(err); !strings.Contains(got, "only as its owner's successor") {
			t.Errorf("a successor's refusal %v got the advice %q", err, got)
		}
	}
	if got := successorAdvice(&client.APIError{Status: http.StatusNotFound}); got != "" {
		t.Errorf("an unrelated error got the advice %q", got)
	}
	// A new run starts with it off.
	watchNotices(client.New("http://example.invalid", ""))
	if successorOnly {
		t.Error("watchNotices left successorOnly set")
	}
}

func TestSuccessorUsage(t *testing.T) {
	for _, args := range [][]string{
		nil, {"frobnicate"}, {"code", "extra"}, {"status", "extra"}, {"remove", "extra"}, {"refuse", "extra"},
		{"request"}, {"request", "a", "b"}, {"notice-email"}, {"nominate"},
	} {
		if err := runSuccessor(args); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("cairn successor %v: %v, want a usage error", args, err)
		}
	}
	if err := runSuccessor([]string{"code"}); err == nil || !strings.Contains(err.Error(), "not logged in") && !strings.Contains(err.Error(), "no credentials") {
		t.Errorf("code without a login: %v", err)
	}
}

func TestWatchNoticesPrintsEachOnceToStderr(t *testing.T) {
	c := client.New("http://example.invalid", "")
	watchNotices(c)
	doneErr, doneOut := captureStderr(t), captureStdout(t)
	for _, n := range []string{"succession-requested", "succession-requested", "rotate-keys", "rotate-keys", "something-new"} {
		c.OnNotice(n)
	}
	out, errOut := doneOut(), doneErr()
	if out != "" || strings.Count(errOut, "\n") != 2 || strings.Count(errOut, "cairn successor refuse") != 1 || strings.Count(errOut, "cairn rotate-keys") != 1 {
		t.Errorf("stdout %q, stderr %q", out, errOut)
	}
	// A new command starts again.
	watchNotices(c)
	doneErr = captureStderr(t)
	c.OnNotice("rotate-keys")
	if errOut := doneErr(); !strings.Contains(errOut, "cairn rotate-keys") {
		t.Errorf("the next run printed %q", errOut)
	}
}
