package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
)

// Applying on its own: a command that can unlock first brings the caller's
// pending items up to date, says so on stderr, and leaves stdout alone.

// pendingOnBob is the others world with cat listed as a manager of Work. That
// changes the managers of bob's item, which only bob signs, so it is pending
// and waits on him. Bob is signed in.
func pendingOnBob(t *testing.T) (w *teamWorld, theirs string) {
	t.Helper()
	w, _, theirs = newOthersWorld(t)
	shareManagerOfOthersItems(t, "cat@example.com")
	w.as(t, "bob")
	return w, theirs
}

// listWithStderr runs cairn artifact list --json and returns what it printed
// on stdout and on stderr.
func listWithStderr(t *testing.T) (stdout, stderr string) {
	t.Helper()
	errDone := captureStderr(t)
	out, err := runQuiet(t, runArtifact, "list", "--json")
	stderr = errDone()
	if err != nil {
		t.Fatalf("artifact list: %v", err)
	}
	return out, stderr
}

func TestACommandAppliesPendingItemsAndSaysSoOnStderr(t *testing.T) {
	w, theirs := pendingOnBob(t)
	out, errOut := listWithStderr(t)
	if errOut != "applied folder sharing to 1 item\n" {
		t.Errorf("stderr = %q", errOut)
	}
	var list []client.Artifact
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list) == 0 {
		t.Fatalf("stdout is not the artifact list: %q, %v", out, err)
	}
	if strings.Contains(out, "applied folder sharing") {
		t.Errorf("stdout carries the summary: %q", out)
	}
	for _, a := range list {
		if a.ID == theirs && a.Inherit == "pending" {
			t.Errorf("the item was listed as pending after the apply: %+v", a)
		}
	}
	// Nothing is pending now: the next command is silent, and cat reads it.
	if _, errOut := listWithStderr(t); errOut != "" {
		t.Errorf("a second command printed %q on stderr", errOut)
	}
	w.as(t, "cat")
	text, err := runQuiet(t, runFolder, "list", "Work")
	if err != nil || strings.Contains(text, "not shared with you yet") {
		t.Errorf("cat's folder list = %q, %v; want the item shared", text, err)
	}
}

// An item that waits on someone else is not the caller's to act on, so the
// automatic summary leaves it to cairn apply.
func TestACommandStaysSilentAboutItemsThatWaitOnSomeoneElse(t *testing.T) {
	w, _ := pendingOnBob(t)
	w.as(t, "ada")
	if _, errOut := listWithStderr(t); errOut != "" {
		t.Errorf("stderr = %q, want nothing", errOut)
	}
	text, err := runQuiet(t, runApply)
	if err != nil || !strings.Contains(text, "waits on bob@example.com") {
		t.Errorf("cairn apply = %q, %v; want it to say what waits on bob", text, err)
	}
}

func TestApplyDoesNotApplyTwice(t *testing.T) {
	_, theirs := pendingOnBob(t)
	errDone := captureStderr(t)
	res := runJSON[applyOut](t, runApply, "--json")
	if errOut := errDone(); errOut != "" {
		t.Errorf("cairn apply printed %q on stderr", errOut)
	}
	if len(res.Applied.Items) != 1 || res.Applied.Items[0].ID != theirs || res.Applied.Items[0].State != "updated" {
		t.Errorf("cairn apply = %+v, want it to bring %s up to date itself", res.Applied, theirs)
	}
}

func TestACommandDoesNotApplyForAClientThatCannotUnlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("request %s %s from a client that cannot unlock", r.Method, r.URL.Path)
	}))
	defer srv.Close()
	if err := autoApply(client.New(srv.URL, "cairn_x_y")); err != nil {
		t.Fatal(err)
	}
}

func TestAnAutoApplyFailureWarnsAndTheCommandCarriesOn(t *testing.T) {
	var buf bytes.Buffer
	if err := reportAutoApply(&buf, nil, errors.New("the server is down")); err != nil {
		t.Fatalf("a failure ended the command: %v", err)
	}
	if got := buf.String(); got != "warning: could not apply folder sharing: the server is down\n" {
		t.Errorf("stderr = %q", got)
	}
}

func TestAnAutoApplyRefusedCredentialEndsTheCommand(t *testing.T) {
	var buf bytes.Buffer
	err := reportAutoApply(&buf, nil, fmt.Errorf("list: %w", &client.APIError{Status: http.StatusUnauthorized, Message: "bad key"}))
	var api *client.APIError
	if !errors.As(err, &api) || buf.Len() != 0 {
		t.Errorf("err = %v, stderr = %q; want the 401 returned and nothing printed", err, buf.String())
	}
}

func TestAnAutoApplySaysWhatFailedWithoutAWarning(t *testing.T) {
	res := &client.ApplyResult{FanOut: client.FanOutResult{Items: []client.FanOutItem{
		{ID: "a", State: client.FanOutUpdated}, {ID: "n", State: client.FanOutNewEpoch}, {ID: "b", State: client.FanOutFailed},
	}}, Waiting: []client.FanOutItem{{ID: "c", OwnerEmail: "bob@example.com"}, {ID: "d", OwnerEmail: "bob@example.com"}}}
	var buf bytes.Buffer
	if err := reportAutoApply(&buf, res, fmt.Errorf("%w: 1 of 3", client.ErrFanOutIncomplete)); err != nil {
		t.Fatal(err)
	}
	want := "applied folder sharing to 2 items; 1 item could not be brought up to date; run cairn apply for the reason\n"
	if buf.String() != want {
		t.Errorf("stderr = %q, want %q", buf.String(), want)
	}
}

// A refused credential ends the command at the automatic apply, as its own
// request would: the server sees one request, not two.
func TestARefusedCredentialEndsTheCommandAtTheAutoApply(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	saveDummyLogin(t, srv.URL)
	if _, err := runQuiet(t, runArtifact, "list"); err == nil || requests != 1 {
		t.Errorf("err = %v after %d requests, want the 401 after one", err, requests)
	}
}

// An item that needs a move is not silent: its owner learns to run cairn
// apply, which says why (a folder they can no longer read, or a placement
// to sign) and how.
func TestAnAutoApplySaysWhenItemsNeedAMove(t *testing.T) {
	move := func(id string) client.FanOutItem { return client.FanOutItem{ID: id, State: client.FanOutNeedsMove} }
	for _, c := range []struct {
		items []client.FanOutItem
		want  string
	}{
		{[]client.FanOutItem{move("a")}, "1 item needs a move; run cairn apply for why and how"},
		{[]client.FanOutItem{move("a"), move("b")}, "2 items need a move; run cairn apply for why and how"},
	} {
		if got := autoApplySummary(&client.ApplyResult{FanOut: client.FanOutResult{Items: c.items}}); got != c.want {
			t.Errorf("summary = %q, want %q", got, c.want)
		}
	}
}

// requestLog swaps the transport the CLI's client uses for one that records
// "METHOD path" for each request, and returns the log so far.
func requestLog(t *testing.T) func() []string {
	t.Helper()
	var log []string
	old := http.DefaultClient.Transport
	http.DefaultClient.Transport = autoApplyRoundTrip(func(r *http.Request) (*http.Response, error) {
		log = append(log, r.Method+" "+r.URL.Path)
		return http.DefaultTransport.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultClient.Transport = old })
	return func() []string { return log }
}

type autoApplyRoundTrip func(*http.Request) (*http.Response, error)

func (f autoApplyRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// inheritOf is the inherit state artifact list --json shows for id.
func inheritOf(t *testing.T, id string) string {
	t.Helper()
	for _, a := range runJSON[[]client.Artifact](t, runArtifact, "list", "--json") {
		if a.ID == id {
			return a.Inherit
		}
	}
	t.Fatalf("%s is not listed", id)
	return ""
}

// The automatic apply costs one request, the list, when the caller has nothing
// to sign: nothing pending, or only items that wait on someone else. It
// unlocks nothing and fetches no directory, and prints nothing.
func TestACommandCostsOneListWhenTheCallerHasNothingToSign(t *testing.T) {
	want := []string{"GET /api/artifacts"}
	apiClientAlone := func(t *testing.T) (log []string, stderr string) {
		t.Helper()
		requests := requestLog(t)
		errDone := captureStderr(t)
		if _, err := apiClient(); err != nil {
			t.Fatal(err)
		}
		stderr = errDone()
		return requests(), stderr
	}
	t.Run("nothing pending", func(t *testing.T) {
		w, _, _ := newOthersWorld(t)
		w.as(t, "ada")
		if log, errOut := apiClientAlone(t); errOut != "" || !slices.Equal(log, want) {
			t.Errorf("stderr %q, requests %v; want no output and %v", errOut, log, want)
		}
	})
	t.Run("only items waiting on others", func(t *testing.T) {
		w, _, _ := newOthersWorld(t)
		// Dan manages Work, which only bob can sign into his item: dan lists
		// it as a pending stub he cannot sign.
		shareManagerOfOthersItems(t, "dan@example.com")
		w.as(t, "dan")
		if text, err := runQuiet(t, runFolder, "list", "Work"); err != nil || !strings.Contains(text, "not shared with you yet") {
			t.Fatalf("dan lists %q, %v; want the pending stub", text, err)
		}
		if log, errOut := apiClientAlone(t); errOut != "" || !slices.Equal(log, want) {
			t.Errorf("stderr %q, requests %v; want no output and %v", errOut, log, want)
		}
	})
}

// With CAIRN_HOST and CAIRN_API_KEY and no saved login, the command applies
// and says so, as for a saved login.
func TestAHeadlessCommandAppliesPendingItems(t *testing.T) {
	_, theirs := pendingOnBob(t)
	cfg := loadConfig()
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "none.json"))
	t.Setenv("CAIRN_HOST", cfg.Host)
	t.Setenv("CAIRN_API_KEY", cfg.APIKey)
	if _, errOut := listWithStderr(t); errOut != "applied folder sharing to 1 item\n" {
		t.Errorf("stderr = %q", errOut)
	}
	if got := inheritOf(t, theirs); got != "ok" {
		t.Errorf("the item is %q, want it applied", got)
	}
}

// An item in a folder its owner can no longer read is not applied: a normal
// command says it needs a move, and writes nothing.
func TestACommandSaysAnItemInAnUnreadableFolderNeedsAMove(t *testing.T) {
	w, _, theirs := newOthersWorld(t)
	if _, err := runQuiet(t, runUnshare, "Work", "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	shareManagerOfOthersItems(t, "cat@example.com")
	w.as(t, "bob")
	log := requestLog(t)
	_, errOut := listWithStderr(t)
	if errOut != "1 item needs a move; run cairn apply for why and how\n" {
		t.Errorf("stderr = %q", errOut)
	}
	for _, r := range log() {
		if strings.Contains(r, "/api/artifacts/") && !strings.HasPrefix(r, "GET ") {
			t.Errorf("the command sent %q", r)
		}
	}
	if got := inheritOf(t, theirs); got != "pending" {
		t.Errorf("the item is %q, want it still pending", got)
	}
}

// The first command applies a pending item and the second finds nothing.
func TestARepeatedCommandPrintsNothing(t *testing.T) {
	pendingOnBob(t)
	if _, errOut := listWithStderr(t); errOut != "applied folder sharing to 1 item\n" {
		t.Fatalf("first command: stderr = %q", errOut)
	}
	if _, errOut := listWithStderr(t); errOut != "" {
		t.Errorf("second command: stderr = %q, want nothing", errOut)
	}
}
