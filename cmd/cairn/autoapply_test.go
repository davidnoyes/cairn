package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestACommandSaysWhoAnItemWaitsOn(t *testing.T) {
	w, _ := pendingOnBob(t)
	w.as(t, "ada")
	out, errOut := listWithStderr(t)
	if errOut != "1 item still waits on bob@example.com\n" {
		t.Errorf("stderr = %q", errOut)
	}
	if strings.Contains(out, "waits on") {
		t.Errorf("stdout carries the summary: %q", out)
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
	want := "applied folder sharing to 2 items; 2 items still wait on bob@example.com; 1 item could not be brought up to date; run cairn apply for the reason\n"
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
