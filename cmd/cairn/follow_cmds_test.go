package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

// rotateAs rotates the keys of who, a user of w.
func rotateAs(t *testing.T, w *teamWorld, who string) {
	t.Helper()
	w.as(t, who)
	withStdin(t, sharePassword+"\n")
	if _, err := runQuiet(t, runRotateKeys, "--password-stdin"); err != nil {
		t.Fatalf("cairn rotate-keys as %s: %v", who, err)
	}
}

// rotatedWorld is the team world with cat listed as a viewer and her pin
// verified, then bob (a listed editor, pinned unverified) and cat rotated.
func rotatedWorld(t *testing.T) *teamWorld {
	t.Helper()
	w := newTeamWorld(t)
	w.as(t, "ada")
	if _, err := runQuiet(t, runShare, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runPin, "cat@example.com", "--verified"); err != nil {
		t.Fatal(err)
	}
	rotateAs(t, w, "bob")
	rotateAs(t, w, "cat")
	w.as(t, "ada")
	return w
}

func lineWith(text, needle string) string {
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, needle) {
			return l
		}
	}
	return ""
}

func TestMembersCommandShowsRotatedKeys(t *testing.T) {
	w := rotatedWorld(t)
	text, err := runQuiet(t, runMembers, w.artifact)
	if err != nil {
		t.Fatal(err)
	}
	if l := lineWith(text, "bob@example.com"); !strings.Contains(l, "keys rotated") || strings.Contains(l, "not re-verified") {
		t.Errorf("bob's line = %q, want keys rotated", l)
	}
	if l := lineWith(text, "cat@example.com"); !strings.Contains(l, "rotated, not re-verified") {
		t.Errorf("cat's line = %q, want rotated, not re-verified", l)
	}
	// A verified pin the rotation dropped says how to verify it again.
	if want := "re-verify cat@example.com: compare the new fingerprint with them, then run: cairn pin cat@example.com --verified"; !strings.Contains(text, want) {
		t.Errorf("cairn members printed %q, want the line %q", text, want)
	}
	if strings.Contains(text, "re-verify bob@example.com") {
		t.Errorf("cairn members told the user to re-verify bob, whose pin was never verified: %q", text)
	}
	out := runJSON[struct {
		Members []struct{ Email, State, WasVerified string } `json:"members"`
	}](t, runMembers, w.artifact, "--json")
	got := map[string]string{}
	for _, m := range out.Members {
		got[m.Email] = m.State + "/" + m.WasVerified
	}
	if got["bob@example.com"] != "rotated/false" || got["cat@example.com"] != "rotated/true" {
		t.Errorf("members JSON = %v, want bob rotated/false and cat rotated/true", got)
	}
}

func TestApproveCommandListsRotatedMembersWithTheirLegend(t *testing.T) {
	w := rotatedWorld(t)
	text, err := runQuiet(t, runApprove, w.artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"rotated: keys rotated since they were listed; the owner's next record lists the new keys",
		fmt.Sprintf("rotated: the owner's next cairn share %s USER or cairn team %s viewer|editor lists the new keys", w.artifact, w.artifact),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("cairn approve printed %q, want %q", text, want)
		}
	}
	if l := lineWith(text, "bob@example.com"); !strings.HasPrefix(l, "rotated") {
		t.Errorf("bob's line = %q, want state rotated", l)
	}
	rows := w.pending(t)
	if rows["bob@example.com"].State != "rotated" || rows["cat@example.com"].State != "rotated" {
		t.Errorf("pending JSON = %+v, want bob and cat rotated", rows)
	}
}

func TestShareCommandFollowsARotationWithoutAFlag(t *testing.T) {
	// The owner's record lists every rotated member under the new keys, so
	// each user is shared with in a world of its own.
	for _, tc := range []struct{ who, want string }{
		{"bob", "keys rotated; the new key is pinned unverified"},
		{"cat", "rotated, not re-verified; the new key is pinned unverified"},
	} {
		w := rotatedWorld(t)
		text, err := runQuiet(t, runShare, w.artifact, tc.who+"@example.com", "--role", "editor")
		if err != nil {
			t.Fatalf("cairn share %s after the rotation: %v", tc.who, err)
		}
		if !strings.Contains(text, tc.want) || strings.Contains(text, "--accept-new-key") {
			t.Errorf("cairn share %s printed %q, want %q", tc.who, text, tc.want)
		}
		if rows := membersByEmail(t, w.artifact); rows[tc.who+"@example.com"].State != "unverified" {
			t.Errorf("%s after sharing = %+v, want unverified at the new keys", tc.who, rows[tc.who+"@example.com"])
		}
	}
}

// A fork or rollback in the rotation records prints the hard warning, and
// any other changed key does not.
func TestExplainRefusalWarnsHardOfAForkedRotation(t *testing.T) {
	c := client.New("http://example.invalid", "")
	forked := &client.KeyChangedError{
		User: "u1", Email: "bob@example.com", PinnedFP: strings.Repeat("ab", 32), CurrentFP: strings.Repeat("cd", 32),
		Fork: fmt.Errorf("rotation records for u1: %w", e2e.ErrRotationFork),
	}
	err := explainRefusal(c, forked)
	if !errors.Is(err, e2e.ErrRotationFork) {
		t.Errorf("explainRefusal lost the fork error: %v", err)
	}
	for _, want := range []string{"WARNING", "conflict", "may be an attack", "tampering", "--accept-new-key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err, want)
		}
	}
	plain := &client.KeyChangedError{User: "u1", Email: "bob@example.com", PinnedFP: strings.Repeat("ab", 32), CurrentFP: strings.Repeat("cd", 32)}
	if got := explainRefusal(c, plain); got != error(plain) || strings.Contains(got.Error(), "attack") {
		t.Errorf("explainRefusal changed a plain key change: %v", got)
	}
}

func TestMembersCommandAfterTwoRotationsBeforeTheOwnerLooks(t *testing.T) {
	ada, bob, artifact, _ := forkedWorld(t)
	bobRotates(t, bob)
	bobRotates(t, bob)
	ada()
	text, err := runQuiet(t, runMembers, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if l := lineWith(text, "bob@example.com"); !strings.Contains(l, "keys rotated") {
		t.Errorf("bob's line = %q, want keys rotated", l)
	}
	if _, err := runQuiet(t, runShare, artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if rows := membersByEmail(t, artifact); rows["bob@example.com"].State != "unverified" {
		t.Errorf("bob's row after cairn share = %+v, want unverified at the new keys", rows["bob@example.com"])
	}
}

func TestPinStateLabels(t *testing.T) {
	for _, tc := range []struct {
		state    string
		verified bool
		want     string
	}{
		{e2e.PinRotated, false, "keys rotated"},
		{e2e.PinRotated, true, "rotated, not re-verified"},
		{e2e.PinVerified, true, "verified"},
		{e2e.PinChanged, false, "changed"},
		{client.MemberConflict, false, "changed: rotation records conflict"},
	} {
		if got := priorLabel(tc.state, tc.verified); got != tc.want {
			t.Errorf("priorLabel(%s, %v) = %q, want %q", tc.state, tc.verified, got, tc.want)
		}
	}
}

// How a test server's rotation records are served through rotationsProxy.
const (
	rotationsAsServed int32 = iota
	rotationsForked         // each list gets a second, different record at its last seq
	rotationsWithheld       // every list is empty
	rotationsFailing        // GET /rotations answers 500, and the membership GET omits the lists
)

// rotationsProxy forwards to host and, as mode says, edits every rotation
// list it answers: on GET /api/users/{id}/rotations and in the membership
// GET.
func rotationsProxy(t *testing.T, host string, mode *atomic.Int32) string {
	t.Helper()
	target, err := url.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	edit := func(recs []e2e.Envelope) []e2e.Envelope {
		switch mode.Load() {
		case rotationsWithheld:
			return nil
		case rotationsForked:
			if len(recs) == 0 {
				return recs
			}
			var b e2e.RotationBody
			if err := e2e.DecodeStrict(recs[len(recs)-1].Body, &b); err != nil {
				t.Error(err)
				return recs
			}
			b.New.X25519 = e2e.B64(bytes.Repeat([]byte{7}, 32))
			forged := recs[len(recs)-1]
			forged.Body, _ = json.Marshal(b)
			return append(slices.Clone(recs), forged)
		}
		return recs
	}
	p := httputil.NewSingleHostReverseProxy(target)
	p.ModifyResponse = func(resp *http.Response) error {
		path := resp.Request.URL.Path
		if resp.Request.Method != "GET" || resp.StatusCode != http.StatusOK ||
			!strings.HasSuffix(path, "/rotations") && !strings.HasSuffix(path, "/membership") {
			return nil
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		failing := mode.Load() == rotationsFailing
		if failing && strings.HasSuffix(path, "/rotations") {
			resp.StatusCode, resp.Status = http.StatusInternalServerError, "500 Internal Server Error"
			data = []byte(`{"error":"disk on fire"}`)
		} else if strings.HasSuffix(path, "/rotations") {
			var out struct {
				Records []e2e.Envelope `json:"records"`
			}
			if err := json.Unmarshal(data, &out); err != nil {
				return err
			}
			out.Records = edit(out.Records)
			data, _ = json.Marshal(out)
		} else {
			var m map[string]json.RawMessage
			var rot map[string][]e2e.Envelope
			if err := json.Unmarshal(data, &m); err != nil {
				return err
			}
			if err := json.Unmarshal(m["rotations"], &rot); err != nil {
				return err
			}
			for id, recs := range rot {
				rot[id] = edit(recs)
				if failing {
					delete(rot, id)
				}
			}
			m["rotations"], _ = json.Marshal(rot)
			data, _ = json.Marshal(m)
		}
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
		return nil
	}
	ts := httptest.NewServer(p)
	t.Cleanup(ts.Close)
	return ts.URL
}

// forkedWorld is a server with ada, who reads it through rotationsProxy, and
// bob, who rotates his keys. ada owns an artifact shared with bob.
func forkedWorld(t *testing.T) (ada, bob func(), artifact string, mode *atomic.Int32) {
	t.Helper()
	host, m := newTestServer(t)
	mode = &atomic.Int32{}
	proxy := rotationsProxy(t, host, mode)
	cfgs := map[string]string{}
	for _, who := range []string{"ada", "bob"} {
		signupVerify(t, host, m, who+"@example.com", sharePassword)
		cfgs[who] = filepath.Join(t.TempDir(), who+".json")
		t.Setenv("CAIRN_CONFIG", cfgs[who])
		h := host
		if who == "ada" {
			h = proxy
		}
		cliLogin(t, h, who+"@example.com", sharePassword)
	}
	ada = func() { t.Setenv("CAIRN_CONFIG", cfgs["ada"]) }
	bob = func() { t.Setenv("CAIRN_CONFIG", cfgs["bob"]) }
	ada()
	a := runJSON[map[string]any](t, artifactCreate, "shared", "--json")
	artifact = a["id"].(string)
	if _, err := runQuiet(t, runShare, artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	return ada, bob, artifact, mode
}

func bobRotates(t *testing.T, bob func()) {
	t.Helper()
	bob()
	withStdin(t, sharePassword+"\n")
	if _, err := runQuiet(t, runRotateKeys, "--password-stdin"); err != nil {
		t.Fatalf("cairn rotate-keys as bob: %v", err)
	}
}

// The warning for a fork reaches the person through the commands, once, with
// the advice; a rollback is worded as what it is.
func TestCommandsWarnOfAForkedOrRolledBackRotation(t *testing.T) {
	ada, bob, artifact, mode := forkedWorld(t)
	bobRotates(t, bob)
	ada()
	mode.Store(rotationsForked)
	for name, run := range map[string]func() error{
		"pin":   func() error { _, err := runQuiet(t, runPin, "bob@example.com"); return err },
		"share": func() error { _, err := runQuiet(t, runShare, artifact, "bob@example.com"); return err },
	} {
		err := run()
		if !errors.Is(err, e2e.ErrRotationFork) {
			t.Fatalf("cairn %s through a forked chain: %v, want ErrRotationFork", name, err)
		}
		for _, want := range []string{
			"WARNING", "conflict with each other or with the record you pinned", "may be an attack",
			"whoever holds one of their old private keys may have signed these",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("cairn %s: message %q lacks %q", name, err, want)
			}
		}
		if n := strings.Count(err.Error(), "--accept-new-key"); n != 1 {
			t.Errorf("cairn %s: message %q gives the advice %d times, want once", name, err, n)
		}
		if strings.Contains(err.Error(), "fewer") || strings.Contains(err.Error(), "someone may hold") {
			t.Errorf("cairn %s: message %q has the wrong or the old wording", name, err)
		}
	}

	// A rollback: ada follows the first rotation, and after the second the
	// server withholds the record she pinned.
	mode.Store(rotationsAsServed)
	if _, err := runQuiet(t, runPin, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	bobRotates(t, bob)
	ada()
	mode.Store(rotationsWithheld)
	_, err := runQuiet(t, runPin, "bob@example.com")
	if !errors.Is(err, e2e.ErrRollback) {
		t.Fatalf("cairn pin with the pinned record withheld: %v, want ErrRollback", err)
	}
	for _, want := range []string{
		"WARNING", "fewer rotation records than you pinned", "may be an attack",
		"which can hide a rotation from you", "confirmed the fingerprint with them over a channel you trust",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "signed these") || strings.Contains(err.Error(), "with the record you pinned") || strings.Count(err.Error(), "--accept-new-key") != 1 {
		t.Errorf("message %q words a rollback as a fork, or gives the advice other than once", err)
	}
}

func TestMembersCommandShowsConflictingRotationRecords(t *testing.T) {
	ada, bob, artifact, mode := forkedWorld(t)
	bobRotates(t, bob)
	ada()
	mode.Store(rotationsForked)
	text, err := runQuiet(t, runMembers, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if l := lineWith(text, "bob@example.com"); !strings.Contains(l, "changed: rotation records conflict") {
		t.Errorf("bob's line = %q, want changed: rotation records conflict", l)
	}
	if rows := membersByEmail(t, artifact); rows["bob@example.com"].State != "conflict" {
		t.Errorf("bob's JSON row = %+v, want state conflict", rows["bob@example.com"])
	}
	// Reading writes nothing: once the records are served again, bob is
	// only rotated.
	mode.Store(rotationsAsServed)
	if rows := membersByEmail(t, artifact); rows["bob@example.com"].State != "rotated" {
		t.Errorf("bob's row afterwards = %+v, want rotated", rows["bob@example.com"])
	}
}

// A rotation list the server fails to serve is not a changed key: the
// commands say so, and give the advice to retry, once.
func TestCommandsAdviseARetryWhenTheRotationRecordsCannotBeRead(t *testing.T) {
	ada, bob, artifact, mode := forkedWorld(t)
	bobRotates(t, bob)
	ada()
	mode.Store(rotationsFailing)
	for name, run := range map[string]func() error{
		"pin":   func() error { _, err := runQuiet(t, runPin, "bob@example.com"); return err },
		"share": func() error { _, err := runQuiet(t, runShare, artifact, "bob@example.com"); return err },
	} {
		err := run()
		var changed *client.KeyChangedError
		if !errors.As(err, &changed) || changed.FetchErr == nil {
			t.Fatalf("cairn %s with the rotation list down: %v, want a KeyChangedError with FetchErr", name, err)
		}
		for _, want := range []string{
			"could not read the rotation records of bob@example.com", "disk on fire (500)",
			"This is usually a network or server fault, and their keys may be fine",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("cairn %s: message %q lacks %q", name, err, want)
			}
		}
		// The error already says to retry, so the advice does not.
		if n := strings.Count(err.Error(), "--accept-new-key"); n != 1 || strings.Contains(err.Error(), "WARNING") ||
			strings.Count(strings.ToLower(err.Error()), "retry") != 1 || strings.Contains(err.Error(), "again") {
			t.Errorf("cairn %s: message %q names the flag %d times, want once, no warning, and one retry", name, err, n)
		}
	}
}

// proxiedTeamWorld is the team world of ada, who owns an artifact shared with
// bob as an editor and with the team as viewers, and cat, who is in the team.
// Ada reads through rotationsProxy.
func proxiedTeamWorld(t *testing.T) (*teamWorld, *atomic.Int32) {
	t.Helper()
	host, m := newTestServer(t)
	mode := &atomic.Int32{}
	proxy := rotationsProxy(t, host, mode)
	w := &teamWorld{m: m, host: host, configs: map[string]string{}}
	for _, who := range []string{"ada", "bob", "cat"} {
		signupVerify(t, host, m, who+"@example.com", sharePassword)
		w.configs[who] = filepath.Join(t.TempDir(), who+".json")
		w.as(t, who)
		h := host
		if who == "ada" {
			h = proxy
		}
		cliLogin(t, h, who+"@example.com", sharePassword)
	}
	w.as(t, "ada")
	w.artifact = runJSON[map[string]any](t, artifactCreate, "shared", "--json")["id"].(string)
	if _, err := runQuiet(t, runShare, w.artifact, "bob@example.com", "--role", "editor"); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runTeam, w.artifact, "viewer"); err != nil {
		t.Fatal(err)
	}
	return w, mode
}

// An approved team member the owner pinned before two rotations is not
// listed when the rotation records fork, are withheld, or cannot be read:
// the owner is warned, or told to retry, instead of being told to share.
func TestTeamWarnsOfAnApprovedUserWhoseRotationRecordsAreInDoubt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  int32
		field string
		want  []string
		once  string // the advice, which must appear once
		lack  string // wording that belongs to another case's advice
	}{
		{"forked", rotationsForked, "rotationConflict", []string{"WARNING", "conflict with each other or with the record you pinned", "may be an attack", "signed these"}, "Do not pass --accept-new-key", "hide a rotation"},
		{"rolled back", rotationsWithheld, "rotationConflict", []string{"WARNING", "fewer rotation records than you pinned", "may be an attack", "hide a rotation"}, "Do not pass --accept-new-key", "signed these"},
		{"unreadable", rotationsFailing, "rotationsUnreadable", []string{"could not read the rotation records of cat@example.com", "disk on fire (500)", "their keys may be fine"}, "retry before considering --accept-new-key", "Run the command again"},
	} {
		w, mode := proxiedTeamWorld(t)
		// Ada pins cat, then again after the first rotation, so that the pin
		// holds a seq, and cat rotates a second time before an editor approves.
		if _, err := runQuiet(t, runPin, "cat@example.com"); err != nil {
			t.Fatal(err)
		}
		rotateAs(t, w, "cat")
		w.as(t, "ada")
		if _, err := runQuiet(t, runPin, "cat@example.com"); err != nil {
			t.Fatal(err)
		}
		rotateAs(t, w, "cat")
		w.as(t, "bob")
		if _, err := runQuiet(t, runApprove, w.artifact, "cat@example.com"); err != nil {
			t.Fatal(err)
		}
		w.as(t, "ada")
		mode.Store(tc.mode)

		text, err := runQuiet(t, runTeam, w.artifact, "viewer")
		if err != nil {
			t.Fatalf("%s: cairn team: %v", tc.name, err)
		}
		for _, want := range append(tc.want, "not listed", "cat@example.com") {
			if !strings.Contains(text, want) {
				t.Errorf("%s: cairn team printed %q, want %q", tc.name, text, want)
			}
		}
		if n := strings.Count(text, "--accept-new-key"); n != 1 || strings.Count(text, tc.once) != 1 {
			t.Errorf("%s: cairn team printed %q, want the advice %q once and no other mention of the flag", tc.name, text, tc.once)
		}
		if strings.Contains(text, tc.lack) {
			t.Errorf("%s: cairn team printed %q, which has the wording %q of another case", tc.name, text, tc.lack)
		}
		if strings.Contains(text, "then run: cairn share") {
			t.Errorf("%s: cairn team printed %q, which tells the owner to share", tc.name, text)
		}
		out := runJSON[struct {
			Unlisted []map[string]string `json:"unlisted"`
		}](t, runTeam, w.artifact, "viewer", "--json")
		if len(out.Unlisted) != 1 || out.Unlisted[0][tc.field] != "true" || len(out.Unlisted[0]) != 6 {
			t.Errorf("%s: cairn team --json unlisted = %v, want one entry with %s true", tc.name, out.Unlisted, tc.field)
		}
	}
}

// A member whose rotation records cannot be read is a changed key to the
// row, which says no more: there is no hint to accept anything.
func TestMembersCommandShowsUnreadableRotationRecordsAsChangedWithoutAdvice(t *testing.T) {
	ada, bob, artifact, mode := forkedWorld(t)
	bobRotates(t, bob)
	ada()
	mode.Store(rotationsFailing)
	text, err := runQuiet(t, runMembers, artifact)
	if err != nil {
		t.Fatal(err)
	}
	l := lineWith(text, "bob@example.com")
	if !strings.Contains(l, "changed") || strings.Contains(l, "conflict") || strings.Contains(l, "rotated") {
		t.Errorf("bob's line = %q, want changed, not conflict or rotated", l)
	}
	if strings.Contains(text, "--accept-new-key") || strings.Contains(text, "cairn share") {
		t.Errorf("cairn members printed %q, which advises the owner", text)
	}
	if rows := membersByEmail(t, artifact); rows["bob@example.com"].State != "changed" {
		t.Errorf("bob's JSON row = %+v, want state changed", rows["bob@example.com"])
	}
}

// A pending entry whose rotation records could not be read says so and to
// retry: it is not told to be shared with again, which would be asking the
// owner to accept keys nobody looked at.
func TestApproveCommandListsAnEntryWhoseRotationRecordsCannotBeReadAsUnreadable(t *testing.T) {
	ada, bob, artifact, mode := forkedWorld(t)
	bobRotates(t, bob)
	ada()
	mode.Store(rotationsFailing)
	text, err := runQuiet(t, runApprove, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if l := lineWith(text, "bob@example.com"); !strings.HasPrefix(l, "keyChanged") {
		t.Errorf("bob's line = %q, want state keyChanged", l)
	}
	want := "keyChanged: the rotation records of bob@example.com could not be read (disk on fire (500)); run cairn approve " + artifact + " again, their keys may be fine"
	if !strings.Contains(text, want) {
		t.Errorf("cairn approve printed %q, want the line %q", text, want)
	}
	if strings.Contains(text, "cairn share") || strings.Contains(text, "shares again") {
		t.Errorf("cairn approve printed %q, which tells the owner to share", text)
	}
	type row struct{ Email, State, RotationsUnreadable string }
	out := runJSON[struct{ Pending []row }](t, runApprove, artifact, "--json")
	if len(out.Pending) != 1 || out.Pending[0].State != "keyChanged" || out.Pending[0].RotationsUnreadable != "true" {
		t.Errorf("cairn approve --json = %+v, want bob keyChanged with rotationsUnreadable true", out.Pending)
	}
	// Served again, the entry is only rotated, and carries no field.
	mode.Store(rotationsAsServed)
	raw := runJSON[struct{ Pending []map[string]string }](t, runApprove, artifact, "--json")
	if len(raw.Pending) != 1 || raw.Pending[0]["state"] != "rotated" {
		t.Fatalf("cairn approve --json afterwards = %+v, want bob rotated", raw.Pending)
	}
	if _, ok := raw.Pending[0]["rotationsUnreadable"]; ok {
		t.Errorf("a readable entry has the field rotationsUnreadable: %v", raw.Pending[0])
	}
}
