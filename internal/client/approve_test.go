package client

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// team is the sharing world plus two more users, cat and dan, who the team
// share leaves waiting for approval.
type team struct {
	*sharing
	cat, dan *Client
}

func newTeam(t *testing.T) *team {
	t.Helper()
	w := &team{sharing: newSharing(t)}
	for _, acct := range []struct {
		email string
		c     **Client
	}{{"cat@example.com", &w.cat}, {"dan@example.com", &w.dan}} {
		signupVerify(t, w.host, w.m, acct.email, testPassword)
		out, err := New(w.host, "").Login(acct.email, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		*acct.c = keyedFor(t, w.host, out.APIKey)
	}
	return w
}

// setup makes bob an editor, and shares with the team as team.
func (w *team) setup(t *testing.T, team string) {
	t.Helper()
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Team(w.artifact, team); err != nil {
		t.Fatalf("Team(%s): %v", team, err)
	}
}

func pendingStates(t *testing.T, c *Client, artifact string) map[string]string {
	t.Helper()
	list, err := c.Pending(artifact)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	out := map[string]string{}
	for _, p := range list {
		out[p.User.Email] = p.State
	}
	return out
}

func wantStates(t *testing.T, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("pending = %v, want %v", got, want)
		return
	}
	for email, state := range want {
		if got[email] != state {
			t.Errorf("pending = %v, want %v", got, want)
			return
		}
	}
}

// rewriting is a copy of c whose GET answers for path are rewritten, and
// that shares c's keys and keyring anchor.
func rewriting(c *Client, path string, rewrite func(body []byte) []byte) *Client {
	out := NewWithKey(c.Host, *c.Key)
	out.Anchors = c.Anchors
	out.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil || r.Method != "GET" || r.URL.Path != path || resp.StatusCode != 200 {
			return resp, err
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		data = rewrite(data)
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
		return resp, nil
	})}
	return out
}

// rewritingList rewrites a JSON array of objects.
func rewritingList(t *testing.T, c *Client, path string, rewrite func([]map[string]any) []map[string]any) *Client {
	return rewriting(c, path, func(body []byte) []byte {
		var list []map[string]any
		if err := json.Unmarshal(body, &list); err != nil {
			t.Error(err)
			return body
		}
		out, err := json.Marshal(rewrite(list))
		if err != nil {
			t.Error(err)
		}
		return out
	})
}

// failing is a copy of c that answers 500 to every POST to path.
func failing(c *Client, path string) *Client {
	out := NewWithKey(c.Host, *c.Key)
	out.Anchors = c.Anchors
	out.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" && r.URL.Path == path {
			return &http.Response{
				StatusCode: 500, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(`{"error":"disk on fire"}`)), Request: r,
			}, nil
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	return out
}

// catEntry is cat's entry in a pending list.
func catEntry(list []map[string]any) map[string]any {
	for _, e := range list {
		if e["email"] == "cat@example.com" {
			return e
		}
	}
	return nil
}

func TestTeamSetsTheShare(t *testing.T) {
	w := newTeam(t)
	res, err := w.ada.Team(w.artifact, "viewer")
	if err != nil {
		t.Fatalf("Team: %v", err)
	}
	if res.Team != "viewer" || res.Epoch != 1 || res.Unchanged {
		t.Errorf("Team result = %+v, want viewer at epoch 1", res)
	}
	m, _ := w.ada.Membership(w.artifact)
	if len(m.Records) != 2 {
		t.Fatalf("%d records, want 2: a same-epoch record", len(m.Records))
	}
	var body e2e.MembershipBody
	if err := json.Unmarshal(m.Records[1].Body, &body); err != nil {
		t.Fatal(err)
	}
	if body.Team != "viewer" || body.Epoch != 1 || body.Seq != 2 {
		t.Errorf("record = team %q epoch %d seq %d, want viewer, 1, 2", body.Team, body.Epoch, body.Seq)
	}

	again, err := w.ada.Team(w.artifact, "viewer")
	if err != nil || !again.Unchanged {
		t.Errorf("Team again = %+v, %v, want unchanged", again, err)
	}
	if m, _ := w.ada.Membership(w.artifact); len(m.Records) != 2 {
		t.Errorf("an unchanged team wrote a record: %d records", len(m.Records))
	}
	if res, err := w.ada.Team(w.artifact, "editor"); err != nil || res.Team != "editor" || res.Unchanged {
		t.Errorf("Team editor = %+v, %v", res, err)
	}
	if res, err := w.ada.Team(w.artifact, "none"); err != nil || res.Team != "none" {
		t.Errorf("Team none with no team member holding a wrap = %+v, %v, want it to land", res, err)
	}
}

func TestTeamRefusals(t *testing.T) {
	w := newTeam(t)
	if _, err := w.ada.Team(w.artifact, "everyone"); err == nil || !strings.Contains(err.Error(), "none, viewer, or editor") {
		t.Errorf("Team everyone: %v, want a message naming none, viewer, or editor", err)
	}
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Team(w.artifact, "viewer"); !errors.Is(err, ErrNotOwner) {
		t.Errorf("a non-owner setting the team: %v, want ErrNotOwner", err)
	}
}

func TestTeamNoneNeedsANextEpochWhileAMemberHoldsAWrap(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	if err := approve(t, w.bob, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	_, err := w.ada.Team(w.artifact, "none")
	if !errors.Is(err, ErrTeamNeedsNextEpoch) {
		t.Fatalf("Team none with cat holding a wrap: %v, want ErrTeamNeedsNextEpoch", err)
	}
	if !strings.Contains(err.Error(), "new epoch") {
		t.Errorf("message %q does not say it needs a new epoch", err)
	}
	if m, _ := w.ada.Membership(w.artifact); len(m.Records) != 3 {
		t.Errorf("a refused change wrote a record: %d records, want 3", len(m.Records))
	}
}

func approve(t *testing.T, c *Client, artifact, who string) error {
	t.Helper()
	_, err := c.Approve(artifact, who, false)
	return err
}

func TestPendingAndApprove(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")

	wantStates(t, pendingStates(t, w.ada, w.artifact), map[string]string{"cat@example.com": "new", "dan@example.com": "new"})
	wantStates(t, pendingStates(t, w.bob, w.artifact), map[string]string{"cat@example.com": "new", "dan@example.com": "new"})
	list, _ := w.ada.Pending(w.artifact)
	cat := list[slices.IndexFunc(list, func(p PendingUser) bool { return p.User.Email == "cat@example.com" })]
	if cat.User.Name != "Ada" || cat.User.FP == "" || cat.Approval != nil || len(cat.User.X25519Pub) != 32 {
		t.Errorf("a pending entry: %+v", cat)
	}

	// Nothing for cat until an editor approves them by name.
	if keys, err := w.cat.Keys(w.artifact); err == nil && len(keys.Wraps) != 0 {
		t.Errorf("cat holds %d wraps before approval", len(keys.Wraps))
	}
	res, err := w.bob.Approve(w.artifact, " Cat@Example.com ", false)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if res.User.Email != "cat@example.com" || res.Prior != e2e.PinNew || res.Epoch != 1 {
		t.Errorf("Approve result = %+v, want cat, a new pin, epoch 1", res)
	}
	if got := openWraps(t, w.cat, w.artifact); len(got) != 1 || got[0] != 1 {
		t.Errorf("cat's wraps = %v, want epoch 1, opened with cat's key and matching the chain's akCommit", got)
	}

	// The owner sees the approval; the editor does not see cat at all.
	wantStates(t, pendingStates(t, w.ada, w.artifact), map[string]string{"cat@example.com": "approved", "dan@example.com": "new"})
	wantStates(t, pendingStates(t, w.bob, w.artifact), map[string]string{"dan@example.com": "new"})
	list, _ = w.ada.Pending(w.artifact)
	for _, p := range list {
		if p.User.Email == "cat@example.com" && (p.Approval == nil || p.Approval.Signer != w.userID(t, w.bob)) {
			t.Errorf("cat's approval: %+v, want one signed by bob", p.Approval)
		}
	}
	// The approver pinned cat, unverified.
	kr, err := w.bob.ReadKeyring(mustUnlock(t, w.bob))
	if err != nil {
		t.Fatal(err)
	}
	if p := kr.Pins[res.User.ID]; p.FP != res.User.FP || p.State != e2e.PinUnverified {
		t.Errorf("bob's pin for cat = %+v, want %s unverified", p, res.User.FP)
	}
	// No membership record changed.
	if m, _ := w.ada.Membership(w.artifact); len(m.Records) != 3 {
		t.Errorf("%d records, want 3: an approval writes none", len(m.Records))
	}
}

func TestApproveRefusals(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, w *team) error
		want error
	}{
		{"a viewer's client never wraps", func(t *testing.T, w *team) error {
			if _, err := w.ada.Share(w.artifact, "bob@example.com", "viewer", false); err != nil {
				t.Fatal(err)
			}
			if _, err := w.ada.Team(w.artifact, "viewer"); err != nil {
				t.Fatal(err)
			}
			return approve(t, w.bob, w.artifact, "cat@example.com")
		}, ErrNotApprover},
		{"a team member", func(t *testing.T, w *team) error {
			w.setup(t, "viewer")
			if err := approve(t, w.bob, w.artifact, "cat@example.com"); err != nil {
				t.Fatal(err)
			}
			return approve(t, w.cat, w.artifact, "dan@example.com")
		}, ErrNotApprover},
		{"team none", func(t *testing.T, w *team) error {
			if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
				t.Fatal(err)
			}
			return approve(t, w.bob, w.artifact, "cat@example.com")
		}, ErrNoTeam},
		{"a listed member", func(t *testing.T, w *team) error {
			w.setup(t, "viewer")
			return approve(t, w.ada, w.artifact, "bob@example.com")
		}, ErrAlreadyListed},
		{"the owner", func(t *testing.T, w *team) error {
			w.setup(t, "viewer")
			return approve(t, w.bob, w.artifact, "ada@example.com")
		}, ErrAlreadyListed},
		{"a user already approved", func(t *testing.T, w *team) error {
			w.setup(t, "viewer")
			if err := approve(t, w.bob, w.artifact, "cat@example.com"); err != nil {
				t.Fatal(err)
			}
			return approve(t, w.ada, w.artifact, "cat@example.com")
		}, ErrAlreadyApproved},
		{"an unknown user", func(t *testing.T, w *team) error {
			w.setup(t, "viewer")
			return approve(t, w.bob, w.artifact, "nobody@example.com")
		}, ErrUnknownUser},
		{"a user whose key changed after approval", func(t *testing.T, w *team) error {
			w.setup(t, "viewer")
			if err := approve(t, w.bob, w.artifact, "cat@example.com"); err != nil {
				t.Fatal(err)
			}
			resetUser(t, w, "cat@example.com", &w.cat)
			return approve(t, w.bob, w.artifact, "cat@example.com")
		}, ErrChangedKey},
		{"a listed user whose key changed", func(t *testing.T, w *team) error {
			w.setup(t, "viewer")
			w.sharing.resetBob(t)
			return approve(t, w.ada, w.artifact, "bob@example.com")
		}, ErrChangedKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newTeam(t)
			if err := c.run(t, w); !errors.Is(err, c.want) {
				t.Errorf("Approve: %v, want %v", err, c.want)
			}
		})
	}
}

// resetUser resets email's account without the recovery code, so its keys
// change, and signs it in again as *c.
func resetUser(t *testing.T, w *team, email string, c **Client) {
	t.Helper()
	if err := New(w.host, "").Forgot(email); err != nil {
		t.Fatal(err)
	}
	if _, err := New(w.host, "").ResetNew(verifyLink(t, w.m, email), "a brand new password"); err != nil {
		t.Fatal(err)
	}
	out, err := New(w.host, "").Login(email, "a brand new password")
	if err != nil {
		t.Fatal(err)
	}
	*c = keyedFor(t, w.host, out.APIKey)
}

// An excluded user, key, or email is refused before the client asks the
// server: the user the directory shows has been rewritten to match an entry
// of the chain's excluded list, and the server would refuse a real one with
// 409.
func TestApproveRefusesAnExcludedUser(t *testing.T) {
	// Bob, an editor, is removed and excluded; cat is waiting.
	setup := func(t *testing.T) (*team, DirectoryUser) {
		w := newTeam(t)
		w.setup(t, "viewer")
		dir, _ := w.ada.Directory()
		bob, err := FindUser(dir, "bob@example.com")
		if err != nil {
			t.Fatal(err)
		}
		writeNextEpoch(t, w.sharing, func(next *e2e.MembershipBody) {
			next.Members = []e2e.Member{}
			next.Excluded = []e2e.ExcludedEntry{{User: bob.ID, FP: bob.FP, Email: bob.Email}}
		})
		return w, bob
	}
	t.Run("by user ID", func(t *testing.T) {
		w, _ := setup(t)
		_, err := w.ada.Approve(w.artifact, "bob@example.com", false)
		if !errors.Is(err, ErrExcluded) {
			t.Errorf("Approve: %v, want ErrExcluded", err)
		}
	})
	for _, tc := range []struct {
		name  string
		forge func(bob DirectoryUser, entry map[string]any) map[string]any
	}{
		{"by fingerprint", func(bob DirectoryUser, e map[string]any) map[string]any {
			e["id"], e["email"] = "impostor", "bob2@example.com"
			return e
		}},
		{"by normalized email", func(bob DirectoryUser, e map[string]any) map[string]any {
			_, pair, _ := strangerKeys(t)
			e["id"], e["email"], e["x25519Pub"], e["ed25519Pub"] = "impostor", " BOB@Example.com", pair.X25519, pair.Ed25519
			return e
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, bob := setup(t)
			c := rewritingList(t, w.ada, "/api/users", func(list []map[string]any) []map[string]any {
				for i, u := range list {
					if u["id"] == bob.ID {
						list[i] = tc.forge(bob, u)
					}
				}
				return list
			})
			_, err := c.Approve(w.artifact, "impostor", false)
			if !errors.Is(err, ErrExcluded) {
				t.Errorf("Approve: %v, want ErrExcluded", err)
			}
		})
	}
}

// writeNextEpoch writes a next-epoch record for the sharing's artifact by
// hand, after edit, with a fresh AK sealed to ada's estate.
func writeNextEpoch(t *testing.T, s *sharing, edit func(next *e2e.MembershipBody)) {
	t.Helper()
	k := mustUnlock(t, s.ada)
	va, err := s.ada.VerifyArtifact(k, s.artifact, k.FP)
	if err != nil {
		t.Fatal(err)
	}
	ak := bytes.Repeat([]byte{byte(va.Chain.Latest.Epoch + 7)}, 32)
	next := va.Chain.Latest
	next.Epoch, next.Seq, next.Prev = next.Epoch+1, next.Seq+1, va.Chain.Head
	next.AKCommit, _ = e2e.AKCommit(ak, s.artifact, uint64(next.Epoch))
	edit(&next)
	body, _ := json.Marshal(next)
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "membership", body)
	if err != nil {
		t.Fatal(err)
	}
	ekKey, _ := e2e.EKSealKey(k.EK)
	sealed, err := e2e.Seal(bytes.NewReader(bytes.Repeat([]byte{3}, 64)), ekKey, estateFields(s.artifact, next.Epoch), ak)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ada.doJSON("PUT", "/api/artifacts/"+s.artifact+"/membership", map[string]any{
		"membership": env, "wraps": []any{}, "linkTokenHash": "",
		"estate": []map[string]any{{"epoch": next.Epoch, "sealed": e2e.B64(sealed)}},
	}, nil); err != nil {
		t.Fatalf("writing the next epoch: %v", err)
	}
}

func TestApproveRefusesADuplicateDirectory(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	c := rewritingList(t, w.bob, "/api/users", func(list []map[string]any) []map[string]any {
		for _, u := range list {
			if u["email"] == "cat@example.com" {
				return append(list, map[string]any{"id": "impostor", "name": "Cat", "email": "CAT@example.com",
					"x25519Pub": u["x25519Pub"], "ed25519Pub": u["ed25519Pub"]})
			}
		}
		return list
	})
	if _, err := c.Approve(w.artifact, "cat@example.com", false); !errors.Is(err, ErrDirectoryDuplicate) {
		t.Errorf("Approve: %v, want ErrDirectoryDuplicate", err)
	}
	if keys, err := w.cat.Keys(w.artifact); err == nil && len(keys.Wraps) != 0 {
		t.Errorf("cat holds %d wraps after a refusal", len(keys.Wraps))
	}
}

func TestApproveChecksThePin(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	pr, err := w.bob.Pin("cat@example.com", true, false)
	if err != nil {
		t.Fatal(err)
	}
	resetUser(t, w, "cat@example.com", &w.cat)

	_, err = w.bob.Approve(w.artifact, "cat@example.com", false)
	var changed *KeyChangedError
	if !errors.As(err, &changed) || changed.PinnedFP != pr.User.FP || changed.CurrentFP == pr.User.FP {
		t.Fatalf("Approve with a changed key: %v, want a KeyChangedError from %s", err, pr.User.FP)
	}
	if keys, err := w.cat.Keys(w.artifact); err == nil && len(keys.Wraps) != 0 {
		t.Errorf("cat holds %d wraps after a refusal", len(keys.Wraps))
	}

	res, err := w.bob.Approve(w.artifact, "cat@example.com", true)
	if err != nil {
		t.Fatalf("Approve --accept-new-key: %v", err)
	}
	if res.Prior != e2e.PinChanged || res.User.FP != changed.CurrentFP {
		t.Errorf("Approve result = %+v, want changed to %s", res, changed.CurrentFP)
	}
	kr, _ := w.bob.ReadKeyring(mustUnlock(t, w.bob))
	if p := kr.Pins[res.User.ID]; p.FP != changed.CurrentFP || p.State != e2e.PinUnverified {
		t.Errorf("bob's pin for cat = %+v, want the new fp, unverified", p)
	}
	if got := openWraps(t, w.cat, w.artifact); len(got) != 1 {
		t.Errorf("cat's wraps under the new key = %v", got)
	}
}

func TestApproveLeavesNoPinWhenTheServerRefuses(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	k := mustUnlock(t, w.bob)
	// Verifying the chain pins its creator, so take the baseline after it.
	if _, _, err := w.bob.Members(w.artifact); err != nil {
		t.Fatal(err)
	}
	before, err := w.bob.ReadKeyring(k)
	if err != nil {
		t.Fatal(err)
	}
	c := failing(w.bob, "/api/artifacts/"+w.artifact+"/keys")
	_, err = c.Approve(w.artifact, "cat@example.com", false)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 500 {
		t.Fatalf("Approve: %v, want the server's 500", err)
	}
	after, err := w.bob.ReadKeyring(k)
	if err != nil {
		t.Fatal(err)
	}
	for id, p := range after.Pins {
		if _, ok := before.Pins[id]; !ok {
			t.Errorf("a failed approval left a pin for %s: %+v", id, p)
		}
	}
}

func TestApproveRefusesAStaleEpoch(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	k := mustUnlock(t, w.bob)
	va, err := w.bob.VerifyArtifact(k, w.artifact, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Epochs[w.artifact] = e2e.KeyringEpoch{Epoch: 2, Seq: 1, Head: e2e.BodyHash(va.Membership.Records[0].Body)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Approve(w.artifact, "cat@example.com", false); !errors.Is(err, e2e.ErrStaleEpoch) {
		t.Errorf("Approve under an epoch older than the pin: %v, want ErrStaleEpoch", err)
	}
	if keys, err := w.cat.Keys(w.artifact); err == nil && len(keys.Wraps) != 0 {
		t.Errorf("cat holds %d wraps after a refusal", len(keys.Wraps))
	}
}

// An approval by an editor who holds a wrap for a later epoch wraps every
// epoch, each opened and checked against the chain's akCommit.
func TestApproveWrapsEveryEpoch(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	// Epoch 2: bob stays an editor, with a wrap for it. Ada's record carries
	// the new epoch's wrap for bob, and the AK the estate holds.
	writeNextEpochKeepingBob(t, w)
	if err := approve(t, w.bob, w.artifact, "cat@example.com"); err != nil {
		t.Fatalf("Approve at epoch 2: %v", err)
	}
	// Each wrap opens, with cat's key, to the AK the chain commits to for its
	// epoch.
	k := mustUnlock(t, w.cat)
	va, err := w.cat.VerifyArtifact(k, w.artifact, "")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := w.cat.Keys(w.artifact)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Wraps) != 2 || keys.Wraps[0].Epoch != 1 || keys.Wraps[1].Epoch != 2 {
		t.Fatalf("cat's wraps: %+v, want epochs 1 and 2", keys.Wraps)
	}
	for _, wr := range keys.Wraps {
		ak, err := e2e.Unwrap(k.X25519Priv, e2e.WrapContext{
			Purpose: "ak", Artifact: w.artifact, Epoch: uint64(wr.Epoch), RecipientID: k.UserID, RecipientPub: k.X25519Pub,
		}, wr.Wrapped)
		if err != nil {
			t.Fatalf("Unwrap epoch %d: %v", wr.Epoch, err)
		}
		if commit, _ := e2e.AKCommit(ak, w.artifact, uint64(wr.Epoch)); commit != epochCommits(va.Chain)[wr.Epoch] {
			t.Errorf("the AK wrapped for epoch %d does not match the chain's akCommit", wr.Epoch)
		}
	}
}

// writeNextEpochKeepingBob starts epoch 2 with bob still an editor. It
// makes the AK for epoch 2 itself, so it can wrap it to bob.
func writeNextEpochKeepingBob(t *testing.T, w *team) {
	t.Helper()
	k := mustUnlock(t, w.ada)
	va, err := w.ada.VerifyArtifact(k, w.artifact, k.FP)
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := w.ada.Directory()
	bob, err := FindUser(dir, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	ak := bytes.Repeat([]byte{42}, 32)
	next := va.Chain.Latest
	next.Epoch, next.Seq, next.Prev = 2, next.Seq+1, va.Chain.Head
	next.AKCommit, _ = e2e.AKCommit(ak, w.artifact, 2)
	wrapped, err := e2e.Wrap(bytes.NewReader(bytes.Repeat([]byte{5}, 64)), e2e.WrapContext{
		Purpose: "ak", Artifact: w.artifact, Epoch: 2, RecipientID: bob.ID, RecipientPub: bob.X25519Pub,
	}, ak)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(next)
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "membership", body)
	if err != nil {
		t.Fatal(err)
	}
	ekKey, _ := e2e.EKSealKey(k.EK)
	sealed, err := e2e.Seal(bytes.NewReader(bytes.Repeat([]byte{3}, 64)), ekKey, estateFields(w.artifact, 2), ak)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.ada.doJSON("PUT", "/api/artifacts/"+w.artifact+"/membership", map[string]any{
		"membership": env, "linkTokenHash": "",
		"wraps":  []map[string]any{{"user": bob.ID, "epoch": 2, "wrapped": e2e.B64(wrapped)}},
		"estate": []map[string]any{{"epoch": 2, "sealed": e2e.B64(sealed)}},
	}, nil); err != nil {
		t.Fatalf("writing epoch 2: %v", err)
	}
}

// The owner's next record lists each approved team member, under the role
// the team share grants, and the record carries no wrap for them.
func TestOwnersRecordListsAnApprovedMember(t *testing.T) {
	for _, team := range []string{"viewer", "editor"} {
		t.Run(team, func(t *testing.T) {
			w := newTeam(t)
			w.setup(t, team)
			if err := approve(t, w.bob, w.artifact, "cat@example.com"); err != nil {
				t.Fatal(err)
			}
			res, err := w.ada.Share(w.artifact, "dan@example.com", "viewer", false)
			if err != nil {
				t.Fatalf("Share: %v", err)
			}
			if len(res.Listed) != 1 || res.Listed[0].Email != "cat@example.com" || len(res.Unlisted) != 0 {
				t.Errorf("Share listed %+v, unlisted %+v, want cat listed", res.Listed, res.Unlisted)
			}
			rows := memberRows(t, w.ada, w.artifact)
			if r := rows["cat@example.com"]; r.Role != team {
				t.Errorf("cat's row = %+v, want a %s", r, team)
			}
			if r := rows["dan@example.com"]; r.Role != "viewer" {
				t.Errorf("dan's row = %+v, want the viewer he was shared as", r)
			}
			// Listed, cat is no longer waiting, and still holds the one wrap.
			wantStates(t, pendingStates(t, w.ada, w.artifact), map[string]string{})
			if got := openWraps(t, w.cat, w.artifact); len(got) != 1 {
				t.Errorf("cat's wraps = %v", got)
			}
		})
	}
}

func TestTeamListsAnApprovedMemberUnderTheNewRole(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	if err := approve(t, w.bob, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	res, err := w.ada.Team(w.artifact, "editor")
	if err != nil {
		t.Fatalf("Team editor: %v", err)
	}
	if len(res.Listed) != 1 || res.Listed[0].Email != "cat@example.com" {
		t.Errorf("Team listed %+v, want cat", res.Listed)
	}
	if r := memberRows(t, w.ada, w.artifact)["cat@example.com"]; r.Role != "editor" {
		t.Errorf("cat's row = %+v, want an editor: the role the new team grants", r)
	}
}

// Sharing by name with a user an editor approved needs no wrap: they hold
// one already, and the server refuses a second.
func TestShareByNameListsAnApprovedUserWithoutWraps(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	if err := approve(t, w.bob, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	res, err := w.ada.Share(w.artifact, "cat@example.com", "editor", false)
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if res.Role != "editor" || len(res.Listed) != 0 {
		t.Errorf("Share result = %+v, want cat shared by name, nothing else listed", res)
	}
	if r := memberRows(t, w.ada, w.artifact)["cat@example.com"]; r.Role != "editor" {
		t.Errorf("cat's row = %+v, want an editor", r)
	}
}

// The four checks. Each case changes what the server serves, or the chain,
// so that exactly one check fails, and the owner's client must report the
// user instead of listing them.
func TestOwnersClientAsksWhenAnApprovalFails(t *testing.T) {
	type world struct {
		*team
		cat DirectoryUser
	}
	// signAs signs an approval of (user, fp) at epoch as c.
	signAs := func(t *testing.T, c *Client, w *world, epoch int, user, fp string) e2e.Envelope {
		t.Helper()
		k := mustUnlock(t, c)
		raw, _ := json.Marshal(e2e.ApprovalBody{V: 1, Artifact: w.artifact, Epoch: epoch, User: user, FP: fp})
		env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "approval", raw)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	// entry is a pending entry for a user, approved by approval.
	entry := func(id, email string, pair e2e.KeyPair, approval any) map[string]any {
		return map[string]any{"id": id, "name": "Forged", "email": email, "x25519Pub": pair.X25519,
			"ed25519Pub": pair.Ed25519, "state": "approved", "approval": approval}
	}
	catPair := func(w *world) e2e.KeyPair {
		return e2e.KeyPair{X25519: e2e.B64(w.cat.X25519Pub), Ed25519: e2e.B64(w.cat.Ed25519Pub)}
	}
	// excludeCat starts epoch 2 with bob and cat removed and excluded.
	excludeCat := func(t *testing.T, w *world) {
		dir, _ := w.ada.Directory()
		bob, _ := FindUser(dir, "bob@example.com")
		writeNextEpoch(t, w.sharing, func(next *e2e.MembershipBody) {
			next.Members = []e2e.Member{}
			next.Excluded = []e2e.ExcludedEntry{
				{User: bob.ID, FP: bob.FP, Email: bob.Email},
				{User: w.cat.ID, FP: w.cat.FP, Email: w.cat.Email},
			}
			if next.Excluded[0].User > next.Excluded[1].User {
				next.Excluded[0], next.Excluded[1] = next.Excluded[1], next.Excluded[0]
			}
		})
	}
	cases := []struct {
		name string
		want error
		// early runs before bob approves cat, and prepare after.
		early   func(t *testing.T, w *world)
		prepare func(t *testing.T, w *world)
		// pending changes the owner's view of GET /pending.
		pending func(t *testing.T, w *world, list []map[string]any) []map[string]any
		// dir changes the owner's view of the directory.
		dir func(t *testing.T, w *world, list []map[string]any) []map[string]any
		// who is the email of the user that must be reported.
		who string
	}{
		{name: "no approval", want: e2e.ErrApprovalMissing, who: "cat@example.com",
			pending: func(t *testing.T, w *world, list []map[string]any) []map[string]any {
				catEntry(list)["approval"] = nil
				return list
			}},
		{name: "a signature that does not verify", want: e2e.ErrDecrypt, who: "cat@example.com",
			pending: func(t *testing.T, w *world, list []map[string]any) []map[string]any {
				env := catEntry(list)["approval"].(map[string]any)
				sig, _ := e2e.UnB64(env["sig"].(string))
				sig[0] ^= 1
				env["sig"] = e2e.B64(sig)
				return list
			}},
		{name: "a signer who is not an editor", want: e2e.ErrApprovalSigner, who: "cat@example.com",
			pending: func(t *testing.T, w *world, list []map[string]any) []map[string]any {
				catEntry(list)["approval"] = signAs(t, w.dan, w, 1, w.cat.ID, w.cat.FP)
				return list
			}},
		{name: "an old epoch", want: e2e.ErrApprovalMismatch, who: "cat@example.com",
			early: func(t *testing.T, w *world) { writeNextEpochKeepingBob(t, w.team) },
			pending: func(t *testing.T, w *world, list []map[string]any) []map[string]any {
				catEntry(list)["approval"] = signAs(t, w.ada, w, 1, w.cat.ID, w.cat.FP)
				return list
			}},
		{name: "another fingerprint", want: e2e.ErrApprovalMismatch, who: "cat@example.com",
			pending: func(t *testing.T, w *world, list []map[string]any) []map[string]any {
				catEntry(list)["approval"] = signAs(t, w.ada, w, 1, w.cat.ID, strings.Repeat("ab", 32))
				return list
			}},
		{name: "another user", want: e2e.ErrApprovalMismatch, who: "cat@example.com",
			pending: func(t *testing.T, w *world, list []map[string]any) []map[string]any {
				catEntry(list)["approval"] = signAs(t, w.ada, w, 1, w.userID(t, w.dan), w.cat.FP)
				return list
			}},
		{name: "a user matching an excluded user ID", want: e2e.ErrApprovalExcluded, who: "cat@example.com",
			prepare: excludeCat,
			pending: func(t *testing.T, w *world, list []map[string]any) []map[string]any {
				return append(list, entry(w.cat.ID, w.cat.Email, catPair(w), signAs(t, w.ada, w, 2, w.cat.ID, w.cat.FP)))
			}},
		{name: "a user matching an excluded fingerprint", want: e2e.ErrApprovalExcluded, who: "twin@example.com",
			prepare: excludeCat,
			pending: func(t *testing.T, w *world, list []map[string]any) []map[string]any {
				return append(list, entry("twin", "twin@example.com", catPair(w), signAs(t, w.ada, w, 2, "twin", w.cat.FP)))
			}},
		{name: "a user matching an excluded normalized email", want: e2e.ErrApprovalExcluded, who: "cat@example.com",
			prepare: excludeCat,
			pending: func(t *testing.T, w *world, list []map[string]any) []map[string]any {
				_, pair, fp := strangerKeys(t)
				return append(list, entry("twin", " CAT@Example.com", pair, signAs(t, w.ada, w, 2, "twin", fp)))
			}},
		{name: "directory keys that differ from the pending entry's", want: ErrPendingKeysDiffer, who: "cat@example.com",
			dir: func(t *testing.T, w *world, list []map[string]any) []map[string]any {
				_, pair, _ := strangerKeys(t)
				for _, e := range list {
					if e["id"] == w.cat.ID {
						e["x25519Pub"], e["ed25519Pub"] = pair.X25519, pair.Ed25519
					}
				}
				return list
			}},
		{name: "another user ID sharing the email", want: e2e.ErrApprovalDuplicate, who: "cat@example.com",
			dir: func(t *testing.T, w *world, list []map[string]any) []map[string]any {
				_, pair, _ := strangerKeys(t)
				return append(list, map[string]any{"id": "impostor", "name": "Cat", "email": " CAT@example.com",
					"x25519Pub": pair.X25519, "ed25519Pub": pair.Ed25519})
			}},
		{name: "another user ID sharing the fingerprint", want: e2e.ErrApprovalDuplicate, who: "cat@example.com",
			dir: func(t *testing.T, w *world, list []map[string]any) []map[string]any {
				return append(list, map[string]any{"id": "impostor", "name": "Cat", "email": "cat2@example.com",
					"x25519Pub": e2e.B64(w.cat.X25519Pub), "ed25519Pub": e2e.B64(w.cat.Ed25519Pub)})
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := &world{team: newTeam(t)}
			w.setup(t, "viewer")
			dir, _ := w.ada.Directory()
			w.cat, _ = FindUser(dir, "cat@example.com")
			if c.early != nil {
				c.early(t, w)
			}
			if err := approve(t, w.bob, w.artifact, "cat@example.com"); err != nil {
				t.Fatal(err)
			}
			if c.prepare != nil {
				c.prepare(t, w)
			}
			owner := w.ada
			if c.pending != nil {
				owner = rewritingList(t, owner, "/api/artifacts/"+w.artifact+"/pending", func(list []map[string]any) []map[string]any {
					return c.pending(t, w, list)
				})
			}
			if c.dir != nil {
				owner = rewritingList(t, owner, "/api/users", func(list []map[string]any) []map[string]any { return c.dir(t, w, list) })
			}
			res, err := owner.Team(w.artifact, "editor")
			if err != nil {
				t.Fatalf("Team: %v", err)
			}
			if len(res.Listed) != 0 || len(res.Unlisted) != 1 {
				t.Fatalf("listed %+v, unlisted %+v, want one user reported and none listed", res.Listed, res.Unlisted)
			}
			u := res.Unlisted[0]
			if !errors.Is(u.Err, c.want) || e2e.NormalizeEmail(u.User.Email) != e2e.NormalizeEmail(c.who) || u.User.FP == "" || u.User.Name == "" {
				t.Errorf("reported %s (%s) with %v, want %s with %v", u.User.Email, u.User.FP, u.Err, c.who, c.want)
			}
			_, rows, err := w.ada.Members(w.artifact)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range rows {
				if r.Email == "cat@example.com" || r.User == "twin" {
					t.Errorf("the record lists %+v", r)
				}
			}
		})
	}
}

// The owner holds no wraps: their approval wraps from the estate copies.
func TestOwnerApproves(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	if _, err := w.ada.Approve(w.artifact, "dan@example.com", false); err != nil {
		t.Fatalf("Approve as the owner: %v", err)
	}
	if got := openWraps(t, w.dan, w.artifact); len(got) != 1 || got[0] != 1 {
		t.Errorf("dan's wraps = %v, want epoch 1", got)
	}
	list, _ := w.ada.Pending(w.artifact)
	for _, p := range list {
		if p.User.Email == "dan@example.com" && (p.State != PendingApproved || p.Approval == nil || p.Approval.Signer != w.userID(t, w.ada)) {
			t.Errorf("dan's entry = %+v, want approved, signed by ada", p)
		}
	}
}

// An approver whose own wrap does not open to the AK the chain commits to
// wraps nothing: the server's copy of the wrap could be anyone's.
func TestApproveRefusesAWrapThatMissesTheCommit(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	k := mustUnlock(t, w.bob)
	wrong, err := e2e.Wrap(rand.Reader, e2e.WrapContext{
		Purpose: "ak", Artifact: w.artifact, Epoch: 1, RecipientID: k.UserID, RecipientPub: k.X25519Pub,
	}, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c := rewriting(w.bob, "/api/artifacts/"+w.artifact+"/keys", func(body []byte) []byte {
		var keys map[string]any
		if err := json.Unmarshal(body, &keys); err != nil {
			t.Error(err)
		}
		keys["wraps"].([]any)[0].(map[string]any)["wrapped"] = e2e.B64(wrong)
		out, _ := json.Marshal(keys)
		return out
	})
	if _, err := c.Approve(w.artifact, "cat@example.com", false); !errors.Is(err, e2e.ErrChain) {
		t.Errorf("Approve with a wrap that misses the commit: %v, want ErrChain", err)
	}
	if keys, err := w.cat.Keys(w.artifact); err == nil && len(keys.Wraps) != 0 {
		t.Errorf("cat holds %d wraps after a refusal", len(keys.Wraps))
	}
}

// The keys the pending list serves for a user must be the directory's.
func TestApproveRefusesPendingKeysThatDifferFromTheDirectory(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	_, pair, _ := strangerKeys(t)
	c := rewritingList(t, w.bob, "/api/artifacts/"+w.artifact+"/pending", func(list []map[string]any) []map[string]any {
		e := catEntry(list)
		e["x25519Pub"], e["ed25519Pub"] = pair.X25519, pair.Ed25519
		return list
	})
	if _, err := c.Approve(w.artifact, "cat@example.com", false); err == nil || !strings.Contains(err.Error(), "different keys") {
		t.Errorf("Approve: %v, want a refusal naming different keys", err)
	}
}

// An owner who pinned a user's earlier key is asked, not told: the approved
// keys contradict the pin, so the record does not list them.
func TestOwnersClientAsksWhenTheApprovedKeysContradictItsPin(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	pinned, err := w.ada.Pin("cat@example.com", true, false)
	if err != nil {
		t.Fatal(err)
	}
	resetUser(t, w, "cat@example.com", &w.cat)
	if _, err := w.bob.Approve(w.artifact, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	res, err := w.ada.Team(w.artifact, "editor")
	if err != nil {
		t.Fatal(err)
	}
	var changed *KeyChangedError
	if len(res.Listed) != 0 || len(res.Unlisted) != 1 || !errors.As(res.Unlisted[0].Err, &changed) || changed.PinnedFP != pinned.User.FP {
		t.Errorf("listed %+v, unlisted %+v, want cat reported with a KeyChangedError from %s", res.Listed, res.Unlisted, pinned.User.FP)
	}
}

// A listed member whose key changed holds no team wrap, so team none does
// not need a new epoch for them.
func TestTeamNoneIgnoresAListedMemberWhoseKeyChanged(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	w.sharing.resetBob(t)
	if states := pendingStates(t, w.ada, w.artifact); states["bob@example.com"] != PendingKeyChanged {
		t.Fatalf("pending = %v, want bob keyChanged", states)
	}
	if res, err := w.ada.Team(w.artifact, "none"); err != nil || res.Team != "none" {
		t.Errorf("Team none = %+v, %v, want it to land", res, err)
	}
}

// Only the owner or a listed editor, under the fingerprint the record lists,
// may approve.
func TestApproverOf(t *testing.T) {
	latest := e2e.MembershipBody{Owner: "o", OwnerFP: "ofp", Members: []e2e.Member{
		{User: "e", Role: "editor", FP: "efp"}, {User: "v", Role: "viewer", FP: "vfp"},
	}}
	for _, c := range []struct {
		name, user, fp string
		want           bool
	}{
		{"the owner", "o", "ofp", true},
		{"the owner under other keys", "o", "other", false},
		{"a listed editor", "e", "efp", true},
		{"a listed editor under other keys", "e", "other", false},
		{"a viewer", "v", "vfp", false},
		{"a stranger", "x", "ofp", false},
	} {
		if got := approverOf(latest, &UnlockedKeys{UserID: c.user, FP: c.fp}); got != c.want {
			t.Errorf("%s: approverOf = %v, want %v", c.name, got, c.want)
		}
	}
}

// A user the server does not list as waiting is not approved, even though the
// directory shows them: the server's pending list is the only way to a wrap.
func TestApproveRefusesAUserTheServerDoesNotListAsWaiting(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	c := rewritingList(t, w.bob, "/api/artifacts/"+w.artifact+"/pending", func(list []map[string]any) []map[string]any {
		kept := list[:0]
		for _, e := range list {
			if e["email"] != "cat@example.com" {
				kept = append(kept, e)
			}
		}
		return kept
	})
	if _, err := c.Approve(w.artifact, "cat@example.com", false); !errors.Is(err, ErrNotWaiting) {
		t.Errorf("Approve: %v, want ErrNotWaiting", err)
	}
	if keys, err := w.cat.Keys(w.artifact); err == nil && len(keys.Wraps) != 0 {
		t.Errorf("cat holds %d wraps after a refusal", len(keys.Wraps))
	}
}

// Sharing by name with a user the server reports as approved skips the
// wraps, so the owner's client runs the same checks listApproved does, and
// the directory's fingerprint must be the one approved. A failing user is
// not listed, and nothing is pinned.
func TestShareByNameRefusesAnApprovalThatDoesNotCheckOut(t *testing.T) {
	cases := []struct {
		name    string
		want    error
		pending func(t *testing.T, w *team, list []map[string]any) []map[string]any
	}{
		{"an approval of another fingerprint", e2e.ErrApprovalMismatch,
			func(t *testing.T, w *team, list []map[string]any) []map[string]any {
				k := mustUnlock(t, w.ada)
				raw, _ := json.Marshal(e2e.ApprovalBody{V: 1, Artifact: w.artifact, Epoch: 1, User: w.userID(t, w.cat), FP: strings.Repeat("ab", 32)})
				env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "approval", raw)
				if err != nil {
					t.Fatal(err)
				}
				catEntry(list)["approval"] = env
				return list
			}},
		{"a signature that does not verify", e2e.ErrDecrypt,
			func(t *testing.T, w *team, list []map[string]any) []map[string]any {
				env := catEntry(list)["approval"].(map[string]any)
				sig, _ := e2e.UnB64(env["sig"].(string))
				sig[0] ^= 1
				env["sig"] = e2e.B64(sig)
				return list
			}},
		{"no approval", e2e.ErrApprovalMissing,
			func(t *testing.T, w *team, list []map[string]any) []map[string]any {
				catEntry(list)["approval"] = nil
				return list
			}},
		{"pending keys that differ from the directory's", ErrPendingKeysDiffer,
			func(t *testing.T, w *team, list []map[string]any) []map[string]any {
				_, pair, _ := strangerKeys(t)
				e := catEntry(list)
				e["x25519Pub"], e["ed25519Pub"] = pair.X25519, pair.Ed25519
				return list
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newTeam(t)
			w.setup(t, "viewer")
			if err := approve(t, w.bob, w.artifact, "cat@example.com"); err != nil {
				t.Fatal(err)
			}
			owner := rewritingList(t, w.ada, "/api/artifacts/"+w.artifact+"/pending", func(list []map[string]any) []map[string]any {
				return c.pending(t, w, list)
			})
			res, err := owner.Share(w.artifact, "cat@example.com", "viewer", false)
			if !errors.Is(err, ErrApprovalUnverified) || !errors.Is(err, c.want) {
				t.Fatalf("Share = %+v, %v, want ErrApprovalUnverified wrapping %v", res, err, c.want)
			}
			if !strings.Contains(err.Error(), "new epoch") {
				t.Errorf("message %q does not say fixing it needs a new epoch", err)
			}
			if m, _ := w.ada.Membership(w.artifact); len(m.Records) != 3 {
				t.Errorf("a refused share wrote a record: %d records, want 3", len(m.Records))
			}
			if r, ok := memberRows(t, w.ada, w.artifact)["cat@example.com"]; ok {
				t.Errorf("the record lists %+v", r)
			}
			kr, err := w.ada.ReadKeyring(mustUnlock(t, w.ada))
			if err != nil {
				t.Fatal(err)
			}
			if p, ok := kr.Pins[w.userID(t, w.cat)]; ok {
				t.Errorf("a pin was stored for cat: %+v", p)
			}
		})
	}
}
