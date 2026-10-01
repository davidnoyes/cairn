package client

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
)

const testPassword = "correct horse battery staple"

// sharing is a server with two accounts, ada (who owns an artifact) and
// bob, each with a keyed client.
type sharing struct {
	host     string
	m        *mail.Capture
	ada, bob *Client
	artifact string
}

func newSharing(t *testing.T) *sharing {
	t.Helper()
	host, m := newTestServer(t)
	s := &sharing{host: host, m: m}
	for _, acct := range []struct {
		email string
		c     **Client
	}{{"ada@example.com", &s.ada}, {"bob@example.com", &s.bob}} {
		signupVerify(t, host, m, acct.email, testPassword)
		out, err := New(host, "").Login(acct.email, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		*acct.c = keyedFor(t, host, out.APIKey)
	}
	a, err := s.ada.CreateArtifact("shared", "")
	if err != nil {
		t.Fatal(err)
	}
	s.artifact = a.ID
	return s
}

func (s *sharing) userID(t *testing.T, c *Client) string {
	t.Helper()
	me, err := c.Me()
	if err != nil {
		t.Fatal(err)
	}
	return me.ID
}

// resetBob resets bob's account without the recovery code, so his keys
// change, and signs him in again.
func (s *sharing) resetBob(t *testing.T) {
	t.Helper()
	if err := New(s.host, "").Forgot("bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(s.host, "").ResetNew(verifyLink(t, s.m, "bob@example.com"), "a brand new password"); err != nil {
		t.Fatal(err)
	}
	out, err := New(s.host, "").Login("bob@example.com", "a brand new password")
	if err != nil {
		t.Fatal(err)
	}
	s.bob = keyedFor(t, s.host, out.APIKey)
}

// openWraps unwraps every AK wrap c holds for the artifact and checks each
// against the chain's akCommit, returning the epochs it opened.
func openWraps(t *testing.T, c *Client, artifact string) []int {
	t.Helper()
	k := mustUnlock(t, c)
	va, err := c.VerifyArtifact(k, artifact, "")
	if err != nil {
		t.Fatalf("VerifyArtifact: %v", err)
	}
	keys, err := c.Keys(artifact)
	if err != nil {
		t.Fatal(err)
	}
	var epochs []int
	for _, w := range keys.Wraps {
		ak, err := e2e.Unwrap(k.X25519Priv, e2e.WrapContext{
			Purpose: "ak", Artifact: artifact, Epoch: uint64(w.Epoch), RecipientID: k.UserID, RecipientPub: k.X25519Pub,
		}, w.Wrapped)
		if err != nil {
			t.Fatalf("Unwrap epoch %d: %v", w.Epoch, err)
		}
		commit, _ := e2e.AKCommit(ak, artifact, uint64(w.Epoch))
		if commit != va.Chain.Bodies[0].AKCommit {
			t.Errorf("the AK wrapped for epoch %d does not match the chain's akCommit", w.Epoch)
		}
		epochs = append(epochs, w.Epoch)
	}
	return epochs
}

func memberRows(t *testing.T, c *Client, artifact string) map[string]MemberView {
	t.Helper()
	_, rows, err := c.Members(artifact)
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	out := map[string]MemberView{}
	for _, r := range rows {
		out[r.Email] = r
	}
	return out
}

func TestShareAddsAMember(t *testing.T) {
	s := newSharing(t)
	res, err := s.ada.Share(s.artifact, " Bob@Example.com ", "viewer", false)
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if res.Prior != e2e.PinNew || res.Role != "viewer" || res.Promoted || res.Unchanged || res.Epoch != 1 {
		t.Errorf("Share result = %+v, want a new viewer at epoch 1", res)
	}
	if got := openWraps(t, s.bob, s.artifact); len(got) != 1 || got[0] != 1 {
		t.Errorf("bob's wraps = %v, want epoch 1", got)
	}

	kr, err := s.ada.ReadKeyring(mustUnlock(t, s.ada))
	if err != nil {
		t.Fatal(err)
	}
	bobID := s.userID(t, s.bob)
	if p := kr.Pins[bobID]; p.FP != res.User.FP || p.State != e2e.PinUnverified {
		t.Errorf("ada's pin for bob = %+v, want %s unverified", p, res.User.FP)
	}
	if e := kr.Epochs[s.artifact]; e.Epoch != 1 || e.Seq != 2 {
		t.Errorf("ada's epochs entry = %+v, want epoch 1 seq 2 after the share", e)
	}

	rows := memberRows(t, s.ada, s.artifact)
	if r := rows["ada@example.com"]; r.Role != "owner" || r.State != "self" {
		t.Errorf("ada's row = %+v, want owner, self", r)
	}
	if r := rows["bob@example.com"]; r.Role != "viewer" || r.State != e2e.PinUnverified || r.FP != res.User.FP {
		t.Errorf("bob's row = %+v, want viewer, unverified, %s", r, res.User.FP)
	}
	// Bob sees ada for the first time through the chain, and pins her.
	if r := memberRows(t, s.bob, s.artifact)["ada@example.com"]; r.Role != "owner" || r.State != e2e.PinUnverified {
		t.Errorf("ada's row as bob sees it = %+v, want owner, unverified", r)
	}

	pr, err := s.ada.Pin("bob@example.com", true, false)
	if err != nil {
		t.Fatalf("Pin --verified: %v", err)
	}
	if pr.Prior != e2e.PinUnverified || pr.State != e2e.PinVerified {
		t.Errorf("Pin result = %+v, want unverified to verified", pr)
	}
	if r := memberRows(t, s.ada, s.artifact)["bob@example.com"]; r.State != e2e.PinVerified {
		t.Errorf("bob's row after pinning = %+v, want verified", r)
	}
}

func TestSharePromotesAndRefusesDemotion(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	res, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false)
	if err != nil || !res.Unchanged {
		t.Errorf("sharing again with the same role: %+v, %v, want unchanged", res, err)
	}
	res, err = s.ada.Share(s.artifact, "bob@example.com", "editor", false)
	if err != nil || !res.Promoted {
		t.Fatalf("promoting: %+v, %v, want promoted", res, err)
	}
	if r := memberRows(t, s.ada, s.artifact)["bob@example.com"]; r.Role != "editor" {
		t.Errorf("bob's row = %+v, want editor", r)
	}
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); !errors.Is(err, ErrNeedsNextEpoch) {
		t.Errorf("demoting: %v, want ErrNeedsNextEpoch", err)
	}
	m, _ := s.ada.Membership(s.artifact)
	if len(m.Records) != 3 {
		t.Errorf("%d records, want 3: the unchanged share and the demotion must write nothing", len(m.Records))
	}
}

func TestShareRefusals(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "admin", false); err == nil || !strings.Contains(err.Error(), "role must be viewer or editor") {
		t.Errorf("an unknown role: %v", err)
	}
	if _, err := s.ada.Share(s.artifact, "nobody@example.com", "viewer", false); !errors.Is(err, ErrUnknownUser) {
		t.Errorf("an unknown user: %v, want ErrUnknownUser", err)
	}
	if _, err := s.ada.Share(s.artifact, "ada@example.com", "viewer", false); !errors.Is(err, ErrShareSelf) {
		t.Errorf("sharing with the owner: %v, want ErrShareSelf", err)
	}
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.bob.Share(s.artifact, "ada@example.com", "viewer", false); !errors.Is(err, ErrNotOwner) {
		t.Errorf("a member sharing: %v, want ErrNotOwner", err)
	}
}

// TestShareRefusesAChangedKey resets bob without his recovery code, so his
// keys change, and checks ada must accept the new key explicitly.
func TestShareRefusesAChangedKey(t *testing.T) {
	s := newSharing(t)
	first, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false)
	if err != nil {
		t.Fatal(err)
	}
	s.resetBob(t)

	if r := memberRows(t, s.ada, s.artifact)["bob@example.com"]; r.State != e2e.PinChanged {
		t.Errorf("bob's row after his reset = %+v, want changed", r)
	}
	_, err = s.ada.Share(s.artifact, "bob@example.com", "editor", false)
	var changed *KeyChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("sharing with a changed key: %v, want a KeyChangedError", err)
	}
	if changed.PinnedFP != first.User.FP || changed.CurrentFP == first.User.FP || changed.ResetAt == "" {
		t.Errorf("KeyChangedError = %+v, want pinned %s, a new fp, and resetAt", changed, first.User.FP)
	}
	for _, want := range []string{formatHexFP(changed.PinnedFP), formatHexFP(changed.CurrentFP), changed.ResetAt, "--accept-new-key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err, want)
		}
	}
	if _, err := s.ada.Pin("bob@example.com", false, false); !errors.As(err, &changed) {
		t.Errorf("pinning a changed key: %v, want a KeyChangedError", err)
	}

	res, err := s.ada.Share(s.artifact, "bob@example.com", "editor", true)
	if err != nil {
		t.Fatalf("Share --accept-new-key: %v", err)
	}
	if res.Prior != e2e.PinChanged || res.User.FP != changed.CurrentFP {
		t.Errorf("Share result = %+v, want changed to the new fp", res)
	}
	if r := memberRows(t, s.ada, s.artifact)["bob@example.com"]; r.State != e2e.PinUnverified || r.FP != changed.CurrentFP || r.Role != "editor" {
		t.Errorf("bob's row = %+v, want an unverified editor under the new fp", r)
	}
	if got := openWraps(t, s.bob, s.artifact); len(got) != 1 || got[0] != 1 {
		t.Errorf("bob's wraps under his new key = %v, want epoch 1", got)
	}
}

// excludeBob writes the next epoch's record by hand: bob removed and
// excluded, with a fresh AK sealed to ada's estate.
func excludeBob(t *testing.T, s *sharing) {
	t.Helper()
	k := mustUnlock(t, s.ada)
	va, err := s.ada.VerifyArtifact(k, s.artifact, k.FP)
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := s.ada.Directory()
	bob, err := FindUser(dir, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	ak := make([]byte, 32)
	rand.Read(ak)
	next := va.Chain.Latest
	next.Epoch, next.Seq, next.Prev = 2, next.Seq+1, va.Chain.Head
	next.AKCommit, _ = e2e.AKCommit(ak, s.artifact, 2)
	next.Members = []e2e.Member{}
	next.Excluded = []e2e.ExcludedEntry{{User: bob.ID, FP: bob.FP, Email: bob.Email}}
	body, _ := json.Marshal(next)
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "membership", body)
	if err != nil {
		t.Fatal(err)
	}
	ekKey, _ := e2e.EKSealKey(k.EK)
	sealed, err := e2e.Seal(rand.Reader, ekKey, estateFields(s.artifact, 2), ak)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ada.doJSON("PUT", "/api/artifacts/"+s.artifact+"/membership", map[string]any{
		"membership": env, "wraps": []any{}, "linkTokenHash": "",
		"estate": []map[string]any{{"epoch": 2, "sealed": e2e.B64(sealed)}},
	}, nil); err != nil {
		t.Fatalf("writing the exclusion: %v", err)
	}
}

func TestShareRefusesAnExcludedUser(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	excludeBob(t, s)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); !errors.Is(err, ErrExcluded) {
		t.Errorf("sharing with an excluded user: %v, want ErrExcluded", err)
	}
	m, _ := s.ada.Membership(s.artifact)
	if len(m.Records) != 3 {
		t.Errorf("%d records, want 3", len(m.Records))
	}
}

func TestExcludedMatch(t *testing.T) {
	excluded := []e2e.ExcludedEntry{
		{User: "u1", FP: strings.Repeat("a", 64), Email: "bob@example.com"},
		{User: "u9", FP: strings.Repeat("9", 64), Email: " Carol@Example.com"},
	}
	for _, tc := range []struct {
		name string
		u    DirectoryUser
		want bool
	}{
		{"same id", DirectoryUser{ID: "u1", FP: strings.Repeat("b", 64), Email: "x@example.com"}, true},
		{"same fingerprint", DirectoryUser{ID: "u2", FP: strings.Repeat("a", 64), Email: "x@example.com"}, true},
		{"same email, other case", DirectoryUser{ID: "u2", FP: strings.Repeat("b", 64), Email: " BOB@example.com"}, true},
		{"an entry's email in another case", DirectoryUser{ID: "u2", FP: strings.Repeat("b", 64), Email: "carol@example.com"}, true},
		{"no match", DirectoryUser{ID: "u2", FP: strings.Repeat("b", 64), Email: "x@example.com"}, false},
	} {
		if got := ExcludedMatch(excluded, tc.u) != nil; got != tc.want {
			t.Errorf("%s: matched %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCheckDirectory(t *testing.T) {
	a := DirectoryUser{ID: "u1", Email: "ada@example.com", FP: strings.Repeat("a", 64)}
	for _, tc := range []struct {
		name string
		dir  []DirectoryUser
		want error
	}{
		{"distinct", []DirectoryUser{a, {ID: "u2", Email: "bob@example.com", FP: strings.Repeat("b", 64)}}, nil},
		{"shared email", []DirectoryUser{a, {ID: "u2", Email: "ADA@example.com ", FP: strings.Repeat("b", 64)}}, ErrDirectoryDuplicate},
		{"shared fingerprint", []DirectoryUser{a, {ID: "u2", Email: "bob@example.com", FP: a.FP}}, ErrDirectoryDuplicate},
	} {
		if err := CheckDirectory(tc.dir); !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

// directoryProxy rewrites the GET /api/users list, and each GET
// /api/users/{id} answer as a list of one.
func directoryProxy(t *testing.T, host string, rewrite func([]map[string]any) []map[string]any) string {
	t.Helper()
	target, err := url.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	p := httputil.NewSingleHostReverseProxy(target)
	p.ModifyResponse = func(resp *http.Response) error {
		one := strings.HasPrefix(resp.Request.URL.Path, "/api/users/")
		if resp.Request.Method != "GET" || resp.Request.URL.Path != "/api/users" && !one || resp.StatusCode != 200 {
			return nil
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		var list []map[string]any
		if one {
			list = []map[string]any{{}}
			err = json.Unmarshal(data, &list[0])
		} else {
			err = json.Unmarshal(data, &list)
		}
		if err != nil {
			return err
		}
		list = rewrite(list)
		var out any = list
		if one {
			out = list[0]
		}
		if data, err = json.Marshal(out); err != nil {
			return err
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

func TestShareRefusesADuplicateDirectory(t *testing.T) {
	s := newSharing(t)
	key := *s.ada.Key
	for _, tc := range []struct {
		name   string
		forge  func(bob map[string]any) map[string]any
		reason string
	}{
		{"a second account with bob's email", func(bob map[string]any) map[string]any {
			_, pair, _ := strangerKeys(t)
			return map[string]any{"id": "impostor", "name": "Bob", "email": "BOB@example.com", "x25519Pub": pair.X25519, "ed25519Pub": pair.Ed25519}
		}, "share the email"},
		{"a second account with bob's keys", func(bob map[string]any) map[string]any {
			return map[string]any{"id": "impostor", "name": "Bob", "email": "bob2@example.com", "x25519Pub": bob["x25519Pub"], "ed25519Pub": bob["ed25519Pub"]}
		}, "share the fingerprint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := directoryProxy(t, s.host, func(list []map[string]any) []map[string]any {
				for _, u := range list {
					if u["email"] == "bob@example.com" {
						return append(list, tc.forge(u))
					}
				}
				t.Error("bob is not in the directory")
				return list
			})
			c := NewWithKey(proxy, key)
			c.Anchors = s.ada.Anchors
			_, err := c.Share(s.artifact, "bob@example.com", "viewer", false)
			if !errors.Is(err, ErrDirectoryDuplicate) || !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("Share: %v, want ErrDirectoryDuplicate (%s)", err, tc.reason)
			}
		})
	}
}

// TestVerifyRefusesAShortenedOrForkedChain shares once, so ada's keyring
// pins seq 2, then serves her the chain cut back to seq 1, and a validly
// signed alternative seq 2.
func TestVerifyRefusesAShortenedOrForkedChain(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	k := mustUnlock(t, s.ada)
	for _, tc := range []struct {
		name    string
		rewrite func(recs []e2e.Envelope) []e2e.Envelope
		want    error
	}{
		{"shorter than the pinned seq", func(recs []e2e.Envelope) []e2e.Envelope { return recs[:1] }, e2e.ErrRollback},
		{"forked at the pinned seq", func(recs []e2e.Envelope) []e2e.Envelope {
			var b e2e.MembershipBody
			json.Unmarshal(recs[1].Body, &b)
			b.Team = "viewer"
			body, _ := json.Marshal(b)
			env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "membership", body)
			if err != nil {
				t.Error(err)
			}
			return []e2e.Envelope{recs[0], env}
		}, e2e.ErrFork},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := tamperingProxy(t, s.host, "/membership", func(m map[string]json.RawMessage) {
				var recs []e2e.Envelope
				json.Unmarshal(m["records"], &recs)
				m["records"] = mustJSON(t, tc.rewrite(recs))
			})
			c := NewWithKey(proxy, *s.ada.Key)
			c.Anchors = s.ada.Anchors
			if _, _, err := c.Members(s.artifact); !errors.Is(err, tc.want) {
				t.Errorf("Members: %v, want %v", err, tc.want)
			}
			if _, err := c.Share(s.artifact, "bob@example.com", "editor", false); !errors.Is(err, tc.want) {
				t.Errorf("Share: %v, want %v", err, tc.want)
			}
			// A device with no keyring entry has nothing to compare with.
			fresh := NewWithKey(proxy, *s.bob.Key)
			fresh.Anchors = newMemAnchors()
			if tc.want == e2e.ErrRollback {
				if _, _, err := fresh.Members(s.artifact); err != nil {
					t.Errorf("Members for bob on the short chain: %v, want it accepted (bob pinned nothing yet)", err)
				}
			}
		})
	}
}

// TestShareRefusesAStaleEpoch pins epoch 2 for an artifact whose chain is
// at epoch 1, and checks nothing is encrypted under it.
func TestShareRefusesAStaleEpoch(t *testing.T) {
	s := newSharing(t)
	k := mustUnlock(t, s.ada)
	m, _ := s.ada.Membership(s.artifact)
	if _, err := s.ada.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Epochs[s.artifact] = e2e.KeyringEpoch{Epoch: 2, Seq: 1, Head: e2e.BodyHash(m.Records[0].Body)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); !errors.Is(err, e2e.ErrStaleEpoch) {
		t.Errorf("Share under an epoch older than the pin: %v, want ErrStaleEpoch", err)
	}
	if keys, _ := s.bob.Keys(s.artifact); keys != nil && len(keys.Wraps) != 0 {
		t.Errorf("bob holds %d wraps, want none", len(keys.Wraps))
	}
}

// TestRecordChainKeepsTheLaterEntry records a chain at seq 1 from a stale
// copy of the keyring, after another write stored seq 2: the merge must
// keep seq 2.
func TestRecordChainKeepsTheLaterEntry(t *testing.T) {
	s := newSharing(t)
	k := mustUnlock(t, s.ada)
	m, err := s.ada.Membership(s.artifact)
	if err != nil {
		t.Fatal(err)
	}
	chain1, err := e2e.VerifyChain(e2e.ChainInput{Artifact: s.artifact, Records: m.Records, Owners: m.Owners, Offers: m.Offers, Anchor: k.FP})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.recordChain(k, e2e.NewKeyring(), s.artifact, chain1, k.UserID, nil); err != nil {
		t.Fatalf("recordChain: %v", err)
	}
	kr, err := s.ada.ReadKeyring(k)
	if err != nil {
		t.Fatal(err)
	}
	if e := kr.Epochs[s.artifact]; e.Seq != 2 {
		t.Errorf("epochs entry = %+v, want seq 2 kept over the stale seq 1", e)
	}
}

// TestShareRefusesAnEstateCopyThatMissesTheCommit writes an epoch 2 record
// whose akCommit is for one AK while the estate holds another, as a buggy
// device of the owner's might, and checks share wraps nothing.
func TestShareRefusesAnEstateCopyThatMissesTheCommit(t *testing.T) {
	s := newSharing(t)
	k := mustUnlock(t, s.ada)
	va, err := s.ada.VerifyArtifact(k, s.artifact, k.FP)
	if err != nil {
		t.Fatal(err)
	}
	committed, stored := make([]byte, 32), make([]byte, 32)
	rand.Read(committed)
	rand.Read(stored)
	next := va.Chain.Latest
	next.Epoch, next.Seq, next.Prev = 2, next.Seq+1, va.Chain.Head
	next.AKCommit, _ = e2e.AKCommit(committed, s.artifact, 2)
	body, _ := json.Marshal(next)
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "membership", body)
	if err != nil {
		t.Fatal(err)
	}
	ekKey, _ := e2e.EKSealKey(k.EK)
	sealed, err := e2e.Seal(rand.Reader, ekKey, estateFields(s.artifact, 2), stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ada.doJSON("PUT", "/api/artifacts/"+s.artifact+"/membership", map[string]any{
		"membership": env, "wraps": []any{}, "linkTokenHash": "",
		"estate": []map[string]any{{"epoch": 2, "sealed": e2e.B64(sealed)}},
	}, nil); err != nil {
		t.Fatalf("writing epoch 2: %v", err)
	}
	_, err = s.ada.Share(s.artifact, "bob@example.com", "viewer", false)
	if !errors.Is(err, e2e.ErrChain) || !strings.Contains(err.Error(), "epoch 2 does not match the chain's akCommit") {
		t.Errorf("Share: %v, want ErrChain for epoch 2's estate copy", err)
	}
}

// TestVerifyAnchorsAtThePinNotTheDirectory pins ada as bob first sees her,
// then has the directory serve other keys for her: the chain still
// verifies against the pin, and her row shows the key changed.
func TestVerifyAnchorsAtThePinNotTheDirectory(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	memberRows(t, s.bob, s.artifact) // first sight: bob pins ada
	adaID := s.userID(t, s.ada)
	_, forged, _ := strangerKeys(t)
	proxy := directoryProxy(t, s.host, func(list []map[string]any) []map[string]any {
		for _, u := range list {
			if u["id"] == adaID {
				u["x25519Pub"], u["ed25519Pub"] = forged.X25519, forged.Ed25519
			}
		}
		return list
	})
	c := NewWithKey(proxy, *s.bob.Key)
	c.Anchors = s.bob.Anchors
	_, rows, err := c.Members(s.artifact)
	if err != nil {
		t.Fatalf("Members with ada's keys swapped in the directory: %v", err)
	}
	for _, r := range rows {
		if r.User == adaID && r.State != e2e.PinChanged {
			t.Errorf("ada's row = %+v, want changed", r)
		}
	}
}

// TestVerifyWritesTheKeyringOnlyOnChange verifies the same chain twice and
// checks the second pass leaves the keyring's rev alone.
func TestVerifyWritesTheKeyringOnlyOnChange(t *testing.T) {
	s := newSharing(t)
	k := mustUnlock(t, s.ada)
	before, err := s.ada.ReadKeyring(k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.VerifyArtifact(k, s.artifact, k.FP); err != nil {
		t.Fatal(err)
	}
	after, err := s.ada.ReadKeyring(k)
	if err != nil {
		t.Fatal(err)
	}
	if after.Rev != before.Rev {
		t.Errorf("keyring rev %d after verifying an unchanged chain, want %d", after.Rev, before.Rev)
	}
}

// TestRecordChainKeepsAPinStoredMeanwhile has bob verify ada's pin while a
// first-sight recordChain still holds a keyring without it: the merge must
// keep the verified pin, not overwrite it with the unverified one.
func TestRecordChainKeepsAPinStoredMeanwhile(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	k := mustUnlock(t, s.bob)
	va, err := s.bob.VerifyArtifact(k, s.artifact, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.bob.Pin("ada@example.com", true, false); err != nil {
		t.Fatal(err)
	}
	adaID := s.userID(t, s.ada)
	stale := e2e.NewKeyring()
	first := &e2e.Pin{FP: va.Keyring.Pins[adaID].FP, State: e2e.PinUnverified}
	if _, err := s.bob.recordChain(k, stale, s.artifact, va.Chain, adaID, first); err != nil {
		t.Fatalf("recordChain: %v", err)
	}
	kr, err := s.bob.ReadKeyring(k)
	if err != nil {
		t.Fatal(err)
	}
	if p := kr.Pins[adaID]; p.State != e2e.PinVerified {
		t.Errorf("bob's pin for ada = %+v, want the verified pin kept", p)
	}
}
