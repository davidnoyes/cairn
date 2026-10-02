package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

func rotateOK(t *testing.T, c *Client, keepEpochs bool) *RotateResult {
	t.Helper()
	res, err := c.RotateKeys(testPassword, keepEpochs)
	if err != nil {
		t.Fatalf("RotateKeys(keepEpochs=%v): %v", keepEpochs, err)
	}
	return res
}

// statusOf is the HTTP status of an API error, or 0 for any other error.
func statusOf(err error) int {
	var api *APIError
	if errors.As(err, &api) {
		return api.Status
	}
	return 0
}

// rotateProxy forwards to host. before runs once, just ahead of the first
// POST /api/me/rotate, and stale makes the first rotation list it serves
// empty, as if another device had not rotated yet.
func rotateProxy(t *testing.T, host string, before func(), stale bool) string {
	t.Helper()
	target, err := url.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	var served atomic.Bool
	p := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		pr.Out.Host = pr.In.Host
		if pr.In.Method == "POST" && pr.In.URL.Path == "/api/me/rotate" && before != nil {
			once.Do(before)
		}
	}}
	p.ModifyResponse = func(resp *http.Response) error {
		r := resp.Request
		if !stale || r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/rotations") || served.Swap(true) {
			return nil
		}
		const empty = `{"records":[]}`
		resp.Body.Close()
		resp.Body = io.NopCloser(strings.NewReader(empty))
		resp.ContentLength = int64(len(empty))
		resp.Header.Set("Content-Length", strconv.Itoa(len(empty)))
		return nil
	}
	ts := httptest.NewServer(p)
	t.Cleanup(ts.Close)
	return ts.URL
}

func TestRotateKeysWithNothingOwnedOrHeld(t *testing.T) {
	host, m := newTestServer(t)
	email := "ada@example.com"
	signupVerify(t, host, m, email, testPassword)
	out, err := New(host, "").Login(email, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	c := keyedFor(t, host, out.APIKey)
	oldKeys := mustUnlock(t, c)
	oldToken := c.Token

	res := rotateOK(t, c, false)
	if res.Seq != 1 || len(res.Epochs) != 0 || len(res.Links) != 0 || len(res.Warnings) != 0 || res.Email != email {
		t.Errorf("RotateKeys = %+v, want seq 1 and nothing else", res)
	}
	if _, err := e2e.ParseRecoveryCode(res.RecoveryCode); err != nil {
		t.Errorf("recovery code %q: %v", res.RecoveryCode, err)
	}

	// The old session and the old key are dead; the client holds the new key.
	if _, err := New(host, oldToken).Me(); statusOf(err) != http.StatusUnauthorized {
		t.Errorf("the old API key after rotation: %v, want 401", err)
	}
	if key, err := e2e.ParseAPIKey(res.APIKey); err != nil || !reflect.DeepEqual(&key, c.Key) || c.Token == oldToken {
		t.Errorf("the client holds %+v and token %q, want the new key %q", c.Key, c.Token, res.APIKey)
	}
	newKeys := mustUnlock(t, c)
	if newKeys.FP == oldKeys.FP || newKeys.UserID != oldKeys.UserID {
		t.Errorf("fingerprint %s after rotation, was %s", newKeys.FP, oldKeys.FP)
	}

	// The rotation record is served, and verifies under both keys.
	recs, err := c.Rotations(oldKeys.UserID)
	if err != nil || len(recs) != 1 {
		t.Fatalf("Rotations = %v, %v, want one record", recs, err)
	}
	var body e2e.RotationBody
	if err := e2e.OpenRotation(recs[0], oldKeys.Ed25519Pub, &body); err != nil {
		t.Fatalf("the rotation record does not verify: %v", err)
	}
	if body.Seq != 1 || body.User != oldKeys.UserID ||
		body.Old != (e2e.KeyPair{X25519: e2e.B64(oldKeys.X25519Pub), Ed25519: e2e.B64(oldKeys.Ed25519Pub)}) ||
		body.New != (e2e.KeyPair{X25519: e2e.B64(newKeys.X25519Pub), Ed25519: e2e.B64(newKeys.Ed25519Pub)}) {
		t.Errorf("rotation body = %+v", body)
	}

	// The keyring's anchor for the new keys is the keyring the server holds.
	raw := rawKeyring(t, c)
	sealed, err := e2e.UnB64(raw.Keyring)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := c.Anchors.LoadAnchor(newKeys.UserID, newKeys.FP)
	if err != nil || anchor == nil || *anchor != e2e.KeyringAnchorOf(raw.Rev, sealed) {
		t.Errorf("anchor for the new keys = %+v, %v, want the keyring at rev %d", anchor, err, raw.Rev)
	}

	// The password still signs in, and the new recovery code resets it
	// without changing the keys.
	if _, err := New(host, "").Login(email, testPassword); err != nil {
		t.Errorf("the password after rotation: %v", err)
	}
	if err := New(host, "").Forgot(email); err != nil {
		t.Fatal(err)
	}
	if err := New(host, "").ResetRecovery(verifyLink(t, m, email), res.RecoveryCode, "a brand new password"); err != nil {
		t.Fatalf("ResetRecovery with the new recovery code: %v", err)
	}
	again, err := New(host, "").Login(email, "a brand new password")
	if err != nil {
		t.Fatal(err)
	}
	if got := mustUnlock(t, keyedFor(t, host, again.APIKey)); got.FP != newKeys.FP {
		t.Errorf("fingerprint after the recovery reset = %s, want %s", got.FP, newKeys.FP)
	}
}

func TestRotateKeysMovesOrKeepsEpochs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		keep  bool
		epoch int
	}{
		{"next epoch", false, 2},
		{"keep epochs", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSharing(t)
			if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
				t.Fatal(err)
			}
			// Bob has read the chain once, so he has pinned ada's old keys and
			// the record she last wrote.
			bobKeys := mustUnlock(t, s.bob)
			if _, err := s.bob.VerifyArtifact(bobKeys, s.artifact, ""); err != nil {
				t.Fatal(err)
			}
			oldToken := s.ada.Token
			oldKeys := mustUnlock(t, s.ada)
			before := latestRecord(t, s.ada, s.artifact)
			rev := rawKeyring(t, s.ada).Rev

			res := rotateOK(t, s.ada, tc.keep)
			// The rotation's keyring already pins the new head, so reading
			// back writes nothing more.
			if got := rawKeyring(t, s.ada).Rev; got != rev+1 {
				t.Errorf("keyring rev = %d after rotation, want %d", got, rev+1)
			}
			if res.Seq != 1 || res.Epochs[s.artifact] != tc.epoch || len(res.Epochs) != 1 || len(res.Links) != 0 {
				t.Errorf("RotateKeys = %+v, want seq 1, the artifact at epoch %d, no links", res, tc.epoch)
			}
			if _, err := New(s.host, oldToken).Me(); statusOf(err) != http.StatusUnauthorized {
				t.Errorf("the old API key after rotation: %v, want 401", err)
			}

			// The owner reads the chain back: a record by the new key at the
			// next seq, and the same members.
			k := mustUnlock(t, s.ada)
			va, err := s.ada.VerifyArtifact(k, s.artifact, k.FP)
			if err != nil {
				t.Fatalf("VerifyArtifact after rotation: %v", err)
			}
			latest := va.Chain.Latest
			if latest.Epoch != tc.epoch || latest.Seq != before.Seq+1 || latest.OwnerFP != k.FP || k.FP == oldKeys.FP ||
				len(latest.Members) != 1 || latest.Members[0].User != s.userID(t, s.bob) {
				t.Errorf("head record = %+v, want epoch %d, seq %d, the new fingerprint, and bob", latest, tc.epoch, before.Seq+1)
			}
			if sameCommit := latest.AKCommit == before.AKCommit; sameCommit != tc.keep {
				t.Errorf("akCommit unchanged = %v, want %v", sameCommit, tc.keep)
			}

			// The estate copies open under the new EK, one for each epoch.
			aks, err := s.ada.epochAKs(k, s.artifact, va.Chain)
			if err != nil {
				t.Fatalf("estate after rotation: %v", err)
			}

			// Bob reads: he holds a wrap of each epoch, and opens the same AKs.
			commits := epochCommits(va.Chain)
			got := ownWraps(t, s.bob, s.artifact)
			if len(got) != tc.epoch {
				t.Errorf("bob holds wraps for %d epochs, want %d", len(got), tc.epoch)
			}
			for epoch, ak := range got {
				if commit, _ := e2e.AKCommit(ak, s.artifact, uint64(epoch)); commit != commits[epoch] || !bytes.Equal(ak, aks[epoch]) {
					t.Errorf("bob's epoch %d AK is not the owner's", epoch)
				}
			}
			// He also follows the owner's rotation from the key he pinned.
			if _, err := s.bob.VerifyArtifact(bobKeys, s.artifact, k.FP); err != nil {
				t.Errorf("bob's VerifyArtifact after the owner rotated: %v", err)
			}
		})
	}
}

func TestVerifyArtifactFollowsTheOwnersRotation(t *testing.T) {
	s := newSharing(t)
	rotateOK(t, s.ada, true)
	k := mustUnlock(t, s.ada)
	va, err := s.ada.VerifyArtifact(k, s.artifact, k.FP)
	if err != nil {
		t.Fatalf("VerifyArtifact of an owned artifact after rotation: %v", err)
	}
	// The first record is still the old key's, so it only reaches the new
	// fingerprint through the rotation record.
	if va.Chain.Bodies[0].OwnerFP == k.FP || va.Chain.Latest.OwnerFP != k.FP || len(va.Membership.Rotations[k.UserID]) != 1 {
		t.Errorf("chain = first ownerFp %s, latest %s, rotations %d; want the key to change along the chain",
			va.Chain.Bodies[0].OwnerFP, va.Chain.Latest.OwnerFP, len(va.Membership.Rotations[k.UserID]))
	}
}

func TestRotateKeysPublicLink(t *testing.T) {
	for _, tc := range []struct {
		name string
		keep bool
	}{
		{"next epoch", false},
		{"keep epochs", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSharing(t)
			pub, err := s.ada.Public(s.artifact, true, nil)
			if err != nil {
				t.Fatal(err)
			}
			res := rotateOK(t, s.ada, tc.keep)
			if tc.keep {
				if len(res.Links) != 0 || res.Epochs[s.artifact] != 1 {
					t.Errorf("RotateKeys = %+v, want no new link at epoch 1", res)
				}
				if opened, err := OpenLink(pub.Link); err != nil || !opened.Chain.Latest.Public {
					t.Errorf("OpenLink of the old link after keeping epochs: %v", err)
				}
				return
			}
			link := res.Links[s.artifact]
			if len(res.Links) != 1 || link == "" || link == pub.Link || res.Epochs[s.artifact] != 2 {
				t.Fatalf("RotateKeys = %+v, want a new link at epoch 2", res)
			}
			l := mustParseLink(t, link)
			if l.Epoch != 2 || l.Artifact != s.artifact || l.Host != s.host {
				t.Errorf("new link = %+v", l)
			}
			// The link names the first owner's fingerprint, and still opens
			// after the owner's keys changed.
			opened, err := OpenLink(link)
			if err != nil || !opened.Chain.Latest.Public || opened.Chain.Latest.Epoch != 2 {
				t.Errorf("OpenLink of the new link: %v", err)
			}
			if _, err := OpenLink(pub.Link); err == nil {
				t.Error("the old link still opens after the artifact moved to a new epoch")
			}
		})
	}
}

func TestRotateKeysRewrapsWhatTheCallerHolds(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	oldAK := ownWraps(t, s.bob, s.artifact)[1]
	if oldAK == nil {
		t.Fatal("bob holds no epoch 1 wrap")
	}

	res := rotateOK(t, s.bob, false)
	if res.Seq != 1 || len(res.Epochs) != 0 {
		t.Errorf("RotateKeys = %+v, want seq 1 and no owned artifacts", res)
	}
	k := mustUnlock(t, s.bob)
	keys, err := s.bob.Keys(s.artifact)
	if err != nil || len(keys.Wraps) != 1 || keys.Wraps[0].FP != k.FP {
		t.Fatalf("bob's wraps after rotation = %+v, %v, want one under the new fingerprint", keys, err)
	}
	if got := ownWraps(t, s.bob, s.artifact)[1]; !bytes.Equal(got, oldAK) {
		t.Error("bob opens another AK after rotation")
	}
	if _, err := s.bob.VerifyArtifact(k, s.artifact, ""); err != nil {
		t.Errorf("bob's VerifyArtifact after rotating: %v", err)
	}
}

// TestRotateKeysLeavesAWrapUnderAnEarlierKey: a wrap made for keys the caller
// no longer has cannot be opened, so rotation leaves it as it is.
func TestRotateKeysLeavesAWrapUnderAnEarlierKey(t *testing.T) {
	s := newSharing(t)
	other, err := s.ada.CreateArtifact("other", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{s.artifact, other.ID} {
		if _, err := s.ada.Share(id, "bob@example.com", "viewer", false); err != nil {
			t.Fatal(err)
		}
	}
	// Bob resets his account, so both wraps are for keys he lost; ada shares
	// the first artifact with his new keys again, and not the second.
	s.resetBob(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", true); err != nil {
		t.Fatal(err)
	}
	stale, err := s.bob.Keys(other.ID)
	if err != nil || len(stale.Wraps) != 1 || stale.Wraps[0].FP == mustUnlock(t, s.bob).FP {
		t.Fatalf("bob's wraps of the second artifact = %+v, %v, want one under his lost keys", stale, err)
	}

	// resetBob left bob a new password.
	if _, err := s.bob.RotateKeys("a brand new password", false); err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	after, err := s.bob.Keys(other.ID)
	if err != nil || len(after.Wraps) != 1 || !bytes.Equal(after.Wraps[0].Wrapped, stale.Wraps[0].Wrapped) || after.Wraps[0].FP != stale.Wraps[0].FP {
		t.Errorf("the wrap under the earlier keys = %+v, %v, want it unchanged", after, err)
	}
	k := mustUnlock(t, s.bob)
	if got := ownWraps(t, s.bob, s.artifact); got[1] == nil {
		t.Error("bob cannot open the artifact whose wrap was current")
	}
	if keys, err := s.bob.Keys(s.artifact); err != nil || len(keys.Wraps) != 1 || keys.Wraps[0].FP != k.FP {
		t.Errorf("the current wrap = %+v, %v, want one under the new fingerprint", keys, err)
	}
}

func TestRotateKeysTwice(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	bobKeys := mustUnlock(t, s.bob)
	if _, err := s.bob.VerifyArtifact(bobKeys, s.artifact, ""); err != nil {
		t.Fatal(err)
	}
	first := rotateOK(t, s.ada, false)
	second := rotateOK(t, s.ada, false)
	if first.Seq != 1 || second.Seq != 2 || second.Epochs[s.artifact] != 3 {
		t.Errorf("rotations = seq %d then %d, epoch %d, want 1, 2, 3", first.Seq, second.Seq, second.Epochs[s.artifact])
	}
	k := mustUnlock(t, s.ada)
	if recs, err := s.ada.Rotations(k.UserID); err != nil || len(recs) != 2 {
		t.Errorf("Rotations = %d records, %v, want 2", len(recs), err)
	}
	if _, err := s.ada.VerifyArtifact(k, s.artifact, k.FP); err != nil {
		t.Errorf("owner's VerifyArtifact after two rotations: %v", err)
	}
	// Bob follows both steps from the key he pinned.
	if _, err := s.bob.VerifyArtifact(bobKeys, s.artifact, k.FP); err != nil {
		t.Errorf("bob's VerifyArtifact after two rotations: %v", err)
	}
	if got := ownWraps(t, s.bob, s.artifact); len(got) != 3 {
		t.Errorf("bob holds wraps for %d epochs, want 3", len(got))
	}
}

func TestRotateKeysRefusesAWrongPassword(t *testing.T) {
	s := newSharing(t)
	before := maps.Clone(s.ada.Anchors.(*memAnchors).m)
	if _, err := s.ada.RotateKeys("not the password", false); statusOf(err) != http.StatusUnauthorized {
		t.Errorf("RotateKeys with a wrong password: %v, want 401", err)
	}
	if _, err := s.ada.RotateKeys("", false); !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("RotateKeys with no password: %v, want ErrEmptyPassword", err)
	}
	if recs, err := s.ada.Rotations(s.userID(t, s.ada)); err != nil || len(recs) != 0 {
		t.Errorf("Rotations = %v, %v, want none", recs, err)
	}
	if !maps.Equal(before, s.ada.Anchors.(*memAnchors).m) {
		t.Error("a refused rotation changed the anchors")
	}
}

// TestRotateKeysConflictChangesNothingHere: the server refuses with 409 when
// something RotateKeys read moved before it posted. The error says what
// moved, nothing local changes, and running the command again works.
func TestRotateKeysConflictChangesNothingHere(t *testing.T) {
	type conflict struct {
		name string
		want string
		// run returns the hook that moves something, and whether the proxy
		// serves a stale rotation list.
		run func(t *testing.T, s *sharing, dev2 *Client) (before func(), stale bool)
	}
	for _, tc := range []conflict{
		{"keyring rev", "the keyring moved from rev", func(t *testing.T, s *sharing, dev2 *Client) (func(), bool) {
			k2 := mustUnlock(t, dev2)
			return func() {
				if _, err := dev2.UpdateKeyring(k2, func(kr *e2e.Keyring) error {
					kr.Pins["someone"] = testPin(1)
					return nil
				}); err != nil {
					t.Errorf("second device's UpdateKeyring: %v", err)
				}
			}, false
		}},
		{"membership", "has a new record", func(t *testing.T, s *sharing, dev2 *Client) (func(), bool) {
			return func() {
				if _, err := dev2.Share(s.artifact, "bob@example.com", "editor", false); err != nil {
					t.Errorf("second device's Share: %v", err)
				}
			}, false
		}},
		{"rotation seq", "the rotation seq moved from 0 to 1", func(t *testing.T, s *sharing, dev2 *Client) (func(), bool) {
			rotateOK(t, s.ada, false)
			return nil, true
		}},
		{"owned set", "you now own artifact", func(t *testing.T, s *sharing, dev2 *Client) (func(), bool) {
			return func() {
				if _, err := dev2.CreateArtifact("another", ""); err != nil {
					t.Errorf("second device's CreateArtifact: %v", err)
				}
			}, false
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSharing(t)
			if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
				t.Fatal(err)
			}
			out, err := New(s.host, "").Login("ada@example.com", testPassword)
			if err != nil {
				t.Fatal(err)
			}
			dev2 := keyedFor(t, s.host, out.APIKey)
			// The second device writes the keyring, so the anchor stored here
			// is behind the server's before the rotation starts.
			if _, err := dev2.UpdateKeyring(mustUnlock(t, dev2), func(kr *e2e.Keyring) error {
				kr.Pins["someone else"] = testPin(2)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before, stale := tc.run(t, s, dev2)

			proxy := rotateProxy(t, s.host, before, stale)
			ada := NewWithKey(proxy, *s.ada.Key)
			ada.Anchors = s.ada.Anchors
			mustUnlock(t, ada)
			anchors, token, key := maps.Clone(ada.Anchors.(*memAnchors).m), ada.Token, *ada.Key
			recs, err := s.ada.Rotations(s.userID(t, ada))
			if err != nil {
				t.Fatal(err)
			}

			_, err = ada.RotateKeys(testPassword, false)
			if statusOf(err) != http.StatusConflict {
				t.Fatalf("RotateKeys = %v, want the server's 409", err)
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "cairn rotate-keys") {
				t.Errorf("RotateKeys = %q, want it to say %q and name cairn rotate-keys", err, tc.want)
			}

			// Nothing local changed, and nothing on the server: the old key
			// still works and no rotation was stored.
			if ada.Token != token || !reflect.DeepEqual(*ada.Key, key) {
				t.Error("a refused rotation changed the client's credentials")
			}
			if !maps.Equal(anchors, ada.Anchors.(*memAnchors).m) {
				t.Errorf("a refused rotation changed the anchors: %v, was %v", ada.Anchors.(*memAnchors).m, anchors)
			}
			if _, err := ada.Me(); err != nil {
				t.Errorf("the old key after a refused rotation: %v", err)
			}
			if got, err := s.ada.Rotations(s.userID(t, ada)); err != nil || len(got) != len(recs) {
				t.Errorf("Rotations = %d, %v, want %d", len(got), err, len(recs))
			}

			// Run again, as the message says.
			if _, err := ada.RotateKeys(testPassword, false); err != nil {
				t.Errorf("RotateKeys again: %v", err)
			}
		})
	}
}

// proxyAct is what faultProxy does with a request.
type proxyAct int

const (
	actPass       proxyAct = iota
	actFail                // answer 503 without forwarding
	actDropBefore          // close the connection without forwarding
	actDropAfter           // forward, then close the connection without answering
)

func isRotatePost(r *http.Request) bool {
	return r.Method == "POST" && r.URL.Path == "/api/me/rotate"
}

// faultProxy forwards to host, except where rule says otherwise. rotated is
// true once a POST /api/me/rotate has reached the server.
func faultProxy(t *testing.T, host string, rule func(r *http.Request, rotated bool) proxyAct) string {
	t.Helper()
	target, err := url.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	forward := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		pr.Out.Host = pr.In.Host
	}}
	var rotated atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch rule(r, rotated.Load()) {
		case actFail:
			http.Error(w, "injected failure", http.StatusServiceUnavailable)
			return
		case actDropBefore:
			panic(http.ErrAbortHandler)
		case actDropAfter:
			forward.ServeHTTP(httptest.NewRecorder(), r)
			if isRotatePost(r) {
				rotated.Store(true)
			}
			panic(http.ErrAbortHandler)
		}
		forward.ServeHTTP(w, r)
		if isRotatePost(r) {
			rotated.Store(true)
		}
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// failAfterRotate fails, once the rotation reached the server, every request
// with this method whose path ends in suffix.
func failAfterRotate(method, suffix string) func(*http.Request, bool) proxyAct {
	return func(r *http.Request, rotated bool) proxyAct {
		if rotated && r.Method == method && strings.HasSuffix(r.URL.Path, suffix) {
			return actFail
		}
		return actPass
	}
}

// rewriteProxy forwards to host and lets rewrite replace the body of any GET
// answer: it returns nil to leave one as it is.
func rewriteProxy(t *testing.T, host string, rewrite func(path string, body []byte) []byte) string {
	t.Helper()
	target, err := url.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	p := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		pr.Out.Host = pr.In.Host
	}}
	p.ModifyResponse = func(resp *http.Response) error {
		if resp.Request.Method != "GET" || resp.StatusCode != http.StatusOK {
			return nil
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		if out := rewrite(resp.Request.URL.Path, body); out != nil {
			body = out
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return nil
	}
	ts := httptest.NewServer(p)
	t.Cleanup(ts.Close)
	return ts.URL
}

// viaProxy is a client for the same account as c, reaching the server
// through proxy and keeping c's anchors.
func viaProxy(proxy string, c *Client) *Client {
	out := NewWithKey(proxy, *c.Key)
	out.Anchors = c.Anchors
	return out
}

// refuseNewAnchors fails to save an anchor for any keys but the old ones.
type refuseNewAnchors struct {
	AnchorStore
	oldFP string
}

func (a refuseNewAnchors) SaveAnchor(userID, fp string, an e2e.KeyringAnchor) error {
	if fp == a.oldFP {
		return a.AnchorStore.SaveAnchor(userID, fp, an)
	}
	return errors.New("disk full")
}

// TestRotateKeysAFailureAfterTheRotationKeepsTheRecoveryCode: once the server
// answered 200 the old recovery code is dead, so whatever fails next, the
// result with the new code comes back with the error, and with the new
// device key when signing in worked.
func TestRotateKeysAFailureAfterTheRotationKeepsTheRecoveryCode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rule    func(*http.Request, bool) proxyAct
		anchors bool
		wantKey bool
		want    string
	}{
		{"signing in again", failAfterRotate("POST", "/api/auth/login"), false, false, "signing in again failed"},
		{"saving the anchor", nil, true, true, "saving the keyring anchor failed"},
		{"unlocking the new keys", failAfterRotate("GET", "/api/me/bundle"), false, true, "unlocking the new keys failed"},
		{"reading an artifact back", failAfterRotate("GET", "/membership"), false, true, "reading artifact"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSharing(t)
			rule := tc.rule
			if rule == nil {
				rule = func(*http.Request, bool) proxyAct { return actPass }
			}
			ada := viaProxy(faultProxy(t, s.host, rule), s.ada)
			if tc.anchors {
				ada.Anchors = refuseNewAnchors{ada.Anchors, mustUnlock(t, ada).FP}
			}
			res, err := ada.RotateKeys(testPassword, false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("RotateKeys error = %v, want it to say %q", err, tc.want)
			}
			if res == nil {
				t.Fatal("RotateKeys returned no result with the error: the new recovery code is lost")
			}
			if _, perr := e2e.ParseRecoveryCode(res.RecoveryCode); perr != nil || res.Seq != 1 {
				t.Errorf("result = %+v (%v), want seq 1 and a valid recovery code", res, perr)
			}
			if (res.APIKey != "") != tc.wantKey {
				t.Fatalf("APIKey = %q, want one: %v", res.APIKey, tc.wantKey)
			}
			if tc.wantKey {
				if _, err := keyedFor(t, s.host, res.APIKey).Me(); err != nil {
					t.Errorf("the returned device key does not work: %v", err)
				}
			}
		})
	}
}

// TestRotateKeysSettlesAnAmbiguousPost: a transport error or a 5xx from the
// rotation POST does not say whether the server applied it, so RotateKeys
// signs in again and reads the rotation list.
func TestRotateKeysSettlesAnAmbiguousPost(t *testing.T) {
	// onRotate faults the first rotation POST only.
	onRotate := func(act proxyAct) func(*http.Request, bool) proxyAct {
		var once sync.Once
		return func(r *http.Request, rotated bool) proxyAct {
			if isRotatePost(r) {
				a := actPass
				once.Do(func() { a = act })
				return a
			}
			return actPass
		}
	}

	t.Run("applied", func(t *testing.T) {
		s := newSharing(t)
		ada := viaProxy(faultProxy(t, s.host, onRotate(actDropAfter)), s.ada)
		oldToken := ada.Token
		res := rotateOK(t, ada, false)
		if res.Seq != 1 || res.Epochs[s.artifact] != 2 || res.APIKey == "" {
			t.Errorf("RotateKeys = %+v, want seq 1, the artifact at epoch 2, and a device key", res)
		}
		if key, err := e2e.ParseAPIKey(res.APIKey); err != nil || !reflect.DeepEqual(&key, ada.Key) || ada.Token == oldToken {
			t.Errorf("the client holds %+v, want the new key %q", ada.Key, res.APIKey)
		}
		if _, err := New(s.host, oldToken).Me(); statusOf(err) != http.StatusUnauthorized {
			t.Errorf("the old API key after the rotation: %v, want 401", err)
		}
	})

	for _, tc := range []struct {
		name    string
		act     proxyAct
		earlier bool
	}{
		{"not applied, connection dropped", actDropBefore, false},
		{"not applied, 5xx", actFail, false},
		{"not applied after an earlier rotation", actDropBefore, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSharing(t)
			seq := 1
			if tc.earlier {
				// The list then ends in a record that is not the one posted.
				rotateOK(t, s.ada, false)
				seq = 2
			}
			ada := viaProxy(faultProxy(t, s.host, onRotate(tc.act)), s.ada)
			token, key := ada.Token, *ada.Key
			res, err := ada.RotateKeys(testPassword, false)
			if res != nil || err == nil || !strings.Contains(err.Error(), "nothing changed") || !strings.Contains(err.Error(), "cairn rotate-keys") {
				t.Fatalf("RotateKeys = %+v, %v, want no result and an error saying nothing changed and to run cairn rotate-keys", res, err)
			}
			if ada.Token != token || !reflect.DeepEqual(*ada.Key, key) {
				t.Error("a rotation that was not applied changed the client's credentials")
			}
			if recs, err := s.ada.Rotations(s.userID(t, s.ada)); err != nil || len(recs) != seq-1 {
				t.Errorf("Rotations = %d records, %v, want %d", len(recs), err, seq-1)
			}
			if _, err := s.ada.Me(); err != nil {
				t.Errorf("the old key after a rotation that was not applied: %v", err)
			}
			// The rule only faults the first POST, so the advice works.
			if res := rotateOK(t, ada, false); res.Seq != seq {
				t.Errorf("RotateKeys again = %+v, want seq %d", res, seq)
			}
		})
	}

	t.Run("cannot be settled", func(t *testing.T) {
		s := newSharing(t)
		rule := func(r *http.Request, rotated bool) proxyAct {
			if isRotatePost(r) {
				return actDropAfter
			}
			if rotated && r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rotations") {
				return actFail
			}
			return actPass
		}
		ada := viaProxy(faultProxy(t, s.host, rule), s.ada)
		res, err := ada.RotateKeys(testPassword, false)
		if res == nil {
			t.Fatalf("RotateKeys = nil, %v, want the recovery code with the error", err)
		}
		if _, perr := e2e.ParseRecoveryCode(res.RecoveryCode); perr != nil {
			t.Errorf("recovery code %q: %v", res.RecoveryCode, perr)
		}
		if err == nil || !strings.Contains(err.Error(), "may have applied") || !strings.Contains(err.Error(), "cairn login") {
			t.Errorf("RotateKeys error = %v, want it to say the server may have applied the rotation and to run cairn login", err)
		}
		if res.APIKey != "" {
			t.Errorf("APIKey = %q, want none: the rotation is unconfirmed", res.APIKey)
		}
		if !res.Unconfirmed || !strings.Contains(err.Error(), "cairn rotate-keys again") {
			t.Errorf("RotateKeys = %+v, %v, want it unconfirmed and to say run cairn rotate-keys again", res, err)
		}
	})
}

// TestRotateKeysConflictWhenTheHeldWrapsMoved: the wraps the caller holds are
// read before the post, and an owner can change them in between.
func TestRotateKeysConflictWhenTheHeldWrapsMoved(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
		// run makes the move; it returns the hook and the artifact it names.
		run func(t *testing.T, s *sharing) (before func(), id string)
	}{
		{"an artifact shared with the caller", "you now hold artifact ", func(t *testing.T, s *sharing) (func(), string) {
			x, err := s.bob.CreateArtifact("bobs", "")
			if err != nil {
				t.Fatal(err)
			}
			return func() {
				if _, err := s.bob.Share(x.ID, "ada@example.com", "viewer", false); err != nil {
					t.Errorf("bob's Share: %v", err)
				}
			}, x.ID
		}},
		{"a held artifact moved to a new epoch", "the wraps you hold on artifact ", func(t *testing.T, s *sharing) (func(), string) {
			x, err := s.bob.CreateArtifact("bobs", "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.bob.Share(x.ID, "ada@example.com", "viewer", false); err != nil {
				t.Fatal(err)
			}
			if _, err := s.bob.Public(x.ID, true, nil); err != nil {
				t.Fatal(err)
			}
			return func() {
				if _, err := s.bob.Public(x.ID, false, nil); err != nil {
					t.Errorf("bob's Public off: %v", err)
				}
			}, x.ID
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSharing(t)
			before, id := tc.run(t, s)
			ada := viaProxy(rotateProxy(t, s.host, before, false), s.ada)
			mustUnlock(t, ada)
			_, err := ada.RotateKeys(testPassword, false)
			if statusOf(err) != http.StatusConflict {
				t.Fatalf("RotateKeys = %v, want the server's 409", err)
			}
			if !strings.Contains(err.Error(), tc.want+id) || !strings.Contains(err.Error(), "cairn rotate-keys") {
				t.Errorf("RotateKeys = %q, want it to say %q and name cairn rotate-keys", err, tc.want+id)
			}
			if recs, err := s.ada.Rotations(s.userID(t, s.ada)); err != nil || len(recs) != 0 {
				t.Errorf("Rotations = %v, %v, want none", recs, err)
			}
			if res := rotateOK(t, ada, false); res.Seq != 1 {
				t.Errorf("RotateKeys again = %+v, want seq 1", res)
			}
		})
	}
}

// TestRotateConflictBranches calls rotateConflict with what RotateKeys would
// have passed, against a server where one thing at a time differs.
func TestRotateConflictBranches(t *testing.T) {
	s := newSharing(t)
	id := s.userID(t, s.ada)
	oldFP := mustUnlock(t, s.ada).FP
	rev := rawKeyring(t, s.ada).Rev
	cause := errors.New("the server's 409")
	conflict := func(c *Client, rev int, owned map[string]int) string {
		t.Helper()
		err := c.rotateConflict(id, oldFP, 0, rev, owned, map[string][]int{}, cause)
		if !errors.Is(err, cause) || !strings.Contains(err.Error(), "Nothing was changed; run cairn rotate-keys again") {
			t.Fatalf("rotateConflict = %v, want the cause and the advice to run it again", err)
		}
		return err.Error()
	}
	const fallback = "something the rotation checks moved"

	if got := conflict(s.ada, rev, map[string]int{s.artifact: 1}); !strings.Contains(got, fallback) {
		t.Errorf("nothing moved: %q, want %q", got, fallback)
	}
	if got := conflict(s.ada, rev, map[string]int{s.artifact: 1, "ghost": 1}); !strings.Contains(got, "you no longer own artifact ghost") || strings.Contains(got, fallback) {
		t.Errorf("an artifact the caller lost: %q", got)
	}
	if got := conflict(s.ada, rev+5, map[string]int{s.artifact: 1}); !strings.Contains(got, "the keyring moved from rev") {
		t.Errorf("a keyring that moved: %q", got)
	}
	// With the keyring unreadable, nothing is said about it.
	failKeyring := faultProxy(t, s.host, func(r *http.Request, _ bool) proxyAct {
		if r.Method == "GET" && r.URL.Path == "/api/me/keyring" {
			return actFail
		}
		return actPass
	})
	if got := conflict(viaProxy(failKeyring, s.ada), rev+5, map[string]int{s.artifact: 1}); strings.Contains(got, "keyring moved") || !strings.Contains(got, fallback) {
		t.Errorf("an unreadable keyring: %q, want the fallback and no word on the keyring", got)
	}
}

// TestRotateKeysSkipsAListedPublicArtifactWithNoWraps: the server lists what
// the caller can open, and a link holder opens a public artifact with no
// wraps, so its wraps are a 404 or a 403. Bob's listing is made to show ada's
// public artifact, as a listing that raced a change would.
func TestRotateKeysSkipsAListedPublicArtifactWithNoWraps(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Public(s.artifact, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.bob.Keys(s.artifact); statusOf(err) != http.StatusForbidden && statusOf(err) != http.StatusNotFound {
		t.Fatalf("bob's Keys of ada's public artifact: %v, want 403 or 404", err)
	}
	ada := s.userID(t, s.ada)
	proxy := rewriteProxy(t, s.host, func(path string, body []byte) []byte {
		if path != "/api/artifacts" {
			return nil
		}
		out, _ := json.Marshal([]map[string]any{{"id": s.artifact, "name": "shared", "owner": ada, "epoch": 1, "public": true}})
		return out
	})
	if res := rotateOK(t, viaProxy(proxy, s.bob), false); res.Seq != 1 || len(res.Epochs) != 0 {
		t.Errorf("RotateKeys = %+v, want seq 1 and nothing owned", res)
	}
}

// TestRotateKeysSkipsAnOwnedArtifactWithNoRecords: an artifact the listing
// shows as the caller's with epoch 0 has no membership chain to read.
func TestRotateKeysSkipsAnOwnedArtifactWithNoRecords(t *testing.T) {
	s := newSharing(t)
	id := s.userID(t, s.ada)
	proxy := rewriteProxy(t, s.host, func(path string, body []byte) []byte {
		if path != "/api/artifacts" {
			return nil
		}
		var arts []map[string]any
		if err := json.Unmarshal(body, &arts); err != nil {
			t.Errorf("the artifact list: %v", err)
			return nil
		}
		arts = append(arts, map[string]any{"id": "legacy", "name": "legacy", "owner": id, "epoch": 0})
		out, _ := json.Marshal(arts)
		return out
	})
	res := rotateOK(t, viaProxy(proxy, s.ada), false)
	if res.Seq != 1 || len(res.Epochs) != 1 || res.Epochs[s.artifact] != 2 {
		t.Errorf("RotateKeys = %+v, want seq 1 and only the artifact with records, at epoch 2", res)
	}
}

// TestRotateKeysNamesTheArtifactOfACorruptWrap: a wrap under the current
// fingerprint that does not open stops the rotation, with what to do.
func TestRotateKeysNamesTheArtifactOfACorruptWrap(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	proxy := rewriteProxy(t, s.host, func(path string, body []byte) []byte {
		if path != "/api/artifacts/"+s.artifact+"/keys" {
			return nil
		}
		var keys struct {
			Wraps  []map[string]any `json:"wraps"`
			Estate []any            `json:"estate"`
		}
		if err := json.Unmarshal(body, &keys); err != nil || len(keys.Wraps) == 0 {
			t.Errorf("bob's keys: %v, %d wraps", err, len(keys.Wraps))
			return nil
		}
		wrapped, err := e2e.UnB64(keys.Wraps[0]["wrapped"].(string))
		if err != nil {
			t.Error(err)
			return nil
		}
		wrapped[len(wrapped)-1] ^= 1
		keys.Wraps[0]["wrapped"] = e2e.B64(wrapped)
		out, _ := json.Marshal(keys)
		return out
	})
	bob := viaProxy(proxy, s.bob)
	res, err := bob.RotateKeys(testPassword, false)
	if res != nil || err == nil {
		t.Fatalf("RotateKeys = %+v, %v, want an error", res, err)
	}
	for _, want := range []string{s.artifact, "cairn unshare " + s.artifact + " bob@example.com", "cairn share " + s.artifact + " bob@example.com", "cairn rotate-keys"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("RotateKeys error = %q, want it to say %q", err, want)
		}
	}
	if recs, err := s.bob.Rotations(s.userID(t, s.bob)); err != nil || len(recs) != 0 {
		t.Errorf("Rotations = %v, %v, want none", recs, err)
	}
}

// TestRotateKeysKeepsWhatTheKeyringHolds: the keyring the rotation seals
// carries the pins and the acknowledged epochs over, a verified pin
// included.
func TestRotateKeysKeepsWhatTheKeyringHolds(t *testing.T) {
	for _, verified := range []bool{false, true} {
		t.Run("verified="+strconv.FormatBool(verified), func(t *testing.T) {
			s := newSharing(t)
			if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
				t.Fatal(err)
			}
			if verified {
				if _, err := s.ada.Pin("bob@example.com", true, false); err != nil {
					t.Fatal(err)
				}
			}
			k := mustUnlock(t, s.ada)
			if _, err := s.ada.UpdateKeyring(k, func(kr *e2e.Keyring) error {
				e, ok := kr.Epochs[s.artifact]
				if !ok {
					return errors.New("the keyring has no epoch entry for the artifact")
				}
				e.Ack = 1
				kr.Epochs[s.artifact] = e
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			kr, _, err := s.ada.openKeyring(k)
			if err != nil {
				t.Fatal(err)
			}
			bob := s.userID(t, s.bob)
			pin, ok := kr.Pins[bob]
			if !ok || (pin.State == e2e.PinVerified) != verified {
				t.Fatalf("bob's pin before = %+v, %v, want verified: %v", pin, ok, verified)
			}

			rotateOK(t, s.ada, false)
			after, _, err := s.ada.openKeyring(mustUnlock(t, s.ada))
			if err != nil {
				t.Fatal(err)
			}
			if got := after.Pins[bob]; got.FP != pin.FP || got.State != pin.State {
				t.Errorf("bob's pin after = %+v, want %+v", got, pin)
			}
			if got := after.Epochs[s.artifact]; got.Ack != 1 || got.Epoch != 2 {
				t.Errorf("the artifact's keyring entry after = %+v, want epoch 2 and ack 1", got)
			}
		})
	}
}

// TestRotateKeysPinsAnApprovedTeamMember: the next epoch lists a team member
// an editor approved, and the pin decided for them goes into the keyring the
// rotation seals.
func TestRotateKeysPinsAnApprovedTeamMember(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	res, err := w.bob.Approve(w.artifact, "cat@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	rotateOK(t, w.ada, false)
	kr, err := w.ada.ReadKeyring(mustUnlock(t, w.ada))
	if err != nil {
		t.Fatal(err)
	}
	if p := kr.Pins[res.User.ID]; p.FP != res.User.FP || p.State != e2e.PinUnverified {
		t.Errorf("ada's pin for cat = %+v, want %s unverified", p, res.User.FP)
	}
}
