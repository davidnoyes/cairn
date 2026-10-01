package client

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// memAnchors is an in-memory AnchorStore. loadErr, when set, is what every
// load returns.
type memAnchors struct {
	mu      sync.Mutex
	m       map[string]e2e.KeyringAnchor
	loadErr error
	// saveErr is what the failSave'th save returns instead of storing.
	saves, failSave int
	saveErr         error
}

func newMemAnchors() *memAnchors { return &memAnchors{m: map[string]e2e.KeyringAnchor{}} }

func (s *memAnchors) LoadAnchor(userID, fp string) (*e2e.KeyringAnchor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	a, ok := s.m[userID+" "+fp]
	if !ok {
		return nil, nil
	}
	return &a, nil
}

func (s *memAnchors) SaveAnchor(userID, fp string, a e2e.KeyringAnchor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves++
	if s.failSave != 0 && s.saves == s.failSave {
		return s.saveErr
	}
	s.m[userID+" "+fp] = a
	return nil
}

func (s *memAnchors) get(t *testing.T, userID, fp string) e2e.KeyringAnchor {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[userID+" "+fp]
	if !ok {
		t.Fatalf("no anchor stored for %s", userID)
	}
	return a
}

func mustUnlock(t *testing.T, c *Client) *UnlockedKeys {
	t.Helper()
	k, err := c.Unlock()
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	return k
}

func testPin(b byte) e2e.Pin {
	return e2e.Pin{FP: strings.Repeat(string("0123456789abcdef"[b%16]), 64), State: e2e.PinUnverified}
}

func addPin(t *testing.T, c *Client, k *UnlockedKeys, user string) *e2e.Keyring {
	t.Helper()
	kr, err := c.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Pins[user] = testPin(byte(len(user)))
		return nil
	})
	if err != nil {
		t.Fatalf("UpdateKeyring: %v", err)
	}
	return kr
}

func rawKeyring(t *testing.T, c *Client) keyringWire {
	t.Helper()
	var w keyringWire
	if err := c.doJSON("GET", "/api/me/keyring", nil, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestReadAndUpdateKeyring(t *testing.T) {
	host, full := keyedLogin(t)
	c := keyedFor(t, host, full)
	k := mustUnlock(t, c)

	kr, err := c.ReadKeyring(k)
	if err != nil {
		t.Fatalf("ReadKeyring before the first write: %v", err)
	}
	if kr.Rev != 0 || len(kr.Pins) != 0 || len(kr.Epochs) != 0 {
		t.Errorf("first read = %+v, want the empty keyring at rev 0", kr)
	}
	if a := c.Anchors.(*memAnchors).get(t, k.UserID, k.FP); a != e2e.KeyringAnchorOf(0, nil) {
		t.Errorf("anchor after the first read = %+v, want rev 0 over no bytes", a)
	}

	written := addPin(t, c, k, "u1")
	if written.Rev != 1 {
		t.Errorf("rev after the first write = %d, want 1", written.Rev)
	}
	raw := rawKeyring(t, c)
	if raw.Rev != 1 {
		t.Errorf("server rev = %d, want 1", raw.Rev)
	}
	sealed, _ := e2e.UnB64(raw.Keyring)
	if a := c.Anchors.(*memAnchors).get(t, k.UserID, k.FP); a != e2e.KeyringAnchorOf(1, sealed) {
		t.Errorf("anchor after the write = %+v, want the hash of the bytes written at rev 1", a)
	}
	kr, err = c.ReadKeyring(k)
	if err != nil {
		t.Fatalf("ReadKeyring: %v", err)
	}
	if kr.Rev != 1 || kr.Pins["u1"] != testPin(2) {
		t.Errorf("read back %+v, want rev 1 with the pin for u1", kr)
	}
}

func TestKeyringNeedsAnAnchorStore(t *testing.T) {
	host, full := keyedLogin(t)
	c := keyedFor(t, host, full)
	k := mustUnlock(t, c)
	c.Anchors = nil
	if _, err := c.ReadKeyring(k); err == nil || !strings.Contains(err.Error(), "no keyring anchor store") {
		t.Errorf("ReadKeyring with no anchor store: %v, want a refusal", err)
	}
	if _, err := c.UpdateKeyring(k, func(*e2e.Keyring) error { return nil }); err == nil || !strings.Contains(err.Error(), "no keyring anchor store") {
		t.Errorf("UpdateKeyring with no anchor store: %v, want a refusal", err)
	}

	loadErr := errors.New("config unreadable")
	c.Anchors = &memAnchors{m: map[string]e2e.KeyringAnchor{}, loadErr: loadErr}
	if _, err := c.ReadKeyring(k); !errors.Is(err, loadErr) || !strings.Contains(err.Error(), "reading the keyring anchor") {
		t.Errorf("ReadKeyring with an unreadable anchor: %v, want the load error", err)
	}
}

// TestReadKeyringRefusals serves the client keyrings its anchor must refuse,
// and checks the anchor stays where it was.
func TestReadKeyringRefusals(t *testing.T) {
	host, full := keyedLogin(t)
	c := keyedFor(t, host, full)
	k := mustUnlock(t, c)
	addPin(t, c, k, "u1")
	old := rawKeyring(t, c)
	addPin(t, c, k, "u2")
	cur := rawKeyring(t, c)
	anchors := c.Anchors.(*memAnchors)
	want := anchors.get(t, k.UserID, k.FP)

	other := e2e.NewKeyring()
	other.Rev = 2
	otherSealed, err := e2e.SealKeyring(rand.Reader, k.MKSealKey, other)
	if err != nil {
		t.Fatal(err)
	}
	tampered, _ := e2e.UnB64(cur.Keyring)
	tampered[len(tampered)-1] ^= 1

	for _, tc := range []struct {
		name    string
		rev     int
		keyring string
		want    error
		msg     string
	}{
		{"rolled back a rev", old.Rev, old.Keyring, e2e.ErrKeyringRollback, ""},
		{"wiped", 0, "", e2e.ErrKeyringRollback, ""},
		{"forked at the anchor's rev", 2, e2e.B64(otherSealed), e2e.ErrKeyringFork, ""},
		{"outer rev not the sealed rev", 3, cur.Keyring, e2e.ErrKeyringRev, ""},
		{"fails to open", 2, e2e.B64(tampered), e2e.ErrDecrypt, ""},
		{"not base64", 2, "!!!", nil, "not base64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := tamperingProxy(t, host, "/api/me/keyring", func(m map[string]json.RawMessage) {
				m["rev"] = mustJSON(t, tc.rev)
				m["keyring"] = mustJSON(t, tc.keyring)
			})
			p := keyedFor(t, proxy, full)
			p.Anchors = anchors
			_, err := p.ReadKeyring(k)
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("ReadKeyring: %v, want %v", err, tc.want)
			}
			if tc.msg != "" && (err == nil || !strings.Contains(err.Error(), tc.msg)) {
				t.Errorf("ReadKeyring: %v, want %q", err, tc.msg)
			}
			if _, err := p.UpdateKeyring(k, func(*e2e.Keyring) error { return nil }); err == nil {
				t.Error("UpdateKeyring wrote over a keyring the anchor refuses")
			}
			if a := anchors.get(t, k.UserID, k.FP); a != want {
				t.Errorf("anchor moved to %+v after a refusal, want %+v", a, want)
			}
		})
	}
}

// TestKeyringAnchorSurvivesLogout signs out and in again with the same
// anchor store, as the CLI does, and checks a rolled-back keyring is still
// refused; a device with no anchor would accept it.
func TestKeyringAnchorSurvivesLogout(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)
	first, err := New(host, "").Login(email, password)
	if err != nil {
		t.Fatal(err)
	}
	c := keyedFor(t, host, first.APIKey)
	k := mustUnlock(t, c)
	addPin(t, c, k, "u1")
	old := rawKeyring(t, c)
	addPin(t, c, k, "u2")
	anchors := c.Anchors.(*memAnchors)

	key, _ := e2e.ParseAPIKey(first.APIKey)
	if err := c.Logout(key.KeyID); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	second, err := New(host, "").Login(email, password)
	if err != nil {
		t.Fatal(err)
	}
	proxy := tamperingProxy(t, host, "/api/me/keyring", func(m map[string]json.RawMessage) {
		m["rev"] = mustJSON(t, old.Rev)
		m["keyring"] = mustJSON(t, old.Keyring)
	})
	again := keyedFor(t, proxy, second.APIKey)
	again.Anchors = anchors
	k2 := mustUnlock(t, again)
	if _, err := again.ReadKeyring(k2); !errors.Is(err, e2e.ErrKeyringRollback) {
		t.Errorf("ReadKeyring after signing in again: %v, want ErrKeyringRollback", err)
	}
	if _, err := keyedFor(t, proxy, second.APIKey).ReadKeyring(k2); err != nil {
		t.Errorf("a device with no anchor: %v, want the old keyring accepted (the anchor is what refuses it)", err)
	}
}

// TestKeyringAnchorIsPerFingerprint serves the empty keyring a reset leaves
// behind. A client with the anchor for its own fingerprint refuses it as a
// rollback; after a reset the fingerprint is new, so there is no anchor for
// it and the client accepts.
func TestKeyringAnchorIsPerFingerprint(t *testing.T) {
	host, full := keyedLogin(t)
	c := keyedFor(t, host, full)
	k := mustUnlock(t, c)
	addPin(t, c, k, "u1")
	anchors := c.Anchors.(*memAnchors)
	if a := anchors.get(t, k.UserID, k.FP); a.Rev != 1 {
		t.Fatalf("anchor = %+v, want rev 1", a)
	}

	proxy := tamperingProxy(t, host, "/api/me/keyring", func(m map[string]json.RawMessage) {
		m["rev"] = mustJSON(t, 0)
		m["keyring"] = mustJSON(t, "")
	})
	same := keyedFor(t, proxy, full)
	same.Anchors = anchors
	if _, err := same.ReadKeyring(k); !errors.Is(err, e2e.ErrKeyringRollback) {
		t.Errorf("same fingerprint: %v, want ErrKeyringRollback", err)
	}

	reset := *k
	reset.FP = strings.Repeat("b", 64)
	fresh := keyedFor(t, proxy, full)
	fresh.Anchors = anchors
	kr, err := fresh.ReadKeyring(&reset)
	if err != nil || kr.Rev != 0 {
		t.Errorf("new fingerprint: %v, %+v, want the empty keyring accepted", err, kr)
	}
	if a := anchors.get(t, k.UserID, k.FP); a.Rev != 1 {
		t.Errorf("the old fingerprint's anchor = %+v, want it left at rev 1", a)
	}
}

// TestUpdateKeyringMergesConcurrentWrites has device B write between device
// A's read and write. A's write gets 409, reads again, and re-applies its
// change, so both pins land.
func TestUpdateKeyringMergesConcurrentWrites(t *testing.T) {
	host, full := keyedLogin(t)
	a, b := keyedFor(t, host, full), keyedFor(t, host, full)
	ka, kb := mustUnlock(t, a), mustUnlock(t, b)

	calls := 0
	kr, err := a.UpdateKeyring(ka, func(kr *e2e.Keyring) error {
		calls++
		if calls == 1 {
			addPin(t, b, kb, "from-b")
		}
		kr.Pins["from-a"] = testPin(1)
		return nil
	})
	if err != nil {
		t.Fatalf("UpdateKeyring: %v", err)
	}
	if calls != 2 {
		t.Errorf("change ran %d times, want 2 (once more after the 409)", calls)
	}
	if kr.Rev != 2 {
		t.Errorf("rev = %d, want 2", kr.Rev)
	}
	got, err := b.ReadKeyring(kb)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Pins["from-a"]; !ok {
		t.Error("A's pin is missing")
	}
	if _, ok := got.Pins["from-b"]; !ok {
		t.Error("B's pin is missing: A's retry wrote over it")
	}
}

func TestUpdateKeyringGivesUp(t *testing.T) {
	host, full := keyedLogin(t)
	a, b := keyedFor(t, host, full), keyedFor(t, host, full)
	ka, kb := mustUnlock(t, a), mustUnlock(t, b)

	calls := 0
	_, err := a.UpdateKeyring(ka, func(kr *e2e.Keyring) error {
		calls++
		addPin(t, b, kb, strings.Repeat("b", calls))
		return nil
	})
	if !errors.Is(err, ErrKeyringBusy) {
		t.Errorf("UpdateKeyring losing every race: %v, want ErrKeyringBusy", err)
	}
	if calls != keyringRetries {
		t.Errorf("change ran %d times, want %d", calls, keyringRetries)
	}
}

func TestUpdateKeyringRefusesWithoutWriting(t *testing.T) {
	host, full := keyedLogin(t)
	c := keyedFor(t, host, full)
	k := mustUnlock(t, c)

	stop := errors.New("stop")
	if _, err := c.UpdateKeyring(k, func(*e2e.Keyring) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("a change that fails: %v, want its error", err)
	}
	if _, err := c.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Pins["u"] = e2e.Pin{FP: "short", State: e2e.PinUnverified}
		return nil
	}); !errors.Is(err, e2e.ErrFormat) {
		t.Errorf("a change that breaks the format: %v, want ErrFormat", err)
	}
	if raw := rawKeyring(t, c); raw.Rev != 0 {
		t.Errorf("server rev = %d after two refused changes, want 0", raw.Rev)
	}
}

// roundTripFunc is an http.RoundTripper made from a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestUpdateKeyringRefusesARollbackAfterAConflict has device B write between
// A's read and write, so A gets 409; then the server serves A an older
// keyring on the re-read. A must return the refusal and make no second write.
func TestUpdateKeyringRefusesARollbackAfterAConflict(t *testing.T) {
	host, full := keyedLogin(t)
	a, b := keyedFor(t, host, full), keyedFor(t, host, full)
	ka, kb := mustUnlock(t, a), mustUnlock(t, b)
	addPin(t, a, ka, "u1")
	old := rawKeyring(t, a)
	addPin(t, a, ka, "u2")
	anchor := a.Anchors.(*memAnchors).get(t, ka.UserID, ka.FP)

	puts, conflicted := 0, false
	a.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/me/keyring" {
			return http.DefaultTransport.RoundTrip(r)
		}
		if r.Method == "PUT" {
			puts++
			if !conflicted {
				conflicted = true
				addPin(t, b, kb, "from-b") // the server now holds rev 3
			}
			return http.DefaultTransport.RoundTrip(r)
		}
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil || !conflicted {
			return resp, err
		}
		resp.Body.Close()
		body, _ := json.Marshal(old)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		return resp, nil
	})}
	_, err := a.UpdateKeyring(ka, func(kr *e2e.Keyring) error {
		kr.Pins["from-a"] = testPin(1)
		return nil
	})
	if !errors.Is(err, e2e.ErrKeyringRollback) {
		t.Errorf("UpdateKeyring: %v, want ErrKeyringRollback", err)
	}
	if puts != 1 {
		t.Errorf("A made %d writes, want only the one that got 409", puts)
	}
	if got := a.Anchors.(*memAnchors).get(t, ka.UserID, ka.FP); got != anchor {
		t.Errorf("anchor moved to %+v, want %+v", got, anchor)
	}
}

// TestUpdateKeyringReportsAFailedAnchorSave makes the anchor store fail the
// save that follows a successful write: the caller must learn the keyring
// changed but its anchor did not move.
func TestUpdateKeyringReportsAFailedAnchorSave(t *testing.T) {
	host, full := keyedLogin(t)
	c := keyedFor(t, host, full)
	k := mustUnlock(t, c)
	saveErr := errors.New("disk full")
	anchors := c.Anchors.(*memAnchors)
	anchors.failSave, anchors.saveErr = 2, saveErr // save 1 is the read's, save 2 follows the write

	_, err := c.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Pins["u1"] = testPin(1)
		return nil
	})
	if !errors.Is(err, saveErr) || !strings.Contains(err.Error(), "the keyring was written, but saving its anchor failed") {
		t.Errorf("UpdateKeyring: %v, want the save error wrapped", err)
	}
	if raw := rawKeyring(t, c); raw.Rev != 1 {
		t.Errorf("server rev = %d, want the write to have landed", raw.Rev)
	}
	if got := anchors.get(t, k.UserID, k.FP); got.Rev != 0 {
		t.Errorf("anchor = %+v, want it left at rev 0", got)
	}
}

func TestCreateArtifactRecordsTheEpoch(t *testing.T) {
	host, full := keyedLogin(t)
	c := keyedFor(t, host, full)
	a, err := c.CreateArtifact("pinned", "")
	if err != nil {
		t.Fatal(err)
	}
	m, err := c.Membership(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := c.ReadKeyring(mustUnlock(t, c))
	if err != nil {
		t.Fatal(err)
	}
	want := e2e.KeyringEpoch{Epoch: 1, Seq: 1, Head: e2e.BodyHash(m.Records[0].Body)}
	if got := kr.Epochs[a.ID]; got != want {
		t.Errorf("epochs entry = %+v, want %+v", got, want)
	}
}
