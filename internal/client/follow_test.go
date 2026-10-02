package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// Rotation: the client follows other users' key rotations (step 7d-2).

// servedRotations edits the rotation records of userID that the server
// serves to the client: on GET /api/users/{id}/rotations and in the
// "rotations" of the membership GET. edit gets the real records.
func servedRotations(t *testing.T, host, userID string, edit func([]e2e.Envelope) []e2e.Envelope) string {
	t.Helper()
	return divergentRotations(t, host, userID, edit, edit)
}

// divergentRotations serves the records of userID in the membership GET as
// inMembership edits them, and on GET /api/users/{id}/rotations as
// onRotations edits them: two copies that can differ.
func divergentRotations(t *testing.T, host, userID string, inMembership, onRotations func([]e2e.Envelope) []e2e.Envelope) string {
	t.Helper()
	return rewriteProxy(t, host, func(path string, body []byte) []byte {
		switch {
		case path == "/api/users/"+userID+"/rotations":
			var out struct {
				Records []e2e.Envelope `json:"records"`
			}
			if err := json.Unmarshal(body, &out); err != nil {
				t.Error(err)
				return nil
			}
			out.Records = onRotations(out.Records)
			b, err := json.Marshal(out)
			if err != nil {
				t.Error(err)
			}
			return b
		case strings.HasSuffix(path, "/membership"):
			var m map[string]json.RawMessage
			if err := json.Unmarshal(body, &m); err != nil {
				t.Error(err)
				return nil
			}
			var rot map[string][]e2e.Envelope
			if err := json.Unmarshal(m["rotations"], &rot); err != nil {
				t.Error(err)
				return nil
			}
			if recs, ok := rot[userID]; ok {
				rot[userID] = inMembership(recs)
			}
			m["rotations"], _ = json.Marshal(rot)
			b, err := json.Marshal(m)
			if err != nil {
				t.Error(err)
			}
			return b
		}
		return nil
	})
}

// rotationsDown is a copy of c for which the rotation records of userID are
// out of reach: GET /api/users/{id}/rotations answers 500, and the membership
// GET omits them.
func rotationsDown(c *Client, userID string) *Client {
	return rotationsAnswering(c, userID, answerStatus(500, "disk on fire"))
}

// answerStatus answers a request with an API error of status.
func answerStatus(status int, message string) func(r *http.Request) (*http.Response, error) {
	return func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"error":"` + message + `"}`)), Request: r,
		}, nil
	}
}

// rotationsAnswering is rotationsDown with the answer to GET
// /api/users/{id}/rotations in the caller's hands.
func rotationsAnswering(c *Client, userID string, answer func(r *http.Request) (*http.Response, error)) *Client {
	out := NewWithKey(c.Host, *c.Key)
	out.Anchors = c.Anchors
	out.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == "GET" && r.URL.Path == "/api/users/"+userID+"/rotations" {
			return answer(r)
		}
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil || r.Method != "GET" || resp.StatusCode != 200 || !strings.HasSuffix(r.URL.Path, "/membership") {
			return resp, err
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		var m map[string]json.RawMessage
		var rot map[string]json.RawMessage
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(m["rotations"], &rot); err != nil {
			return nil, err
		}
		delete(rot, userID)
		m["rotations"], _ = json.Marshal(rot)
		if data, err = json.Marshal(m); err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
		return resp, nil
	})}
	return out
}

// forkOf is a rotation record for the same seq as real, from the same old
// keys to new keys of the attacker's making, signed by the old key oldKeys.
func forkOf(t *testing.T, real e2e.Envelope, oldKeys *UnlockedKeys) e2e.Envelope {
	t.Helper()
	var b e2e.RotationBody
	if err := e2e.DecodeStrict(real.Body, &b); err != nil {
		t.Fatal(err)
	}
	_, xPub, err := e2e.GenerateX25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed, edPub, err := e2e.GenerateEd25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b.New = e2e.KeyPair{X25519: e2e.B64(xPub), Ed25519: e2e.B64(edPub)}
	body, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.SignRotation(oldKeys.Ed25519Seed, seed, body, b.User)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func pinOf(t *testing.T, c *Client, userID string) e2e.Pin {
	t.Helper()
	kr, err := c.ReadKeyring(mustUnlock(t, c))
	if err != nil {
		t.Fatal(err)
	}
	return kr.Pins[userID]
}

// bobRotatesAfterAdaPinned has ada share with bob, bob rotate n times, and
// returns bob's id and the keys he had before the first rotation.
func bobRotatesAfterAdaPinned(t *testing.T, s *sharing, n int) (string, *UnlockedKeys) {
	t.Helper()
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	first := mustUnlock(t, s.bob)
	for range n {
		rotateOK(t, s.bob, false)
	}
	return first.UserID, first
}

func TestShareFollowsARotationWithoutAFlag(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 1)
	bobNow := mustUnlock(t, s.bob)
	recs, err := s.ada.Rotations(bobID)
	if err != nil || len(recs) != 1 {
		t.Fatalf("Rotations = %v, %v", recs, err)
	}
	before := recordCount(t, s.ada, s.artifact)

	res, err := s.ada.Share(s.artifact, "bob@example.com", "editor", false)
	if err != nil {
		t.Fatalf("Share after bob rotated, with no flag: %v", err)
	}
	if res.Prior != e2e.PinRotated || res.User.FP != bobNow.FP || !res.Promoted {
		t.Errorf("Share = %+v, want a promotion after rotated to %s", res, bobNow.FP)
	}
	want := e2e.Pin{FP: bobNow.FP, State: e2e.PinUnverified, RotSeq: 1, RotHead: e2e.BodyHash(recs[0].Body)}
	if p := pinOf(t, s.ada, bobID); p != want {
		t.Errorf("ada's pin for bob = %+v, want %+v", p, want)
	}
	// Bob re-made his own wrap when he rotated, so the record carries none
	// and he still reads.
	if got := recordCount(t, s.ada, s.artifact); got != before+1 {
		t.Errorf("records = %d, want %d", got, before+1)
	}
	if r := latestRecord(t, s.ada, s.artifact).Members; len(r) != 1 || r[0].FP != bobNow.FP || r[0].Role != "editor" {
		t.Errorf("latest record members = %+v, want bob under his new fingerprint", r)
	}
	if got := openWraps(t, s.bob, s.artifact); !slices.Equal(got, []int{1}) {
		t.Errorf("bob's wraps = %v, want epoch 1", got)
	}
}

func TestShareRelistsARotatedMemberAtTheSameRole(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 1)
	bobNow := mustUnlock(t, s.bob)
	res, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Unchanged || res.Prior != e2e.PinRotated {
		t.Errorf("Share = %+v, want a re-listing, not Unchanged", res)
	}
	if r := latestRecord(t, s.ada, s.artifact).Members; len(r) != 1 || r[0].User != bobID || r[0].FP != bobNow.FP {
		t.Errorf("members = %+v, want bob under the new fingerprint", r)
	}
}

func TestShareFollowsTwoRotations(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 2)
	recs, _ := s.ada.Rotations(bobID)
	if len(recs) != 2 {
		t.Fatalf("%d rotation records, want 2", len(recs))
	}
	res, err := s.ada.Share(s.artifact, "bob@example.com", "editor", false)
	if err != nil {
		t.Fatalf("Share after two rotations: %v", err)
	}
	if p := pinOf(t, s.ada, bobID); res.Prior != e2e.PinRotated || p.RotSeq != 2 || p.RotHead != e2e.BodyHash(recs[1].Body) || p.FP != mustUnlock(t, s.bob).FP {
		t.Errorf("prior %s, pin %+v, want rotated and the pin at seq 2", res.Prior, p)
	}
}

func TestMembersShowsARotatedPinAndWritesNothing(t *testing.T) {
	for _, verified := range []bool{false, true} {
		s := newSharing(t)
		if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
			t.Fatal(err)
		}
		bobID := s.userID(t, s.bob)
		if verified {
			if _, err := s.ada.Pin("bob@example.com", true, false); err != nil {
				t.Fatal(err)
			}
		}
		oldPin := pinOf(t, s.ada, bobID)
		rotateOK(t, s.bob, false)
		r := memberRows(t, s.ada, s.artifact)["bob@example.com"]
		if r.State != e2e.PinRotated || r.WasVerified != verified {
			t.Errorf("verified=%v: bob's row = %+v, want rotated, was verified %v", verified, r, verified)
		}
		if p := pinOf(t, s.ada, bobID); p != oldPin {
			t.Errorf("verified=%v: Members wrote the pin: %+v, was %+v", verified, p, oldPin)
		}
	}
}

func TestPinVerifiedAfterARotationKeepsTheRotSeq(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 1)
	res, err := s.ada.Pin("bob@example.com", true, false)
	if err != nil {
		t.Fatalf("Pin --verified after a rotation: %v", err)
	}
	if p := pinOf(t, s.ada, bobID); res.Prior != e2e.PinRotated || p.State != e2e.PinVerified || p.RotSeq != 1 || p.FP != mustUnlock(t, s.bob).FP {
		t.Errorf("prior %s, pin %+v, want rotated and a verified pin at seq 1", res.Prior, p)
	}
}

func TestPinRefusesAForkedRotationChain(t *testing.T) {
	s := newSharing(t)
	bobID, oldKeys := bobRotatesAfterAdaPinned(t, s, 1)
	recs, _ := s.ada.Rotations(bobID)
	forged := forkOf(t, recs[0], oldKeys)
	ada := viaProxy(servedRotations(t, s.host, bobID, func(r []e2e.Envelope) []e2e.Envelope {
		return append(slices.Clone(r), forged)
	}), s.ada)

	for name, call := range map[string]func(accept bool) error{
		"pin":   func(a bool) error { _, err := ada.Pin("bob@example.com", false, a); return err },
		"share": func(a bool) error { _, err := ada.Share(s.artifact, "bob@example.com", "editor", a); return err },
	} {
		err := call(false)
		var changed *KeyChangedError
		if !errors.As(err, &changed) || !errors.Is(err, e2e.ErrRotationFork) {
			t.Fatalf("%s through a forked chain: %v, want a KeyChangedError wrapping ErrRotationFork", name, err)
		}
		for _, want := range []string{"rotation records", "conflict", "with each other or with the record you pinned", "attack"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: message %q lacks %q", name, err, want)
			}
		}
		// The advice is the command's, given once.
		if strings.Contains(err.Error(), "--accept-new-key") || strings.Contains(err.Error(), "fewer") {
			t.Errorf("%s: message %q carries advice or the rollback wording", name, err)
		}
		if p := pinOf(t, s.ada, bobID); p.FP == mustUnlock(t, s.bob).FP {
			t.Fatalf("%s: a refused call stored the pin %+v", name, p)
		}
	}
	if _, err := ada.Pin("bob@example.com", false, true); err != nil {
		t.Fatalf("Pin --accept-new-key through a fork: %v", err)
	}
	if p := pinOf(t, s.ada, bobID); p.FP != mustUnlock(t, s.bob).FP || p.State != e2e.PinUnverified {
		t.Errorf("pin after accepting = %+v, want unverified at bob's current fingerprint", p)
	}
}

func TestPinRefusesARollbackOfTheRotationRecords(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 1)
	// Ada follows the first rotation, so her pin is at seq 1.
	if _, err := s.ada.Pin("bob@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	rotateOK(t, s.bob, false)
	pinned := pinOf(t, s.ada, bobID)
	if pinned.RotSeq != 1 {
		t.Fatalf("pin = %+v, want seq 1", pinned)
	}

	// The server withholds the record the pin names.
	ada := viaProxy(servedRotations(t, s.host, bobID, func(r []e2e.Envelope) []e2e.Envelope { return nil }), s.ada)
	_, err := ada.Pin("bob@example.com", false, false)
	var changed *KeyChangedError
	if !errors.As(err, &changed) || !errors.Is(err, e2e.ErrRollback) {
		t.Fatalf("Pin with the pinned record withheld: %v, want a KeyChangedError wrapping ErrRollback", err)
	}
	for _, want := range []string{"fewer rotation records than you pinned", "attack"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "with each other") || strings.Contains(err.Error(), "--accept-new-key") {
		t.Errorf("message %q words a rollback as a fork, or carries advice", err)
	}
	if p := pinOf(t, s.ada, bobID); p != pinned {
		t.Errorf("a refused Pin changed the pin to %+v", p)
	}

	// A chain cut short ends at keys that are not bob's: only a changed key.
	short := viaProxy(servedRotations(t, s.host, bobID, func(r []e2e.Envelope) []e2e.Envelope { return r[:1] }), s.ada)
	_, err = short.Pin("bob@example.com", false, false)
	if !errors.As(err, &changed) || errors.Is(err, e2e.ErrRollback) || errors.Is(err, e2e.ErrRotationFork) {
		t.Fatalf("Pin with the chain cut short: %v, want a plain KeyChangedError", err)
	}
	if _, err := short.Pin("bob@example.com", false, true); err != nil {
		t.Errorf("Pin --accept-new-key: %v", err)
	}
}

// rotationRequests counts the requests for rotation records among paths.
func rotationRequests(paths []string) int {
	n := 0
	for _, p := range paths {
		if strings.HasSuffix(p, "/rotations") {
			n++
		}
	}
	return n
}

// A pin that stands reads no rotation records. A first pin reads them, so
// that it records the seq, and so does a pin that changed.
// Members shows a fork or a rollback as a state of its own, and writes nothing.
func TestMembersShowsConflictingRotationRecordsAsTheirOwnState(t *testing.T) {
	s := newSharing(t)
	bobID, oldKeys := bobRotatesAfterAdaPinned(t, s, 1)
	recs, _ := s.ada.Rotations(bobID)
	forged := forkOf(t, recs[0], oldKeys)
	oldPin := pinOf(t, s.ada, bobID)

	fork := viaProxy(servedRotations(t, s.host, bobID, func(r []e2e.Envelope) []e2e.Envelope {
		return append(slices.Clone(r), forged)
	}), s.ada)
	if r := memberRows(t, fork, s.artifact)["bob@example.com"]; r.State != MemberConflict {
		t.Errorf("bob's row with a forked chain = %+v, want %s", r, MemberConflict)
	}

	// A rollback: ada follows the first rotation, bob rotates again, and the
	// server withholds the record she pinned.
	if _, err := s.ada.Pin("bob@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	rotateOK(t, s.bob, false)
	pinned := pinOf(t, s.ada, bobID)
	withheld := viaProxy(servedRotations(t, s.host, bobID, func([]e2e.Envelope) []e2e.Envelope { return nil }), s.ada)
	if r := memberRows(t, withheld, s.artifact)["bob@example.com"]; r.State != MemberConflict {
		t.Errorf("bob's row with the pinned record withheld = %+v, want %s", r, MemberConflict)
	}
	// A broken chain is only a changed key.
	broken := viaProxy(servedRotations(t, s.host, bobID, func(r []e2e.Envelope) []e2e.Envelope { return r[:1] }), s.ada)
	if r := memberRows(t, broken, s.artifact)["bob@example.com"]; r.State != e2e.PinChanged {
		t.Errorf("bob's row with a chain cut short = %+v, want changed", r)
	}
	if p := pinOf(t, s.ada, bobID); p != pinned || oldPin == pinned {
		t.Errorf("Members changed the pin: %+v, was %+v", p, pinned)
	}
}

func TestPinFetchesRotationsForANewOrAChangedPinOnly(t *testing.T) {
	w := newTeam(t)
	if _, err := w.ada.Pin("bob@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	catID := w.userID(t, w.cat)
	var fetched []string
	c := NewWithKey(w.host, *w.ada.Key)
	c.Anchors = w.ada.Anchors
	c.HTTP = recordingHTTP(&fetched)

	if _, err := c.Pin("bob@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	if n := rotationRequests(fetched); n != 0 {
		t.Errorf("a pin that stands fetched %d rotation lists: %v", n, fetched)
	}
	fetched = nil
	if res, err := c.Pin("cat@example.com", false, false); err != nil || res.Prior != e2e.PinNew {
		t.Fatalf("Pin of cat = %+v, %v, want a first pin", res, err)
	}
	if n := rotationRequests(fetched); n != 1 || !slices.Contains(fetched, "/api/users/"+catID+"/rotations") {
		t.Errorf("a first pin fetched %v, want exactly cat's rotation list", fetched)
	}
	fetched = nil
	if _, err := c.Pin("cat@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	if n := rotationRequests(fetched); n != 0 {
		t.Errorf("cat's standing pin fetched %d rotation lists", n)
	}
	rotateOK(t, w.bob, false)
	fetched = nil
	if res, err := c.Pin("bob@example.com", false, false); err != nil || res.Prior != e2e.PinRotated {
		t.Fatalf("Pin of bob = %+v, %v, want rotated", res, err)
	}
	if n := rotationRequests(fetched); n != 1 {
		t.Errorf("a changed pin fetched %d rotation lists, want exactly 1: %v", n, fetched)
	}
}

func TestPendingShowsARotatedMemberAndChecksTheChain(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 1)
	if got := pendingStates(t, s.ada, s.artifact); got["bob@example.com"] != PendingRotated {
		t.Fatalf("pending = %v, want bob rotated", got)
	}
	// A chain whose signature does not verify is a changed key.
	broken := viaProxy(servedRotations(t, s.host, bobID, func(r []e2e.Envelope) []e2e.Envelope {
		out := slices.Clone(r)
		out[0].Sig = bytes.Repeat([]byte{1}, len(out[0].Sig))
		return out
	}), s.ada)
	if got := pendingStates(t, broken, s.artifact); got["bob@example.com"] != PendingKeyChanged {
		t.Errorf("pending through a broken chain = %v, want bob keyChanged", got)
	}
	// So is a chain that does not lead to his current keys.
	short := viaProxy(servedRotations(t, s.host, bobID, func(r []e2e.Envelope) []e2e.Envelope { return nil }), s.ada)
	if got := pendingStates(t, short, s.artifact); got["bob@example.com"] != PendingKeyChanged {
		t.Errorf("pending with no chain = %v, want bob keyChanged", got)
	}
}

// A server that calls a member rotated whose keys are the ones the record
// lists is not believed: there is no change for a chain to explain.
func TestPendingRotatedForAMemberWhoseKeysDidNotChangeIsKeyChanged(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	dir, err := s.ada.Directory()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := FindUser(dir, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	lying := rewritingList(t, s.ada, "/api/artifacts/"+s.artifact+"/pending", func(list []map[string]any) []map[string]any {
		return append(list, map[string]any{
			"id": bob.ID, "name": bob.Name, "email": bob.Email,
			"x25519Pub": e2e.B64(bob.X25519Pub), "ed25519Pub": e2e.B64(bob.Ed25519Pub), "state": "rotated",
		})
	})
	if got := pendingStates(t, lying, s.artifact); got["bob@example.com"] != PendingKeyChanged {
		t.Errorf("pending = %v, want bob keyChanged: his keys are the listed ones", got)
	}
}

func TestPendingRotatedFromANonOwnerIsKeyChanged(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	// Cat rotated, so a chain that verifies leads to her keys: the server
	// would show her to the owner as rotated, but never shows rotated to an
	// editor, so an editor who is told so does not believe it.
	rotateOK(t, w.cat, false)
	setState := func(email string) func([]map[string]any) []map[string]any {
		return func(list []map[string]any) []map[string]any {
			for _, e := range list {
				if e["email"] == email {
					e["state"] = "rotated"
				}
			}
			return list
		}
	}
	edited := rewritingList(t, w.bob, "/api/artifacts/"+w.artifact+"/pending", setState("cat@example.com"))
	if got := pendingStates(t, edited, w.artifact); got["cat@example.com"] != PendingKeyChanged {
		t.Errorf("an editor's pending = %v, want a rotated entry read as keyChanged", got)
	}
	// The owner is told a user who never rotated is rotated: no chain, so keyChanged.
	owner := rewritingList(t, w.ada, "/api/artifacts/"+w.artifact+"/pending", setState("dan@example.com"))
	if got := pendingStates(t, owner, w.artifact); got["dan@example.com"] != PendingKeyChanged {
		t.Errorf("owner's pending for a user who never rotated = %v, want keyChanged", got)
	}
}

func TestOwnersNextRecordRelistsARotatedMember(t *testing.T) {
	w := newTeam(t)
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	bobID := w.userID(t, w.bob)
	rotateOK(t, w.bob, false)
	bobNow := mustUnlock(t, w.bob)
	recs, _ := w.ada.Rotations(bobID)
	before := recordCount(t, w.ada, w.artifact)

	// A record about someone else lists bob under his new fingerprint, with
	// no wrap for him, and stores the unverified pin.
	if _, err := w.ada.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	latest := latestRecord(t, w.ada, w.artifact)
	if recordCount(t, w.ada, w.artifact) != before+1 || latest.Epoch != 1 {
		t.Fatalf("records %d, epoch %d, want one more record at epoch 1", recordCount(t, w.ada, w.artifact), latest.Epoch)
	}
	if i := slices.IndexFunc(latest.Members, func(m e2e.Member) bool { return m.User == bobID }); i < 0 || latest.Members[i].FP != bobNow.FP {
		t.Errorf("members = %+v, want bob under %s", latest.Members, bobNow.FP)
	}
	want := e2e.Pin{FP: bobNow.FP, State: e2e.PinUnverified, RotSeq: 1, RotHead: e2e.BodyHash(recs[0].Body)}
	if p := pinOf(t, w.ada, bobID); p != want {
		t.Errorf("bob's pin = %+v, want %+v", p, want)
	}
	if got := openWraps(t, w.bob, w.artifact); !slices.Equal(got, []int{1}) {
		t.Errorf("bob's wraps = %v, want epoch 1", got)
	}
	if got := pendingStates(t, w.ada, w.artifact); got["bob@example.com"] != "" {
		t.Errorf("pending after the re-listing = %v, want no entry for bob", got)
	}
}

func TestTeamRelistsARotatedMember(t *testing.T) {
	w := newTeam(t)
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	rotateOK(t, w.bob, false)
	if _, err := w.ada.Team(w.artifact, "viewer"); err != nil {
		t.Fatal(err)
	}
	if m := latestRecord(t, w.ada, w.artifact).Members; len(m) != 1 || m[0].FP != mustUnlock(t, w.bob).FP {
		t.Errorf("members = %+v, want bob under his new fingerprint", m)
	}
}

func TestNextEpochRelistsARotatedMemberAndWrapsToTheNewKeys(t *testing.T) {
	w := newTeam(t)
	for _, who := range []string{"bob@example.com", "cat@example.com"} {
		if _, err := w.ada.Share(w.artifact, who, "viewer", false); err != nil {
			t.Fatal(err)
		}
	}
	bobID := w.userID(t, w.bob)
	rotateOK(t, w.bob, false)
	if _, err := w.ada.Unshare(w.artifact, "cat@example.com"); err != nil {
		t.Fatalf("Unshare with bob rotated: %v", err)
	}
	bobNow := mustUnlock(t, w.bob)
	latest := latestRecord(t, w.ada, w.artifact)
	if latest.Epoch != 2 || len(latest.Members) != 1 || latest.Members[0].User != bobID || latest.Members[0].FP != bobNow.FP {
		t.Errorf("latest = epoch %d, members %+v, want epoch 2 with bob under %s", latest.Epoch, latest.Members, bobNow.FP)
	}
	// Bob opens the wrap of each epoch with his new key, and the new epoch's
	// AK is the one the chain commits to.
	got := ownWraps(t, w.bob, w.artifact)
	if len(got) != 2 || got[1] == nil || got[2] == nil {
		t.Fatalf("bob opens wraps of %d epochs, want 1 and 2", len(got))
	}
	if commit, _ := e2e.AKCommit(got[2], w.artifact, 2); commit != latest.AKCommit {
		t.Error("the AK bob opens for epoch 2 does not match the chain's akCommit")
	}
	if p := pinOf(t, w.ada, bobID); p.FP != bobNow.FP || p.State != e2e.PinUnverified || p.RotSeq != 1 {
		t.Errorf("bob's pin = %+v, want unverified at his new fingerprint, seq 1", p)
	}
}

func TestNextEpochRefusesAMemberWhoseRotationChainIsBroken(t *testing.T) {
	w := newTeam(t)
	for _, who := range []string{"bob@example.com", "cat@example.com"} {
		if _, err := w.ada.Share(w.artifact, who, "viewer", false); err != nil {
			t.Fatal(err)
		}
	}
	bobID := w.userID(t, w.bob)
	rotateOK(t, w.bob, false)
	ada := viaProxy(servedRotations(t, w.host, bobID, func(r []e2e.Envelope) []e2e.Envelope { return nil }), w.ada)
	if _, err := ada.Unshare(w.artifact, "cat@example.com"); !errors.Is(err, ErrMemberKeyChanged) {
		t.Errorf("Unshare with bob's chain withheld: %v, want ErrMemberKeyChanged", err)
	}
}

func TestAnUnlistedHolderWhoRotatedIsNeitherListedNorExcluded(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	if _, err := w.bob.Approve(w.artifact, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	rotateOK(t, w.cat, false)
	if got := pendingStates(t, w.ada, w.artifact); got["cat@example.com"] != PendingRotated {
		t.Fatalf("pending = %v, want cat rotated", got)
	}
	// The owner's next record: neither lists cat nor excludes her.
	if _, err := w.ada.Share(w.artifact, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	latest := latestRecord(t, w.ada, w.artifact)
	catID := w.userID(t, w.cat)
	if slices.ContainsFunc(latest.Members, func(m e2e.Member) bool { return m.User == catID }) || len(latest.Excluded) != 0 {
		t.Errorf("latest = members %+v, excluded %+v, want cat in neither", latest.Members, latest.Excluded)
	}
	if _, err := w.ada.Team(w.artifact, "viewer"); err != nil {
		t.Fatal(err)
	}
	latest = latestRecord(t, w.ada, w.artifact)
	if slices.ContainsFunc(latest.Members, func(m e2e.Member) bool { return m.User == catID }) || len(latest.Excluded) != 0 {
		t.Errorf("after Team: members %+v, excluded %+v, want cat in neither", latest.Members, latest.Excluded)
	}
	if got := pendingStates(t, w.ada, w.artifact); got["cat@example.com"] != PendingRotated {
		t.Errorf("pending after the owner's records = %v, want cat still rotated", got)
	}
}

func TestAnUnlistedHolderWhoRotatedIsExcludedByANewEpochTheServerRequiresToDecideThem(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	if _, err := w.bob.Approve(w.artifact, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	rotateOK(t, w.cat, false)
	if _, err := w.ada.Unshare(w.artifact, "bob@example.com"); err != nil {
		t.Fatalf("Unshare with a rotated holder: %v", err)
	}
	latest := latestRecord(t, w.ada, w.artifact)
	if got := excludedEmails(latest); !slices.Contains(got, "cat@example.com") {
		t.Errorf("excluded = %v, want cat decided by the new epoch", got)
	}
}

// rotatedHolder is the team world with cat approved by bob, who is an
// editor, and then rotated: she holds wraps under her new keys, an approval
// for her old ones, and is not listed.
func rotatedHolder(t *testing.T) *team {
	t.Helper()
	w := newTeam(t)
	w.setup(t, "viewer")
	if _, err := w.bob.Approve(w.artifact, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	rotateOK(t, w.cat, false)
	return w
}

func TestTeamNoneDecidesARotatedHolderInANewEpoch(t *testing.T) {
	w := rotatedHolder(t)
	res, err := w.ada.Team(w.artifact, "none")
	if err != nil {
		t.Fatalf("Team none with a rotated holder: %v", err)
	}
	if !res.NewEpoch || !slices.Contains(excludedEmails(latestRecord(t, w.ada, w.artifact)), "cat@example.com") {
		t.Errorf("Team none = %+v, want a new epoch that excludes cat", res)
	}
}

func TestUnshareRemovesARotatedHolder(t *testing.T) {
	w := rotatedHolder(t)
	res, err := w.ada.Unshare(w.artifact, "cat@example.com")
	if err != nil {
		t.Fatalf("Unshare of a rotated holder: %v", err)
	}
	if !res.NewEpoch || !slices.Contains(excludedEmails(latestRecord(t, w.ada, w.artifact)), "cat@example.com") {
		t.Errorf("Unshare = %+v, want a new epoch that excludes cat", res)
	}
}

func TestApproveRefusesAnUnlistedHolderWhoRotated(t *testing.T) {
	w := rotatedHolder(t)
	// Only the owner is told she rotated; she holds a wrap already, and the
	// owner lists her by name.
	if err := approve(t, w.ada, w.artifact, "cat@example.com"); !errors.Is(err, ErrChangedKey) {
		t.Errorf("Approve of a rotated holder: %v, want ErrChangedKey", err)
	}
}

func TestShareListsAnUnlistedHolderWhoRotatedWithoutAWrap(t *testing.T) {
	w := rotatedHolder(t)
	if _, err := w.ada.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatalf("Share by name with a rotated holder: %v", err)
	}
	catKeys := mustUnlock(t, w.cat)
	if m := latestRecord(t, w.ada, w.artifact).Members; !slices.ContainsFunc(m, func(m e2e.Member) bool { return m.User == catKeys.UserID && m.FP == catKeys.FP }) {
		t.Errorf("members = %+v, want cat under her new keys", m)
	}
	if got := ownWraps(t, w.cat, w.artifact); len(got) != 1 || got[1] == nil {
		t.Errorf("cat's wraps = %v, want epoch 1", got)
	}
}

// A listed member whose chain verifies but whose pin the owner set to other
// keys is left as listed by a record about someone else; the owner decides.
func TestOwnersNextRecordLeavesAMemberWhoseKeysContradictThePin(t *testing.T) {
	w := newTeam(t)
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	bobKeys := mustUnlock(t, w.bob)
	k := mustUnlock(t, w.ada)
	if _, err := w.ada.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Pins[bobKeys.UserID] = e2e.Pin{FP: strings.Repeat("ab", 32), State: e2e.PinVerified}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rotateOK(t, w.bob, false)
	if _, err := w.ada.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatalf("Share with a rotated member whose pin differs: %v", err)
	}
	if m := latestRecord(t, w.ada, w.artifact).Members; !slices.ContainsFunc(m, func(m e2e.Member) bool { return m.User == bobKeys.UserID && m.FP == bobKeys.FP }) {
		t.Errorf("members = %+v, want bob still under his old fingerprint", m)
	}
	if p := pinOf(t, w.ada, bobKeys.UserID); p.FP != strings.Repeat("ab", 32) || p.State != e2e.PinVerified {
		t.Errorf("pin = %+v, want the owner's pin untouched", p)
	}
}

// For a user the latest record does not list, the owner's pin says which
// keys the chain must start from.
func TestPendingRotatedHolderStartsTheChainAtTheOwnersPin(t *testing.T) {
	for _, tc := range []struct {
		name string
		pin  func(catFP string) string
		want string
	}{
		{"pinned at the old keys", func(fp string) string { return fp }, PendingRotated},
		{"pinned elsewhere", func(string) string { return strings.Repeat("ab", 32) }, PendingKeyChanged},
	} {
		w := newTeam(t)
		w.setup(t, "viewer")
		if _, err := w.bob.Approve(w.artifact, "cat@example.com", false); err != nil {
			t.Fatal(err)
		}
		cat := mustUnlock(t, w.cat)
		k := mustUnlock(t, w.ada)
		if _, err := w.ada.UpdateKeyring(k, func(kr *e2e.Keyring) error {
			kr.Pins[cat.UserID] = e2e.Pin{FP: tc.pin(cat.FP), State: e2e.PinUnverified}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		rotateOK(t, w.cat, false)
		if got := pendingStates(t, w.ada, w.artifact); got["cat@example.com"] != tc.want {
			t.Errorf("%s: pending = %v, want cat %s", tc.name, got, tc.want)
		}
	}
}

// The owner's own commands re-list a rotated member wherever they write a
// record, and report Unchanged only when there is nothing to re-list.

func TestTeamAgainRelistsARotatedMember(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	bobID := w.userID(t, w.bob)
	rotateOK(t, w.bob, false)
	bobNow := mustUnlock(t, w.bob)
	recs, _ := w.ada.Rotations(bobID)
	before := recordCount(t, w.ada, w.artifact)

	// The legend the owner reads names this command to list the new keys.
	res, err := w.ada.Team(w.artifact, "viewer")
	if err != nil {
		t.Fatal(err)
	}
	if res.Unchanged || recordCount(t, w.ada, w.artifact) != before+1 {
		t.Errorf("Team = %+v, records %d, want a new record and no Unchanged", res, recordCount(t, w.ada, w.artifact))
	}
	if m := latestRecord(t, w.ada, w.artifact).Members; len(m) != 1 || m[0].FP != bobNow.FP {
		t.Errorf("members = %+v, want bob under %s", m, bobNow.FP)
	}
	want := e2e.Pin{FP: bobNow.FP, State: e2e.PinUnverified, RotSeq: 1, RotHead: e2e.BodyHash(recs[0].Body)}
	if p := pinOf(t, w.ada, bobID); p != want {
		t.Errorf("bob's pin = %+v, want %+v", p, want)
	}
	if got := openWraps(t, w.bob, w.artifact); !slices.Equal(got, []int{1}) {
		t.Errorf("bob's wraps = %v, want epoch 1", got)
	}
	if again, err := w.ada.Team(w.artifact, "viewer"); err != nil || !again.Unchanged {
		t.Errorf("Team with nothing left to list = %+v, %v, want Unchanged", again, err)
	}
}

func TestShareOfAnUnchangedUserRelistsAnotherRotatedMember(t *testing.T) {
	for _, team := range []string{"none", "viewer"} {
		w := newTeam(t)
		role := "viewer"
		if team == "none" {
			if _, err := w.ada.Share(w.artifact, "bob@example.com", role, false); err != nil {
				t.Fatal(err)
			}
		} else {
			w.setup(t, team) // bob is an editor
			role = "editor"
		}
		if _, err := w.ada.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
			t.Fatal(err)
		}
		catID := w.userID(t, w.cat)
		rotateOK(t, w.cat, false)
		catNow := mustUnlock(t, w.cat)

		res, err := w.ada.Share(w.artifact, "bob@example.com", role, false)
		if err != nil {
			t.Fatal(err)
		}
		if res.Unchanged {
			t.Errorf("team %s: Share = %+v, want a record that lists cat's new keys, not Unchanged", team, res)
		}
		m := latestRecord(t, w.ada, w.artifact).Members
		if i := slices.IndexFunc(m, func(m e2e.Member) bool { return m.User == catID }); i < 0 || m[i].FP != catNow.FP {
			t.Errorf("team %s: members = %+v, want cat under %s", team, m, catNow.FP)
		}
		if p := pinOf(t, w.ada, catID); p.FP != catNow.FP || p.RotSeq != 1 {
			t.Errorf("team %s: cat's pin = %+v, want her new keys at seq 1", team, p)
		}
		if got := openWraps(t, w.cat, w.artifact); !slices.Equal(got, []int{1}) {
			t.Errorf("team %s: cat's wraps = %v, want epoch 1", team, got)
		}
		if again, err := w.ada.Share(w.artifact, "bob@example.com", role, false); err != nil || !again.Unchanged {
			t.Errorf("team %s: Share with nothing left to list = %+v, %v, want Unchanged", team, again, err)
		}
	}
}

// Public on is a same-epoch record, and off a next-epoch one: both list a
// rotated member under the new keys.
func TestPublicRelistsARotatedMember(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 1)
	listedAt := func(seq int) {
		t.Helper()
		bobNow := mustUnlock(t, s.bob)
		m := latestRecord(t, s.ada, s.artifact).Members
		if len(m) != 1 || m[0].User != bobID || m[0].FP != bobNow.FP {
			t.Errorf("members = %+v, want bob under %s", m, bobNow.FP)
		}
		if p := pinOf(t, s.ada, bobID); p.FP != bobNow.FP || p.RotSeq != seq {
			t.Errorf("bob's pin = %+v, want his new keys at seq %d", p, seq)
		}
	}

	res, err := s.ada.Public(s.artifact, true, nil)
	if err != nil {
		t.Fatalf("Public on with bob rotated: %v", err)
	}
	if res.Unchanged || !latestRecord(t, s.ada, s.artifact).Public {
		t.Errorf("Public on = %+v, want a public record", res)
	}
	listedAt(1)
	if got := openWraps(t, s.bob, s.artifact); !slices.Equal(got, []int{1}) {
		t.Errorf("bob's wraps = %v, want epoch 1", got)
	}

	// Already public, with nothing to change but a rotated member.
	rotateOK(t, s.bob, false)
	before := recordCount(t, s.ada, s.artifact)
	res, err = s.ada.Public(s.artifact, true, nil)
	if err != nil {
		t.Fatalf("Public on again with bob rotated: %v", err)
	}
	if res.Unchanged || recordCount(t, s.ada, s.artifact) != before+1 {
		t.Errorf("Public on again = %+v, want a record that lists bob's new keys", res)
	}
	listedAt(2)
	if again, err := s.ada.Public(s.artifact, true, nil); err != nil || !again.Unchanged {
		t.Errorf("Public on with nothing left to list = %+v, %v, want Unchanged", again, err)
	}

	rotateOK(t, s.bob, false)
	res, err = s.ada.Public(s.artifact, false, nil)
	if err != nil || !res.NewEpoch {
		t.Fatalf("Public off with bob rotated = %+v, %v, want a new epoch", res, err)
	}
	listedAt(3)
	if got := ownWraps(t, s.bob, s.artifact); len(got) != 2 || got[1] == nil || got[2] == nil {
		t.Errorf("bob opens wraps of %d epochs, want 1 and 2", len(got))
	}
}

// A rotation list the server fails to serve cannot be told from one that
// does not lead to the user's keys: the user is a changed key, and the rest
// of the artifact goes on working.
func TestAFailedRotationsFetchDegradesInsteadOfAborting(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	if _, err := w.ada.Share(w.artifact, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	// Cat is approved after the owner's last record, so she waits unlisted.
	if _, err := w.bob.Approve(w.artifact, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Pin("cat@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	catID := w.userID(t, w.cat)
	rotateOK(t, w.cat, false)
	if got := pendingStates(t, w.ada, w.artifact); got["cat@example.com"] != PendingRotated {
		t.Fatalf("pending = %v, want cat rotated", got)
	}

	down := rotationsDown(w.ada, catID)
	list, err := down.Pending(w.artifact)
	if err != nil {
		t.Fatalf("Pending with cat's rotation list down: %v", err)
	}
	if len(list) != 1 || list[0].User.ID != catID || list[0].State != PendingKeyChanged {
		t.Errorf("pending = %+v, want cat as keyChanged", list)
	}
	if _, rows, err := down.Members(w.artifact); err != nil || len(rows) != 3 {
		t.Errorf("Members = %d rows, %v, want 3", len(rows), err)
	}
	if res, err := down.Share(w.artifact, "dan@example.com", "editor", false); err != nil || !res.Promoted {
		t.Errorf("Share of an unrelated user with cat's rotation list down = %+v, %v, want a promotion", res, err)
	}
	if res, err := down.Team(w.artifact, "viewer"); err != nil || !res.Unchanged {
		t.Errorf("Team with cat's rotation list down = %+v, %v, want Unchanged", res, err)
	}
	// Excluding cat needs the fingerprint her wraps were made for, which only
	// her chain says: the command is refused before it posts, with the
	// reason, and it goes through once the list is served again.
	before, catPin, danPin := recordCount(t, w.ada, w.artifact), pinOf(t, w.ada, catID), pinOf(t, w.ada, w.userID(t, w.dan))
	_, err = down.Unshare(w.artifact, "dan@example.com")
	want := fmt.Sprintf("cannot read the rotation records of cat@example.com (%s): disk on fire (500); without them cairn cannot tell which keys their wraps were made for. Retry when the records can be read", catID)
	if err == nil || err.Error() != want {
		t.Errorf("Unshare with cat's rotation list down: %v, want %q", err, want)
	}
	var api *APIError
	if !errors.As(err, &api) || api.Status != 500 {
		t.Errorf("Unshare's refusal wraps %v, want the 500", api)
	}
	if got := recordCount(t, w.ada, w.artifact); got != before {
		t.Errorf("a refused Unshare wrote a record: %d, was %d", got, before)
	}
	if pinOf(t, w.ada, catID) != catPin || pinOf(t, w.ada, w.userID(t, w.dan)) != danPin {
		t.Errorf("a refused Unshare changed a pin")
	}
	res, err := w.ada.Unshare(w.artifact, "dan@example.com")
	if err != nil {
		t.Fatalf("Unshare once the list is served again: %v", err)
	}
	if got := excludedEmails(latestRecord(t, w.ada, w.artifact)); !slices.Equal(got, []string{"cat@example.com", "dan@example.com"}) || !res.NewEpoch {
		t.Errorf("excluded = %v, want cat and dan", got)
	}
}

func TestAFailedRotationsFetchForAMemberIsAChangedKey(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 1)
	bobNow := mustUnlock(t, s.bob)
	oldPin := pinOf(t, s.ada, bobID)
	before := recordCount(t, s.ada, s.artifact)
	down := rotationsDown(s.ada, bobID)

	if got := pendingStates(t, down, s.artifact); got["bob@example.com"] != PendingKeyChanged {
		t.Errorf("pending = %v, want bob keyChanged", got)
	}
	if r := memberRows(t, down, s.artifact)["bob@example.com"]; r.State != e2e.PinChanged {
		t.Errorf("bob's row = %+v, want changed", r)
	}
	_, err := down.Share(s.artifact, "bob@example.com", "viewer", false)
	var changed *KeyChangedError
	if !errors.As(err, &changed) || changed.Fork != nil {
		t.Fatalf("Share with bob's rotation list down: %v, want a plain KeyChangedError", err)
	}
	if p := pinOf(t, s.ada, bobID); p != oldPin || recordCount(t, s.ada, s.artifact) != before {
		t.Errorf("a refused Share stored pin %+v or a record", p)
	}
	if _, err := down.Pin("bob@example.com", false, true); err != nil {
		t.Fatalf("Pin --accept-new-key: %v", err)
	}
	want := e2e.Pin{FP: bobNow.FP, State: e2e.PinUnverified}
	if p := pinOf(t, s.ada, bobID); p != want {
		t.Errorf("pin after accepting = %+v, want %+v", p, want)
	}

	// A pin that records a seq is no rollback when the list cannot be read:
	// the records are not served, not withheld.
	if _, err := s.ada.UpdateKeyring(mustUnlock(t, s.ada), func(kr *e2e.Keyring) error {
		delete(kr.Pins, bobID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.Pin("bob@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	rotateOK(t, s.bob, false)
	if pinOf(t, s.ada, bobID).RotSeq != 1 {
		t.Fatalf("pin = %+v, want seq 1", pinOf(t, s.ada, bobID))
	}
	_, err = rotationsDown(s.ada, bobID).Pin("bob@example.com", false, false)
	if !errors.As(err, &changed) || changed.Fork != nil || errors.Is(err, e2e.ErrRollback) {
		t.Errorf("Pin of a seq-1 pin with the list down: %v, want a plain KeyChangedError", err)
	}
}

// A failed fetch is named as one: the owner is told to retry, not that the
// keys changed, and nothing is stored without the flag.
func TestAFailedRotationsFetchIsNotPresentedAsAChangedKey(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 1)
	oldPin := pinOf(t, s.ada, bobID)
	before := recordCount(t, s.ada, s.artifact)
	down := rotationsDown(s.ada, bobID)
	for name, run := range map[string]func() error{
		"pin":   func() error { _, err := down.Pin("bob@example.com", false, false); return err },
		"share": func() error { _, err := down.Share(s.artifact, "bob@example.com", "viewer", false); return err },
	} {
		err := run()
		var changed *KeyChangedError
		if !errors.As(err, &changed) || changed.FetchErr == nil || changed.Fork != nil {
			t.Fatalf("%s with bob's rotation list down: %v, want a KeyChangedError with FetchErr", name, err)
		}
		var api *APIError
		if !errors.As(changed.FetchErr, &api) || api.Status != 500 {
			t.Errorf("%s: FetchErr = %v, want the 500", name, changed.FetchErr)
		}
		for _, want := range []string{
			"could not read the rotation records of bob@example.com", "disk on fire (500)",
			"retry before considering --accept-new-key",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: message %q lacks %q", name, err, want)
			}
		}
		if strings.Contains(err.Error(), "changed") {
			t.Errorf("%s: message %q presents a failed fetch as a change", name, err)
		}
	}
	if p := pinOf(t, s.ada, bobID); p != oldPin || recordCount(t, s.ada, s.artifact) != before {
		t.Errorf("a refused command stored pin %+v or a record", p)
	}
}

// A cancelled command, and one the server will not answer, stop; neither is
// a reason to ask about the user's keys.
func TestAContextOrAuthFailureOnTheRotationsFetchAborts(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 1)
	fresh := newSharing(t)
	freshBob := fresh.userID(t, fresh.bob)
	rotateOK(t, fresh.bob, false)
	for name, tc := range map[string]struct {
		answer func(r *http.Request) (*http.Response, error)
		is     func(error) bool
	}{
		"unauthorized": {answerStatus(401, "unauthorized"), func(err error) bool { return statusOf(err) == 401 }},
		"cancelled": {func(*http.Request) (*http.Response, error) { return nil, context.Canceled },
			func(err error) bool { return errors.Is(err, context.Canceled) }},
		"deadline": {func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded },
			func(err error) bool { return errors.Is(err, context.DeadlineExceeded) }},
	} {
		c := rotationsAnswering(s.ada, bobID, tc.answer)
		// Bob is pinned, listed, and rotated: every reader fetches his records.
		for op, run := range map[string]func() error{
			"pin":     func() error { _, err := c.Pin("bob@example.com", false, false); return err },
			"share":   func() error { _, err := c.Share(s.artifact, "bob@example.com", "viewer", false); return err },
			"members": func() error { _, _, err := c.Members(s.artifact); return err },
			"pending": func() error { _, err := c.Pending(s.artifact); return err },
		} {
			err := run()
			var changed *KeyChangedError
			if err == nil || !tc.is(err) || errors.As(err, &changed) {
				t.Errorf("%s: %s with the fetch failing = %v, want that error, not a KeyChangedError", name, op, err)
			}
		}
		// A first pin takes the records too, and stops the same way.
		if _, err := rotationsAnswering(fresh.ada, freshBob, tc.answer).Pin("bob@example.com", false, false); err == nil || !tc.is(err) {
			t.Errorf("%s: a first pin with the fetch failing = %v, want that error", name, err)
		}
	}
	if p := pinOf(t, fresh.ada, freshBob); p != (e2e.Pin{}) {
		t.Errorf("an aborted first pin stored %+v", p)
	}
}

// The flag stores a pin, but the server refuses a wrap for a member who
// rotated, so nothing is written; the error says why the wrap was sent.
func TestShareAcceptingTheNewKeyWhileTheRotationsFetchFailsIsRefused(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 1)
	oldPin := pinOf(t, s.ada, bobID)
	before := recordCount(t, s.ada, s.artifact)
	_, err := rotationsDown(s.ada, bobID).Share(s.artifact, "bob@example.com", "viewer", true)
	if err == nil {
		t.Fatal("Share --accept-new-key with the rotation list down succeeded")
	}
	for _, want := range []string{
		"the rotation records of bob@example.com could not be read (disk on fire (500))",
		"a wrap the server did not need", "retry when the records can be read",
		"is not needed (400)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err, want)
		}
	}
	if statusOf(err) != 400 {
		t.Errorf("the refusal wraps status %d, want the server's 400", statusOf(err))
	}
	if p := pinOf(t, s.ada, bobID); p != oldPin || recordCount(t, s.ada, s.artifact) != before {
		t.Errorf("a refused Share stored pin %+v or a record", p)
	}
}

// A first pin taken while the records are down is at seq 0, and stays there:
// the pin is on the member's current keys, so later reads fetch nothing.
func TestAFirstPinWhileTheRotationsFetchFailsStaysAtSeqZero(t *testing.T) {
	s := newSharing(t)
	bobID := s.userID(t, s.bob)
	rotateOK(t, s.bob, false)
	want := e2e.Pin{FP: mustUnlock(t, s.bob).FP, State: e2e.PinUnverified}
	if _, err := rotationsDown(s.ada, bobID).Pin("bob@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	if p := pinOf(t, s.ada, bobID); p != want {
		t.Fatalf("pin = %+v, want %+v", p, want)
	}
	// The records are served again.
	res, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false)
	if err != nil || res.Prior != e2e.PinUnverified {
		t.Fatalf("Share = %+v, %v, want a share of an unverified pin", res, err)
	}
	if r := memberRows(t, s.ada, s.artifact)["bob@example.com"]; r.State != e2e.PinUnverified {
		t.Errorf("bob's row = %+v, want unverified", r)
	}
	if p := pinOf(t, s.ada, bobID); p != want {
		t.Errorf("pin afterwards = %+v, want it unchanged at seq 0: %+v", p, want)
	}
}

func TestAFirstPinRecordsTheRotationSeq(t *testing.T) {
	s := newSharing(t)
	bobID := s.userID(t, s.bob)
	rotateOK(t, s.bob, false)
	bobNow := mustUnlock(t, s.bob)
	recs, err := s.ada.Rotations(bobID)
	if err != nil || len(recs) != 1 {
		t.Fatalf("Rotations = %v, %v", recs, err)
	}

	// Its fetch failing, the pin falls back to seq 0.
	if res, err := rotationsDown(s.ada, bobID).Pin("bob@example.com", false, false); err != nil || res.Prior != e2e.PinNew {
		t.Fatalf("Pin with the rotation list down = %+v, %v, want a first pin", res, err)
	}
	if p := pinOf(t, s.ada, bobID); p != (e2e.Pin{FP: bobNow.FP, State: e2e.PinUnverified}) {
		t.Errorf("pin with the list down = %+v, want seq 0", p)
	}

	k := mustUnlock(t, s.ada)
	if _, err := s.ada.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		delete(kr.Pins, bobID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	res, err := s.ada.Pin("bob@example.com", false, false)
	if err != nil || res.Prior != e2e.PinNew {
		t.Fatalf("Pin = %+v, %v, want a first pin", res, err)
	}
	want := e2e.Pin{FP: bobNow.FP, State: e2e.PinUnverified, RotSeq: 1, RotHead: e2e.BodyHash(recs[0].Body)}
	if p := pinOf(t, s.ada, bobID); p != want {
		t.Errorf("first pin = %+v, want %+v", p, want)
	}
}

func TestAFirstPinByShareRecordsTheRotationSeq(t *testing.T) {
	s := newSharing(t)
	bobID := s.userID(t, s.bob)
	rotateOK(t, s.bob, false)
	recs, _ := s.ada.Rotations(bobID)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	want := e2e.Pin{FP: mustUnlock(t, s.bob).FP, State: e2e.PinUnverified, RotSeq: 1, RotHead: e2e.BodyHash(recs[0].Body)}
	if p := pinOf(t, s.ada, bobID); p != want {
		t.Errorf("first pin by Share = %+v, want %+v", p, want)
	}
}

// A member who rotates with --keep-epochs keeps what they hold the same way:
// the flag is about the epochs of what they own.
func TestOwnerRelistsAMemberWhoRotatedWithKeepEpochs(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 0)
	rotateOK(t, s.bob, true)
	bobNow := mustUnlock(t, s.bob)
	if r := memberRows(t, s.ada, s.artifact)["bob@example.com"]; r.State != e2e.PinRotated {
		t.Fatalf("bob's row = %+v, want rotated", r)
	}
	res, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false)
	if err != nil || res.Unchanged {
		t.Fatalf("Share = %+v, %v, want a re-listing", res, err)
	}
	if m := latestRecord(t, s.ada, s.artifact).Members; len(m) != 1 || m[0].User != bobID || m[0].FP != bobNow.FP {
		t.Errorf("members = %+v, want bob under %s", m, bobNow.FP)
	}
	if r := memberRows(t, s.ada, s.artifact)["bob@example.com"]; r.State != e2e.PinUnverified {
		t.Errorf("bob's row after the re-listing = %+v, want unverified", r)
	}
	if got := openWraps(t, s.bob, s.artifact); !slices.Equal(got, []int{1}) {
		t.Errorf("bob's wraps = %v, want epoch 1", got)
	}
}

// The membership GET and /rotations may serve different chains for a user.
// The client reads the membership's copy when it has one, and a copy that
// does not lead to the user's keys is a changed key, never a re-listing.
func TestDivergentRotationCopiesFailClosed(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 1)
	oldPin := pinOf(t, s.ada, bobID)
	before := recordCount(t, s.ada, s.artifact)
	real := func(r []e2e.Envelope) []e2e.Envelope { return r }
	for name, bad := range map[string]func([]e2e.Envelope) []e2e.Envelope{
		"a bad signature": func(r []e2e.Envelope) []e2e.Envelope {
			out := slices.Clone(r)
			out[0].Sig = bytes.Repeat([]byte{1}, len(out[0].Sig))
			return out
		},
		"no records": func([]e2e.Envelope) []e2e.Envelope { return nil },
		"a body that is not a record": func(r []e2e.Envelope) []e2e.Envelope {
			out := slices.Clone(r)
			out[0].Body = []byte("not json")
			return out
		},
		"a record of another user": func(r []e2e.Envelope) []e2e.Envelope {
			var b e2e.RotationBody
			if err := e2e.DecodeStrict(r[0].Body, &b); err != nil {
				t.Fatal(err)
			}
			b.User = "someone-else"
			out := slices.Clone(r)
			out[0].Body, _ = json.Marshal(b)
			return out
		},
	} {
		ada := viaProxy(divergentRotations(t, s.host, bobID, bad, real), s.ada)
		if got := pendingStates(t, ada, s.artifact); got["bob@example.com"] != PendingKeyChanged {
			t.Errorf("%s: pending = %v, want bob keyChanged", name, got)
		}
		_, err := ada.Share(s.artifact, "bob@example.com", "editor", false)
		var changed *KeyChangedError
		if !errors.As(err, &changed) {
			t.Errorf("%s: Share = %v, want a KeyChangedError", name, err)
		}
		if p := pinOf(t, s.ada, bobID); p != oldPin || recordCount(t, s.ada, s.artifact) != before {
			t.Errorf("%s: a refused Share stored pin %+v or a record", name, p)
		}
	}
	// A bad copy at /rotations is never read for a listed member, whose
	// records came with the membership.
	ada := viaProxy(divergentRotations(t, s.host, bobID, real, func([]e2e.Envelope) []e2e.Envelope { return nil }), s.ada)
	if got := pendingStates(t, ada, s.artifact); got["bob@example.com"] != PendingRotated {
		t.Errorf("pending with a bad /rotations copy = %v, want bob rotated by the membership's copy", got)
	}
}

func TestTwoRotationsBeforeTheOwnerLooks(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 2)
	bobNow := mustUnlock(t, s.bob)
	recs, _ := s.ada.Rotations(bobID)
	if got := pendingStates(t, s.ada, s.artifact); got["bob@example.com"] != PendingRotated {
		t.Errorf("pending = %v, want bob rotated", got)
	}
	if r := memberRows(t, s.ada, s.artifact)["bob@example.com"]; r.State != e2e.PinRotated || r.WasVerified {
		t.Errorf("bob's row = %+v, want rotated", r)
	}
	if _, err := s.ada.Public(s.artifact, true, nil); err != nil {
		t.Fatal(err)
	}
	m := latestRecord(t, s.ada, s.artifact).Members
	if len(m) != 1 || m[0].FP != bobNow.FP {
		t.Errorf("members = %+v, want bob under %s", m, bobNow.FP)
	}
	want := e2e.Pin{FP: bobNow.FP, State: e2e.PinUnverified, RotSeq: 2, RotHead: e2e.BodyHash(recs[1].Body)}
	if p := pinOf(t, s.ada, bobID); p != want {
		t.Errorf("bob's pin = %+v, want %+v", p, want)
	}
}

func TestApproveAndTeamRefuseAForkedRotationChain(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	catID := w.userID(t, w.cat)
	catOld := mustUnlock(t, w.cat)
	// Bob and ada have pinned cat's old keys.
	for _, c := range []*Client{w.bob, w.ada} {
		if _, err := c.Pin("cat@example.com", false, false); err != nil {
			t.Fatal(err)
		}
	}
	rotateOK(t, w.cat, false)
	recs, _ := w.ada.Rotations(catID)
	forged := forkOf(t, recs[0], catOld)
	fork := func(r []e2e.Envelope) []e2e.Envelope { return append(slices.Clone(r), forged) }

	bob := viaProxy(servedRotations(t, w.host, catID, fork), w.bob)
	_, err := bob.Approve(w.artifact, "cat@example.com", false)
	var changed *KeyChangedError
	if !errors.As(err, &changed) || !errors.Is(err, e2e.ErrRotationFork) {
		t.Fatalf("Approve through a forked chain: %v, want a KeyChangedError wrapping ErrRotationFork", err)
	}

	// An editor approves her through the real chain, and the owner's Team
	// lists her unless the chain forks.
	if _, err := w.bob.Approve(w.artifact, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	ada := viaProxy(servedRotations(t, w.host, catID, fork), w.ada)
	res, err := ada.Team(w.artifact, "viewer")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Listed) != 0 || len(res.Unlisted) != 1 || !errors.Is(res.Unlisted[0].Err, e2e.ErrRotationFork) {
		t.Errorf("Team = listed %v, unlisted %+v, want cat unlisted for the fork", res.Listed, res.Unlisted)
	}
	if m := latestRecord(t, w.ada, w.artifact).Members; slices.ContainsFunc(m, func(m e2e.Member) bool { return m.User == catID }) {
		t.Errorf("members = %+v, want cat not listed", m)
	}
}

func TestOwnerRotationWrapsANewEpochToARotatedMember(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 1)
	bobNow := mustUnlock(t, s.bob)
	recs, _ := s.ada.Rotations(bobID)
	rotateOK(t, s.ada, false)

	latest := latestRecord(t, s.ada, s.artifact)
	if latest.Epoch != 2 || len(latest.Members) != 1 || latest.Members[0].FP != bobNow.FP {
		t.Errorf("latest = epoch %d, members %+v, want epoch 2 with bob under %s", latest.Epoch, latest.Members, bobNow.FP)
	}
	want := e2e.Pin{FP: bobNow.FP, State: e2e.PinUnverified, RotSeq: 1, RotHead: e2e.BodyHash(recs[0].Body)}
	if p := pinOf(t, s.ada, bobID); p != want {
		t.Errorf("ada's pin for bob after her rotation = %+v, want %+v", p, want)
	}
	got := ownWraps(t, s.bob, s.artifact)
	if len(got) != 2 || got[1] == nil || got[2] == nil {
		t.Fatalf("bob opens wraps of %d epochs, want 1 and 2", len(got))
	}
	if commit, _ := e2e.AKCommit(got[2], s.artifact, 2); commit != latest.AKCommit {
		t.Error("the AK bob opens for epoch 2 does not match the chain's akCommit")
	}
}

// The owner's rotation is not a member's: nothing lists them as rotated or
// changed, whatever the keep-epochs choice.
func TestOwnerWhoRotatedWithKeepEpochsIsNeverShownAsRotated(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	adaID := s.userID(t, s.ada)
	rotateOK(t, s.ada, true)
	if got := pendingStates(t, s.ada, s.artifact); len(got) != 0 {
		t.Errorf("pending = %v, want empty", got)
	}
	rows := memberRows(t, s.ada, s.artifact)
	if r := rows["ada@example.com"]; r.User != adaID || r.State != "self" || r.Role != "owner" {
		t.Errorf("ada's row = %+v, want self", r)
	}
	if r := rows["bob@example.com"]; r.State != e2e.PinUnverified {
		t.Errorf("bob's row = %+v, want unverified", r)
	}
	if res, err := s.ada.Share(s.artifact, "bob@example.com", "editor", false); err != nil || !res.Promoted {
		t.Errorf("Share after the owner rotated = %+v, %v, want a promotion", res, err)
	}
	if got := pendingStates(t, s.ada, s.artifact); len(got) != 0 {
		t.Errorf("pending after Share = %v, want empty", got)
	}
}

// A listed member the owner holds no pin for is re-listed too: the chain is
// anchored on the fingerprint the owner's record lists. The pin is stored at
// the new keys, unverified, at the chain's seq.
func TestAListedMemberWithNoOwnerPinIsRelistedAndPinned(t *testing.T) {
	w := newTeam(t)
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	bobID := w.userID(t, w.bob)
	dropPin := func() {
		t.Helper()
		if _, err := w.ada.UpdateKeyring(mustUnlock(t, w.ada), func(kr *e2e.Keyring) error {
			delete(kr.Pins, bobID)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	check := func(seq int, what string) {
		t.Helper()
		bobNow := mustUnlock(t, w.bob)
		recs, _ := w.ada.Rotations(bobID)
		m := latestRecord(t, w.ada, w.artifact).Members
		if i := slices.IndexFunc(m, func(m e2e.Member) bool { return m.User == bobID }); i < 0 || m[i].FP != bobNow.FP {
			t.Errorf("%s: members = %+v, want bob under %s", what, m, bobNow.FP)
		}
		want := e2e.Pin{FP: bobNow.FP, State: e2e.PinUnverified, RotSeq: seq, RotHead: e2e.BodyHash(recs[seq-1].Body)}
		if p := pinOf(t, w.ada, bobID); p != want {
			t.Errorf("%s: bob's pin = %+v, want %+v", what, p, want)
		}
	}

	dropPin()
	rotateOK(t, w.bob, false)
	if _, err := w.ada.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	check(1, "a same-epoch record")

	dropPin()
	rotateOK(t, w.bob, false)
	if _, err := w.ada.Unshare(w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	check(2, "a next-epoch record")
}

// intercepting is a copy of c whose requests rule may answer itself: it
// returns a response to answer without forwarding, or nil to go on through
// c's own transport.
func intercepting(c *Client, rule func(r *http.Request) *http.Response) *Client {
	inner := http.DefaultTransport
	if c.HTTP != nil && c.HTTP.Transport != nil {
		inner = c.HTTP.Transport
	}
	out := NewWithKey(c.Host, *c.Key)
	out.Anchors = c.Anchors
	out.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if resp := rule(r); resp != nil {
			resp.Request = r
			return resp, nil
		}
		return inner.RoundTrip(r)
	})}
	return out
}

// answer is an API error response of status.
func answer(status int, message string) *http.Response {
	resp, _ := answerStatus(status, message)(nil)
	return resp
}

// unreadable is the refusal for a user whose rotation records fail with the
// 500 of rotationsDown.
func unreadable(email, id string) string {
	return fmt.Sprintf("cannot read the rotation records of %s (%s): disk on fire (500); without them cairn cannot tell which keys their wraps were made for. Retry when the records can be read", email, id)
}

// A listed member who rotated, whose records cannot be read, is not a member
// whose keys the owner is to decide about: the owner is told to retry.
func TestUnshareRefusesAListedRotatedMemberWhoseRecordsCannotBeRead(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	if _, err := w.ada.Share(w.artifact, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	bobID, danID := w.userID(t, w.bob), w.userID(t, w.dan)
	rotateOK(t, w.bob, false)
	before, bobPin, danPin := recordCount(t, w.ada, w.artifact), pinOf(t, w.ada, bobID), pinOf(t, w.ada, danID)
	_, err := rotationsDown(w.ada, bobID).Unshare(w.artifact, "dan@example.com")
	if err == nil || err.Error() != unreadable("bob@example.com", bobID) {
		t.Errorf("Unshare with a listed member's records down: %v, want %q", err, unreadable("bob@example.com", bobID))
	}
	if errors.Is(err, ErrMemberKeyChanged) {
		t.Errorf("the refusal is ErrMemberKeyChanged: %v", err)
	}
	if statusOf(err) != 500 {
		t.Errorf("the refusal wraps status %d, want the 500", statusOf(err))
	}
	if got := recordCount(t, w.ada, w.artifact); got != before {
		t.Errorf("a refused Unshare wrote a record: %d, was %d", got, before)
	}
	if pinOf(t, w.ada, bobID) != bobPin || pinOf(t, w.ada, danID) != danPin {
		t.Errorf("a refused Unshare changed a pin")
	}
	// Once the records are served, bob is relisted and dan removed.
	if _, err := w.ada.Unshare(w.artifact, "dan@example.com"); err != nil {
		t.Fatalf("Unshare once the records are served: %v", err)
	}
	bobNow := mustUnlock(t, w.bob)
	latest := latestRecord(t, w.ada, w.artifact)
	if i := slices.IndexFunc(latest.Members, func(m e2e.Member) bool { return m.User == bobID }); i < 0 || latest.Members[i].FP != bobNow.FP {
		t.Errorf("members = %+v, want bob under %s", latest.Members, bobNow.FP)
	}
	if !slices.ContainsFunc(latest.Excluded, func(x e2e.ExcludedEntry) bool { return x.User == danID }) {
		t.Errorf("excluded = %+v, want dan", latest.Excluded)
	}
}

// Unshare of the user whose records cannot be read names them in the refusal.
func TestUnshareOfAHolderWhoseRecordsCannotBeReadNamesThem(t *testing.T) {
	w := rotatedHolder(t)
	catID := w.userID(t, w.cat)
	before, catPin := recordCount(t, w.ada, w.artifact), pinOf(t, w.ada, catID)
	_, err := rotationsDown(w.ada, catID).Unshare(w.artifact, "cat@example.com")
	if err == nil || err.Error() != unreadable("cat@example.com", catID) {
		t.Errorf("Unshare of cat with her records down: %v, want %q", err, unreadable("cat@example.com", catID))
	}
	if recordCount(t, w.ada, w.artifact) != before || pinOf(t, w.ada, catID) != catPin {
		t.Errorf("a refused Unshare wrote a record or changed a pin")
	}
}

// A listed member is removed under the keys the record listed them by, which
// needs no records, so a failing fetch does not stop their removal.
func TestUnshareOfAListedRotatedMemberWhoseRecordsCannotBeReadExcludesThemUnderTheListedKeys(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	bobID := w.userID(t, w.bob)
	listedFP := latestRecord(t, w.ada, w.artifact).Members[0].FP
	rotateOK(t, w.bob, false)
	if _, err := rotationsDown(w.ada, bobID).Unshare(w.artifact, "bob@example.com"); err != nil {
		t.Fatalf("Unshare of bob with his records down: %v", err)
	}
	x := latestRecord(t, w.ada, w.artifact).Excluded
	if len(x) != 1 || x[0].User != bobID || x[0].FP != listedFP {
		t.Errorf("excluded = %+v, want bob under the fingerprint the record listed him by, %s", x, listedFP)
	}
}

// A pin that differs from an approved user's keys is followed through their
// records, and a fetch that must stop the command does: it is no reason to
// leave the user unlisted and go on.
func TestAFatalRotationsFetchForAnApprovedUserAbortsTeamShareAndUnshare(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	// Cat is approved after the owner's last record, so she waits unlisted,
	// and the owner's pin is for other keys than hers.
	if _, err := w.bob.Approve(w.artifact, "cat@example.com", false); err != nil {
		t.Fatal(err)
	}
	catID, danID := w.userID(t, w.cat), w.userID(t, w.dan)
	if _, err := w.ada.Pin("cat@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.UpdateKeyring(mustUnlock(t, w.ada), func(kr *e2e.Keyring) error {
		kr.Pins[catID] = e2e.Pin{FP: strings.Repeat("ab", 32), State: e2e.PinUnverified}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := pendingStates(t, w.ada, w.artifact); got["cat@example.com"] != PendingApproved {
		t.Fatalf("pending = %v, want cat approved", got)
	}
	before, catPin := recordCount(t, w.ada, w.artifact), pinOf(t, w.ada, catID)
	c := rotationsAnswering(w.ada, catID, answerStatus(401, "unauthorized"))
	for op, run := range map[string]func() error{
		"team":    func() error { _, err := c.Team(w.artifact, "viewer"); return err },
		"share":   func() error { _, err := c.Share(w.artifact, "dan@example.com", "viewer", false); return err },
		"unshare": func() error { _, err := c.Unshare(w.artifact, "bob@example.com"); return err },
	} {
		if err := run(); statusOf(err) != 401 {
			t.Errorf("%s with the rotations fetch refused = %v, want the 401", op, err)
		}
		if recordCount(t, w.ada, w.artifact) != before || pinOf(t, w.ada, catID) != catPin || pinOf(t, w.ada, danID) != (e2e.Pin{}) {
			t.Errorf("%s wrote a record or changed a pin", op)
		}
	}
}

// A 401 on a listed member's pin check stops Unshare: the member is no
// "changed key" and nothing is written.
func TestUnshareStopsOnAFatalRotationsFetchForAListedMember(t *testing.T) {
	w := newTeam(t)
	w.setup(t, "viewer")
	if _, err := w.ada.Share(w.artifact, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	bobID := w.userID(t, w.bob)
	// Bob's keys are the listed ones, and the owner's pin is for others.
	if _, err := w.ada.UpdateKeyring(mustUnlock(t, w.ada), func(kr *e2e.Keyring) error {
		kr.Pins[bobID] = e2e.Pin{FP: strings.Repeat("ab", 32), State: e2e.PinUnverified}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, bobPin, danPin := recordCount(t, w.ada, w.artifact), pinOf(t, w.ada, bobID), pinOf(t, w.ada, w.userID(t, w.dan))
	_, err := rotationsAnswering(w.ada, bobID, answerStatus(401, "unauthorized")).Unshare(w.artifact, "dan@example.com")
	var api *APIError
	var changed *KeyChangedError
	if !errors.As(err, &api) || api.Status != 401 || errors.As(err, &changed) {
		t.Errorf("Unshare with the fetch refused = %v, want the 401 and no KeyChangedError", err)
	}
	if recordCount(t, w.ada, w.artifact) != before || pinOf(t, w.ada, bobID) != bobPin || pinOf(t, w.ada, w.userID(t, w.dan)) != danPin {
		t.Errorf("a refused Unshare wrote a record or changed a pin")
	}
}

// RotateKeys builds every artifact's next epoch before it posts anything, so
// an artifact it refuses leaves nothing done: the one POST carries the
// rotation and the records together, and the unconfirmed state is for a lost
// answer to it, which this is not.
func TestRotateKeysRefusesAnUnlistedHolderWhoseRecordsCannotBeReadAndWritesNothing(t *testing.T) {
	w := rotatedHolder(t)
	catID, adaID := w.userID(t, w.cat), w.userID(t, w.ada)
	adaKeys := mustUnlock(t, w.ada)
	before := recordCount(t, w.ada, w.artifact)
	var writes []string
	down := intercepting(rotationsDown(w.ada, catID), func(r *http.Request) *http.Response {
		if r.Method != "GET" {
			writes = append(writes, r.Method+" "+r.URL.Path)
		}
		return nil
	})
	res, err := down.RotateKeys(testPassword, false)
	if want := "artifact " + w.artifact + ": " + unreadable("cat@example.com", catID); err == nil || err.Error() != want {
		t.Errorf("RotateKeys with cat's records down: %v, want %q", err, want)
	}
	if res != nil {
		t.Errorf("RotateKeys returned a result %+v with its refusal", res)
	}
	// The only POSTs are the sign-in with the password, which makes a session
	// and changes no keys; neither the rotation nor any record was posted.
	if !slices.Equal(writes, []string{"POST /api/auth/prelogin", "POST /api/auth/login"}) {
		t.Errorf("writes = %v, want the sign-in only", writes)
	}
	if recs, err := w.ada.Rotations(adaID); err != nil || len(recs) != 0 {
		t.Errorf("ada's rotation records = %d, %v, want none", len(recs), err)
	}
	if k := mustUnlock(t, w.ada); k.FP != adaKeys.FP {
		t.Errorf("ada's keys changed")
	}
	if recordCount(t, w.ada, w.artifact) != before {
		t.Errorf("a refused RotateKeys wrote a record")
	}
	// Once the records are served, the same call goes through and excludes cat.
	out := rotateOK(t, w.ada, false)
	if out.Unconfirmed || out.Epochs[w.artifact] != 2 {
		t.Errorf("RotateKeys on retry = %+v, want epoch 2, confirmed", out)
	}
	if got := excludedEmails(latestRecord(t, w.ada, w.artifact)); !slices.Equal(got, []string{"cat@example.com"}) {
		t.Errorf("excluded after the retry = %v, want cat", got)
	}
}

// The refusal for a wrap the server did not need names the unreadable records
// only for a 400, which says so: any other failure of the record passes.
func TestShareWrapRefusalWrapperOnlyForABadRequest(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 1)
	oldPin := pinOf(t, s.ada, bobID)
	before := recordCount(t, s.ada, s.artifact)
	for _, status := range []int{409, 500} {
		c := intercepting(rotationsDown(s.ada, bobID), func(r *http.Request) *http.Response {
			if r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/membership") {
				return answer(status, "injected")
			}
			return nil
		})
		_, err := c.Share(s.artifact, "bob@example.com", "viewer", true)
		if statusOf(err) != status {
			t.Fatalf("Share with the record refused with %d = %v, want that status", status, err)
		}
		if strings.Contains(err.Error(), "could not be read") || strings.Contains(err.Error(), "wrap the server did not need") {
			t.Errorf("a %d carries the wrapper: %v", status, err)
		}
	}
	if p := pinOf(t, s.ada, bobID); p != oldPin || recordCount(t, s.ada, s.artifact) != before {
		t.Errorf("a refused Share stored pin %+v or a record", p)
	}
}

// A request that carries no wrap has no wrap to blame: a 400 passes through
// unwrapped even for a user whose records could not be read. Only a lying
// pending list gets here, for a member whose keys are the listed ones.
func TestShareBadRequestWithoutAWrapIsNotBlamedOnTheWrap(t *testing.T) {
	s := newSharing(t)
	bobID, _ := bobRotatesAfterAdaPinned(t, s, 0)
	dir, err := s.ada.Directory()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := FindUser(dir, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	lying := rewritingList(t, s.ada, "/api/artifacts/"+s.artifact+"/pending", func(list []map[string]any) []map[string]any {
		return append(list, map[string]any{
			"id": bob.ID, "name": bob.Name, "email": bob.Email,
			"x25519Pub": e2e.B64(bob.X25519Pub), "ed25519Pub": e2e.B64(bob.Ed25519Pub), "state": "rotated",
		})
	})
	c := intercepting(lying, func(r *http.Request) *http.Response {
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/users/"+bobID+"/rotations":
			return answer(500, "disk on fire")
		case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/membership"):
			return answer(400, "injected")
		}
		return nil
	})
	if got := pendingStates(t, c, s.artifact); got["bob@example.com"] != PendingKeyChanged {
		t.Fatalf("pending = %v, want bob keyChanged", got)
	}
	_, err = c.Share(s.artifact, "bob@example.com", "editor", false)
	if statusOf(err) != 400 || strings.Contains(err.Error(), "could not be read") {
		t.Errorf("Share with a 400 and no wrap = %v, want the bare 400", err)
	}
}

// recordingHTTP is an HTTP client that notes the path of every request.
func recordingHTTP(paths *[]string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		*paths = append(*paths, r.URL.Path)
		return http.DefaultTransport.RoundTrip(r)
	})}
}
