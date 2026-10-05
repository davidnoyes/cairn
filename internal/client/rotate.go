// Key rotation: the client side of POST /api/me/rotate. As elsewhere in this
// package, every byte of cryptography is built with internal/e2e; see
// "Rotating keys" in design/e2e-api.md.
package client

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// RotateResult is what RotateKeys did.
type RotateResult struct {
	// RecoveryCode is the new recovery code, in display form. The old one no
	// longer opens anything.
	RecoveryCode string
	// Seq is the rotation record's seq.
	Seq int
	// Epochs is the epoch of every artifact the caller owns.
	Epochs map[string]int
	// Links holds the new public link of each public artifact that moved to a
	// new epoch: the old link stopped working.
	Links    map[string]string
	Warnings []string
	// APIKey and Email are the new device key and the account it belongs to,
	// for the caller to save. The old key and every other one were revoked.
	APIKey string
	Email  string
	// Unconfirmed is set when the server's answer was lost and reading the
	// result failed too, so the rotation may or may not have been applied.
	Unconfirmed bool
}

// Rotations lists a user's rotation records, oldest first.
func (c *Client) Rotations(userID string) ([]e2e.Envelope, error) {
	var out struct {
		Records []e2e.Envelope `json:"records"`
	}
	if err := c.doJSON("GET", "/api/users/"+userID+"/rotations", nil, &out); err != nil {
		return nil, err
	}
	return out.Records, nil
}

// lastRotationSeq is the seq of the last of a user's rotation records, or 0
// for none.
func lastRotationSeq(records []e2e.Envelope) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}
	var b e2e.RotationBody
	if err := e2e.DecodeStrict(records[len(records)-1].Body, &b); err != nil {
		return 0, fmt.Errorf("the server's last rotation record: %w", err)
	}
	return b.Seq, nil
}

func keyPairOf(k *UnlockedKeys) e2e.KeyPair {
	return e2e.KeyPair{X25519: e2e.B64(k.X25519Pub), Ed25519: e2e.B64(k.Ed25519Pub)}
}

// rotateTransfer is a change of owner to or from the caller in the last 30
// days, as the rotate answer lists it.
type rotateTransfer struct {
	Artifact string `json:"artifact"`
	From     string `json:"from"`
	To       string `json:"to"`
	At       string `json:"at"`
}

// transferWarnings makes one warning for each change of owner the server
// reported, because whoever held the old key could have signed an offer or
// accepted one. emails maps user IDs to the emails the directory knows; a
// user it does not know is named by ID.
func transferWarnings(transfers []rotateTransfer, me string, emails map[string]string) []string {
	name := func(id string) string {
		if e := emails[id]; e != "" {
			return e
		}
		return id
	}
	var out []string
	for _, t := range transfers {
		if t.From == me {
			out = append(out, fmt.Sprintf("you handed ownership of artifact %s to %s on %s; check that you made that offer, because anyone who held your old key could have signed one", t.Artifact, name(t.To), t.At))
		} else {
			out = append(out, fmt.Sprintf("you took ownership of artifact %s from %s on %s; check that you accepted it, because anyone who held your old key could have accepted for you", t.Artifact, name(t.From), t.At))
		}
	}
	return out
}

// RotateKeys replaces the caller's keys, as design/e2e-api.md ("Rotating
// keys") describes, and keeps the password. It signs in with the password,
// generates new keys, EK, and recovery code, and posts one request that the
// server applies whole. Nothing is changed, here or on the server, before the
// server answers 200. Without keepEpochs every artifact the caller owns moves
// to its next epoch; with it each keeps its epoch, and the AKs are the same.
//
// The server revokes every API key, so RotateKeys signs in again and sets c
// to the new device key. After the server accepted the rotation, a failure is
// returned together with the result, which holds the new recovery code and
// device key: the rotation happened, and they are not recoverable otherwise.
// On 409 the server's state moved after this read it; the error says what,
// and the caller runs RotateKeys again. When the answer to the POST is lost
// (a transport error or a 5xx), it reads the rotation list again to learn
// whether the server applied the rotation.
func (c *Client) RotateKeys(password string, keepEpochs bool) (*RotateResult, error) {
	me, err := c.Me()
	if err != nil {
		return nil, err
	}
	ps, err := c.passwordSignIn(me.Email, password)
	if err != nil {
		return nil, err
	}
	// The endpoint is session-only, and every read below uses the session too.
	s := &Client{Host: c.Host, Token: ps.Token, HTTP: c.HTTP, Anchors: c.Anchors, OnNotice: c.OnNotice}
	old, err := openKeys(me.ID, ps.MK, ps.Bundle)
	if err != nil {
		return nil, err
	}
	// The KDF and salt are the account's own, so the password still opens the
	// new bundle.
	na, err := newBundle(me.Email, password, ps.Params)
	if err != nil {
		return nil, err
	}
	nk := na.Keys
	nk.UserID = me.ID

	rotations, err := s.Rotations(me.ID)
	if err != nil {
		return nil, err
	}
	last, err := lastRotationSeq(rotations)
	if err != nil {
		return nil, err
	}
	kr, _, err := s.openKeyring(old)
	if err != nil {
		return nil, err
	}
	newKR := kr.Clone()
	newKR.Rev = kr.Rev + 1

	arts, err := s.listArtifacts()
	if err != nil {
		return nil, err
	}
	dir, err := s.Directory()
	if err != nil {
		return nil, err
	}
	newEKKey, err := e2e.EKSealKey(nk.EK)
	if err != nil {
		return nil, err
	}

	res := &RotateResult{RecoveryCode: na.RecoveryDisplay, Email: me.Email, Links: map[string]string{}}
	wraps, estate, records := []map[string]any{}, []map[string]any{}, []map[string]any{}
	// owned maps each artifact the caller owns to the seq of its last record.
	owned := map[string]int{}
	// held maps each artifact the caller does not own to the epochs of the
	// wraps they hold on it under their current keys, and epochs maps each
	// owned artifact to the epoch it moves to.
	held, epochs := map[string][]int{}, map[string]int{}
	for _, a := range arts {
		if a.OwnerID != me.ID {
			rewrapped, heldEpochs, err := s.rewrapHeld(old, nk, a.ID, me.Email)
			if err != nil {
				return nil, err
			}
			wraps = append(wraps, rewrapped...)
			if len(heldEpochs) > 0 {
				held[a.ID] = heldEpochs
			}
			continue
		}
		if a.Epoch == 0 {
			continue // owned, but created with no membership record
		}
		va, creator, pin, err := s.checkArtifact(old, kr, a.ID, old.FP)
		if err != nil {
			return nil, err
		}
		if va.Chain.Latest.Owner != me.ID {
			return nil, fmt.Errorf("the server lists you as the owner of artifact %s, but its chain does not", a.ID)
		}
		next := va.Chain.Latest
		next.OwnerFP = nk.FP

		var newWraps []map[string]any
		var linkHash string
		var aks map[int][]byte
		if keepEpochs {
			if aks, err = s.epochAKs(old, a.ID, va.Chain); err != nil {
				return nil, err
			}
			if next.Public {
				if linkHash, err = linkTokenHash(aks[next.Epoch], a.ID, next.Epoch); err != nil {
					return nil, err
				}
			}
		} else {
			pending, err := s.pendingFor(old, a.ID, va)
			if err != nil {
				return nil, err
			}
			b, err := s.buildNextEpoch(old, a.ID, va, dir, pending, nextEpochRecord{next: next})
			if err != nil {
				return nil, fmt.Errorf("artifact %s: %w", a.ID, err)
			}
			next, newWraps, linkHash, aks = b.next, b.wraps, b.linkHash, b.aks
			if next.Public {
				res.Links[a.ID] = b.change.Link
			}
			for user, d := range b.lst.pins {
				if cur, ok := newKR.Pins[user]; ok && cur.FP == d.pin.FP && cur.State == e2e.PinVerified {
					continue
				}
				newKR.Pins[user] = d.pin
			}
		}
		next, env, err := signNext(nk.Ed25519Seed, me.ID, va, next)
		if err != nil {
			return nil, err
		}
		if newWraps == nil {
			newWraps = []map[string]any{}
		}
		records = append(records, map[string]any{
			"artifact": a.ID, "membership": env, "wraps": newWraps, "linkTokenHash": linkHash,
		})
		// Every epoch's estate copy is sealed again under the new EK.
		for epoch := 1; epoch <= next.Epoch; epoch++ {
			sealed, err := e2e.Seal(rand.Reader, newEKKey, estateFields(a.ID, epoch), aks[epoch])
			if err != nil {
				return nil, err
			}
			estate = append(estate, map[string]any{"artifact": a.ID, "epoch": epoch, "sealed": e2e.B64(sealed)})
		}
		// The new head is the keyring's pin, so the next read accepts it.
		newKR.Epochs[a.ID] = e2e.KeyringEpoch{Epoch: next.Epoch, Seq: next.Seq, Head: e2e.BodyHash(env.Body), Ack: kr.Epochs[a.ID].Ack}
		if _, ok := newKR.Pins[creator]; pin != nil && !ok {
			newKR.Pins[creator] = *pin
		}
		owned[a.ID] = va.Chain.Latest.Seq
		epochs[a.ID] = next.Epoch
	}

	body, err := json.Marshal(e2e.RotationBody{V: 1, User: me.ID, Seq: last + 1, Old: keyPairOf(old), New: keyPairOf(nk)})
	if err != nil {
		return nil, err
	}
	rotation, err := e2e.SignRotation(old.Ed25519Seed, nk.Ed25519Seed, body, me.ID)
	if err != nil {
		return nil, err
	}
	sealedKR, err := e2e.SealKeyring(rand.Reader, nk.MKSealKey, newKR)
	if err != nil {
		return nil, err
	}

	var ans struct {
		Seq       int              `json:"seq"`
		Epochs    map[string]int   `json:"epochs"`
		Transfers []rotateTransfer `json:"transfers"`
	}
	if err := s.doJSON("POST", "/api/me/rotate", map[string]any{
		"authKey": e2e.B64(ps.AuthKey), "bundle": na.Wire, "rotation": rotation,
		"keyring": keyringWire{Rev: newKR.Rev, Keyring: e2e.B64(sealedKR)},
		"wraps":   wraps, "estate": estate, "records": records,
	}, &ans); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status < http.StatusInternalServerError {
			if apiErr.Status == http.StatusConflict {
				return nil, s.rotateConflict(me.ID, old.FP, last, kr.Rev, owned, held, err)
			}
			return nil, err
		}
		// Neither a transport error nor a 5xx says whether the server applied
		// the rotation, and if it did the old recovery code is dead.
		applied, serr := c.rotationApplied(me, password, last+1, nk)
		if serr != nil {
			res.Seq, res.Epochs, res.Unconfirmed = last+1, epochs, true
			return res, fmt.Errorf("the rotation request failed (%v) and reading the result failed (%v), so the server may have applied the rotation; keep the shown recovery code until this is settled: run cairn login, then cairn rotate-keys again, and keep the code that run shows instead", err, serr)
		}
		if !applied {
			return nil, fmt.Errorf("the rotation request failed (%w) and the server did not apply it: nothing changed; run cairn rotate-keys again", err)
		}
		ans.Seq, ans.Epochs = last+1, epochs
	}

	// The server rotated: every key it knew is revoked. What follows only
	// carries the result to this client, and reports the new recovery code
	// whatever fails. Signing in comes first, because it yields the device
	// key, and a failure to save the anchor must not cost the CLI that key.
	res.Seq, res.Epochs, res.Warnings = ans.Seq, ans.Epochs, transferWarnings(ans.Transfers, me.ID, nil)
	var first error
	keep := func(err error) {
		if first == nil {
			first = err
		}
	}
	signedIn := &Client{Host: c.Host, HTTP: c.HTTP}
	out, err := signedIn.Login(me.Email, password)
	if err != nil {
		keep(fmt.Errorf("the keys were rotated, but signing in again failed: %w; save the new recovery code and run cairn login", err))
	} else {
		res.APIKey = out.APIKey
		// Now the directory can name the other party of each transfer.
		if dir, err := signedIn.Directory(); err == nil && len(ans.Transfers) > 0 {
			emails := map[string]string{}
			for _, u := range dir {
				emails[u.ID] = u.Email
			}
			res.Warnings = transferWarnings(ans.Transfers, me.ID, emails)
		}
		if key, err := e2e.ParseAPIKey(out.APIKey); err != nil {
			keep(err)
		} else {
			c.Token, c.Key = signedIn.Token, &key
		}
	}
	if err := c.Anchors.SaveAnchor(me.ID, nk.FP, e2e.KeyringAnchorOf(newKR.Rev, sealedKR)); err != nil {
		keep(fmt.Errorf("the keys were rotated, but saving the keyring anchor failed: %w; save the new recovery code and run cairn login", err))
	}
	if res.APIKey == "" {
		return res, first
	}

	// Read each owned artifact back under the new keys.
	k, err := c.Unlock()
	if err != nil {
		keep(fmt.Errorf("the keys were rotated, but unlocking the new keys failed: %w", err))
		return res, first
	}
	if k.FP != nk.FP {
		keep(errors.New("the keys were rotated, but the server now serves other public keys than the ones generated"))
		return res, first
	}
	for id := range owned {
		if _, err := c.VerifyArtifact(k, id, k.FP); err != nil {
			keep(fmt.Errorf("the keys were rotated, but reading artifact %s back failed: %w", id, err))
			break
		}
	}
	return res, first
}

// rotationApplied settles a rotation POST whose answer was lost: whether the
// last rotation record is the one that was posted, seq with the keys nk. The
// authKey is the same before and after, so signing in with the password works
// either way.
func (c *Client) rotationApplied(me *store.User, password string, seq int, nk *UnlockedKeys) (bool, error) {
	ps, err := c.passwordSignIn(me.Email, password)
	if err != nil {
		return false, err
	}
	s := &Client{Host: c.Host, Token: ps.Token, HTTP: c.HTTP}
	records, err := s.Rotations(me.ID)
	if err != nil {
		return false, err
	}
	if len(records) == 0 {
		return false, nil
	}
	var b e2e.RotationBody
	if err := e2e.DecodeStrict(records[len(records)-1].Body, &b); err != nil {
		return false, fmt.Errorf("the server's last rotation record: %w", err)
	}
	return b.Seq == seq && b.New == keyPairOf(nk), nil
}

// rewrapHeld wraps again, to nk, every wrap the caller holds on an artifact
// they do not own under their current keys. A wrap made for any earlier keys
// cannot be opened, and stays as it is. An artifact the caller reads without
// holding wraps, a public one, has none. It also returns the epochs of the
// wraps it remade. email is the caller's, for the remedy when one does not
// open.
func (c *Client) rewrapHeld(old, nk *UnlockedKeys, artifactID, email string) ([]map[string]any, []int, error) {
	keys, err := c.Keys(artifactID)
	var apiErr *APIError
	if errors.As(err, &apiErr) && (apiErr.Status == http.StatusForbidden || apiErr.Status == http.StatusNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var out []map[string]any
	var epochs []int
	for _, w := range keys.Wraps {
		if w.FP != old.FP {
			continue
		}
		ak, err := e2e.Unwrap(old.X25519Priv, e2e.WrapContext{
			Purpose: "ak", Artifact: artifactID, Epoch: uint64(w.Epoch), RecipientID: old.UserID, RecipientPub: old.X25519Pub,
		}, w.Wrapped)
		if err != nil {
			return nil, nil, fmt.Errorf("opening the wrap of epoch %d of artifact %s: %w; its owner can run cairn unshare %s %s and then cairn share %s %s again, which makes a wrap that opens; then run cairn rotate-keys again", w.Epoch, artifactID, err, artifactID, email, artifactID, email)
		}
		wrapped, err := e2e.Wrap(rand.Reader, e2e.WrapContext{
			Purpose: "ak", Artifact: artifactID, Epoch: uint64(w.Epoch), RecipientID: nk.UserID, RecipientPub: nk.X25519Pub,
		}, ak)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, map[string]any{"artifact": artifactID, "epoch": w.Epoch, "wrapped": e2e.B64(wrapped)})
		epochs = append(epochs, w.Epoch)
	}
	return out, epochs, nil
}

// heldMoved reads again the wraps the caller holds on an artifact they do not
// own, and says so if their epochs differ from was, the epochs RotateKeys
// built the request from.
func (c *Client) heldMoved(artifactID, oldFP string, was []int) []string {
	keys, err := c.Keys(artifactID)
	if err != nil {
		return nil
	}
	var now []int
	for _, w := range keys.Wraps {
		if w.FP == oldFP {
			now = append(now, w.Epoch)
		}
	}
	if slices.Equal(now, was) {
		return nil
	}
	if len(was) == 0 {
		return []string{"you now hold artifact " + artifactID}
	}
	return []string{fmt.Sprintf("the wraps you hold on artifact %s changed (epochs %v, were %v)", artifactID, now, was)}
}

// rotateConflict explains a 409: it reads again what RotateKeys built the
// request from, and names what differs. Nothing has changed, so the user
// runs the command again. cause is the server's answer.
func (c *Client) rotateConflict(userID, oldFP string, last, rev int, owned map[string]int, held map[string][]int, cause error) error {
	var moved []string
	if recs, err := c.Rotations(userID); err == nil {
		if now, err := lastRotationSeq(recs); err == nil && now != last {
			moved = append(moved, fmt.Sprintf("the rotation seq moved from %d to %d", last, now))
		}
	}
	var kw keyringWire
	if err := c.doJSON("GET", "/api/me/keyring", nil, &kw); err == nil && kw.Rev != rev {
		moved = append(moved, fmt.Sprintf("the keyring moved from rev %d to rev %d", rev, kw.Rev))
	}
	if arts, err := c.listArtifacts(); err == nil {
		now := map[string]bool{}
		for _, a := range arts {
			if a.OwnerID == userID && a.Epoch > 0 {
				now[a.ID] = true
				if _, ok := owned[a.ID]; !ok {
					moved = append(moved, "you now own artifact "+a.ID)
				}
			}
			if a.OwnerID != userID {
				moved = append(moved, c.heldMoved(a.ID, oldFP, held[a.ID])...)
			}
		}
		for id := range owned {
			if !now[id] {
				moved = append(moved, "you no longer own artifact "+id)
			}
		}
	}
	for id, seq := range owned {
		if m, err := c.Membership(id); err == nil && len(m.Records) != seq {
			moved = append(moved, fmt.Sprintf("artifact %s has a new record (%d, was %d)", id, len(m.Records), seq))
		}
	}
	slices.Sort(moved)
	what := "something the rotation checks moved"
	if len(moved) > 0 {
		what = strings.Join(moved, "; ")
	}
	return fmt.Errorf("the server changed while the rotation was prepared: %s. Nothing was changed; run cairn rotate-keys again: %w", what, cause)
}
