package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/membership"
	"github.com/aloisdeniel/cairn/internal/store"
)

// Key rotation. See "Rotating keys" in design/e2e-api.md.

// maxRotateBodyBytes caps a rotation request: the sealed keyring alone may be
// 1 MiB, a third more in base64, and every estate copy and wrap goes with it.
const maxRotateBodyBytes = 16 << 20

// rotateWrapSize is the size of a wrap: a version, an ephemeral key, AK, and
// a tag. An estate copy is sealedKeyLen, the size of any sealed 32-byte key.
const rotateWrapSize = 1 + 32 + 32 + 16

type rotateWrapWire struct {
	Artifact string `json:"artifact"`
	Epoch    int    `json:"epoch"`
	Wrapped  string `json:"wrapped"`
}

type rotateEstateWire struct {
	Artifact string `json:"artifact"`
	Epoch    int    `json:"epoch"`
	Sealed   string `json:"sealed"`
}

type rotateRecordWire struct {
	Artifact      string       `json:"artifact"`
	Membership    e2e.Envelope `json:"membership"`
	Wraps         []wrapWire   `json:"wraps"`
	LinkTokenHash string       `json:"linkTokenHash"`
}

type rotateRequest struct {
	AuthKey  string             `json:"authKey"`
	Bundle   bundleWire         `json:"bundle"`
	Rotation e2e.Envelope       `json:"rotation"`
	Keyring  keyringBody        `json:"keyring"`
	Wraps    []rotateWrapWire   `json:"wraps"`
	Estate   []rotateEstateWire `json:"estate"`
	Records  []rotateRecordWire `json:"records"`
}

// rotateError is a refused rotation: the status and message to answer with,
// and for a stale keyring the stored rev.
type rotateError struct {
	status int
	msg    string
	rev    *int
}

func (e *rotateError) Error() string { return e.msg }

func badRotation(format string, args ...any) error {
	return &rotateError{status: http.StatusBadRequest, msg: fmt.Sprintf(format, args...)}
}

func conflictRotation(format string, args ...any) error {
	return &rotateError{status: http.StatusConflict, msg: fmt.Sprintf(format, args...)}
}

type wrapRef struct {
	artifact string
	epoch    int
}

// sameSet returns a 409 naming the first artifact in have and not in want, or
// in want and not in have: an artifact gained or lost since the client read
// the list is a race it recovers from by reading again. Both are sorted.
func sameSet(have, want []string) error {
	inHave, inWant := map[string]bool{}, map[string]bool{}
	for _, id := range have {
		inHave[id] = true
	}
	for _, id := range want {
		inWant[id] = true
	}
	for _, id := range have {
		if !inWant[id] {
			return conflictRotation("records: no record for artifact %s, which the caller owns", id)
		}
	}
	for _, id := range want {
		if !inHave[id] {
			return conflictRotation("records: a record for artifact %s, which the caller does not own", id)
		}
	}
	return nil
}

func (s *Server) handleMeRotate(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	r.Body = http.MaxBytesReader(w, r.Body, maxRotateBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req rotateRequest
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request exceeds 16 MiB")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid JSON body: trailing data")
		return
	}
	if !s.requireFreshAuthKey(w, r, req.AuthKey) {
		return
	}
	bundle, err := decodeBundle(req.Bundle)
	if err == nil {
		err = validateBundle(bundle)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed key bundle")
		return
	}
	sealedKeyring, err := e2e.UnB64(req.Keyring.Keyring)
	switch {
	case err != nil:
		writeError(w, http.StatusBadRequest, "keyring is not base64")
		return
	case len(sealedKeyring) == 0:
		writeError(w, http.StatusBadRequest, "keyring is required")
		return
	case len(sealedKeyring) > maxKeyringBytes:
		writeError(w, http.StatusRequestEntityTooLarge, "keyring exceeds 1 MiB")
		return
	}
	newWraps := map[wrapRef][]byte{}
	for _, wr := range req.Wraps {
		b, err := e2e.UnB64(wr.Wrapped)
		if err != nil || len(b) != rotateWrapSize {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("wraps: the wrap for artifact %s at epoch %d is not %d bytes of base64", wr.Artifact, wr.Epoch, rotateWrapSize))
			return
		}
		ref := wrapRef{wr.Artifact, wr.Epoch}
		if _, dup := newWraps[ref]; dup {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("wraps: the wrap for artifact %s at epoch %d is given twice", wr.Artifact, wr.Epoch))
			return
		}
		newWraps[ref] = b
	}
	changes := map[string]membership.Change{}
	var owned []string
	for _, rec := range req.Records {
		if _, dup := changes[rec.Artifact]; dup {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("records: two records for artifact %s", rec.Artifact))
			return
		}
		ch, err := changeOf(rec.Membership, rec.Wraps, nil, rec.LinkTokenHash)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("records: artifact %s: %s", rec.Artifact, err))
			return
		}
		changes[rec.Artifact] = ch
		owned = append(owned, rec.Artifact)
	}
	sort.Strings(owned)
	estate := map[string][]membership.EstateIn{}
	for _, e := range req.Estate {
		if _, ok := changes[e.Artifact]; !ok {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("estate: a copy for artifact %s, which has no record", e.Artifact))
			return
		}
		b, err := e2e.UnB64(e.Sealed)
		if err != nil || len(b) != sealedKeyLen {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("estate: the copy for artifact %s at epoch %d is not %d bytes of base64", e.Artifact, e.Epoch, sealedKeyLen))
			return
		}
		estate[e.Artifact] = append(estate[e.Artifact], membership.EstateIn{Epoch: e.Epoch, Sealed: b})
	}
	// Only artifacts the caller owns get a lock of their own, so name them
	// before RotateKeys does; the transaction checks again.
	have, err := s.store.OwnedWithRecords(u.ID)
	if err != nil {
		s.writeStoreError(w, err, "account")
		return
	}
	if err := sameSet(have, owned); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	var seq int
	epochs := map[string]int{}
	err = s.store.RotateKeys(u.ID, owned, func(rt *store.RotateTx) error {
		cur, err := rt.User()
		if err != nil {
			return err
		}
		curBundle, err := rt.Bundle()
		if err != nil {
			return err
		}
		last, err := rt.LastRotationSeq()
		if err != nil {
			return err
		}

		// The rotation record.
		if req.Rotation.Signer != u.ID {
			return badRotation("rotation: the signer is not the caller")
		}
		var body e2e.RotationBody
		if err := e2e.OpenRotation(req.Rotation, ed25519.PublicKey(cur.Ed25519Pub), &body); err != nil {
			return badRotation("rotation: does not verify under the current key and the new key: %v", err)
		}
		if body.User != u.ID {
			return badRotation("rotation: the record is for another user")
		}
		if body.Seq != last+1 {
			return conflictRotation("rotation: seq %d, want %d", body.Seq, last+1)
		}
		oldMatches, err := keyPairIs(body.Old, cur.X25519Pub, cur.Ed25519Pub)
		if err != nil {
			return badRotation("rotation: old keys are not base64")
		}
		if !oldMatches {
			return conflictRotation("rotation: old is not the current public keys; read the bundle again")
		}
		newMatches, err := keyPairIs(body.New, bundle.X25519Pub, bundle.Ed25519Pub)
		if err != nil || !newMatches {
			return badRotation("rotation: new is not the bundle's public keys")
		}
		newFP := hex.EncodeToString(e2e.Fingerprint(bundle.X25519Pub, bundle.Ed25519Pub))
		if newFP == cur.FP {
			return badRotation("rotation: the new keys are the current keys")
		}
		if used, err := rt.OtherUserHasFP(newFP); err != nil {
			return err
		} else if used {
			return conflictRotation("rotation: another account has these keys")
		}

		// The bundle changes keys, not the password.
		var kdfNew, kdfOld bytes.Buffer
		if json.Compact(&kdfNew, bundle.KDF) != nil || json.Compact(&kdfOld, curBundle.KDF) != nil ||
			!bytes.Equal(kdfNew.Bytes(), kdfOld.Bytes()) {
			return badRotation("bundle: kdf must equal the current one; rotation does not change the password")
		}

		stored, err := rt.OwnedWithRecords()
		if err != nil {
			return err
		}
		if err := sameSet(stored, owned); err != nil {
			return err
		}
		if err := rt.SetBundle(bundle); err != nil {
			return err
		}
		if current, err := rt.PutKeyring(req.Keyring.Rev, sealedKeyring); errors.Is(err, store.ErrStale) {
			return &rotateError{status: http.StatusConflict, rev: &current,
				msg: "rev must be one more than the stored rev; read the keyring again and merge"}
		} else if err != nil {
			return err
		}

		// Wraps: one for each the caller can open, which are those made to
		// their current fingerprint. A wrap under any other fingerprint, left
		// by a reset, stays as it is.
		held, err := rt.HeldWraps()
		if err != nil {
			return err
		}
		need := map[wrapRef]bool{}
		for _, h := range held {
			if h.FP == cur.FP {
				need[wrapRef{h.ArtifactID, h.Epoch}] = true
			}
		}
		for ref := range newWraps {
			if !need[ref] {
				return conflictRotation("wraps: the wrap for artifact %s at epoch %d is not one the caller holds under their current keys", ref.artifact, ref.epoch)
			}
		}
		for _, h := range held {
			ref := wrapRef{h.ArtifactID, h.Epoch}
			if !need[ref] {
				continue
			}
			wrapped, ok := newWraps[ref]
			if !ok {
				return conflictRotation("wraps: missing the wrap for artifact %s at epoch %d", ref.artifact, ref.epoch)
			}
			if err := rt.ReplaceHeldWrap(h.ArtifactID, h.Epoch, wrapped, newFP); err != nil {
				return err
			}
		}

		// The head record of each artifact, verified under the new key, and
		// the estate copies of every epoch.
		for _, id := range owned {
			at := rt.Artifact(id)
			a, err := at.Artifact()
			if err != nil {
				return err
			}
			ch := changes[id]
			for _, e := range estate[id] {
				if e.Epoch > a.Epoch {
					ch.Estate = append(ch.Estate, e)
				}
			}
			res, err := applyChange(at, ch)
			var refused *membership.Error
			if errors.As(err, &refused) {
				return &membership.Error{Status: refused.Status, Rule: refused.Rule, Msg: fmt.Sprintf("artifact %s: %s", id, refused.Msg)}
			}
			if err != nil {
				return err
			}
			epoch := res.Body.Epoch
			seen := map[int]bool{}
			for _, e := range estate[id] {
				if e.Epoch < 1 || e.Epoch > epoch || seen[e.Epoch] {
					return badRotation("estate: artifact %s has a copy for epoch %d, but wants one for each of epochs 1 to %d", id, e.Epoch, epoch)
				}
				seen[e.Epoch] = true
			}
			if len(seen) != epoch {
				return badRotation("estate: artifact %s has %d copies, but wants one for each of epochs 1 to %d", id, len(seen), epoch)
			}
			if err := at.DeleteEstates(); err != nil {
				return err
			}
			for _, e := range estate[id] {
				if err := at.PutEstate(e.Epoch, e.Sealed); err != nil {
					return err
				}
			}
			epochs[id] = epoch
		}

		seq = body.Seq
		if err := rt.AddRotation(store.Rotation{Seq: body.Seq, OldFP: cur.FP, NewFP: newFP,
			Body: req.Rotation.Body, Sig: req.Rotation.Sig, NewSig: req.Rotation.NewSig}); err != nil {
			return err
		}
		if err := rt.RevokeAPIKeys(); err != nil {
			return err
		}
		if err := rt.CloseOffersToUser(); err != nil {
			return err
		}
		return rt.BumpTokenVersion()
	})
	var refusal *rotateError
	switch {
	case errors.As(err, &refusal):
		if refusal.rev != nil {
			writeJSON(w, refusal.status, map[string]any{"error": refusal.msg, "rev": *refusal.rev})
			return
		}
		writeError(w, refusal.status, refusal.msg)
		return
	case err != nil:
		s.writeChangeError(w, err)
		return
	}
	u, err = s.store.UserByID(u.ID)
	if err != nil {
		s.writeStoreError(w, err, "account")
		return
	}
	token, err := s.issueToken(u)
	if err != nil {
		s.writeStoreError(w, err, "token")
		return
	}
	s.setSessionCookie(w, token, s.cfg.TokenTTL)
	s.log.Info("keys rotated", "email", u.Email, "seq", seq)
	writeJSON(w, http.StatusOK, map[string]any{"seq": seq, "epochs": epochs})
}

// keyPairIs reports whether kp holds exactly these public keys. A key that is
// not base64 is an error.
func keyPairIs(kp e2e.KeyPair, x25519, ed25519Pub []byte) (bool, error) {
	x, err := e2e.UnB64(kp.X25519)
	if err != nil {
		return false, err
	}
	ed, err := e2e.UnB64(kp.Ed25519)
	if err != nil {
		return false, err
	}
	return bytes.Equal(x, x25519) && bytes.Equal(ed, ed25519Pub), nil
}

// rotationLinked reports whether rows, a user's rotation records oldest
// first, lead from fromFP to toFP: they start at a row that moves from
// fromFP, each next row moves from where the one before ended, and one of
// them ends at toFP. A password-only reset changes the keys with no record,
// so a row that does not pick up where the last stopped breaks the walk.
func rotationLinked(rows []store.Rotation, fromFP, toFP string) bool {
	for i := range rows {
		if rows[i].OldFP != fromFP {
			continue
		}
		for j := i; j < len(rows); j++ {
			if j > i && rows[j].OldFP != rows[j-1].NewFP {
				break
			}
			if rows[j].NewFP == toFP {
				return true
			}
		}
	}
	return false
}

func rotationEnvelope(r store.Rotation) e2e.Envelope {
	return e2e.Envelope{Body: r.Body, Sig: r.Sig, Signer: r.UserID, NewSig: r.NewSig}
}

// handleUserRotations serves a user's rotation records, oldest first, to
// whoever may see the user in the directory.
func (s *Server) handleUserRotations(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.UserByID(r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	if u.Disabled || u.VerifiedAt == "" {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	rows, err := s.store.Rotations(u.ID)
	if err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	records := []e2e.Envelope{}
	for _, row := range rows {
		records = append(records, rotationEnvelope(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": records})
}
