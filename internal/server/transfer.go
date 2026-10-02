package server

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/aloisdeniel/cairn/internal/access"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/membership"
	"github.com/aloisdeniel/cairn/internal/store"
)

// Ownership transfer. See "Ownership transfer" in design/e2e-api.md.

// transferError is a refusal the handlers decide on, outside the membership
// rules: the status and message to answer with.
type transferError struct {
	status int
	msg    string
}

func (e *transferError) Error() string { return e.msg }

func transferRefusal(status int, format string, args ...any) error {
	return &transferError{status: status, msg: fmt.Sprintf(format, args...)}
}

// writeTransferError answers a refusal or failure from a transfer handler.
func (s *Server) writeTransferError(w http.ResponseWriter, err error) {
	var refused *transferError
	if errors.As(err, &refused) {
		writeError(w, refused.status, refused.msg)
		return
	}
	s.writeChangeError(w, err)
}

// openOffer returns the open offer, or nil when there is none.
func openOffer(tx *store.ArtifactTx) (*store.Offer, error) {
	o, err := tx.OpenOffer()
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return o, err
}

// editorFor returns the user to, if membership.CheckNewOwner allows them as
// the next owner. Otherwise it is a 409.
func editorFor(cur membership.Current, dir membership.Directory, to string) (*membership.User, error) {
	u, err := dir.User(to)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, transferRefusal(http.StatusConflict, "only a listed editor can take ownership")
	}
	if err := membership.CheckNewOwner(cur, u); err != nil {
		return nil, err
	}
	return u, nil
}

type offerTransferRequest struct {
	To         string        `json:"to"`
	Offer      e2e.Envelope  `json:"offer"`
	Membership *e2e.Envelope `json:"membership"`
}

// handleOfferTransfer opens an owner's offer. With an offer already open, the
// request carries a record that closes it; the record and the new offer land
// in one transaction.
func (s *Server) handleOfferTransfer(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	var req offerTransferRequest
	if !readJSON(w, r, &req) {
		return
	}
	var closing membership.Change
	if req.Membership != nil {
		var err error
		if closing, err = changeOf(*req.Membership, nil, nil, ""); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	var view *transferView
	err := s.store.WithArtifact(a.ID, func(tx *store.ArtifactTx) error {
		open, err := openOffer(tx)
		if err != nil {
			return err
		}
		if open != nil && req.Membership == nil {
			return transferRefusal(http.StatusConflict, "an offer is already open; withdraw it, or send a membership record that closes it")
		}
		if open == nil && req.Membership != nil {
			return transferRefusal(http.StatusConflict, "no offer is open for the membership record to close")
		}
		if req.Membership != nil {
			if _, err := applyChange(tx, closing); err != nil {
				return err
			}
		}
		dir := membership.TxDirectory(tx)
		cur, err := membership.Load(tx, dir)
		if err != nil {
			return err
		}
		var offer e2e.TransferBody
		switch {
		case req.Offer.Signer != cur.Owner.ID:
			return transferRefusal(http.StatusBadRequest, "the offer is not signed by the owner")
		case e2e.OpenEnvelope(req.Offer, cur.Owner.Ed25519Pub, "transfer", &offer) != nil:
			return transferRefusal(http.StatusBadRequest, "the offer does not verify under the owner's current key")
		case offer.Artifact != a.ID:
			return transferRefusal(http.StatusBadRequest, "the offer is for another artifact")
		case offer.From != cur.Owner.ID:
			return transferRefusal(http.StatusBadRequest, "the offer is not from the owner")
		case offer.To != req.To:
			return transferRefusal(http.StatusBadRequest, "the offer is not to the user it names")
		case offer.Prev != cur.LatestHash:
			return transferRefusal(http.StatusBadRequest, "the offer's prev is not the latest record's hash")
		}
		u, err := editorFor(cur, dir, req.To)
		if err != nil {
			return err
		}
		if offer.ToFP != u.FP {
			return transferRefusal(http.StatusConflict, "the offer's toFp is not the user's current fingerprint")
		}
		if err := tx.PutOffer(store.Offer{To: req.To, By: "owner", Hash: e2e.BodyHash(req.Offer.Body),
			Envelope: &store.Envelope{Body: req.Offer.Body, Sig: req.Offer.Sig, Signer: req.Offer.Signer}}); err != nil {
			return err
		}
		view, err = currentOffer(tx)
		return err
	})
	if err != nil {
		s.writeTransferError(w, err)
		return
	}
	s.log.Info("ownership offered", "artifact", a.ID, "to", req.To, "by", requestUser(r).Email)
	writeJSON(w, http.StatusOK, map[string]*transferView{"transfer": view})
}

// currentOffer returns the open offer as the API shows it.
func currentOffer(tx *store.ArtifactTx) (*transferView, error) {
	o, err := tx.OpenOffer()
	if err != nil {
		return nil, err
	}
	return &transferView{To: o.To, By: o.By, At: o.CreatedAt}, nil
}

type closeTransferRequest struct {
	Membership e2e.Envelope `json:"membership"`
}

// handleCloseTransfer withdraws an open offer, for the owner with a
// same-epoch record, or declines it, for the offered user.
func (s *Server) handleCloseTransfer(w http.ResponseWriter, r *http.Request) {
	a, caller := requestArtifact(r), requestUser(r)
	var ch membership.Change
	isOwner := access.LevelOf(requestAccess(r)) == access.LevelOwner
	if isOwner {
		var req closeTransferRequest
		if !readJSON(w, r, &req) {
			return
		}
		var err error
		if ch, err = changeOf(req.Membership, nil, nil, ""); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	err := s.store.WithArtifact(a.ID, func(tx *store.ArtifactTx) error {
		open, err := openOffer(tx)
		switch {
		case err != nil:
			return err
		case open == nil:
			return transferRefusal(http.StatusConflict, "no offer is open")
		case isOwner:
			_, err := applyChange(tx, ch)
			return err
		case open.To == caller.ID:
			return tx.SetOfferState("closed")
		}
		return transferRefusal(http.StatusForbidden, "only the owner or the offered user can close an offer")
	})
	if err != nil {
		s.writeTransferError(w, err)
		return
	}
	s.log.Info("ownership offer closed", "artifact", a.ID, "by", caller.Email)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAcceptTransfer takes the offered ownership with a record signed by
// the offered user.
func (s *Server) handleAcceptTransfer(w http.ResponseWriter, r *http.Request) {
	a, caller := requestArtifact(r), requestUser(r)
	var req membershipRequest
	if !readJSON(w, r, &req) {
		return
	}
	ch, err := changeOf(req.Membership, req.Wraps, req.Estate, req.LinkTokenHash)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var epoch int
	var prevOwnerEmail string
	err = s.store.WithArtifact(a.ID, func(tx *store.ArtifactTx) error {
		open, err := openOffer(tx)
		if err != nil {
			return err
		}
		if open == nil || open.To != caller.ID {
			return transferRefusal(http.StatusConflict, "no offer to you is open")
		}
		dir := membership.TxDirectory(tx)
		cur, err := membership.Load(tx, dir)
		if err != nil {
			return err
		}
		u, err := editorFor(cur, dir, caller.ID)
		if err != nil {
			return err
		}
		if open.By == "owner" {
			var stored e2e.TransferBody
			if open.Envelope == nil || e2e.DecodeStrict(open.Envelope.Body, &stored) != nil {
				return transferRefusal(http.StatusConflict, "the stored offer cannot be read")
			}
			if stored.ToFP != u.FP {
				return transferRefusal(http.StatusConflict, "the offer's toFp is not your current fingerprint")
			}
			if stored.Prev != cur.LatestHash {
				return transferRefusal(http.StatusConflict, "the offer is stale: the membership record has changed since")
			}
		} else if cur.Owner.Active {
			return transferRefusal(http.StatusConflict, "the owner's account is active")
		}
		ch.Accept = &membership.Acceptance{NewOwner: u, OfferHash: open.Hash}
		prevOwnerEmail = cur.Owner.Email
		res, err := applyChange(tx, ch)
		if err != nil {
			return err
		}
		epoch = res.Body.Epoch
		return nil
	})
	if err != nil {
		s.writeTransferError(w, err)
		return
	}
	s.deliverMail(prevOwnerEmail, "Ownership of an artifact was transferred",
		fmt.Sprintf("%s accepted ownership of the artifact %q (%s).\n", caller.Email, a.Name, a.ID))
	s.log.Info("ownership transferred", "artifact", a.ID, "to", caller.Email)
	writeJSON(w, http.StatusOK, map[string]int{"epoch": epoch})
}

// Administrator endpoints

type adminArtifactView struct {
	ID      string            `json:"id"`
	Editors []adminEditorView `json:"editors"`
}

type adminEditorView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// handleAdminUserArtifacts lists the artifacts a user owns, with the editors
// each could be handed to. It names no artifact.
func (s *Server) handleAdminUserArtifacts(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.UserByID(id); err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	owned, err := s.store.OwnedWithRecords(id)
	if err != nil {
		s.writeStoreError(w, err, "artifacts")
		return
	}
	out := []adminArtifactView{}
	for _, aid := range owned {
		v := adminArtifactView{ID: aid, Editors: []adminEditorView{}}
		err := s.store.WithArtifact(aid, func(tx *store.ArtifactTx) error {
			members, err := tx.Members()
			if err != nil {
				return err
			}
			for _, m := range members {
				if m.Role != access.RoleEditor {
					continue
				}
				u, err := tx.UserByID(m.UserID)
				if errors.Is(err, store.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				v.Editors = append(v.Editors, adminEditorView{ID: u.ID, Name: u.Name})
			}
			return nil
		})
		if err != nil {
			s.writeStoreError(w, err, "artifact")
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

type adminOfferRequest struct {
	To string `json:"to"`
}

// handleAdminOfferTransfer offers a deactivated owner's artifact to a listed
// editor.
func (s *Server) handleAdminOfferTransfer(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.ArtifactByID(r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	var req adminOfferRequest
	if !readJSON(w, r, &req) {
		return
	}
	var view *transferView
	var ownerEmail, toEmail string
	err = s.store.WithArtifact(a.ID, func(tx *store.ArtifactTx) error {
		dir := membership.TxDirectory(tx)
		cur, err := membership.Load(tx, dir)
		if err != nil {
			return err
		}
		if cur.Owner.Active {
			return transferRefusal(http.StatusConflict, "the owner's account is active, so the owner must agree")
		}
		u, err := editorFor(cur, dir, req.To)
		if err != nil {
			return err
		}
		if err := tx.SetOfferState("closed"); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := tx.PutOffer(store.Offer{To: req.To, By: "admin"}); err != nil {
			return err
		}
		ownerEmail, toEmail = cur.Owner.Email, u.Email
		view, err = currentOffer(tx)
		return err
	})
	if err != nil {
		s.writeTransferError(w, err)
		return
	}
	s.deliverMail(ownerEmail, "An administrator offered your artifact to someone else",
		fmt.Sprintf("An administrator offered your artifact %q (%s) to %s.\n", a.Name, a.ID, toEmail))
	s.log.Info("ownership offered by an administrator", "artifact", a.ID, "to", req.To, "by", requestUser(r).Email)
	writeJSON(w, http.StatusOK, map[string]*transferView{"transfer": view})
}

// handleAdminDeleteArtifact deletes an artifact whose owner is deactivated.
func (s *Server) handleAdminDeleteArtifact(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.ArtifactByID(r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	s.deleteArtifact(w, a, requestUser(r).Email, s.store.DeleteArtifactOfDisabledOwner)
}
