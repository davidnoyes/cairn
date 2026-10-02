// Ownership transfer: offering, withdrawing, declining, and accepting, and the
// notice of an administrator's handover. As elsewhere in this package, every
// byte of cryptography is built with internal/e2e; see "Ownership transfer"
// in design/e2e-api.md.
package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

var (
	// ErrTransferNotOwner means only the artifact's owner can offer or
	// withdraw ownership.
	ErrTransferNotOwner = errors.New("only the artifact's owner can offer or withdraw ownership")
	// ErrTransferNotEditor means the user is not listed as an editor, so the
	// server would refuse the offer.
	ErrTransferNotEditor = errors.New("ownership can be offered only to a user the latest record lists as an editor")
	// ErrNotListedEditor means the latest record does not list the caller as an
	// editor, so they cannot take ownership.
	ErrNotListedEditor = errors.New("the latest record does not list you as an editor, so you cannot take ownership")
	// ErrNoOffer means no ownership offer is open on the artifact.
	ErrNoOffer = errors.New("no ownership offer is open on this artifact")
	// ErrNoOfferToYou means no open ownership offer is to the caller.
	ErrNoOfferToYou = errors.New("no ownership offer to you is open on this artifact")
	// ErrOfferRefused means the offer the server served does not check out.
	ErrOfferRefused = errors.New("the ownership offer does not check out")
	// ErrPreviousOwnerGone means the previous owner cannot be kept as an
	// editor: the directory does not list them, or lists other keys than the
	// ones the latest record names. Dropping them needs no keys of theirs.
	ErrPreviousOwnerGone = errors.New("the previous owner cannot be kept as an editor; accept with --drop-previous-owner")
)

// HandoverNotice is the latest administrator's handover in a membership
// chain. Date is the day the server stored the record, empty when it did not
// say. Acked is set when this client's keyring acknowledges it.
type HandoverNotice struct {
	Seq   int
	Date  string
	Acked bool
}

// String is the notice the commands print.
func (n *HandoverNotice) String() string {
	if n.Date == "" {
		return "ownership was handed over by an administrator"
	}
	return "ownership was handed over by an administrator on " + n.Date
}

// HandoverNotAckedError means a write was refused because the artifact's
// ownership was handed over by an administrator and the person has not
// acknowledged it. The person confirms it with the people involved, then
// sets Client.AcceptNewOwner.
type HandoverNotAckedError struct {
	Date string
	Seq  int
}

func (e *HandoverNotAckedError) Error() string {
	return (&HandoverNotice{Seq: e.Seq, Date: e.Date}).String() + ", and you have not acknowledged it"
}

// handoverOf is the notice for chain, whose latest handover record m dates,
// against ack, the seq of the latest handover the keyring acknowledges. It is
// nil when the chain has no handover.
func handoverOf(chain *e2e.Chain, m *Membership, ack int) *HandoverNotice {
	if len(chain.Handovers) == 0 {
		return nil
	}
	seq := chain.Handovers[len(chain.Handovers)-1]
	return &HandoverNotice{Seq: seq, Date: m.OwnerChanges[strconv.Itoa(seq)], Acked: ack >= seq}
}

// checkHandover is what each function that writes to an artifact calls once
// it holds the verified chain. An unacknowledged handover is refused, unless
// the client was told to accept: then the keyring records it, and the write
// goes ahead.
func (c *Client) checkHandover(k *UnlockedKeys, artifactID string, va *VerifiedArtifact) error {
	h := va.Handover
	if h == nil || h.Acked {
		return nil
	}
	if !c.AcceptNewOwner {
		return &HandoverNotAckedError{Date: h.Date, Seq: h.Seq}
	}
	if err := c.ackHandover(k, artifactID, h.Seq); err != nil {
		return fmt.Errorf("recording that you accepted the handover: %w", err)
	}
	h.Acked = true
	if c.OnHandover != nil {
		c.OnHandover(artifactID, *h)
	}
	return nil
}

// ackHandover records in the keyring that the handover at seq is acknowledged.
func (c *Client) ackHandover(k *UnlockedKeys, artifactID string, seq int) error {
	_, err := c.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		if e, ok := kr.Epochs[artifactID]; ok && e.Ack < seq {
			e.Ack = seq
			kr.Epochs[artifactID] = e
		}
		return nil
	})
	return err
}

// TransferOffer is an open ownership offer, as GET /api/artifacts/{id} shows
// it. Offer is the owner's signed offer, nil for an administrator's.
type TransferOffer struct {
	To    string        `json:"to"`
	By    string        `json:"by"`
	At    string        `json:"at"`
	Offer *e2e.Envelope `json:"offer"`
}

// OpenTransfer returns the artifact's open ownership offer, or nil.
func (c *Client) OpenTransfer(artifactID string) (*TransferOffer, error) {
	var a struct {
		Transfer *TransferOffer `json:"transfer"`
	}
	if err := c.doJSON("GET", "/api/artifacts/"+artifactID, nil, &a); err != nil {
		return nil, err
	}
	return a.Transfer, nil
}

// closingRecord signs a same-epoch record that changes nothing. It moves
// prev, so any offer made against the old head is stale, and it is what the
// server takes to close an open offer. A public record carries the hash of
// the epoch's link token.
func (c *Client) closingRecord(k *UnlockedKeys, artifactID string, va *VerifiedArtifact) (e2e.Envelope, string, error) {
	next, env, err := signNext(k.Ed25519Seed, k.UserID, va, va.Chain.Latest)
	if err != nil || !next.Public {
		return env, "", err
	}
	linkHash, err := c.linkTokenHashFor(k, artifactID, va.Chain, next.Epoch)
	return env, linkHash, err
}

// OfferResult is what OfferTransfer did.
type OfferResult struct {
	User        DirectoryUser
	Prior       string // the pin state before
	WasVerified bool   // Prior is rotated and the pin was verified
	// Replaced is set when an offer was open: a record closed it first.
	Replaced bool
}

// OfferTransfer offers the artifact's ownership to who, which only its owner
// can do, and only to a user the latest record lists as an editor under their
// current fingerprint. A changed key is a *KeyChangedError unless
// acceptNewKey, as for Share. While an offer is open, the request carries a
// same-epoch record that closes it, and the new offer names that record.
func (c *Client) OfferTransfer(artifactID, who string, acceptNewKey bool) (*OfferResult, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return nil, err
	}
	if err := c.checkHandover(k, artifactID, va); err != nil {
		return nil, err
	}
	latest := va.Chain.Latest
	if latest.Owner != k.UserID || latest.OwnerFP != k.FP {
		return nil, ErrTransferNotOwner
	}
	dir, err := c.Directory()
	if err != nil {
		return nil, err
	}
	u, err := FindUser(dir, who)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(latest.Members, func(m e2e.Member) bool { return m.User == u.ID })
	if i < 0 || latest.Members[i].Role != "editor" {
		return nil, fmt.Errorf("%w: %s", ErrTransferNotEditor, u.Email)
	}
	prior, pin, err := c.checkPin(va.Keyring, u, acceptNewKey, va.Membership.Rotations)
	if err != nil {
		return nil, err
	}
	listedFP := latest.Members[i].FP
	if listedFP != u.FP {
		return nil, fmt.Errorf("%w: %s (%s); share with them again with cairn share --accept-new-key, then offer", ErrMemberKeyChanged, u.Email, u.ID)
	}
	open, err := c.OpenTransfer(artifactID)
	if err != nil {
		return nil, err
	}
	req := map[string]any{"to": u.ID}
	prev := va.Chain.Head
	if open != nil {
		env, linkHash, err := c.closingRecord(k, artifactID, va)
		if err != nil {
			return nil, err
		}
		req["membership"] = env
		if linkHash != "" {
			req["linkTokenHash"] = linkHash
		}
		prev = e2e.BodyHash(env.Body)
	}
	body, err := json.Marshal(e2e.TransferBody{V: 1, Artifact: artifactID, From: k.UserID, To: u.ID, ToFP: listedFP, Prev: prev})
	if err != nil {
		return nil, err
	}
	if req["offer"], err = e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "transfer", body); err != nil {
		return nil, err
	}
	if err := c.doJSON("POST", "/api/artifacts/"+artifactID+"/transfer", req, nil); err != nil {
		return nil, err
	}
	if pin != nil {
		if err := c.storePin(k, u.ID, *pin, va.Keyring.Pins[u.ID].FP); err != nil {
			return nil, fmt.Errorf("the server accepted the offer, but pinning %s failed: %w", u.Email, err)
		}
	}
	if open != nil {
		if err := c.readBack(k, artifactID, ""); err != nil {
			return nil, err
		}
	}
	return &OfferResult{User: u, Prior: prior, WasVerified: wasVerified(va.Keyring, u.ID, prior), Replaced: open != nil}, nil
}

// WithdrawTransfer withdraws the open offer, which only the owner can do,
// with a same-epoch record that moves prev, so the old offer can never be
// accepted.
func (c *Client) WithdrawTransfer(artifactID string) error {
	k, err := c.Unlock()
	if err != nil {
		return err
	}
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return err
	}
	if err := c.checkHandover(k, artifactID, va); err != nil {
		return err
	}
	if latest := va.Chain.Latest; latest.Owner != k.UserID || latest.OwnerFP != k.FP {
		return ErrTransferNotOwner
	}
	open, err := c.OpenTransfer(artifactID)
	if err != nil {
		return err
	}
	if open == nil {
		return ErrNoOffer
	}
	env, linkHash, err := c.closingRecord(k, artifactID, va)
	if err != nil {
		return err
	}
	req := map[string]any{"membership": env}
	if linkHash != "" {
		req["linkTokenHash"] = linkHash
	}
	if err := c.doJSON("DELETE", "/api/artifacts/"+artifactID+"/transfer", req, nil); err != nil {
		return err
	}
	return c.readBack(k, artifactID, "")
}

// offerToCaller returns the open offer, which must be to the caller.
func (c *Client) offerToCaller(k *UnlockedKeys, artifactID string) (*TransferOffer, error) {
	open, err := c.OpenTransfer(artifactID)
	if err != nil {
		return nil, err
	}
	if open == nil || open.To != k.UserID {
		return nil, ErrNoOfferToYou
	}
	return open, nil
}

// DeclineTransfer declines the open offer to the caller. It signs nothing, so
// it needs no acknowledgement of a handover.
func (c *Client) DeclineTransfer(artifactID string) error {
	k, err := c.Unlock()
	if err != nil {
		return err
	}
	if _, err := c.VerifyArtifact(k, artifactID, ""); err != nil {
		return err
	}
	if _, err := c.offerToCaller(k, artifactID); err != nil {
		return err
	}
	return c.doJSON("DELETE", "/api/artifacts/"+artifactID+"/transfer", nil, nil)
}

// ownerKey returns the Ed25519 key the verified chain's latest ownerFp names,
// from the pairs the server served, only if the pair hashes to the
// fingerprint.
func ownerKey(owners map[string]e2e.KeyPair, fp string) (ed25519.PublicKey, error) {
	kp, ok := owners[fp]
	if !ok {
		return nil, errors.New("the server served no keys for the owner's fingerprint")
	}
	x, errX := e2e.UnB64(kp.X25519)
	ed, errEd := e2e.UnB64(kp.Ed25519)
	if errX != nil || errEd != nil || hex.EncodeToString(e2e.Fingerprint(x, ed)) != fp {
		return nil, errors.New("the keys the server served for the owner do not hash to their fingerprint")
	}
	return ed, nil
}

// checkOffer verifies an owner's offer to the caller before they accept: it
// opens under the key the latest record's ownerFp names, and names this
// artifact, the latest owner, the caller, the fp the latest record lists for
// the caller, and the chain's head.
func checkOffer(env e2e.Envelope, va *VerifiedArtifact, artifactID, me, listedFP string) error {
	latest := va.Chain.Latest
	pub, err := ownerKey(va.Membership.Owners, latest.OwnerFP)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrOfferRefused, err)
	}
	var t e2e.TransferBody
	if err := e2e.OpenEnvelope(env, pub, "transfer", &t); err != nil {
		return fmt.Errorf("%w: signature: it does not verify under the owner's key (%v)", ErrOfferRefused, err)
	}
	switch {
	case t.Artifact != artifactID:
		return fmt.Errorf("%w: artifact is %q, not this one", ErrOfferRefused, t.Artifact)
	case t.From != latest.Owner:
		return fmt.Errorf("%w: from is %q, not the owner", ErrOfferRefused, t.From)
	case t.To != me:
		return fmt.Errorf("%w: to is %q, not you", ErrOfferRefused, t.To)
	case t.ToFP != listedFP:
		return fmt.Errorf("%w: toFp is not the fingerprint the latest record lists for you", ErrOfferRefused)
	case t.Prev != va.Chain.Head:
		return fmt.Errorf("%w: prev is not the latest record's hash; the membership changed since, and the owner must offer again", ErrOfferRefused)
	}
	return nil
}

// AcceptTransferOptions are the choices of AcceptTransfer.
type AcceptTransferOptions struct {
	// DropPreviousOwner moves the artifact to a new epoch and excludes the
	// previous owner, who cannot read it afterwards. By default they stay as
	// an editor with every epoch's AK.
	// An administrator's offer always drops them: it is open only while they
	// are deactivated, so they cannot be kept.
	DropPreviousOwner bool
}

// AcceptResult is what AcceptTransfer did.
type AcceptResult struct {
	Epoch int
	// Handover is set when the offer was an administrator's.
	Handover bool
	// PreviousOwner is who owned the artifact; Kept is set when they stay as
	// an editor.
	PreviousOwner DirectoryUser
	Kept          bool
	// EpochChange is set when the previous owner was dropped.
	EpochChange
}

// AcceptTransfer takes the ownership offered to the caller. It verifies the
// chain and, for an owner's offer, the offer itself, before it signs anything.
// The record names the caller as owner, lists the previous owner as an editor
// with a wrap of every epoch unless opts drops them, and carries an estate
// copy of every epoch under the caller's EK. After an administrator's
// handover the caller's keyring acknowledges the new record, because the
// person who accepted needs no notice.
func (c *Client) AcceptTransfer(artifactID string, opts AcceptTransferOptions) (*AcceptResult, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return nil, err
	}
	if err := c.checkHandover(k, artifactID, va); err != nil {
		return nil, err
	}
	open, err := c.offerToCaller(k, artifactID)
	if err != nil {
		return nil, err
	}
	latest := va.Chain.Latest
	i := slices.IndexFunc(latest.Members, func(m e2e.Member) bool { return m.User == k.UserID && m.Role == "editor" })
	if i < 0 {
		return nil, ErrNotListedEditor
	}
	listedFP := latest.Members[i].FP
	if listedFP != k.FP {
		return nil, fmt.Errorf("%w: the latest record lists you under other keys", ErrMemberKeyChanged)
	}
	next := latest
	next.Owner, next.OwnerFP = k.UserID, k.FP
	switch open.By {
	case "owner":
		if open.Offer == nil {
			return nil, fmt.Errorf("%w: the server sent no offer", ErrOfferRefused)
		}
		if err := checkOffer(*open.Offer, va, artifactID, k.UserID, listedFP); err != nil {
			return nil, err
		}
		next.Transfer = e2e.BodyHash(open.Offer.Body)
	case "admin":
		next.Handover = "admin"
	default:
		return nil, fmt.Errorf("the server says the offer is by %q, which this client does not know", open.By)
	}
	dir, err := c.Directory()
	if err != nil {
		return nil, err
	}
	// An offer by an administrator exists only while the owner is deactivated,
	// and the directory lists active users only. "by" is the server's word.
	if open.By == "admin" && slices.ContainsFunc(dir, func(u DirectoryUser) bool { return u.ID == latest.Owner }) {
		return nil, fmt.Errorf("%w: the server says an administrator made it, but the owner is still active", ErrOfferRefused)
	}
	drop := opts.DropPreviousOwner || open.By == "admin"
	members := slices.DeleteFunc(slices.Clone(latest.Members), func(m e2e.Member) bool { return m.User == k.UserID })

	res := &AcceptResult{Handover: open.By == "admin"}
	var wraps, estate []map[string]any
	var linkHash string
	var aks map[int][]byte
	var pins map[string]pinDecision
	if drop {
		pending, err := c.pendingFor(k, artifactID, va)
		if err != nil {
			return nil, err
		}
		next.Members = members
		b, err := c.buildNextEpoch(k, artifactID, va, dir, pending, nextEpochRecord{next: next, newOwner: k.UserID, prevOwner: latest.Owner})
		if err != nil {
			return nil, err
		}
		next, wraps, linkHash, aks, pins = b.next, b.wraps, b.linkHash, b.aks, b.lst.pins
		res.EpochChange = *b.change
		if i := slices.IndexFunc(dir, func(u DirectoryUser) bool { return u.ID == latest.Owner }); i >= 0 {
			res.PreviousOwner = dir[i]
		} else {
			res.PreviousOwner = DirectoryUser{ID: latest.Owner}
		}
	} else {
		prev := slices.IndexFunc(dir, func(u DirectoryUser) bool { return u.ID == latest.Owner })
		if prev < 0 || dir[prev].FP != latest.OwnerFP {
			return nil, ErrPreviousOwnerGone
		}
		res.PreviousOwner, res.Kept = dir[prev], true
		if aks, err = c.callerAKs(k, artifactID, va.Chain); err != nil {
			return nil, err
		}
		next.Members = append(members, e2e.Member{User: latest.Owner, Role: "editor", FP: latest.OwnerFP})
		slices.SortFunc(next.Members, func(a, b e2e.Member) int { return strings.Compare(a.User, b.User) })
		for epoch := 1; epoch <= latest.Epoch; epoch++ {
			w, err := e2e.Wrap(rand.Reader, e2e.WrapContext{
				Purpose: "ak", Artifact: artifactID, Epoch: uint64(epoch),
				RecipientID: latest.Owner, RecipientPub: dir[prev].X25519Pub,
			}, aks[epoch])
			if err != nil {
				return nil, err
			}
			wraps = append(wraps, map[string]any{"user": latest.Owner, "epoch": epoch, "wrapped": e2e.B64(w)})
		}
		if next.Public {
			if linkHash, err = linkTokenHash(aks[latest.Epoch], artifactID, latest.Epoch); err != nil {
				return nil, err
			}
		}
	}

	// An estate copy of every epoch, under the caller's EK.
	ekKey, err := e2e.EKSealKey(k.EK)
	if err != nil {
		return nil, err
	}
	for epoch := 1; epoch <= next.Epoch; epoch++ {
		sealed, err := e2e.Seal(rand.Reader, ekKey, estateFields(artifactID, epoch), aks[epoch])
		if err != nil {
			return nil, err
		}
		estate = append(estate, map[string]any{"epoch": epoch, "sealed": e2e.B64(sealed)})
	}

	next, env, err := signChained(k.Ed25519Seed, k.UserID, va, next)
	if err != nil {
		return nil, err
	}
	if wraps == nil {
		wraps = []map[string]any{}
	}
	var out struct {
		Epoch int `json:"epoch"`
	}
	if err := c.doJSON("POST", "/api/artifacts/"+artifactID+"/transfer/accept", map[string]any{
		"membership": env, "wraps": wraps, "estate": estate, "linkTokenHash": linkHash,
	}, &out); err != nil {
		return nil, err
	}
	res.Epoch = out.Epoch
	for id, d := range pins {
		if err := c.storePin(k, id, d.pin, d.basedOn); err != nil {
			return nil, fmt.Errorf("the server accepted the new membership record, but pinning %s failed: %w", id, err)
		}
	}
	// Acknowledged before the read-back, so the notice it shows is.
	if res.Handover {
		if err := c.ackHandover(k, artifactID, next.Seq); err != nil {
			return nil, fmt.Errorf("the server accepted the handover, but recording that you accepted it failed: %w", err)
		}
	}
	if err := c.readBack(k, artifactID, res.Link); err != nil {
		return nil, err
	}
	return res, nil
}
