package e2e

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// The errors CheckApproval returns, besides ErrFormat and ErrDecrypt for an
// approval that does not parse or verify.
var (
	// ErrApprovalMissing means the server served no approval for the user.
	ErrApprovalMissing = errors.New("e2e: approval missing")
	// ErrApprovalSigner means the signer is neither the owner nor an editor
	// the current record lists under the fingerprint their key hashes to.
	ErrApprovalSigner = errors.New("e2e: approval signer is not the owner or a listed editor")
	// ErrApprovalMismatch means the approval names another artifact, epoch,
	// user, or fingerprint than the ones it must.
	ErrApprovalMismatch = errors.New("e2e: approval names another artifact, epoch, user, or fingerprint")
	// ErrApprovalExcluded means the user matches an excluded entry.
	ErrApprovalExcluded = errors.New("e2e: the user matches an excluded entry")
	// ErrApprovalDuplicate means another user ID shares the user's
	// fingerprint or normalized email.
	ErrApprovalDuplicate = errors.New("e2e: another user shares the user's fingerprint or email")
)

// ApprovalUser is a user as the server serves them: ID, email, and the
// public keys in wire form. The fingerprint is always computed from Keys.
type ApprovalUser struct {
	ID    string  `json:"id"`
	Email string  `json:"email"`
	Keys  KeyPair `json:"keys"`
}

// ApprovalInput is everything the four checks need. Latest is the current
// record of a chain the caller verified. SignerKeys are the keys the server
// serves for Approval.Signer, User is the user the approval is for as the
// server serves them, and Directory is every user the directory lists.
type ApprovalInput struct {
	Artifact   string
	Latest     *MembershipBody
	Approval   *Envelope
	SignerKeys KeyPair
	User       ApprovalUser
	Directory  []ApprovalUser
}

// fp returns the hex fingerprint of a wire-form key pair, and its Ed25519 key.
func (k KeyPair) fp() (string, []byte, error) {
	x, errX := UnB64(k.X25519)
	ed, errEd := UnB64(k.Ed25519)
	if errX != nil || errEd != nil {
		return "", nil, fmt.Errorf("%w: a public key is not base64", ErrFormat)
	}
	return hex.EncodeToString(Fingerprint(x, ed)), ed, nil
}

// CheckApproval runs the four checks that let an owner's client list an
// approved team member, as "Team approval" in design/e2e-api.md lists them:
//
//  1. The signer is the owner, or an editor in the current record, and the
//     keys the server serves for them hash to the fingerprint listed.
//  2. artifact is this artifact, and epoch is the current epoch.
//  3. user is the user, and fp is the fingerprint of the keys served for them.
//  4. The user matches no excluded entry by ID, fingerprint, or normalized
//     email, and no other user ID in the directory shares their fingerprint
//     or normalized email.
//
// The signature is checked after the signer and before the body's fields,
// which are only meaningful once signed.
func CheckApproval(in ApprovalInput) error {
	if in.Approval == nil {
		return ErrApprovalMissing
	}
	latest := in.Latest
	signerFP, signerEd, err := in.SignerKeys.fp()
	if err != nil {
		return err
	}
	var listedFP string
	if in.Approval.Signer == latest.Owner {
		listedFP = latest.OwnerFP
	} else {
		for _, m := range latest.Members {
			if m.User == in.Approval.Signer && m.Role == "editor" {
				listedFP = m.FP
			}
		}
	}
	if listedFP == "" || signerFP != listedFP {
		return fmt.Errorf("%w: %s", ErrApprovalSigner, in.Approval.Signer)
	}
	var body ApprovalBody
	if err := OpenEnvelope(*in.Approval, signerEd, "approval", &body); err != nil {
		return err
	}
	userFP, _, err := in.User.Keys.fp()
	if err != nil {
		return err
	}
	switch {
	case body.Artifact != in.Artifact:
		return fmt.Errorf("%w: artifact %q", ErrApprovalMismatch, body.Artifact)
	case body.Epoch != latest.Epoch:
		return fmt.Errorf("%w: epoch %d, current %d", ErrApprovalMismatch, body.Epoch, latest.Epoch)
	case body.User != in.User.ID:
		return fmt.Errorf("%w: user %q", ErrApprovalMismatch, body.User)
	case body.FP != userFP:
		return fmt.Errorf("%w: fp is not the fingerprint of the keys served for %s", ErrApprovalMismatch, in.User.ID)
	}
	if x := ExcludedMatch(latest.Excluded, in.User.ID, userFP, in.User.Email); x != nil {
		return fmt.Errorf("%w: %s", ErrApprovalExcluded, x.User)
	}
	email := NormalizeEmail(in.User.Email)
	for _, d := range in.Directory {
		if d.ID == in.User.ID {
			continue
		}
		dfp, _, err := d.Keys.fp()
		if err != nil {
			return err
		}
		if dfp == userFP || NormalizeEmail(d.Email) == email {
			return fmt.Errorf("%w: %s", ErrApprovalDuplicate, d.ID)
		}
	}
	return nil
}

// ExcludedMatch returns the excluded entry a user matches by ID,
// fingerprint (hex), or normalized email, or nil.
func ExcludedMatch(excluded []ExcludedEntry, id, fp, email string) *ExcludedEntry {
	email = NormalizeEmail(email)
	for i, e := range excluded {
		if e.User == id || e.FP == fp || NormalizeEmail(e.Email) == email {
			return &excluded[i]
		}
	}
	return nil
}
