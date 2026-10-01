package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
)

// Errors for a keyring the client refuses against the server's rev or its
// own anchor. A keyring that fails to open is ErrDecrypt, and one that fails
// to parse is ErrFormat; neither is ever read as an empty keyring.
var (
	// ErrKeyringRev means the rev sealed inside differs from the server's.
	ErrKeyringRev = errors.New("e2e: keyring rev differs from the server's rev")
	// ErrKeyringRollback means a rev below the anchor's.
	ErrKeyringRollback = errors.New("e2e: keyring older than the anchor")
	// ErrKeyringFork means the anchor's rev, but other sealed bytes.
	ErrKeyringFork = errors.New("e2e: keyring differs from the anchor at the same rev")
)

// Pin states. PinNew and PinChanged are what PinState reports; only
// PinUnverified and PinVerified are ever stored.
const (
	PinNew        = "new"
	PinUnverified = "unverified"
	PinVerified   = "verified"
	PinChanged    = "changed"
)

// Keyring is the user's pins and epoch records, sealed under MK.
type Keyring struct {
	V      int                     `json:"v"`
	Rev    int                     `json:"rev"`
	Pins   map[string]Pin          `json:"pins"`
	Epochs map[string]KeyringEpoch `json:"epochs"`
}

// Pin is the fingerprint the user accepted for another user. RotSeq and
// RotHead record the last rotation accepted; until step 7 adds rotation
// they only round-trip, and nothing here follows or checks a rotation chain.
type Pin struct {
	FP      string `json:"fp"`
	State   string `json:"state"`
	RotSeq  int    `json:"rotSeq"`
	RotHead string `json:"rotHead"`
}

// KeyringEpoch is the record of one artifact's membership chain: the highest
// epoch seen, the seq and body hash of the latest record accepted, and the
// seq of the latest handover acknowledged.
type KeyringEpoch struct {
	Epoch int    `json:"epoch"`
	Seq   int    `json:"seq"`
	Head  string `json:"head"`
	Ack   int    `json:"ack"`
}

// KeyringAnchor is the highest rev a client has seen and the hash of the
// sealed keyring at that rev.
type KeyringAnchor struct {
	Rev  int    `json:"rev"`
	Hash string `json:"hash"`
}

// NewKeyring is the keyring before the first write.
func NewKeyring() *Keyring {
	return &Keyring{V: 1, Pins: map[string]Pin{}, Epochs: map[string]KeyringEpoch{}}
}

// Clone returns a copy that shares no map with k.
func (k *Keyring) Clone() *Keyring {
	c := *k
	c.Pins = maps.Clone(k.Pins)
	c.Epochs = maps.Clone(k.Epochs)
	return &c
}

// EpochPin is the keyring's pin for artifact, for VerifyChain and
// CheckEncryptEpoch, or nil on first sight.
func (k *Keyring) EpochPin(artifact string) *EpochPin {
	e, ok := k.Epochs[artifact]
	if !ok {
		return nil
	}
	return &EpochPin{Epoch: e.Epoch, Seq: e.Seq, Head: e.Head}
}

// SetEpoch records a verified chain as artifact's epochs entry, keeping the
// acknowledged handover.
func (k *Keyring) SetEpoch(artifact string, c *Chain) {
	k.Epochs[artifact] = KeyringEpoch{Epoch: c.Latest.Epoch, Seq: c.Latest.Seq, Head: c.Head, Ack: k.Epochs[artifact].Ack}
}

// Check refuses a keyring that breaks the wire format's rules for its
// values. DecodeStrict has already refused its shape.
func (k *Keyring) Check() error {
	if k.V != 1 {
		return fmt.Errorf("%w: keyring v %d", ErrFormat, k.V)
	}
	if k.Rev < 0 {
		return fmt.Errorf("%w: keyring rev %d", ErrFormat, k.Rev)
	}
	if k.Pins == nil || k.Epochs == nil {
		return fmt.Errorf("%w: keyring pins and epochs must be objects", ErrFormat)
	}
	for user, p := range k.Pins {
		if !isHex64(p.FP) {
			return fmt.Errorf("%w: pin for %s: fp is not 64 lowercase hex digits", ErrFormat, user)
		}
		if p.State != PinUnverified && p.State != PinVerified {
			return fmt.Errorf("%w: pin for %s: state %q", ErrFormat, user, p.State)
		}
		if p.RotSeq < 0 || (p.RotSeq == 0) != (p.RotHead == "") || p.RotHead != "" && !isHex64(p.RotHead) {
			return fmt.Errorf("%w: pin for %s: rotSeq %d with rotHead %q", ErrFormat, user, p.RotSeq, p.RotHead)
		}
	}
	for artifact, e := range k.Epochs {
		if e.Epoch < 1 || e.Seq < 1 || e.Ack < 0 || !isHex64(e.Head) {
			return fmt.Errorf("%w: epochs entry for %s: %+v", ErrFormat, artifact, e)
		}
	}
	return nil
}

func keyringFields() [][]byte { return [][]byte{[]byte("keyring")} }

// SealKeyring seals k under mkSealKey. It refuses a keyring Check refuses,
// so nothing sealed fails to open.
func SealKeyring(rnd io.Reader, mkSealKey []byte, k *Keyring) ([]byte, error) {
	if err := k.Check(); err != nil {
		return nil, err
	}
	pt, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}
	return Seal(rnd, mkSealKey, keyringFields(), pt)
}

// KeyringAnchorOf is the anchor for a keyring the client accepted.
func KeyringAnchorOf(rev int, sealed []byte) KeyringAnchor {
	sum := sha256.Sum256(sealed)
	return KeyringAnchor{Rev: rev, Hash: hex.EncodeToString(sum[:])}
}

// Check refuses an anchor no client would have stored.
func (a KeyringAnchor) Check() error {
	if a.Rev < 0 || !isHex64(a.Hash) {
		return fmt.Errorf("%w: keyring anchor %+v", ErrFormat, a)
	}
	return nil
}

// OpenKeyring opens the keyring GET /api/me/keyring served: rev is the
// server's rev and sealed the keyring, empty before the first write. It
// checks the sealed rev against rev, then against anchor (nil on a device
// that has never read the keyring), and returns the keyring and the anchor
// to store. An empty answer is the empty keyring at rev 0, held to the same
// anchor checks, so a server that wipes the keyring is a rollback.
func OpenKeyring(mkSealKey []byte, rev int, sealed []byte, anchor *KeyringAnchor) (*Keyring, KeyringAnchor, error) {
	if anchor != nil {
		if err := anchor.Check(); err != nil {
			return nil, KeyringAnchor{}, err
		}
	}
	var k *Keyring
	if len(sealed) == 0 {
		if rev != 0 {
			return nil, KeyringAnchor{}, fmt.Errorf("%w: no keyring at rev %d", ErrFormat, rev)
		}
		k = NewKeyring()
	} else {
		pt, err := Open(mkSealKey, keyringFields(), sealed)
		if err != nil {
			return nil, KeyringAnchor{}, err
		}
		k = &Keyring{}
		if err := DecodeStrict(pt, k); err != nil {
			return nil, KeyringAnchor{}, err
		}
		if err := k.Check(); err != nil {
			return nil, KeyringAnchor{}, err
		}
	}
	if k.Rev != rev {
		return nil, KeyringAnchor{}, fmt.Errorf("%w: sealed rev %d, server rev %d", ErrKeyringRev, k.Rev, rev)
	}
	next := KeyringAnchorOf(k.Rev, sealed)
	if anchor != nil {
		if k.Rev < anchor.Rev {
			return nil, KeyringAnchor{}, fmt.Errorf("%w: rev %d, anchor rev %d", ErrKeyringRollback, k.Rev, anchor.Rev)
		}
		if k.Rev == anchor.Rev && next.Hash != anchor.Hash {
			return nil, KeyringAnchor{}, fmt.Errorf("%w: rev %d", ErrKeyringFork, k.Rev)
		}
	}
	return k, next, nil
}

// PinState compares a user's current public keys with the pin for them, nil
// if there is none, and returns the state to show and the current
// fingerprint in hex: PinNew with no pin, the pin's own state when the
// fingerprint matches, and PinChanged when it differs. A changed key that a
// rotation chain explains is step 7's.
func PinState(pin *Pin, x25519Pub, ed25519Pub []byte) (state, fp string) {
	fp = hex.EncodeToString(Fingerprint(x25519Pub, ed25519Pub))
	switch {
	case pin == nil:
		return PinNew, fp
	case pin.FP == fp:
		return pin.State, fp
	default:
		return PinChanged, fp
	}
}
