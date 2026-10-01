package server

import (
	"encoding/json"
	"errors"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// errBadBundle is returned by validateBundle and its helpers; handlers map it
// to 400.
var errBadBundle = errors.New("malformed key bundle")

// Argon2id ceiling: a bundle's kdf must not ask a client to do more work than
// this, so a hostile server cannot exhaust a client's memory or hang it. The
// floor lives in e2e.Params.CheckFloor.
const (
	ceilingMemory = 1048576 // KiB, 1 GiB
	ceilingTime   = 10
)

// kdfSaltLen is the exact salt length a bundle's own kdf must carry. Prelogin
// and NewParams always produce one of this length; CheckFloor alone would
// accept a wider 16-64 byte range, which is only meant for a server raising
// its own defaults, not for what a client is allowed to upload.
const kdfSaltLen = 16

// sealedKeyLen is the length of a sealed 32-byte key: a 1-byte version, a
// 12-byte nonce, the 32-byte plaintext, and a 16-byte GCM tag.
const sealedKeyLen = 61

// validateKDF parses and bounds-checks a bundle's kdf object: argon2id only,
// at or above the floor, at or below the ceiling, with an exact 16-byte salt.
func validateKDF(raw json.RawMessage) (e2e.Params, error) {
	var p e2e.Params
	if err := json.Unmarshal(raw, &p); err != nil {
		return e2e.Params{}, errBadBundle
	}
	if err := p.CheckFloor(); err != nil {
		return e2e.Params{}, errBadBundle
	}
	if p.Memory > ceilingMemory || p.Time > ceilingTime {
		return e2e.Params{}, errBadBundle
	}
	if len(p.Salt) != kdfSaltLen {
		return e2e.Params{}, errBadBundle
	}
	return p, nil
}

// validateSealedLen refuses anything but an exactly sealedKeyLen-byte sealed
// value.
func validateSealedLen(b []byte) error {
	if len(b) != sealedKeyLen {
		return errBadBundle
	}
	return nil
}

// validatePub refuses anything but a 32-byte public key. A small-order-key
// check belongs here too, once internal/e2e exposes one.
func validatePub(b []byte) error {
	if len(b) != 32 {
		return errBadBundle
	}
	return nil
}

// validateBundle checks everything the server can check about a key bundle
// without being able to read it: the kdf floor and ceiling, and that every
// public key and sealed key has the exact length the wire format fixes.
func validateBundle(b store.Bundle) error {
	if _, err := validateKDF(b.KDF); err != nil {
		return err
	}
	for _, pub := range [][]byte{b.X25519Pub, b.Ed25519Pub} {
		if err := validatePub(pub); err != nil {
			return err
		}
	}
	if e2e.CheckPublicKeys(b.X25519Pub, b.Ed25519Pub) != nil {
		return errBadBundle
	}
	for _, sealed := range [][]byte{b.MKPassword, b.MKRecovery, b.X25519Priv, b.Ed25519Priv, b.EK} {
		if err := validateSealedLen(sealed); err != nil {
			return err
		}
	}
	return nil
}
