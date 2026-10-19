// Package webauthn checks WebAuthn assertions for passkey unlock. It holds
// only the server's half of the ceremony: the checks on one assertion made
// with a key stored at enrollment. Everything else (challenge issue, storage,
// sessions) belongs to the HTTP handlers, so this package stays free of
// state and can be fuzzed on its own.
package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// COSE algorithm identifiers accepted. Only these three are enrolled, so a
// stored key never needs a parser for anything else.
const (
	AlgEdDSA = -8   // Ed25519
	AlgES256 = -7   // ECDSA P-256 with SHA-256, ASN.1 DER signatures
	AlgRS256 = -257 // RSASSA-PKCS1-v1_5 with SHA-256, modulus >= 2048 bits
)

// minRSABits is the smallest RSA modulus accepted. Below it the key is
// weak enough that a signature proves little.
const minRSABits = 2048

// authDataMinLen is the fixed part of authenticator data: the RP ID hash
// (32), the flags byte (1), and the signature counter (4).
const authDataMinLen = 37

// Flag bits in the authenticator data's flags byte.
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
)

// Each sentinel is returned, possibly wrapped, for exactly one failed check,
// so a handler and a test can tell which check refused with errors.Is.
var (
	// ErrMalformed means the client data JSON, the authenticator data, or the
	// public key could not be parsed.
	ErrMalformed = errors.New("webauthn: malformed input")
	// ErrAlgorithm means the algorithm is unsupported or does not match the key type.
	ErrAlgorithm = errors.New("webauthn: unsupported algorithm or key type mismatch")
	// ErrType means the client data type is not "webauthn.get".
	ErrType = errors.New("webauthn: wrong client data type")
	// ErrChallenge means the client data challenge is not the one issued.
	ErrChallenge = errors.New("webauthn: challenge mismatch")
	// ErrOrigin means the origin differs from the expected one, or the
	// assertion was made from a cross-origin frame.
	ErrOrigin = errors.New("webauthn: origin mismatch")
	// ErrRPID means the authenticator data names a different relying party.
	ErrRPID = errors.New("webauthn: RP ID hash mismatch")
	// ErrUserPresent means the user-present flag is clear.
	ErrUserPresent = errors.New("webauthn: user presence flag not set")
	// ErrUserVerified means the user-verified flag is clear.
	ErrUserVerified = errors.New("webauthn: user verification flag not set")
	// ErrSignature means the signature does not verify under the stored key.
	ErrSignature = errors.New("webauthn: signature invalid")
	// ErrCounter means the signature counter did not advance, which can
	// mean a cloned authenticator.
	ErrCounter = errors.New("webauthn: signature counter did not increase")
)

// Credential is what the server stored at enrollment for one passkey.
type Credential struct {
	PublicKey []byte // SubjectPublicKeyInfo DER, as getPublicKey() returns
	Alg       int
	SignCount uint32 // last counter stored
}

// Expect is what the server knows about this ceremony before the browser
// answers: it comes from configuration and the issued challenge, never from
// the request.
type Expect struct {
	RPID      string // relying party ID, a host name
	Origin    string // exact expected origin, e.g. "https://cairn.example.com"
	Challenge []byte // the raw challenge bytes the server issued
}

// Assertion is the three byte strings the browser returns from
// navigator.credentials.get.
type Assertion struct {
	ClientDataJSON    []byte
	AuthenticatorData []byte
	Signature         []byte
}

// clientData is the part of the client data JSON the checks read. Unknown
// fields are ignored: the browser may add some.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// CheckPublicKey parses spki and confirms its key type matches alg (Ed25519
// for AlgEdDSA, ECDSA on P-256 for AlgES256, RSA >= 2048 bits for AlgRS256).
// Enrollment calls it so a key that could never verify is refused up front
// rather than stored and found useless at unlock.
func CheckPublicKey(spki []byte, alg int) error {
	_, err := parsePublicKey(spki, alg)
	return err
}

// parsePublicKey is CheckPublicKey that also returns the key, so Verify
// parses once. An unsupported alg is reported before the bytes are read.
func parsePublicKey(spki []byte, alg int) (crypto.PublicKey, error) {
	if alg != AlgEdDSA && alg != AlgES256 && alg != AlgRS256 {
		return nil, fmt.Errorf("%w: alg %d", ErrAlgorithm, alg)
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("%w: public key: %v", ErrMalformed, err)
	}
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if alg == AlgEdDSA {
			return k, nil
		}
	case *ecdsa.PublicKey:
		if alg == AlgES256 && k.Curve == elliptic.P256() {
			return k, nil
		}
	case *rsa.PublicKey:
		if alg == AlgRS256 && k.N.BitLen() >= minRSABits {
			return k, nil
		}
	}
	return nil, fmt.Errorf("%w: key does not fit alg %d", ErrAlgorithm, alg)
}

// Verify checks an assertion and returns the authenticator's new signature
// counter. The checks run cheapest and most telling first, and the signature
// last among the ceremony checks, so a request aimed at the wrong site or
// ceremony is refused before any public-key work. The counter comes last
// because it only means something once the signature has proved who sent it.
func Verify(a Assertion, cred Credential, exp Expect) (signCount uint32, err error) {
	pub, err := parsePublicKey(cred.PublicKey, cred.Alg)
	if err != nil {
		return 0, err
	}
	if len(a.AuthenticatorData) < authDataMinLen {
		return 0, fmt.Errorf("%w: authenticator data is %d bytes", ErrMalformed, len(a.AuthenticatorData))
	}
	var cd clientData
	if err := json.Unmarshal(a.ClientDataJSON, &cd); err != nil {
		return 0, fmt.Errorf("%w: client data: %v", ErrMalformed, err)
	}

	if cd.Type != "webauthn.get" {
		return 0, fmt.Errorf("%w: %q", ErrType, cd.Type)
	}
	// RawURLEncoding refuses padding and the standard alphabet.
	got, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil || subtle.ConstantTimeCompare(got, exp.Challenge) != 1 {
		return 0, ErrChallenge
	}
	if cd.Origin != exp.Origin || cd.CrossOrigin {
		return 0, fmt.Errorf("%w: %q (crossOrigin %t)", ErrOrigin, cd.Origin, cd.CrossOrigin)
	}
	rpHash := sha256.Sum256([]byte(exp.RPID))
	if !bytes.Equal(a.AuthenticatorData[:32], rpHash[:]) {
		return 0, ErrRPID
	}
	flags := a.AuthenticatorData[32]
	if flags&flagUserPresent == 0 {
		return 0, ErrUserPresent
	}
	if flags&flagUserVerified == 0 {
		return 0, ErrUserVerified
	}

	cdHash := sha256.Sum256(a.ClientDataJSON)
	msg := append(append([]byte{}, a.AuthenticatorData...), cdHash[:]...)
	if !verifySignature(pub, msg, a.Signature) {
		return 0, ErrSignature
	}

	signCount = binary.BigEndian.Uint32(a.AuthenticatorData[33:37])
	if (cred.SignCount != 0 || signCount != 0) && signCount <= cred.SignCount {
		return 0, fmt.Errorf("%w: stored %d, got %d", ErrCounter, cred.SignCount, signCount)
	}
	return signCount, nil
}

// verifySignature checks sig over msg with the key parsePublicKey returned.
// Ed25519 signs the message itself; the other two sign its SHA-256.
func verifySignature(pub crypto.PublicKey, msg, sig []byte) bool {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(k, msg, sig)
	case *ecdsa.PublicKey:
		d := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(k, d[:], sig)
	case *rsa.PublicKey:
		d := sha256.Sum256(msg)
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, d[:], sig) == nil
	}
	return false
}
