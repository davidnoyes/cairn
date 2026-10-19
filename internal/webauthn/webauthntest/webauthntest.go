// Package webauthntest is a software authenticator. It builds assertions the
// way a browser and a passkey would, and can break any one part of one, so
// tests in this and other packages can exercise every check in
// internal/webauthn and the handlers built on it. It is a non-test file so
// other packages' tests can import it; no production code should.
package webauthntest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/aloisdeniel/cairn/internal/webauthn"
)

// Authenticator holds one key and a signature counter.
type Authenticator struct {
	key     crypto.Signer
	alg     int
	counter uint32
}

// New generates a fresh key for alg. It panics on an unsupported alg, since
// that is a mistake in the test.
func New(alg int) *Authenticator {
	var key crypto.Signer
	var err error
	switch alg {
	case webauthn.AlgEdDSA:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case webauthn.AlgES256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case webauthn.AlgRS256:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		panic(fmt.Sprintf("webauthntest: unsupported alg %d", alg))
	}
	if err != nil {
		panic(err)
	}
	return &Authenticator{key: key, alg: alg}
}

// SPKI returns the public key as the browser's getPublicKey() does.
func (a *Authenticator) SPKI() []byte {
	der, err := x509.MarshalPKIXPublicKey(a.key.Public())
	if err != nil {
		panic(err)
	}
	return der
}

// Alg returns the COSE algorithm of the key.
func (a *Authenticator) Alg() int { return a.alg }

// settings is what Assert builds from the expectation and the options.
type settings struct {
	typ         string
	origin      string
	crossOrigin bool
	challenge   []byte
	rpID        string
	flags       byte
	counter     *uint32
	badSig      bool
}

// Option changes one part of an assertion so it breaks one check.
type Option func(*settings)

// WithType sets the client data type.
func WithType(t string) Option { return func(s *settings) { s.typ = t } }

// WithOrigin sets the client data origin.
func WithOrigin(o string) Option { return func(s *settings) { s.origin = o } }

// WithCrossOrigin sets crossOrigin to true in the client data.
func WithCrossOrigin() Option { return func(s *settings) { s.crossOrigin = true } }

// WithChallenge signs a challenge other than the expected one.
func WithChallenge(c []byte) Option { return func(s *settings) { s.challenge = c } }

// WithRPID hashes a relying party ID other than the expected one.
func WithRPID(id string) Option { return func(s *settings) { s.rpID = id } }

// WithFlags sets the authenticator data flags byte (default 0x05, user
// present and user verified).
func WithFlags(f byte) Option { return func(s *settings) { s.flags = f } }

// WithCounter sets the counter value used, including 0, and keeps it as the
// authenticator's counter.
func WithCounter(c uint32) Option { return func(s *settings) { s.counter = &c } }

// WithBadSignature flips a bit in the signature.
func WithBadSignature() Option { return func(s *settings) { s.badSig = true } }

// Assert builds a valid assertion for exp, incrementing the counter, unless
// opts change something.
func (a *Authenticator) Assert(exp webauthn.Expect, opts ...Option) webauthn.Assertion {
	s := settings{
		typ:       "webauthn.get",
		origin:    exp.Origin,
		challenge: exp.Challenge,
		rpID:      exp.RPID,
		flags:     0x05,
	}
	for _, o := range opts {
		o(&s)
	}
	if s.counter != nil {
		a.counter = *s.counter
	} else {
		a.counter++
	}

	cd, err := json.Marshal(map[string]any{
		"type":        s.typ,
		"challenge":   base64.RawURLEncoding.EncodeToString(s.challenge),
		"origin":      s.origin,
		"crossOrigin": s.crossOrigin,
	})
	if err != nil {
		panic(err)
	}
	rp := sha256.Sum256([]byte(s.rpID))
	ad := append([]byte{}, rp[:]...)
	ad = append(ad, s.flags)
	ad = binary.BigEndian.AppendUint32(ad, a.counter)

	cdHash := sha256.Sum256(cd)
	msg := append(append([]byte{}, ad...), cdHash[:]...)
	var sig []byte
	if a.alg == webauthn.AlgEdDSA {
		sig, err = a.key.Sign(rand.Reader, msg, crypto.Hash(0))
	} else {
		d := sha256.Sum256(msg)
		sig, err = a.key.Sign(rand.Reader, d[:], crypto.SHA256)
	}
	if err != nil {
		panic(err)
	}
	if s.badSig {
		sig[len(sig)-1] ^= 1
	}
	return webauthn.Assertion{ClientDataJSON: cd, AuthenticatorData: ad, Signature: sig}
}
