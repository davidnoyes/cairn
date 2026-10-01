package e2e

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"

	"filippo.io/edwards25519"
)

// GenerateEd25519 reads a 32-byte seed from rnd and derives an Ed25519 key
// pair from it.
func GenerateEd25519(rnd io.Reader) (seed, pub []byte, err error) {
	seed = make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub = []byte(priv.Public().(ed25519.PublicKey))
	return seed, pub, nil
}

// Sign signs body over sig = Ed25519(signingKey, enc("cairn/v1/sig", purpose, body)).
func Sign(seed []byte, purpose string, body []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: seed length %d, want %d", ErrFormat, len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	msg := Enc([]byte(LabelSig), []byte(purpose), body)
	return ed25519.Sign(priv, msg), nil
}

// Verify checks a signature produced by Sign. Before the curve equation it
// runs signatureEncodingOK, so it accepts exactly the signatures every
// strict verifier (cofactored or not) accepts, and the browser module
// agrees with it whichever WebCrypto implementation runs there.
func Verify(pub []byte, purpose string, body, sig []byte) bool {
	if !signatureEncodingOK(pub, sig) {
		return false
	}
	msg := Enc([]byte(LabelSig), []byte(purpose), body)
	return ed25519.Verify(pub, msg, sig)
}

// signatureEncodingOK is every check Verify makes before the curve
// equation: the public key A and the signature's R (its first 32 bytes) must
// each be the canonical encoding of a point of prime order L (see
// isPrimeOrderEd25519), and S (its last 32 bytes) must be below L.
// crypto/ed25519 already refuses some of these through its own equation,
// but a cofactored verifier accepts a signature with a small-order or
// mixed-order R or A that a cofactorless one refuses; refusing them here
// makes the result the same under both. Split out so a test can show each
// check refuses on its own.
func signatureEncodingOK(pub, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	if !isPrimeOrderEd25519(pub) || !isPrimeOrderEd25519(sig[:32]) {
		return false
	}
	_, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	return err == nil
}

// isPrimeOrderEd25519 reports whether enc is the canonical encoding of a
// curve point in the prime-order subgroup other than the identity: not
// refused by isSmallOrderEd25519, on the curve, and torsion-free. A
// mixed-order point (a prime-order point plus one of the small-order ones)
// passes the first two, so it needs the third: [L]P = O, computed as
// [L-1]P + P because a Scalar only holds values below L. The inputs are
// public, so the variable-time multiplication is fine.
func isPrimeOrderEd25519(enc []byte) bool {
	if len(enc) != 32 || isSmallOrderEd25519(enc) {
		return false
	}
	p, err := new(edwards25519.Point).SetBytes(enc)
	if err != nil {
		return false
	}
	q := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(scalarLMinus1, p, edwards25519.NewScalar())
	q.Add(q, p)
	return q.Equal(edwards25519.NewIdentityPoint()) == 1
}

// scalarLMinus1 is L-1, the largest value a Scalar holds: -1 mod L.
var scalarLMinus1 = func() *edwards25519.Scalar {
	one := make([]byte, 32)
	one[0] = 1
	s, err := edwards25519.NewScalar().SetCanonicalBytes(one)
	if err != nil {
		panic("e2e: scalar 1 is not canonical")
	}
	return s.Negate(s)
}()

// smallOrderEd25519 is the 8 canonical Ed25519 public key encodings whose
// decoded point has order dividing 8: the identity, the order-2 point, the
// two order-4 points, and the four order-8 points — the four points of the
// curve's torsion subgroup that aren't the identity, plus the identity
// itself. Computed directly from the curve equation -x^2+y^2 = 1+dx^2y^2 (d =
// -121665/121666 mod p, p = 2^255-19) and confirmed by scalar multiplication
// that each point P satisfies 8P = the identity and 4P != the identity (for
// the order-8 points) — this is the same list documented by, among others,
// libsodium's small-order point table and "Taming the many EdDSAs".
//
// Every other invalid or non-canonical encoding — a y coordinate >= p, or
// the impossible combination x=0 with the sign bit set — is rejected
// structurally by isSmallOrderEd25519 below instead of by a longer list:
// several decoders accept such an encoding anyway by reducing y mod p, which
// silently maps it onto one of these 8 points or another one entirely, so
// every out-of-range or x=0-with-sign-bit encoding must be refused on its
// own, not just the specific ones a fixed list happens to name.
var smallOrderEd25519 = [][32]byte{
	hexArray32("0100000000000000000000000000000000000000000000000000000000000000"),
	hexArray32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	hexArray32("0000000000000000000000000000000000000000000000000000000000000000"),
	hexArray32("0000000000000000000000000000000000000000000000000000000000000080"),
	hexArray32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
	hexArray32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
	hexArray32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
	hexArray32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
}

func hexArray32(s string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic("e2e: malformed small-order point literal")
	}
	var a [32]byte
	copy(a[:], b)
	return a
}

// edwards25519P is the field prime shared by Curve25519 and Ed25519:
// 2^255 - 19.
var edwards25519P = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

var edwards25519PMinus1 = new(big.Int).Sub(edwards25519P, big.NewInt(1))

// leToBigInt interprets b as a little-endian unsigned integer, the byte
// order every key and coordinate in this package uses, unlike math/big's own
// SetBytes which assumes big-endian.
func leToBigInt(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i, c := range b {
		rev[len(b)-1-i] = c
	}
	return new(big.Int).SetBytes(rev)
}

// isSmallOrderEd25519 rejects a public key encoding a verifier must never
// accept: a non-canonical y coordinate (the low 255 bits, little-endian, >=
// p), the impossible combination x=0 with the sign bit set (only y=1 or
// y=p-1 give x=0, so a set sign bit there is not an encoding this curve ever
// produces), or one of the 8 canonical small-order points above. The first
// two checks are structural rather than a longer hardcoded list, because a
// decoder that doesn't itself reject an out-of-range y will still decode one
// to some point by reducing mod p.
func isSmallOrderEd25519(pub []byte) bool {
	if len(pub) != 32 {
		return false
	}
	signSet := pub[31]&0x80 != 0
	yBytes := append([]byte(nil), pub...)
	yBytes[31] &= 0x7f
	y := leToBigInt(yBytes)
	if y.Cmp(edwards25519P) >= 0 {
		return true
	}
	if signSet && (y.Cmp(big.NewInt(1)) == 0 || y.Cmp(edwards25519PMinus1) == 0) {
		return true
	}
	var a [32]byte
	copy(a[:], pub)
	for _, p := range smallOrderEd25519 {
		if a == p {
			return true
		}
	}
	return false
}

// isNonCanonicalX25519 rejects an X25519 public key that isn't the unique
// canonical encoding of its u-coordinate: the high bit of the last byte set,
// or the full 32-byte little-endian value >= p (2^255-19). RFC 7748 permits
// an implementation to mask the high bit and reduce mod p instead of
// rejecting, which would let two different byte strings be accepted as the
// same key — checking the raw, unmasked value catches both cases in one
// comparison, since a set high bit alone already puts the value at or above
// 2^255 > p.
func isNonCanonicalX25519(pub []byte) bool {
	return leToBigInt(pub).Cmp(edwards25519P) >= 0
}

// CheckPublicKeys rejects a malformed, non-canonical, or low-order X25519 or
// Ed25519 public key, so a user's keyring can never be made to hold a key an
// attacker chose to force a predictable shared secret or a universally-valid
// signature.
//
// An X25519 key is checked for canonical form, then by attempting ECDH with
// a fresh ephemeral key: crypto/ecdh returns an error exactly when the
// result would be the all-zero output RFC 7748 requires implementations to
// reject, which is what every low-order point produces. An Ed25519 key must
// be a canonical, on-curve, torsion-free point; see isPrimeOrderEd25519.
// X25519 needs no torsion check: a clamped scalar is a multiple of 8, so
// the torsion component of a mixed-order key never reaches the shared
// secret.
func CheckPublicKeys(x25519Pub, ed25519Pub []byte) error {
	if len(x25519Pub) != 32 {
		return fmt.Errorf("%w: x25519 public key length %d, want 32", ErrFormat, len(x25519Pub))
	}
	if len(ed25519Pub) != 32 {
		return fmt.Errorf("%w: ed25519 public key length %d, want 32", ErrFormat, len(ed25519Pub))
	}
	if isNonCanonicalX25519(x25519Pub) {
		return fmt.Errorf("%w: x25519 public key is not canonically encoded", ErrFormat)
	}
	pub, err := ecdh.X25519().NewPublicKey(x25519Pub)
	if err != nil {
		return fmt.Errorf("%w: x25519 public key: %v", ErrFormat, err)
	}
	fresh, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if _, err := fresh.ECDH(pub); err != nil {
		return fmt.Errorf("%w: x25519 public key is low-order", ErrFormat)
	}
	if !isPrimeOrderEd25519(ed25519Pub) {
		return fmt.Errorf("%w: ed25519 public key is not a canonical point of prime order", ErrFormat)
	}
	return nil
}

// Envelope carries a signed record: the exact body bytes, its signature, and
// the signer's user ID. Verification runs over the exact body bytes, so no
// JSON canonicalization is needed. NewSig is set only for a rotation
// envelope: the same body signed again by the new Ed25519 key, so a verifier
// can check continuity of control over both the old and the new key.
type Envelope struct {
	Body   []byte
	Sig    []byte
	Signer string
	NewSig []byte
}

type envelopeJSON struct {
	Body   string `json:"body"`
	Sig    string `json:"sig"`
	Signer string `json:"signer"`
	NewSig string `json:"newSig,omitempty"`
}

func (e Envelope) MarshalJSON() ([]byte, error) {
	aux := envelopeJSON{Body: B64(e.Body), Sig: B64(e.Sig), Signer: e.Signer}
	if e.NewSig != nil {
		aux.NewSig = B64(e.NewSig)
	}
	return json.Marshal(aux)
}

// UnmarshalJSON parses an envelope strictly: {"body","sig","signer"} plus an
// optional "newSig", nothing else, no duplicate keys, and no trailing data.
func (e *Envelope) UnmarshalJSON(data []byte) error {
	var aux envelopeJSON
	if err := DecodeStrict(data, &aux); err != nil {
		return err
	}
	body, err := UnB64(aux.Body)
	if err != nil {
		return err
	}
	sig, err := UnB64(aux.Sig)
	if err != nil {
		return err
	}
	var newSig []byte
	if aux.NewSig != "" {
		newSig, err = UnB64(aux.NewSig)
		if err != nil {
			return err
		}
	}
	*e = Envelope{Body: body, Sig: sig, Signer: aux.Signer, NewSig: newSig}
	return nil
}

// NewEnvelope signs body with seed and wraps it as an envelope from signer.
func NewEnvelope(seed []byte, signer, purpose string, body []byte) (Envelope, error) {
	sig, err := Sign(seed, purpose, body)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Body: body, Sig: sig, Signer: signer}, nil
}

// Verify checks the envelope's signature against pub for purpose. It does
// not interpret the body.
func (e Envelope) Verify(pub []byte, purpose string) bool {
	return Verify(pub, purpose, e.Body, e.Sig)
}

// Fingerprint is a SHA-256 hash over a user's public keys, for comparing
// aloud in short groups.
func Fingerprint(x25519Pub, ed25519Pub []byte) []byte {
	return sha256Sum(Enc([]byte(LabelFingerprint), x25519Pub, ed25519Pub))
}

// FormatFingerprint renders the first 20 bytes of a fingerprint as hex, in
// groups of four characters separated by spaces.
func FormatFingerprint(fp []byte) string {
	n := min(len(fp), 20)
	h := hex.EncodeToString(fp[:n])
	var groups []string
	for i := 0; i < len(h); i += 4 {
		groups = append(groups, h[i:min(i+4, len(h))])
	}
	return strings.Join(groups, " ")
}
