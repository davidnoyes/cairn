package e2e

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
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

// Verify checks a signature produced by Sign. It refuses a public key of the
// wrong length and a public key that is one of the small-order Ed25519
// encodings, which would let a forged "signature" verify against more than
// one message under a cofactored verifier.
func Verify(pub []byte, purpose string, body, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || isSmallOrderEd25519(pub) {
		return false
	}
	msg := Enc([]byte(LabelSig), []byte(purpose), body)
	return ed25519.Verify(pub, msg, sig)
}

// smallOrderEd25519 is the well-known list of Ed25519 public key encodings
// whose decoded point has order dividing 8: the four points of the curve's
// torsion subgroup that aren't the identity, plus the non-canonical
// encodings of those with y < 19 (y+p is still < 2^255 and so still decodes,
// to the same point, on a decoder that doesn't reject y >= p). Computed
// directly from the curve equation -x^2+y^2 = 1+dx^2y^2 (d = -121665/121666
// mod 2^255-19) and confirmed by scalar multiplication that each point P
// satisfies 8P = the identity and 4P != the identity (for the order-8
// points) — this is the same list documented by, among others, libsodium's
// small-order point table and "Taming the many EdDSAs".
var smallOrderEd25519 = [][32]byte{
	hexArray32("0100000000000000000000000000000000000000000000000000000000000000"),
	hexArray32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	hexArray32("0000000000000000000000000000000000000000000000000000000000000000"),
	hexArray32("0000000000000000000000000000000000000000000000000000000000000080"),
	hexArray32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
	hexArray32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
	hexArray32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
	hexArray32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
	// Non-canonical: y+p for the two points above with y < 19 (identity and
	// the two order-4 points), still < 2^255 and so still decodable.
	hexArray32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	hexArray32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	hexArray32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
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

func isSmallOrderEd25519(pub []byte) bool {
	if len(pub) != 32 {
		return false
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

// CheckPublicKeys rejects a malformed or low-order X25519 or Ed25519 public
// key, so a user's keyring can never be made to hold a key an attacker chose
// to force a predictable shared secret or a universally-valid signature.
//
// An X25519 key is checked by attempting ECDH with a fresh ephemeral key:
// crypto/ecdh returns an error exactly when the result would be the all-zero
// output RFC 7748 requires implementations to reject, which is what every
// low-order point produces. An Ed25519 key is checked against the hardcoded
// small-order list.
func CheckPublicKeys(x25519Pub, ed25519Pub []byte) error {
	if len(x25519Pub) != 32 {
		return fmt.Errorf("%w: x25519 public key length %d, want 32", ErrFormat, len(x25519Pub))
	}
	if len(ed25519Pub) != 32 {
		return fmt.Errorf("%w: ed25519 public key length %d, want 32", ErrFormat, len(ed25519Pub))
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
	if isSmallOrderEd25519(ed25519Pub) {
		return fmt.Errorf("%w: ed25519 public key is low-order", ErrFormat)
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
