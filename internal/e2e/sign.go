package e2e

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
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
func Sign(seed []byte, purpose string, body []byte) []byte {
	priv := ed25519.NewKeyFromSeed(seed)
	msg := Enc([]byte(LabelSig), []byte(purpose), body)
	return ed25519.Sign(priv, msg)
}

// Verify checks a signature produced by Sign.
func Verify(pub []byte, purpose string, body, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	msg := Enc([]byte(LabelSig), []byte(purpose), body)
	return ed25519.Verify(pub, msg, sig)
}

// Envelope carries a signed record: the exact body bytes, its signature, and
// the signer's user ID. Verification runs over the exact body bytes, so no
// JSON canonicalization is needed.
type Envelope struct {
	Body   []byte
	Sig    []byte
	Signer string
}

type envelopeJSON struct {
	Body   string `json:"body"`
	Sig    string `json:"sig"`
	Signer string `json:"signer"`
}

func (e Envelope) MarshalJSON() ([]byte, error) {
	return json.Marshal(envelopeJSON{B64(e.Body), B64(e.Sig), e.Signer})
}

func (e *Envelope) UnmarshalJSON(data []byte) error {
	var aux envelopeJSON
	if err := json.Unmarshal(data, &aux); err != nil {
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
	*e = Envelope{body, sig, aux.Signer}
	return nil
}

// NewEnvelope signs body with seed and wraps it as an envelope from signer.
func NewEnvelope(seed []byte, signer, purpose string, body []byte) Envelope {
	return Envelope{Body: body, Sig: Sign(seed, purpose, body), Signer: signer}
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
