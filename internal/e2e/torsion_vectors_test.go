package e2e

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/json"
	"io"
	"math/big"
	"testing"

	"filippo.io/edwards25519"
)

// The ed25519Strict entries built here are signatures that satisfy the
// cofactored verification equation [8]([S]B - [k]A - R) = O under a lenient
// point decoder, so some deployed Ed25519 verifier accepts each one. Verify
// and verify must refuse every one of them through checks beyond that
// equation: R must be a canonical, torsion-free point other than the
// identity, and so must A. They are generated with filippo.io/edwards25519,
// independently of the production checks, so a wrong check cannot also
// produce a vector that agrees with it.

func mustPoint(t testing.TB, enc []byte) *edwards25519.Point {
	t.Helper()
	p, err := new(edwards25519.Point).SetBytes(enc)
	if err != nil {
		t.Fatalf("%x is not a curve point: %v", enc, err)
	}
	return p
}

// ed25519Secret returns the RFC 8032 secret scalar a for seed, and the
// encoding of its public point [a]B.
func ed25519Secret(t testing.TB, seed []byte) (*edwards25519.Scalar, []byte) {
	t.Helper()
	h := sha512.Sum512(seed)
	a, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		t.Fatal(err)
	}
	return a, new(edwards25519.Point).ScalarBaseMult(a).Bytes()
}

// challenge is k = SHA-512(R || A || msg) mod L, computed over the
// encodings exactly as sent, as RFC 8032 verification does.
func challenge(t testing.TB, rEnc, aEnc, msg []byte) *edwards25519.Scalar {
	t.Helper()
	h := sha512.New()
	h.Write(rEnc)
	h.Write(aEnc)
	h.Write(msg)
	k, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// sigWith returns R || S with S = r + k*a. An honest signer uses R = [r]B;
// any other R builds a signature only a verifier missing a check accepts.
func sigWith(rEnc []byte, r, k, a *edwards25519.Scalar) []byte {
	s := edwards25519.NewScalar().MultiplyAdd(k, a, r)
	return append(append([]byte{}, rEnc...), s.Bytes()...)
}

func randomScalar(t testing.TB, rnd io.Reader) *edwards25519.Scalar {
	t.Helper()
	b := make([]byte, 64)
	if _, err := io.ReadFull(rnd, b); err != nil {
		t.Fatal(err)
	}
	s, err := edwards25519.NewScalar().SetUniformBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// cofactoredValid reports whether sig satisfies [8]([S]B - [k]A - R) = O
// with A and R decoded leniently (y reduced mod p): the equation a
// cofactored verifier checks, and the one every signature entry here is
// built to pass.
func cofactoredValid(t testing.TB, aEnc, msg, sig []byte) bool {
	t.Helper()
	A, errA := new(edwards25519.Point).SetBytes(aEnc)
	R, errR := new(edwards25519.Point).SetBytes(sig[:32])
	S, errS := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if errA != nil || errR != nil || errS != nil {
		return false
	}
	k := challenge(t, sig[:32], aEnc, msg)
	d := new(edwards25519.Point).ScalarBaseMult(S)
	d.Subtract(d, new(edwards25519.Point).ScalarMult(k, A))
	d.Subtract(d, R)
	d.MultByCofactor(d)
	return d.Equal(edwards25519.NewIdentityPoint()) == 1
}

// inPrimeOrderSubgroup reports whether [8^-1 mod L]([8]P) = P, which holds
// exactly when P has no torsion component. Deliberately a different test
// from the production [L]P = O, so the two can't share a mistake.
func inPrimeOrderSubgroup(t testing.TB, p *edwards25519.Point) bool {
	t.Helper()
	inv := new(big.Int).ModInverse(big.NewInt(8), edwards25519Order)
	invBytes := reverse(inv.FillBytes(make([]byte, 32)))
	s, err := edwards25519.NewScalar().SetCanonicalBytes(invBytes)
	if err != nil {
		t.Fatal(err)
	}
	q := new(edwards25519.Point).MultByCofactor(p)
	q.ScalarMult(s, q)
	return q.Equal(p) == 1
}

// identityRSig is the R = identity signature reported against Verify and
// verify: seed 0..31, purpose "reset", body {"v":1,"user":"u1","token":"t"},
// S = k*a. The generator must reproduce it exactly.
const identityRSig = "0100000000000000000000000000000000000000000000000000000000000000" +
	"734a4de83d6a0f42c55b95e7f026c5d3ac924a15c367f779e431202a2cdb5803"

// mixedOrderKey is a mixed-order Ed25519 public key reported as passing
// CheckPublicKeys and checkPublicKeys: on the curve and not small-order,
// but with a torsion component.
const mixedOrderKey = "ea9d1a3a083c9b4655ae5e7e6e0dc9064a2a2ce0861e1f5ac01cfea6ec46b3e6"

func ed25519StrictTorsionVectors(t testing.TB) []ed25519StrictVec {
	t.Helper()
	order8 := mustPoint(t, smallOrderEd25519[4][:])
	four := new(edwards25519.Point).Add(order8, order8)
	four.Add(four, four)
	if four.Equal(edwards25519.NewIdentityPoint()) == 1 || inPrimeOrderSubgroup(t, order8) {
		t.Fatal("smallOrderEd25519[4] is not of order 8")
	}

	const purpose = "reset"
	body := []byte(`{"v":1,"user":"u1","token":"t"}`)
	msg := Enc([]byte(LabelSig), []byte(purpose), body)
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	a, aEnc := ed25519Secret(t, seed)
	zero := edwards25519.NewScalar()
	withR := func(rEnc []byte, r *edwards25519.Scalar) []byte {
		return sigWith(rEnc, r, challenge(t, rEnc, aEnc, msg), a)
	}

	identityR := withR(smallOrderEd25519[0][:], zero)
	if hexEnc(identityR) != identityRSig {
		t.Fatalf("R = identity signature is %x, want the reported %s", identityR, identityRSig)
	}
	smallOrderR := withR(smallOrderEd25519[4][:], zero)
	nonCanonicalIdentity := encodeLE255(new(big.Int).Add(edwards25519P, big.NewInt(1)), false)
	nonCanonicalR := withR(nonCanonicalIdentity[:], zero)
	r := randomScalar(t, newDRBG("vector-ed25519-strict-mixed-r"))
	mixedREnc := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(r), order8).Bytes()
	mixedR := withR(mixedREnc, r)

	// A mixed-order key A' = A + T with an honest R = [r]B: the cofactorless
	// equation [S]B = R + [k]A' holds exactly when [k]T = O, that is when
	// k = 0 mod 8, so grind r until it does. crypto/ed25519 then accepts
	// the signature, and only the key's torsion check refuses it.
	mixedKey := new(edwards25519.Point).Add(mustPoint(t, aEnc), order8).Bytes()
	var mixedKeySig []byte
	rnd := newDRBG("vector-ed25519-strict-mixed-key")
	for i := 0; mixedKeySig == nil; i++ {
		if i == 1000 {
			t.Fatal("no k = 0 mod 8 in 1000 tries")
		}
		r := randomScalar(t, rnd)
		rEnc := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
		if k := challenge(t, rEnc, mixedKey, msg); k.Bytes()[0]&7 == 0 {
			mixedKeySig = sigWith(rEnc, r, k, a)
		}
	}
	if !ed25519.Verify(mixedKey, msg, mixedKeySig) {
		t.Fatal("the mixed-order key signature fails crypto/ed25519, so it would not isolate the key torsion check")
	}

	sigEntries := []ed25519StrictVec{
		{Name: "r-identity", Pub: hexEnc(aEnc), Sig: identityRSig, Why: "R is the identity point"},
		{Name: "r-small-order", Pub: hexEnc(aEnc), Sig: hexEnc(smallOrderR), Why: "R is a point of order 8"},
		{Name: "r-non-canonical", Pub: hexEnc(aEnc), Sig: hexEnc(nonCanonicalR), Why: "R encodes the identity with y = p+1"},
		{Name: "r-mixed-order", Pub: hexEnc(aEnc), Sig: hexEnc(mixedR), Why: "R has a torsion component of order 8"},
		{Name: "mixed-order-key-signature", Pub: hexEnc(mixedKey), Sig: hexEnc(mixedKeySig), Why: "the key has a torsion component; the signature passes the cofactorless equation"},
	}
	for i := range sigEntries {
		e := &sigEntries[i]
		e.Purpose = purpose
		e.Body = hexEnc(body)
		if !cofactoredValid(t, hexDec(t, e.Pub), msg, hexDec(t, e.Sig)) {
			t.Fatalf("%s: not valid under the cofactored equation, so it tests nothing", e.Name)
		}
	}

	// R = p+k for the smallest k > 1 that is a curve y-coordinate: a
	// non-canonical spelling of a point that is neither the identity nor
	// small-order, unlike r-non-canonical's p+1. No signature with this R
	// passes any curve equation (its discrete log is unknown). The torsion
	// check refuses this R too: every on-curve y below 19 has a torsion
	// component, so no prime-order point has a non-canonical spelling, and
	// no vector can isolate the y < p rule for R. This one is a second line
	// of defense, failing only when both checks are gone.
	var nonCanonicalPoint []byte
	for k := int64(2); nonCanonicalPoint == nil; k++ {
		canonical := encodeLE255(big.NewInt(k), false)
		if p, err := new(edwards25519.Point).SetBytes(canonical[:]); err == nil && !isSmallOrderEd25519(canonical[:]) && p.Equal(edwards25519.NewIdentityPoint()) == 0 {
			enc := encodeLE255(new(big.Int).Add(edwards25519P, big.NewInt(k)), false)
			nonCanonicalPoint = enc[:]
		}
	}
	sigEntries = append(sigEntries, ed25519StrictVec{
		Name: "r-non-canonical-point", Pub: hexEnc(aEnc), Purpose: purpose, Body: hexEnc(body),
		Sig: hexEnc(withR(nonCanonicalPoint, zero)), Why: "R spells an on-curve point other than the identity with y = p+k",
	})

	given := hexDec(t, mixedOrderKey)
	if p := mustPoint(t, given); isSmallOrderEd25519(given) || inPrimeOrderSubgroup(t, p) {
		t.Fatalf("%s is not a mixed-order key", mixedOrderKey)
	}
	var offCurve []byte
	for y := int64(2); offCurve == nil; y++ {
		enc := encodeLE255(big.NewInt(y), false)
		if _, err := new(edwards25519.Point).SetBytes(enc[:]); err != nil {
			offCurve = enc[:]
		}
	}
	return append(sigEntries,
		ed25519StrictVec{Name: "mixed-order-key", Pub: mixedOrderKey, Why: "on the curve and not small-order, but with a torsion component"},
		ed25519StrictVec{Name: "not-on-curve", Pub: hexEnc(offCurve), Why: "y is canonical but no x satisfies the curve equation"},
	)
}

// mixedOrderX25519 is the Montgomery u-coordinate of mixedOrderKey: a
// canonical X25519 public key on the curve with a torsion component.
func mixedOrderX25519(t testing.TB) []byte {
	t.Helper()
	p := mustPoint(t, hexDec(t, mixedOrderKey))
	if inPrimeOrderSubgroup(t, p) {
		t.Fatal("mixedOrderKey has no torsion component")
	}
	u := p.BytesMontgomery()
	if isNonCanonicalX25519(u) {
		t.Fatalf("%x is not canonical", u)
	}
	return u
}

// mixedOrderRotation is a rotation envelope whose new Ed25519 key is
// mixed-order, A' = A + T with T of order 8, signed by the old key and with
// a newSig that crypto/ed25519 accepts under A': the cofactorless equation
// holds when k = 0 mod 8, so r is ground until it does. Only the key check
// on the new Ed25519 key can refuse it as malformed.
func mixedOrderRotation(t testing.TB, oldSeed, oldPub, x25519Pub []byte) rotationVec {
	t.Helper()
	newSeed := make([]byte, 32)
	if _, err := io.ReadFull(newDRBG("vector-rotation-mixed-new"), newSeed); err != nil {
		t.Fatal(err)
	}
	a, aEnc := ed25519Secret(t, newSeed)
	order8 := mustPoint(t, smallOrderEd25519[4][:])
	mixedPub := new(edwards25519.Point).Add(mustPoint(t, aEnc), order8).Bytes()
	body, err := json.Marshal(RotationBody{
		V: 1, User: "user-1", Seq: 2,
		Old: KeyPair{X25519: B64(x25519Pub), Ed25519: B64(oldPub)},
		New: KeyPair{X25519: B64(x25519Pub), Ed25519: B64(mixedPub)},
	})
	if err != nil {
		t.Fatal(err)
	}
	msg := Enc([]byte(LabelSig), []byte("rotation"), body)
	var newSig []byte
	rnd := newDRBG("vector-rotation-mixed-r")
	for i := 0; newSig == nil; i++ {
		if i == 1000 {
			t.Fatal("no k = 0 mod 8 in 1000 tries")
		}
		r := randomScalar(t, rnd)
		rEnc := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
		if k := challenge(t, rEnc, mixedPub, msg); k.Bytes()[0]&7 == 0 {
			newSig = sigWith(rEnc, r, k, a)
		}
	}
	if !ed25519.Verify(mixedPub, msg, newSig) {
		t.Fatal("newSig fails crypto/ed25519, so it would not isolate the new key check")
	}
	sig, err := Sign(oldSeed, "rotation", body)
	if err != nil {
		t.Fatal(err)
	}
	return rotationVec{
		Name: "mixed-order-new-ed25519", OldSeed: hexEnc(oldSeed), OldPub: hexEnc(oldPub),
		NewSeed: hexEnc(newSeed), NewPub: hexEnc(mixedPub), Signer: "user-1",
		Body: hexEnc(body), Sig: hexEnc(sig), NewSig: hexEnc(newSig),
		Refuse: "the new Ed25519 key has a torsion component; newSig passes the cofactorless equation",
	}
}
