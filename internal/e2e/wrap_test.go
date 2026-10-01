package e2e

import (
	"bytes"
	"errors"
	"testing"
)

func testWrapParties(t *testing.T) (recipientPriv, recipientPub []byte) {
	t.Helper()
	priv, pub, err := GenerateX25519(newDRBG("wrap-recipient"))
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func testWrapContext(recipientPub []byte) WrapContext {
	return WrapContext{
		Purpose:      "ak",
		Artifact:     "artifact-1",
		Epoch:        3,
		RecipientID:  "user-1",
		RecipientPub: recipientPub,
	}
}

func TestGenerateX25519KeyLengths(t *testing.T) {
	priv, pub, err := GenerateX25519(newDRBG("gen-x25519"))
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != 32 || len(pub) != 32 {
		t.Fatalf("len(priv)=%d len(pub)=%d, want 32 and 32", len(priv), len(pub))
	}
}

func TestGenerateX25519Deterministic(t *testing.T) {
	priv1, pub1, err := GenerateX25519(newDRBG("gen-x25519-det"))
	if err != nil {
		t.Fatal(err)
	}
	priv2, pub2, err := GenerateX25519(newDRBG("gen-x25519-det"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv1, priv2) || !bytes.Equal(pub1, pub2) {
		t.Fatal("GenerateX25519 not deterministic for the same reader seed")
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	recipientPriv, recipientPub := testWrapParties(t)
	ctx := testWrapContext(recipientPub)
	key := testKey("wrapped-key")
	wrapped, err := Wrap(newDRBG("wrap-eph"), ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) != 81 {
		t.Fatalf("len(wrapped) = %d, want 81 for a 32-byte key", len(wrapped))
	}
	got, err := Unwrap(recipientPriv, ctx, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("Unwrap did not reproduce the wrapped key")
	}
}

func TestWrapUnwrapFlippedBit(t *testing.T) {
	recipientPriv, recipientPub := testWrapParties(t)
	ctx := testWrapContext(recipientPub)
	wrapped, err := Wrap(newDRBG("wrap-eph-2"), ctx, testKey("wrapped-key-2"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range wrapped {
		mutated := append([]byte(nil), wrapped...)
		mutated[i] ^= 0x01
		if _, err := Unwrap(recipientPriv, ctx, mutated); err == nil {
			t.Fatalf("flipped bit at %d: opened without error", i)
		}
	}
}

func TestUnwrapRejectsWrongPrivateKey(t *testing.T) {
	_, recipientPub := testWrapParties(t)
	ctx := testWrapContext(recipientPub)
	wrapped, err := Wrap(newDRBG("wrap-eph-3"), ctx, testKey("wrapped-key-3"))
	if err != nil {
		t.Fatal(err)
	}
	otherPriv, _, err := GenerateX25519(newDRBG("wrap-other"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unwrap(otherPriv, ctx, wrapped); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
}

func TestUnwrapRejectsEachContextFieldChange(t *testing.T) {
	recipientPriv, recipientPub := testWrapParties(t)
	ctx := testWrapContext(recipientPub)
	wrapped, err := Wrap(newDRBG("wrap-eph-4"), ctx, testKey("wrapped-key-4"))
	if err != nil {
		t.Fatal(err)
	}
	otherPriv, otherPub, err := GenerateX25519(newDRBG("wrap-other-2"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unwrap(otherPriv, ctx, wrapped); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong recipient private key: got %v, want ErrDecrypt", err)
	}
	variants := []WrapContext{
		{Purpose: "ek", Artifact: ctx.Artifact, Epoch: ctx.Epoch, RecipientID: ctx.RecipientID, RecipientPub: ctx.RecipientPub},
		{Purpose: ctx.Purpose, Artifact: "artifact-2", Epoch: ctx.Epoch, RecipientID: ctx.RecipientID, RecipientPub: ctx.RecipientPub},
		{Purpose: ctx.Purpose, Artifact: ctx.Artifact, Epoch: ctx.Epoch + 1, RecipientID: ctx.RecipientID, RecipientPub: ctx.RecipientPub},
		{Purpose: ctx.Purpose, Artifact: ctx.Artifact, Epoch: ctx.Epoch, RecipientID: "user-2", RecipientPub: ctx.RecipientPub},
		{Purpose: ctx.Purpose, Artifact: ctx.Artifact, Epoch: ctx.Epoch, RecipientID: ctx.RecipientID, RecipientPub: otherPub},
	}
	for i, v := range variants {
		if _, err := Unwrap(recipientPriv, v, wrapped); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("variant %d (%+v): got %v, want ErrDecrypt", i, v, err)
		}
	}
}

func TestUnwrapRejectsWrongLength(t *testing.T) {
	recipientPriv, recipientPub := testWrapParties(t)
	ctx := testWrapContext(recipientPub)
	for _, n := range []int{0, 1, 32, 48} {
		if _, err := Unwrap(recipientPriv, ctx, make([]byte, n)); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("len=%d: got %v, want ErrDecrypt", n, err)
		}
	}
}

func TestUnwrapRejectsWrongVersionByte(t *testing.T) {
	recipientPriv, recipientPub := testWrapParties(t)
	ctx := testWrapContext(recipientPub)
	wrapped, err := Wrap(newDRBG("wrap-eph-5"), ctx, testKey("wrapped-key-5"))
	if err != nil {
		t.Fatal(err)
	}
	wrapped[0] = 0x02
	if _, err := Unwrap(recipientPriv, ctx, wrapped); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong version byte: got %v, want ErrDecrypt", err)
	}
}

func TestWrapRejectsAllZeroSharedSecret(t *testing.T) {
	// A recipient public key of all zeros is a low-order point: the shared
	// secret comes out all zero for any ephemeral scalar, so Wrap must
	// refuse it rather than seal under a known key.
	ctx := testWrapContext(make([]byte, 32))
	if _, err := Wrap(newDRBG("wrap-eph-6"), ctx, testKey("wrapped-key-6")); !errors.Is(err, ErrFormat) {
		t.Fatalf("got %v, want ErrFormat", err)
	}
}

func TestUnwrapRejectsAllZeroSharedSecret(t *testing.T) {
	recipientPriv, recipientPub := testWrapParties(t)
	ctx := testWrapContext(recipientPub)
	// Hand-craft a wrapped value whose embedded ephemeral public key is the
	// all-zero low-order point, so the shared secret is zero whatever priv
	// is.
	wrapped := make([]byte, wrapSize)
	wrapped[0] = wrapVersion
	if _, err := Unwrap(recipientPriv, ctx, wrapped); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
}

func TestWrapRejectsWrongRecipientPubLength(t *testing.T) {
	ctx := testWrapContext(make([]byte, 16))
	if _, err := Wrap(newDRBG("wrap-eph-7"), ctx, testKey("wrapped-key-7")); !errors.Is(err, ErrFormat) {
		t.Fatalf("got %v, want ErrFormat", err)
	}
}

func TestWrapRejectsWrongKeyLength(t *testing.T) {
	_, recipientPub := testWrapParties(t)
	ctx := testWrapContext(recipientPub)
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := Wrap(newDRBG("wrap-eph-8"), ctx, make([]byte, n)); !errors.Is(err, ErrFormat) {
			t.Errorf("len(key)=%d: got %v, want ErrFormat", n, err)
		}
	}
}

func TestUnwrapRejectsWrongLengthExactly(t *testing.T) {
	recipientPriv, recipientPub := testWrapParties(t)
	ctx := testWrapContext(recipientPub)
	wrapped, err := Wrap(newDRBG("wrap-eph-9"), ctx, testKey("wrapped-key-9"))
	if err != nil {
		t.Fatal(err)
	}
	// One byte longer than the fixed 81-byte wrap size must fail even though
	// the old "at least wrapMinSize" check would have accepted it.
	extended := append(append([]byte(nil), wrapped...), 0x00)
	if _, err := Unwrap(recipientPriv, ctx, extended); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("one byte too long: got %v, want ErrDecrypt", err)
	}
}
