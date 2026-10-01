package e2e

import (
	"encoding/json"
	"errors"
	"testing"
)

func membershipBody() string {
	return `{"v":1,"artifact":"artifact-1","epoch":3,"owner":"user-1","akCommit":"aa",` +
		`"members":[{"user":"user-1","role":"editor","fp":"bb"}],"team":"none",` +
		`"public":false,"publicWrites":false,"prev":""}`
}

func TestOpenEnvelopeAccepts(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("openenv-ok"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnvelope(seed, "user-1", "membership", []byte(membershipBody()))
	if err != nil {
		t.Fatal(err)
	}
	var out MembershipBody
	if err := OpenEnvelope(env, pub, "membership", &out); err != nil {
		t.Fatalf("OpenEnvelope rejected a valid envelope: %v", err)
	}
	if out.Artifact != "artifact-1" || out.Owner != "user-1" {
		t.Fatalf("decoded body mismatch: %+v", out)
	}
}

func TestOpenEnvelopeRejectsDuplicateKey(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("openenv-dup"))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef","manifest":"beefdead"}`
	env, err := NewEnvelope(seed, "user-1", "vouch", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	var out VouchBody
	if err := OpenEnvelope(env, pub, "vouch", &out); !errors.Is(err, ErrFormat) {
		t.Fatalf("duplicate key: got %v, want ErrFormat", err)
	}
}

func TestOpenEnvelopeRejectsCaseVariantKey(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("openenv-case"))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"v":1,"artifact":"a1","version":"v1","epoch":3,"Files":[],"files":[]}`
	env, err := NewEnvelope(seed, "user-1", "manifest", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	var out ManifestBody
	if err := OpenEnvelope(env, pub, "manifest", &out); !errors.Is(err, ErrFormat) {
		t.Fatalf("case-variant key: got %v, want ErrFormat", err)
	}
}

func TestOpenEnvelopeRejectsUnknownKey(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("openenv-unknown"))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef","extra":"nope"}`
	env, err := NewEnvelope(seed, "user-1", "vouch", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	var out VouchBody
	if err := OpenEnvelope(env, pub, "vouch", &out); !errors.Is(err, ErrFormat) {
		t.Fatalf("unknown key: got %v, want ErrFormat", err)
	}
}

func TestOpenEnvelopeRejectsMissingKey(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("openenv-missing"))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"v":1,"artifact":"a1","version":"v1"}` // vouch also needs "manifest"
	env, err := NewEnvelope(seed, "user-1", "vouch", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	var out VouchBody
	if err := OpenEnvelope(env, pub, "vouch", &out); !errors.Is(err, ErrFormat) {
		t.Fatalf("missing key: got %v, want ErrFormat", err)
	}
}

func TestOpenEnvelopeRejectsTrailingGarbage(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("openenv-trailing"))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef"} garbage`
	env, err := NewEnvelope(seed, "user-1", "vouch", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	var out VouchBody
	if err := OpenEnvelope(env, pub, "vouch", &out); !errors.Is(err, ErrFormat) {
		t.Fatalf("trailing garbage: got %v, want ErrFormat", err)
	}
}

func TestOpenEnvelopeRejectsWrongVersion(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("openenv-v2"))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"v":2,"artifact":"a1","version":"v1","manifest":"deadbeef"}`
	env, err := NewEnvelope(seed, "user-1", "vouch", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	var out VouchBody
	if err := OpenEnvelope(env, pub, "vouch", &out); !errors.Is(err, ErrFormat) {
		t.Fatalf("v=2: got %v, want ErrFormat", err)
	}
}

func TestOpenEnvelopeRejectsWrongPurpose(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("openenv-purpose"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnvelope(seed, "user-1", "vouch", []byte(`{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef"}`))
	if err != nil {
		t.Fatal(err)
	}
	var out VouchBody
	if err := OpenEnvelope(env, pub, "manifest", &out); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong purpose: got %v, want ErrDecrypt", err)
	}
}

func TestOpenEnvelopeRejectsBadSig(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("openenv-badsig"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnvelope(seed, "user-1", "vouch", []byte(`{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef"}`))
	if err != nil {
		t.Fatal(err)
	}
	env.Sig[0] ^= 0x01
	var out VouchBody
	if err := OpenEnvelope(env, pub, "vouch", &out); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("bad sig: got %v, want ErrDecrypt", err)
	}
}

func TestOpenEnvelopeJSONItselfIsStrict(t *testing.T) {
	seed, _, err := GenerateEd25519(newDRBG("openenv-envjson"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnvelope(seed, "user-1", "vouch", []byte(`{"v":1}`))
	if err != nil {
		t.Fatal(err)
	}
	good, err := env.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		string(good[:len(good)-1]) + `,"Body":"AA"}`, // case-variant key
		string(good[:len(good)-1]) + `,"extra":1}`,   // unknown key
		`{"sig":"AA","signer":"user-1"}`,             // missing body
	}
	for _, c := range cases {
		var got Envelope
		if err := got.UnmarshalJSON([]byte(c)); err == nil {
			t.Errorf("UnmarshalJSON(%q) succeeded, want an error", c)
		}
	}
}

func TestOpenRotationRejectsMissingNewSig(t *testing.T) {
	oldSeed, oldPub, err := GenerateEd25519(newDRBG("rotation-missing-old"))
	if err != nil {
		t.Fatal(err)
	}
	_, newPub, err := GenerateEd25519(newDRBG("rotation-missing-new"))
	if err != nil {
		t.Fatal(err)
	}
	_, x25519Pub, err := GenerateX25519(newDRBG("rotation-missing-x25519"))
	if err != nil {
		t.Fatal(err)
	}
	body := RotationBody{
		V: 1, User: "user-1", Seq: 1,
		Old: KeyPair{X25519: B64(x25519Pub), Ed25519: B64(oldPub)},
		New: KeyPair{X25519: B64(x25519Pub), Ed25519: B64(newPub)},
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnvelope(oldSeed, "user-1", "rotation", bodyBytes)
	if err != nil {
		t.Fatal(err)
	}
	// env.NewSig is deliberately left nil: SignRotation was not used.
	var out RotationBody
	if err := OpenRotation(env, oldPub, &out); !errors.Is(err, ErrFormat) {
		t.Fatalf("missing newSig: got %v, want ErrFormat", err)
	}
}

func TestCheckPublicKeysAcceptsGenuineKeys(t *testing.T) {
	_, x25519Pub, err := GenerateX25519(newDRBG("checkpub-x25519"))
	if err != nil {
		t.Fatal(err)
	}
	_, ed25519Pub, err := GenerateEd25519(newDRBG("checkpub-ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPublicKeys(x25519Pub, ed25519Pub); err != nil {
		t.Fatalf("CheckPublicKeys rejected genuine keys: %v", err)
	}
}

func TestCheckPublicKeysRejectsWrongLengths(t *testing.T) {
	_, x25519Pub, err := GenerateX25519(newDRBG("checkpub-len-x"))
	if err != nil {
		t.Fatal(err)
	}
	_, ed25519Pub, err := GenerateEd25519(newDRBG("checkpub-len-e"))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPublicKeys(make([]byte, 31), ed25519Pub); !errors.Is(err, ErrFormat) {
		t.Fatalf("short x25519: got %v, want ErrFormat", err)
	}
	if err := CheckPublicKeys(x25519Pub, make([]byte, 31)); !errors.Is(err, ErrFormat) {
		t.Fatalf("short ed25519: got %v, want ErrFormat", err)
	}
}

func TestCheckPublicKeysRejectsLowOrderX25519(t *testing.T) {
	_, ed25519Pub, err := GenerateEd25519(newDRBG("checkpub-loworder-e"))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPublicKeys(make([]byte, 32), ed25519Pub); !errors.Is(err, ErrFormat) {
		t.Fatalf("all-zero x25519: got %v, want ErrFormat", err)
	}
}

func TestCheckPublicKeysRejectsLowOrderEd25519(t *testing.T) {
	_, x25519Pub, err := GenerateX25519(newDRBG("checkpub-loworder-x"))
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range smallOrderEd25519 {
		if err := CheckPublicKeys(x25519Pub, p[:]); !errors.Is(err, ErrFormat) {
			t.Errorf("small-order ed25519 #%d: got %v, want ErrFormat", i, err)
		}
	}
}

// TestCheckStrictNumber pins the number rule directly: a non-negative integer
// lexeme with no leading zero, no sign, fraction or exponent, at most 2^53-1.
func TestCheckStrictNumber(t *testing.T) {
	for _, ok := range []string{"0", "1", "42", "9007199254740991"} {
		if err := checkStrictNumber(ok); err != nil {
			t.Errorf("checkStrictNumber(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"", "-0", "-1", "+1", "01", "00", "1.0", "1.5", "1e0", "1E0",
		"9007199254740992", "18446744073709551616",
	} {
		if err := checkStrictNumber(bad); !errors.Is(err, ErrFormat) {
			t.Errorf("checkStrictNumber(%q) = %v, want ErrFormat", bad, err)
		}
	}
}

// TestCheckStrictBytesBOM refuses a leading UTF-8 BOM, and only a leading one:
// the same code point inside a string is an ordinary character.
func TestCheckStrictBytesBOM(t *testing.T) {
	bom := "\xEF\xBB\xBF"
	if err := checkStrictBytes([]byte(`{"a":1}`)); err != nil {
		t.Errorf("plain object: %v", err)
	}
	if err := checkStrictBytes([]byte(`{"a":"` + bom + `"}`)); err != nil {
		t.Errorf("U+FEFF inside a string: %v", err)
	}
	if err := checkStrictBytes([]byte(bom + `{"a":1}`)); !errors.Is(err, ErrFormat) {
		t.Errorf("leading BOM: %v, want ErrFormat", err)
	}
}
