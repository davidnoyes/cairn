package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Fuzz tests: any input to a parser must return an error or a value, never
// panic.

func FuzzOpen(f *testing.F) {
	key := testKey("fuzz-open-key")
	fields := [][]byte{[]byte("mk")}
	sealed, err := Seal(newDRBG("fuzz-open-nonce"), key, fields, []byte("plaintext"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed)
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		Open(key, fields, data)
	})
}

func FuzzOpenBlob(f *testing.F) {
	ak := testKey("fuzz-blob-ak")
	ctx := testBlobCtx()
	blob, err := SealBlob(newDRBG("fuzz-blob-salt"), ak, ctx, fillBytes(200000))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(blob)
	f.Add([]byte{})
	f.Add(blob[:blobHeaderSize])
	f.Fuzz(func(t *testing.T, data []byte) {
		OpenBlob(ak, ctx, data)
	})
}

func FuzzUnwrap(f *testing.F) {
	recipientPriv, recipientPub := func() ([]byte, []byte) {
		priv, pub, err := GenerateX25519(newDRBG("fuzz-wrap-recipient"))
		if err != nil {
			f.Fatal(err)
		}
		return priv, pub
	}()
	ctx := testWrapContext(recipientPub)
	wrapped, err := Wrap(newDRBG("fuzz-wrap-eph"), ctx, testKey("fuzz-wrapped-key"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wrapped)
	f.Add([]byte{})
	f.Add(make([]byte, 81))
	f.Fuzz(func(t *testing.T, data []byte) {
		Unwrap(recipientPriv, ctx, data)
	})
}

func FuzzParseRecoveryCode(f *testing.F) {
	_, display, err := NewRecoveryCode(newDRBG("fuzz-recovery"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(display)
	f.Add("")
	f.Add(strings.ToLower(display))
	f.Fuzz(func(t *testing.T, s string) {
		ParseRecoveryCode(s)
	})
}

func FuzzParseAPIKey(f *testing.F) {
	full, _, _, _, err := NewAPIKey(newDRBG("fuzz-apikey"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(full)
	f.Add("")
	f.Add("cairn_")
	f.Fuzz(func(t *testing.T, s string) {
		ParseAPIKey(s)
	})
}

func FuzzEnvelopeJSON(f *testing.F) {
	seed, _, err := GenerateEd25519(newDRBG("fuzz-envelope"))
	if err != nil {
		f.Fatal(err)
	}
	env, err := NewEnvelope(seed, "user-1", "manifest", []byte(`{"v":1}`))
	if err != nil {
		f.Fatal(err)
	}
	b, err := json.Marshal(env)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(b))
	f.Add("")
	f.Add("{}")
	f.Fuzz(func(t *testing.T, s string) {
		var e Envelope
		json.Unmarshal([]byte(s), &e)
	})
}

// FuzzBlobRoundTrip checks a property rather than a fixed corpus: any
// plaintext length seals and reopens to itself, and any truncation of the
// result must fail (truncation always lands on a chunk whose "last chunk"
// flag no longer matches its position).
func FuzzBlobRoundTrip(f *testing.F) {
	ak := testKey("fuzz-blob-roundtrip-ak")
	ctx := testBlobCtx()
	f.Add(byte(0), uint32(0))
	f.Add(byte(1), uint32(1))
	f.Add(byte(200), uint32(3))
	f.Fuzz(func(t *testing.T, lenMultiplier byte, truncateBy uint32) {
		n := int(lenMultiplier) * 800 // up to 255*800, just over 200 KB
		pt := fillBytes(n)
		blob, err := SealBlob(newDRBG(fmt.Sprintf("fuzz-blob-rt-%d", n)), ak, ctx, pt)
		if err != nil {
			t.Fatalf("SealBlob(n=%d): %v", n, err)
		}
		got, err := OpenBlob(ak, ctx, blob)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("round trip failed for n=%d: %v", n, err)
		}
		truncateBy = truncateBy % uint32(len(blob)+1)
		if truncateBy == 0 {
			return
		}
		truncated := blob[:len(blob)-int(truncateBy)]
		if _, err := OpenBlob(ak, ctx, truncated); err == nil {
			t.Fatalf("n=%d truncated by %d bytes: opened without error", n, truncateBy)
		}
	})
}

// FuzzBlobMutation checks that flipping any one bit of a valid multi-chunk
// blob always breaks it.
func FuzzBlobMutation(f *testing.F) {
	ak := testKey("fuzz-blob-mutation-ak")
	ctx := testBlobCtx()
	blob, err := SealBlob(newDRBG("fuzz-blob-mutation-salt"), ak, ctx, fillBytes(2*BlobChunkSize+100))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(0, byte(1))
	f.Fuzz(func(t *testing.T, byteIndex int, bitMask byte) {
		if bitMask == 0 {
			bitMask = 1
		}
		i := ((byteIndex % len(blob)) + len(blob)) % len(blob)
		mutated := append([]byte(nil), blob...)
		mutated[i] ^= bitMask
		if _, err := OpenBlob(ak, ctx, mutated); err == nil {
			t.Fatalf("flipped byte %d mask %#x: opened without error", i, bitMask)
		}
	})
}

// FuzzSealMutation is the same mutation property as FuzzBlobMutation, for
// sealed values.
func FuzzSealMutation(f *testing.F) {
	key := testKey("fuzz-seal-mutation-key")
	fields := [][]byte{[]byte("mk")}
	sealed, err := Seal(newDRBG("fuzz-seal-mutation-nonce"), key, fields, []byte("plaintext for mutation fuzzing"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(0, byte(1))
	f.Fuzz(func(t *testing.T, byteIndex int, bitMask byte) {
		if bitMask == 0 {
			bitMask = 1
		}
		i := ((byteIndex % len(sealed)) + len(sealed)) % len(sealed)
		mutated := append([]byte(nil), sealed...)
		mutated[i] ^= bitMask
		if _, err := Open(key, fields, mutated); err == nil {
			t.Fatalf("flipped byte %d mask %#x: opened without error", i, bitMask)
		}
	})
}

// FuzzWrapMutation is the same mutation property as FuzzBlobMutation, for
// wrapped keys.
func FuzzWrapMutation(f *testing.F) {
	recipientPriv, recipientPub, err := GenerateX25519(newDRBG("fuzz-wrap-mutation-recipient"))
	if err != nil {
		f.Fatal(err)
	}
	ctx := testWrapContext(recipientPub)
	wrapped, err := Wrap(newDRBG("fuzz-wrap-mutation-eph"), ctx, testKey("fuzz-wrap-mutation-key"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(0, byte(1))
	f.Fuzz(func(t *testing.T, byteIndex int, bitMask byte) {
		if bitMask == 0 {
			bitMask = 1
		}
		i := ((byteIndex % len(wrapped)) + len(wrapped)) % len(wrapped)
		mutated := append([]byte(nil), wrapped...)
		mutated[i] ^= bitMask
		if _, err := Unwrap(recipientPriv, ctx, mutated); err == nil {
			t.Fatalf("flipped byte %d mask %#x: opened without error", i, bitMask)
		}
	})
}

// FuzzDecodeStrict must never panic, and whenever it accepts input, the
// round-trip property it relies on (re-marshal and compare as generic JSON)
// must itself still hold.
func FuzzDecodeStrict(f *testing.F) {
	f.Add(`{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef"}`)
	f.Add(`{}`)
	f.Add(``)
	f.Add(`{"v":1,"v":1}`)
	f.Add(`[1,2,3]`)
	f.Add(`{"v":1,"artifact":"a1","version":"v1","Manifest":"x","manifest":"deadbeef"}`)
	f.Fuzz(func(t *testing.T, s string) {
		var out VouchBody
		if err := DecodeStrict([]byte(s), &out); err != nil {
			return
		}
		again, err := json.Marshal(out)
		if err != nil {
			t.Fatalf("re-marshal after an accepted decode: %v", err)
		}
		var a, b any
		if err := json.Unmarshal([]byte(s), &a); err != nil {
			t.Fatalf("accepted input no longer parses as JSON: %v", err)
		}
		if err := json.Unmarshal(again, &b); err != nil {
			t.Fatalf("re-marshalled bytes don't parse as JSON: %v", err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("DecodeStrict accepted %q but its own round-trip check should have rejected it", s)
		}
	})
}

// FuzzParamsJSON must never panic, whether or not the JSON parses, and
// CheckFloor must never panic on whatever UnmarshalJSON accepts.
func FuzzParamsJSON(f *testing.F) {
	f.Add(`{"alg":"argon2id","m":65536,"t":3,"p":1,"salt":"AAAAAAAAAAAAAAAAAAAAAA"}`)
	f.Add(`{}`)
	f.Add(``)
	f.Add(`{"alg":"argon2id","m":-1,"t":3,"p":1,"salt":""}`)
	f.Fuzz(func(t *testing.T, s string) {
		var p Params
		if err := json.Unmarshal([]byte(s), &p); err != nil {
			return
		}
		_ = p.CheckFloor()
	})
}
