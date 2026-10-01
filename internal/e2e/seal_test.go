package e2e

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func testKey(seed string) []byte {
	k := make([]byte, 32)
	newDRBG(seed).Read(k)
	return k
}

func TestNewGCMRejectsWrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := Seal(newDRBG("seal-badkey"), make([]byte, n), nil, []byte("x")); !errors.Is(err, ErrFormat) {
			t.Errorf("Seal len(key)=%d: got %v, want ErrFormat", n, err)
		}
		if _, err := Open(make([]byte, n), nil, make([]byte, 20)); !errors.Is(err, ErrDecrypt) {
			t.Errorf("Open len(key)=%d: got %v, want ErrDecrypt", n, err)
		}
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := testKey("seal-key")
	fields := [][]byte{[]byte("mk")}
	pt := []byte("plaintext master key material")
	sealed, err := Seal(newDRBG("seal-nonce"), key, fields, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, fields, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("Open = %q, want %q", got, pt)
	}
}

func TestSealOpenEmptyPlaintext(t *testing.T) {
	key := testKey("seal-key-2")
	sealed, err := Seal(newDRBG("seal-nonce-2"), key, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, nil, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("Open = %q, want empty", got)
	}
}

func TestSealVersionByte(t *testing.T) {
	key := testKey("seal-key-3")
	sealed, err := Seal(newDRBG("seal-nonce-3"), key, nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if sealed[0] != 0x01 {
		t.Fatalf("version byte = %#x, want 0x01", sealed[0])
	}
}

func TestOpenRejectsFlippedBit(t *testing.T) {
	key := testKey("seal-key-4")
	sealed, err := Seal(newDRBG("seal-nonce-4"), key, [][]byte{[]byte("f")}, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range sealed {
		mutated := append([]byte(nil), sealed...)
		mutated[i] ^= 0x01
		if _, err := Open(key, [][]byte{[]byte("f")}, mutated); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("flipped bit at %d: got %v, want ErrDecrypt", i, err)
		}
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	sealed, err := Seal(newDRBG("seal-nonce-5"), testKey("seal-key-5"), nil, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(testKey("seal-key-wrong"), nil, sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong key: got %v, want ErrDecrypt", err)
	}
}

func TestOpenRejectsWrongFields(t *testing.T) {
	key := testKey("seal-key-6")
	sealed, err := Seal(newDRBG("seal-nonce-6"), key, [][]byte{[]byte("mk"), []byte("id-1")}, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	cases := [][][]byte{
		nil,
		{[]byte("mk")},
		{[]byte("mk"), []byte("id-2")},
		{[]byte("ek"), []byte("id-1")},
	}
	for _, f := range cases {
		if _, err := Open(key, f, sealed); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("fields %v: got %v, want ErrDecrypt", f, err)
		}
	}
}

func TestOpenRejectsWrongVersionByte(t *testing.T) {
	key := testKey("seal-key-7")
	sealed, err := Seal(newDRBG("seal-nonce-7"), key, nil, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	sealed[0] = 0x02
	if _, err := Open(key, nil, sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong version byte: got %v, want ErrDecrypt", err)
	}
}

func TestOpenRejectsShortInput(t *testing.T) {
	key := testKey("seal-key-8")
	for _, n := range []int{0, 1, 5, 12} {
		if _, err := Open(key, nil, make([]byte, n)); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("len=%d: got %v, want ErrDecrypt", n, err)
		}
	}
}

func TestOpenRejectsTruncation(t *testing.T) {
	key := testKey("seal-key-9")
	sealed, err := Seal(newDRBG("seal-nonce-9"), key, nil, []byte("some secret bytes"))
	if err != nil {
		t.Fatal(err)
	}
	truncated := sealed[:len(sealed)-1]
	if _, err := Open(key, nil, truncated); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("truncated: got %v, want ErrDecrypt", err)
	}
}

func TestOpenRejectsTrailingBytes(t *testing.T) {
	key := testKey("seal-key-10")
	sealed, err := Seal(newDRBG("seal-nonce-10"), key, nil, []byte("some secret bytes"))
	if err != nil {
		t.Fatal(err)
	}
	extended := append(append([]byte(nil), sealed...), 0x00)
	if _, err := Open(key, nil, extended); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("trailing byte: got %v, want ErrDecrypt", err)
	}
}

func TestSealedValueMovedToAnotherKeyFails(t *testing.T) {
	// Sealing the same plaintext under a different key must produce
	// ciphertext that doesn't open under the first key.
	fields := [][]byte{[]byte("mk")}
	pt := []byte("secret")
	sealedA, err := Seal(newDRBG("seal-a"), testKey("key-a"), fields, pt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(testKey("key-b"), fields, sealedA); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
}

func TestMKSealKeyIndexKeyDiffer(t *testing.T) {
	mk := testKey("mk")
	a, err := MKSealKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	b, err := IndexKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("mkSealKey and indexKey must differ")
	}
}

func TestEKSealKeyDeterministic(t *testing.T) {
	ek := testKey("ek")
	a, err := EKSealKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EKSealKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("EKSealKey not deterministic")
	}
}

func TestDerivedKeysRejectWrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		bad := make([]byte, n)
		if _, err := MKSealKey(bad); !errors.Is(err, ErrFormat) {
			t.Errorf("MKSealKey len=%d: got %v, want ErrFormat", n, err)
		}
		if _, err := IndexKey(bad); !errors.Is(err, ErrFormat) {
			t.Errorf("IndexKey len=%d: got %v, want ErrFormat", n, err)
		}
		if _, err := EKSealKey(bad); !errors.Is(err, ErrFormat) {
			t.Errorf("EKSealKey len=%d: got %v, want ErrFormat", n, err)
		}
		if _, err := LinkToken(bad, "artifact-1", 1); !errors.Is(err, ErrFormat) {
			t.Errorf("LinkToken len=%d: got %v, want ErrFormat", n, err)
		}
		if _, err := FileKey(bad, "artifact-1", 1); !errors.Is(err, ErrFormat) {
			t.Errorf("FileKey len=%d: got %v, want ErrFormat", n, err)
		}
	}
}

func TestLinkTokenBoundToArtifactAndEpoch(t *testing.T) {
	ak := testKey("ak")
	a, err := LinkToken(ak, "artifact-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		artifact string
		epoch    uint64
	}{
		{"artifact", "artifact-2", 1},
		{"epoch", "artifact-1", 2},
	}
	for _, c := range cases {
		b, err := LinkToken(ak, c.artifact, c.epoch)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(a, b) {
			t.Fatalf("changing %s did not change linkToken", c.name)
		}
	}
}

func TestFileKeyBoundToArtifactAndEpoch(t *testing.T) {
	ak := testKey("ak-2")
	a, err := FileKey(ak, "artifact-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := FileKey(ak, "artifact-1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("changing epoch did not change fileKey")
	}
}

func TestLinkTokenHashDeterministic(t *testing.T) {
	token := testKey("token")
	hashA := LinkTokenHash(token)
	hashB := LinkTokenHash(append([]byte(nil), token...))
	if hashA != hashB {
		t.Fatal("LinkTokenHash not deterministic")
	}
	if len(hashA) != 64 {
		t.Fatalf("len(hash) = %d, want 64 hex chars", len(hashA))
	}
}

func TestFileAddressBoundToPath(t *testing.T) {
	fk := testKey("filekey")
	a, errA := FileAddress(fk, "/a.txt")
	b, errB := FileAddress(fk, "/b.txt")
	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}
	if a == b {
		t.Fatal("FileAddress ignored the path")
	}
}

func TestAKCommitDeterministic(t *testing.T) {
	ak := testKey("ak-commit")
	a, err := AKCommit(ak, "artifact-1", 3)
	if err != nil {
		t.Fatal(err)
	}
	b, err := AKCommit(ak, "artifact-1", 3)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("AKCommit not deterministic")
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Fatalf("AKCommit is not hex: %v", err)
	}
}

func TestAKCommitDiffersByArtifactAndEpoch(t *testing.T) {
	ak := testKey("ak-commit-2")
	a, err := AKCommit(ak, "artifact-1", 3)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := AKCommit(ak, "artifact-2", 3); err != nil || a == b {
		t.Fatalf("changing artifact did not change AKCommit (err=%v)", err)
	}
	if b, err := AKCommit(ak, "artifact-1", 4); err != nil || a == b {
		t.Fatalf("changing epoch did not change AKCommit (err=%v)", err)
	}
}

func TestAKCommitRejectsWrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := AKCommit(make([]byte, n), "artifact-1", 3); !errors.Is(err, ErrFormat) {
			t.Fatalf("len(ak)=%d: got %v, want ErrFormat", n, err)
		}
	}
}

func TestBlindIndexBoundToTypeAndValue(t *testing.T) {
	ik := testKey("indexkey")
	a, err := BlindIndex(ik, "session", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, typ, value string
	}{
		{"type", "other", "abc123"},
		{"value", "session", "xyz789"},
	}
	for _, c := range cases {
		b, err := BlindIndex(ik, c.typ, c.value)
		if err != nil {
			t.Fatal(err)
		}
		if a == b {
			t.Fatalf("changing %s did not change BlindIndex", c.name)
		}
	}
}
