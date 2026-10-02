package e2e

import (
	"bytes"
	"errors"
	"testing"
)

// useFastKDF swaps in the stand-in for one test and restores real Argon2id
// afterwards, so the vector tests keep exercising the real thing.
func useFastKDF(t *testing.T) {
	t.Helper()
	real := argon2Key
	UseFastKDFForTests()
	t.Cleanup(func() { argon2Key = real })
}

func TestFastKDFDependsOnEveryInput(t *testing.T) {
	useFastKDF(t)
	pw, salt := []byte("pw"), []byte("salt")
	base := fastKDF(pw, salt, 3, 65536, 1, 32)
	if len(base) != 32 {
		t.Fatalf("len %d, want 32", len(base))
	}
	if !bytes.Equal(base, fastKDF(pw, salt, 3, 65536, 1, 32)) {
		t.Fatal("not deterministic")
	}
	variants := map[string][]byte{
		"password": fastKDF([]byte("pW"), salt, 3, 65536, 1, 32),
		"salt":     fastKDF(pw, []byte("sAlt"), 3, 65536, 1, 32),
		"time":     fastKDF(pw, salt, 4, 65536, 1, 32),
		"memory":   fastKDF(pw, salt, 3, 65537, 1, 32),
		"threads":  fastKDF(pw, salt, 3, 65536, 2, 32),
		"keyLen":   fastKDF(pw, salt, 3, 65536, 1, 33)[:32],
	}
	for name, v := range variants {
		if bytes.Equal(base, v) {
			t.Errorf("output unchanged when %s changes", name)
		}
	}
	if got := len(fastKDF(pw, salt, 3, 65536, 1, 100)); got != 100 {
		t.Fatalf("expanded len %d, want 100", got)
	}
}

func TestStretchUsesFastKDFAndKeepsFloor(t *testing.T) {
	real, err := Stretch([]byte("pw"), "a@example.com", floorParams())
	if err != nil {
		t.Fatal(err)
	}
	useFastKDF(t)
	fast, err := Stretch([]byte("pw"), "a@example.com", floorParams())
	if err != nil {
		t.Fatal(err)
	}
	if len(fast) != 32 || bytes.Equal(fast, real) {
		t.Fatal("Stretch did not go through the stand-in")
	}
	p := floorParams()
	p.Time = floorTime - 1
	if _, err := Stretch([]byte("pw"), "a@example.com", p); !errors.Is(err, ErrFloor) {
		t.Fatalf("below-floor params: err %v, want ErrFloor", err)
	}
}
