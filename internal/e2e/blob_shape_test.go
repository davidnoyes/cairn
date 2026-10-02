package e2e

import (
	"crypto/rand"
	"testing"
)

func TestBlobShape(t *testing.T) {
	ak := make([]byte, 32)
	blob, err := SealBlob(rand.Reader, ak, BlobContext{Artifact: "a", Version: "v", Kind: "content", Name: "x"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != BlobMinSize {
		t.Errorf("an empty plaintext seals to %d bytes, want BlobMinSize %d", len(blob), BlobMinSize)
	}
	if !HasBlobHeader(blob) {
		t.Error("a sealed blob has no blob header")
	}
	for name, b := range map[string][]byte{
		"empty":         nil,
		"magic only":    []byte("CRNB"),
		"wrong magic":   []byte("CRNX\x01"),
		"wrong version": []byte("CRNB\x02"),
	} {
		if HasBlobHeader(b) {
			t.Errorf("%s: HasBlobHeader is true", name)
		}
	}
}
