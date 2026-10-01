package e2e

import (
	"bytes"
	"testing"
)

func TestLabelsDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, l := range Labels() {
		if seen[l] {
			t.Fatalf("label %q appears twice", l)
		}
		seen[l] = true
	}
	if len(seen) == 0 {
		t.Fatal("Labels() returned none")
	}
}

func TestDeriveLength(t *testing.T) {
	k := Derive([]byte("ikm"), nil, LabelAuth)
	if len(k) != 32 {
		t.Fatalf("len(k) = %d, want 32", len(k))
	}
}

func TestDeriveDeterministic(t *testing.T) {
	a := Derive([]byte("ikm"), []byte("salt"), LabelKEK, []byte("f1"))
	b := Derive([]byte("ikm"), []byte("salt"), LabelKEK, []byte("f1"))
	if !bytes.Equal(a, b) {
		t.Fatal("Derive is not deterministic for the same inputs")
	}
}

func TestDeriveDiffersByLabel(t *testing.T) {
	a := Derive([]byte("ikm"), nil, LabelAuth)
	b := Derive([]byte("ikm"), nil, LabelKEK)
	if bytes.Equal(a, b) {
		t.Fatal("Derive produced the same key for two different labels")
	}
}

func TestDeriveDiffersByField(t *testing.T) {
	a := Derive([]byte("ikm"), nil, LabelLinkToken, []byte("artifact-1"), []byte("3"))
	b := Derive([]byte("ikm"), nil, LabelLinkToken, []byte("artifact-2"), []byte("3"))
	if bytes.Equal(a, b) {
		t.Fatal("Derive produced the same key for two different fields")
	}
}

func TestDeriveDiffersByIKM(t *testing.T) {
	a := Derive([]byte("ikm-1"), nil, LabelAuth)
	b := Derive([]byte("ikm-2"), nil, LabelAuth)
	if bytes.Equal(a, b) {
		t.Fatal("Derive produced the same key for two different ikm values")
	}
}

func TestDeriveDiffersBySalt(t *testing.T) {
	a := Derive([]byte("ikm"), []byte("salt-1"), LabelBlob)
	b := Derive([]byte("ikm"), []byte("salt-2"), LabelBlob)
	if bytes.Equal(a, b) {
		t.Fatal("Derive produced the same key for two different salts")
	}
}

func TestLabelsMatchSpecTable(t *testing.T) {
	// The wire-format spec's label table has 16 rows, ending with prelogin.
	if got := len(Labels()); got != 16 {
		t.Fatalf("len(Labels()) = %d, want 16", got)
	}
	if LabelPrelogin != "cairn/v1/prelogin" {
		t.Fatalf("LabelPrelogin = %q", LabelPrelogin)
	}
}
