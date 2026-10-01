package e2e

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEncLayout(t *testing.T) {
	got := Enc([]byte("ab"), []byte("c"))
	var want []byte
	want = append(want, 0, 0, 0, 2)
	want = append(want, 'a', 'b')
	want = append(want, 0, 0, 0, 1)
	want = append(want, 'c')
	if !bytes.Equal(got, want) {
		t.Fatalf("Enc = %x, want %x", got, want)
	}
}

func TestEncEmpty(t *testing.T) {
	if got := Enc(); len(got) != 0 {
		t.Fatalf("Enc() = %x, want empty", got)
	}
}

func TestEncNoCollisionAcrossSplit(t *testing.T) {
	// enc("ab", "c") must differ from enc("a", "bc"): the length prefix
	// is what prevents two field lists from colliding.
	a := Enc([]byte("ab"), []byte("c"))
	b := Enc([]byte("a"), []byte("bc"))
	if bytes.Equal(a, b) {
		t.Fatal("Enc collided across a different split of the same bytes")
	}
}

func TestEncFieldCountDistinguishesEmptyField(t *testing.T) {
	// enc("a", "") must differ from enc("a"): an empty trailing field is
	// still a field.
	a := Enc([]byte("a"), []byte(""))
	b := Enc([]byte("a"))
	if bytes.Equal(a, b) {
		t.Fatal("Enc collided between a trailing empty field and no field")
	}
}

func TestEncLengthPrefixIsBigEndian(t *testing.T) {
	got := Enc(make([]byte, 300))
	if len(got) != 4+300 {
		t.Fatalf("len(got) = %d, want %d", len(got), 4+300)
	}
	if n := binary.BigEndian.Uint32(got[:4]); n != 300 {
		t.Fatalf("length prefix = %d, want 300", n)
	}
}
