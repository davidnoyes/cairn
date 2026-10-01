package e2e

import (
	"crypto/sha256"
	"encoding/binary"
)

// drbg is a deterministic io.Reader for tests and vector generation: a
// SHA-256 counter mode seeded from a fixed string, so the same seed always
// produces the same byte stream. Production code never uses this; it always
// takes crypto/rand.
type drbg struct {
	seed    []byte
	counter uint64
	buf     []byte
}

func newDRBG(seed string) *drbg {
	return &drbg{seed: []byte(seed)}
}

func (d *drbg) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(d.buf) == 0 {
			h := sha256.New()
			h.Write(d.seed)
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], d.counter)
			h.Write(c[:])
			d.buf = h.Sum(nil)
			d.counter++
		}
		k := copy(p[n:], d.buf)
		d.buf = d.buf[k:]
		n += k
	}
	return n, nil
}
