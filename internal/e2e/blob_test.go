package e2e

import (
	"bytes"
	"errors"
	"testing"
)

func testBlobCtx() BlobContext {
	return BlobContext{Artifact: "artifact-1", Version: "version-1", Kind: "content", Name: "index.html"}
}

func fillBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func TestBlobRoundTripSizes(t *testing.T) {
	ak := testKey("blob-ak")
	ctx := testBlobCtx()
	sizes := []int{0, 1, 65535, 65536, 65537, 131072, 131073}
	for _, n := range sizes {
		pt := fillBytes(n)
		blob, err := SealBlob(newDRBG("blob-salt"), ak, ctx, pt)
		if err != nil {
			t.Fatalf("size %d: SealBlob: %v", n, err)
		}
		got, err := OpenBlob(ak, ctx, blob)
		if err != nil {
			t.Fatalf("size %d: OpenBlob: %v", n, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("size %d: round trip mismatch", n)
		}
	}
}

func TestBlobCiphertextLengths(t *testing.T) {
	ak := testKey("blob-ak-len")
	ctx := testBlobCtx()
	cases := []struct {
		n    int
		want int
	}{
		{0, blobHeaderSize + blobTagSize},                   // one empty last chunk
		{1, blobHeaderSize + 1 + blobTagSize},               // one 1-byte last chunk
		{BlobChunkSize, blobHeaderSize + blobFullChunkSize}, // exactly one full chunk, no extra
		{BlobChunkSize + 1, blobHeaderSize + blobFullChunkSize + 1 + blobTagSize},
		{2 * BlobChunkSize, blobHeaderSize + 2*blobFullChunkSize},
	}
	for _, c := range cases {
		blob, err := SealBlob(newDRBG("blob-salt-len"), ak, ctx, fillBytes(c.n))
		if err != nil {
			t.Fatal(err)
		}
		if len(blob) != c.want {
			t.Errorf("size %d: len(blob) = %d, want %d", c.n, len(blob), c.want)
		}
	}
}

func TestBlobHeaderSize(t *testing.T) {
	if blobHeaderSize != 37 {
		t.Fatalf("blobHeaderSize = %d, want 37", blobHeaderSize)
	}
	if blobFullChunkSize != 65552 {
		t.Fatalf("blobFullChunkSize = %d, want 65552", blobFullChunkSize)
	}
}

func TestOpenBlobRejectsFlippedBit(t *testing.T) {
	ak := testKey("blob-ak-flip")
	ctx := testBlobCtx()
	blob, err := SealBlob(newDRBG("blob-salt-flip"), ak, ctx, []byte("hello, world"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range blob {
		mutated := append([]byte(nil), blob...)
		mutated[i] ^= 0x01
		if _, err := OpenBlob(ak, ctx, mutated); err == nil {
			t.Fatalf("flipped bit at %d: opened without error", i)
		}
	}
}

func TestOpenBlobRejectsWrongKey(t *testing.T) {
	ctx := testBlobCtx()
	blob, err := SealBlob(newDRBG("blob-salt-wrongkey"), testKey("blob-ak-a"), ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBlob(testKey("blob-ak-b"), ctx, blob); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
}

func TestOpenBlobRejectsEachContextFieldChange(t *testing.T) {
	ak := testKey("blob-ak-ctx")
	ctx := testBlobCtx()
	blob, err := SealBlob(newDRBG("blob-salt-ctx"), ak, ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	variants := []BlobContext{
		{Artifact: "other", Version: ctx.Version, Kind: ctx.Kind, Name: ctx.Name},
		{Artifact: ctx.Artifact, Version: "other", Kind: ctx.Kind, Name: ctx.Name},
		{Artifact: ctx.Artifact, Version: ctx.Version, Kind: "other", Name: ctx.Name},
		{Artifact: ctx.Artifact, Version: ctx.Version, Kind: ctx.Kind, Name: "other"},
	}
	for i, v := range variants {
		if _, err := OpenBlob(ak, v, blob); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("variant %d (%+v): got %v, want ErrDecrypt", i, v, err)
		}
	}
}

func TestOpenBlobRejectsTruncationAtChunkBoundary(t *testing.T) {
	ak := testKey("blob-ak-trunc")
	ctx := testBlobCtx()
	// Two full chunks plus a short last chunk.
	pt := fillBytes(2*BlobChunkSize + 100)
	blob, err := SealBlob(newDRBG("blob-salt-trunc"), ak, ctx, pt)
	if err != nil {
		t.Fatal(err)
	}
	// Drop the last chunk entirely: the new final chunk was sealed as not
	// last, so it must fail even though it sits on a chunk boundary.
	truncated := blob[:blobHeaderSize+2*blobFullChunkSize]
	if _, err := OpenBlob(ak, ctx, truncated); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("truncated at chunk boundary: got %v, want ErrDecrypt", err)
	}
}

func TestOpenBlobRejectsDroppedChunk(t *testing.T) {
	ak := testKey("blob-ak-drop")
	ctx := testBlobCtx()
	pt := fillBytes(2*BlobChunkSize + 100)
	blob, err := SealBlob(newDRBG("blob-salt-drop"), ak, ctx, pt)
	if err != nil {
		t.Fatal(err)
	}
	// Drop the middle chunk (index 1), keeping chunk 0 and the last chunk.
	chunk0End := blobHeaderSize + blobFullChunkSize
	chunk1End := chunk0End + blobFullChunkSize
	dropped := append(append([]byte(nil), blob[:chunk0End]...), blob[chunk1End:]...)
	if _, err := OpenBlob(ak, ctx, dropped); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("dropped chunk: got %v, want ErrDecrypt", err)
	}
}

func TestOpenBlobRejectsReorderedChunks(t *testing.T) {
	ak := testKey("blob-ak-reorder")
	ctx := testBlobCtx()
	pt := fillBytes(2 * BlobChunkSize)
	blob, err := SealBlob(newDRBG("blob-salt-reorder"), ak, ctx, pt)
	if err != nil {
		t.Fatal(err)
	}
	chunk0End := blobHeaderSize + blobFullChunkSize
	chunk1End := chunk0End + blobFullChunkSize
	header := blob[:blobHeaderSize]
	chunk0 := blob[blobHeaderSize:chunk0End]
	chunk1 := blob[chunk0End:chunk1End]
	reordered := append(append(append([]byte(nil), header...), chunk1...), chunk0...)
	if _, err := OpenBlob(ak, ctx, reordered); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("reordered chunks: got %v, want ErrDecrypt", err)
	}
}

func TestOpenBlobRejectsChangedHeader(t *testing.T) {
	ak := testKey("blob-ak-header")
	ctx := testBlobCtx()
	blob, err := SealBlob(newDRBG("blob-salt-header"), ak, ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), blob...)
	mutated[len(blobMagic)+1] ^= 0x01 // flip a salt byte
	if _, err := OpenBlob(ak, ctx, mutated); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("changed header: got %v, want ErrDecrypt", err)
	}
}

func TestOpenBlobRejectsWrongMagic(t *testing.T) {
	ak := testKey("blob-ak-magic")
	ctx := testBlobCtx()
	blob, err := SealBlob(newDRBG("blob-salt-magic"), ak, ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), blob...)
	mutated[0] = 'X'
	if _, err := OpenBlob(ak, ctx, mutated); !errors.Is(err, ErrFormat) {
		t.Fatalf("wrong magic: got %v, want ErrFormat", err)
	}
}

func TestOpenBlobRejectsWrongVersionByte(t *testing.T) {
	ak := testKey("blob-ak-ver")
	ctx := testBlobCtx()
	blob, err := SealBlob(newDRBG("blob-salt-ver"), ak, ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), blob...)
	mutated[len(blobMagic)] = 0x02
	if _, err := OpenBlob(ak, ctx, mutated); !errors.Is(err, ErrFormat) {
		t.Fatalf("wrong version byte: got %v, want ErrFormat", err)
	}
}

func TestOpenBlobRejectsShortInput(t *testing.T) {
	ak := testKey("blob-ak-short")
	ctx := testBlobCtx()
	for _, n := range []int{0, 1, 10, 36} {
		if _, err := OpenBlob(ak, ctx, make([]byte, n)); !errors.Is(err, ErrFormat) {
			t.Fatalf("len=%d: got %v, want ErrFormat", n, err)
		}
	}
}

func TestOpenBlobRejectsHeaderOnly(t *testing.T) {
	ak := testKey("blob-ak-headeronly")
	ctx := testBlobCtx()
	blob, err := SealBlob(newDRBG("blob-salt-headeronly"), ak, ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	headerOnly := blob[:blobHeaderSize]
	if _, err := OpenBlob(ak, ctx, headerOnly); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("header only (no chunks): got %v, want ErrDecrypt", err)
	}
}

func TestOpenBlobRejectsAppendedEmptyChunk(t *testing.T) {
	ak := testKey("blob-ak-appended")
	ctx := testBlobCtx()
	blob, err := SealBlob(newDRBG("blob-salt-appended"), ak, ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// An extra, independently-sealed empty "chunk" appended after the real
	// last chunk must not be accepted as part of the stream.
	appended := append(append([]byte(nil), blob...), make([]byte, blobTagSize)...)
	if _, err := OpenBlob(ak, ctx, appended); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("appended empty chunk: got %v, want ErrDecrypt", err)
	}
}

func TestOpenBlobRejectsTrailingBytes(t *testing.T) {
	ak := testKey("blob-ak-trailing")
	ctx := testBlobCtx()
	blob, err := SealBlob(newDRBG("blob-salt-trailing"), ak, ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	extended := append(append([]byte(nil), blob...), 0x00)
	if _, err := OpenBlob(ak, ctx, extended); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("trailing byte: got %v, want ErrDecrypt", err)
	}
}

func TestSealBlobFreshSaltPerWrite(t *testing.T) {
	ak := testKey("blob-ak-fresh")
	ctx := testBlobCtx()
	a, err := SealBlob(newDRBG("blob-salt-fresh-a"), ak, ctx, []byte("same content"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealBlob(newDRBG("blob-salt-fresh-b"), ak, ctx, []byte("same content"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two writes of the same content produced identical ciphertext")
	}
}
