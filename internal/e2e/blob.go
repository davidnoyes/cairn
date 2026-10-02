package e2e

import (
	"encoding/binary"
	"io"
)

// Blobs are a header followed by STREAM chunks:
//
//	header = "CRNB" ‖ 0x01 ‖ salt(32)                       37 bytes
//	key    = derive(AK, salt, "cairn/v1/blob", artifact, version, kind, name)
//	chunk  = AES-GCM(key, nonce_i, plaintext_i, ad = header)
//	nonce_i = i as 11 bytes big-endian ‖ last-chunk flag (0x01 last, 0x00 not)
//	blob   = header ‖ chunk_0 ‖ … ‖ chunk_(n-1)

const (
	blobMagic      = "CRNB"
	blobVersion    = 0x01
	blobSaltSize   = 32
	blobHeaderSize = len(blobMagic) + 1 + blobSaltSize // 37

	// BlobChunkSize is the plaintext size of every chunk but the last.
	BlobChunkSize = 65536
	blobTagSize   = 16
	// A full (non-last) encrypted chunk: plaintext plus a GCM tag.
	blobFullChunkSize = BlobChunkSize + blobTagSize
)

// BlobContext binds a blob to the artifact, version, kind, and name it
// belongs to, so it cannot be moved to another one.
type BlobContext struct {
	Artifact string
	Version  string
	Kind     string
	Name     string
}

func blobHeader(salt []byte) []byte {
	h := make([]byte, 0, blobHeaderSize)
	h = append(h, blobMagic...)
	h = append(h, blobVersion)
	h = append(h, salt...)
	return h
}

func blobKey(ak []byte, salt []byte, ctx BlobContext) []byte {
	return Derive(ak, salt, LabelBlob, []byte(ctx.Artifact), []byte(ctx.Version), []byte(ctx.Kind), []byte(ctx.Name))
}

// chunkNonce builds the STREAM nonce: an 11-byte big-endian chunk counter
// followed by a 1-byte last-chunk flag.
func chunkNonce(i uint64, last bool) []byte {
	nonce := make([]byte, gcmNonceSize)
	binary.BigEndian.PutUint64(nonce[3:11], i)
	if last {
		nonce[11] = 0x01
	}
	return nonce
}

// SealBlob encrypts pt as a fresh blob under ak and ctx, with a random
// 32-byte salt.
func SealBlob(rnd io.Reader, ak []byte, ctx BlobContext, pt []byte) ([]byte, error) {
	if err := checkKeyLen(ak); err != nil {
		return nil, err
	}
	salt := make([]byte, blobSaltSize)
	if _, err := io.ReadFull(rnd, salt); err != nil {
		return nil, err
	}
	header := blobHeader(salt)
	key := blobKey(ak, salt, ctx)
	defer clear(key) // best-effort zeroing: the AEAD holds its own key schedule
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	n := len(pt)
	chunks := n / BlobChunkSize
	if n%BlobChunkSize != 0 || n == 0 {
		chunks++
	}

	out := make([]byte, 0, len(header)+n+chunks*blobTagSize)
	out = append(out, header...)
	for i := 0; i < chunks; i++ {
		start := i * BlobChunkSize
		end := min(start+BlobChunkSize, n)
		last := i == chunks-1
		out = gcm.Seal(out, chunkNonce(uint64(i), last), pt[start:end], header)
	}
	return out, nil
}

// OpenBlob decrypts a blob sealed with SealBlob, checking the header, the
// context, and every chunk's authentication tag and position.
func OpenBlob(ak []byte, ctx BlobContext, blob []byte) ([]byte, error) {
	if err := checkKeyLen(ak); err != nil {
		return nil, err
	}
	if len(blob) < blobHeaderSize || string(blob[:len(blobMagic)]) != blobMagic || blob[len(blobMagic)] != blobVersion {
		return nil, ErrFormat
	}
	header := blob[:blobHeaderSize]
	salt := blob[len(blobMagic)+1 : blobHeaderSize]
	rest := blob[blobHeaderSize:]
	if len(rest) == 0 {
		// A valid blob always has at least one chunk, even an empty one.
		return nil, ErrDecrypt
	}

	key := blobKey(ak, salt, ctx)
	defer clear(key) // best-effort zeroing, as in SealBlob
	gcm, err := newGCM(key)
	if err != nil {
		return nil, ErrDecrypt
	}

	var out []byte
	for i := uint64(0); len(rest) > 0; i++ {
		last := len(rest) <= blobFullChunkSize
		var chunkCT []byte
		if last {
			chunkCT, rest = rest, nil
		} else {
			chunkCT, rest = rest[:blobFullChunkSize], rest[blobFullChunkSize:]
		}
		pt, err := gcm.Open(nil, chunkNonce(i, last), chunkCT, header)
		if err != nil {
			return nil, ErrDecrypt
		}
		out = append(out, pt...)
	}
	return out, nil
}

// BlobMinSize is the length of the shortest valid blob: the header and one
// empty chunk, which is a tag alone.
const BlobMinSize = blobHeaderSize + blobTagSize

// HasBlobHeader reports whether b starts with the blob magic and version
// byte. It reads no further, so a holder who cannot decrypt can still check a
// blob's shape.
func HasBlobHeader(b []byte) bool {
	return len(b) > len(blobMagic) && string(b[:len(blobMagic)]) == blobMagic && b[len(blobMagic)] == blobVersion
}
