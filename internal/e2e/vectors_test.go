package e2e

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vectors.json is the cross-language fixture: Go generates it from a seeded
// random source, and a Go test and a Node test each check every entry. The
// schema is documented in testdata/README.md. Every byte value is hex.

var updateVectors = flag.Bool("update", false, "regenerate testdata/vectors.json")

func hexEnc(b []byte) string { return hex.EncodeToString(b) }

// nonZeroTrailingBitsChar returns a base32 character other than avoid whose
// value's low 2 bits are non-zero, for building a recovery-code negative
// whose otherwise-valid encoding carries meaning in bits ParseRecoveryCode
// must treat as padding.
func nonZeroTrailingBitsChar(avoid byte) string {
	if avoid != 'C' {
		return "C" // value 2: low 2 bits are 10
	}
	return "D" // value 3: low 2 bits are 11
}

// edwards25519Order is L, the prime order of the Ed25519 base point, fixed
// by RFC 8032: 2^252 + 27742317777372353535851937790883648493.
var edwards25519Order = func() *big.Int {
	l := new(big.Int).Lsh(big.NewInt(1), 252)
	delta, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	return l.Add(l, delta)
}()

// nonCanonicalS returns sig with its S half (the last 32 bytes, a
// little-endian integer) replaced by S+L: still congruent to S mod L, so it
// signs the same thing under any verifier that only checks mod L, but no
// longer a value a strict RFC 8032 verifier accepts.
func nonCanonicalS(sig []byte) []byte {
	s := new(big.Int).SetBytes(reverse(sig[32:64]))
	s.Add(s, edwards25519Order)
	out := append([]byte(nil), sig[:32]...)
	sBytes := s.FillBytes(make([]byte, 32))
	return append(out, reverse(sBytes)...)
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[len(b)-1-i] = c
	}
	return out
}

// encodeLE255 encodes y (which must be less than 2^255) little-endian into
// 32 bytes, with the sign/high bit set according to sign. Used to build
// Ed25519 and X25519 public-key encodings directly from their y/u
// coordinate instead of transcribing hex by hand.
func encodeLE255(y *big.Int, sign bool) [32]byte {
	var out [32]byte
	b := y.Bytes() // big-endian
	for i, c := range b {
		out[len(b)-1-i] = c
	}
	if sign {
		out[31] |= 0x80
	}
	return out
}

// nonCanonicalEd25519 returns the known non-canonical Ed25519 public-key
// encodings a lenient decoder still accepts: the identity and the order-4
// point encoded with y >= p (still < 2^255, so still decodable by reducing
// mod p), and the identity, order-2, and y+p-identity points encoded with
// the sign bit set despite x=0 forcing it to 0. isSmallOrderEd25519 rejects
// every one of these structurally (see sign.go); they're built here only so
// vectors.json carries them all as explicit negatives.
func nonCanonicalEd25519() [][32]byte {
	one := big.NewInt(1)
	zero := big.NewInt(0)
	pPlus1 := new(big.Int).Add(edwards25519P, one)
	pPlusZero := new(big.Int).Add(edwards25519P, zero)
	return [][32]byte{
		encodeLE255(pPlus1, false),             // y = p+1 (≡1, identity), sign 0
		encodeLE255(pPlusZero, false),          // y = p   (≡0, order-4), sign 0
		encodeLE255(pPlusZero, true),           // y = p   (≡0, order-4), sign 1
		encodeLE255(one, true),                 // y = 1   (identity),    sign 1
		encodeLE255(edwards25519PMinus1, true), // y = p-1 (order-2),     sign 1
		encodeLE255(pPlus1, true),              // y = p+1 (≡1, identity), sign 1
	}
}

// mutateBase64TrailingBits returns encoded with its last character replaced
// by the next character in the base64url alphabet, which — because a
// canonical encoding's last character in a partial group always has its
// unused low bits zero — always introduces non-zero trailing bits without
// changing the string's length or alphabet.
func mutateBase64TrailingBits(t testing.TB, encoded string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if len(encoded) == 0 {
		t.Fatal("mutateBase64TrailingBits: empty input")
	}
	last := encoded[len(encoded)-1]
	idx := strings.IndexByte(alphabet, last)
	if idx == -1 {
		t.Fatalf("mutateBase64TrailingBits: %q not in the base64url alphabet", string(last))
	}
	return encoded[:len(encoded)-1] + string(alphabet[(idx+1)%64])
}

// applyBlobCtxOverride returns base with whichever fields ov names replaced.
func applyBlobCtxOverride(t testing.TB, base BlobContext, ov map[string]any) BlobContext {
	t.Helper()
	out := base
	if v, ok := ov["artifact"]; ok {
		out.Artifact = v.(string)
	}
	if v, ok := ov["version"]; ok {
		out.Version = v.(string)
	}
	if v, ok := ov["kind"]; ok {
		out.Kind = v.(string)
	}
	if v, ok := ov["name"]; ok {
		out.Name = v.(string)
	}
	return out
}

// applyWrapCtxOverride returns base with whichever fields ov names replaced.
func applyWrapCtxOverride(t testing.TB, base WrapContext, ov map[string]any) WrapContext {
	t.Helper()
	out := base
	if v, ok := ov["purpose"]; ok {
		out.Purpose = v.(string)
	}
	if v, ok := ov["artifact"]; ok {
		out.Artifact = v.(string)
	}
	if v, ok := ov["epoch"]; ok {
		out.Epoch = v.(uint64)
	}
	if v, ok := ov["recipientId"]; ok {
		out.RecipientID = v.(string)
	}
	return out
}

// splitBlobChunks splits a blob's post-header bytes into chunks using the
// same rule OpenBlob does: full blobFullChunkSize chunks while more than
// that remains, the rest as the last chunk.
func splitBlobChunks(rest []byte) [][]byte {
	var chunks [][]byte
	for len(rest) > 0 {
		if len(rest) <= blobFullChunkSize {
			chunks = append(chunks, rest)
			rest = nil
		} else {
			chunks = append(chunks, rest[:blobFullChunkSize])
			rest = rest[blobFullChunkSize:]
		}
	}
	return chunks
}

// applyBlobTransform mutates a valid blob's bytes per the schema documented
// in testdata/README.md, without ever producing a blob OpenBlob would
// accept.
func applyBlobTransform(t testing.TB, blob []byte, tr transform) []byte {
	t.Helper()
	header := blob[:blobHeaderSize]
	chunks := splitBlobChunks(blob[blobHeaderSize:])
	switch tr.Op {
	case "truncate":
		k := tr.Chunks.(int)
		if k > len(chunks) {
			k = len(chunks)
		}
		chunks = chunks[:k]
	case "drop":
		i := tr.Chunk
		chunks = append(append([][]byte{}, chunks[:i]...), chunks[i+1:]...)
	case "swap":
		idx := tr.Chunks.([]int)
		chunks[idx[0]], chunks[idx[1]] = chunks[idx[1]], chunks[idx[0]]
	case "append":
		chunks = append(chunks, hexDec(t, tr.Bytes))
	case "flip":
		out := append(append([]byte{}, header...), bytes.Join(chunks, nil)...)
		out[tr.Offset] ^= 0x01
		return out
	default:
		t.Fatalf("unknown blob transform op %q", tr.Op)
	}
	return append(append([]byte{}, header...), bytes.Join(chunks, nil)...)
}

func hexDec(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// negative is the one schema every primitive's negative cases use: a reason,
// plus whichever overrides apply to that primitive. Every field the positive
// entry already has keeps its value; only the fields named here change, and
// the operation must then fail. See testdata/README.md for which overrides
// each primitive reads.
type negative struct {
	Why       string           `json:"why"`
	Input     string           `json:"input,omitempty"`     // replaces ciphertext, display string, or JSON text
	Ctx       map[string]any   `json:"ctx,omitempty"`       // merged over the positive entry's ctx
	Key       string           `json:"key,omitempty"`       // hex, replaces the key used to open/verify
	Fields    []string         `json:"fields,omitempty"`    // hex, replaces seal's AD fields
	Purpose   string           `json:"purpose,omitempty"`   // replaces a signature's purpose
	Pub       string           `json:"pub,omitempty"`       // hex, replaces a signature's public key
	Params    *argon2ParamsVec `json:"params,omitempty"`    // a complete, standalone Argon2id params object
	NewSig    string           `json:"newSig,omitempty"`    // hex, replaces a rotation envelope's newSig
	Transform *transform       `json:"transform,omitempty"` // applied to want, instead of a literal input
}

// transform mutates a blob's want bytes without storing a second literal
// copy of a large ciphertext. Chunks is an int for "truncate" and a []int
// for "swap"; which one applies depends on Op.
type transform struct {
	Op     string `json:"op"`
	Chunks any    `json:"chunks,omitempty"`
	Chunk  int    `json:"chunk,omitempty"`
	Bytes  string `json:"bytes,omitempty"`
	Offset int    `json:"offset,omitempty"`
}

type vectorFile struct {
	Enc           []encVec           `json:"enc"`
	Derive        []deriveVec        `json:"derive"`
	Argon2        []argon2Vec        `json:"argon2"`
	RecoveryCode  []recoveryVec      `json:"recoveryCode"`
	APIKey        []apiKeyVec        `json:"apiKey"`
	AKCommit      []akCommitVec      `json:"akCommit"`
	Seal          []sealVec          `json:"seal"`
	Blob          []blobVec          `json:"blob"`
	Wrap          []wrapVec          `json:"wrap"`
	Signature     []sigVec           `json:"signature"`
	Rotation      []rotationVec      `json:"rotation"`
	Ed25519Strict []ed25519StrictVec `json:"ed25519Strict"`
	X25519Strict  []x25519StrictVec  `json:"x25519Strict"`
	Fingerprint   []fingerprintVec   `json:"fingerprint"`
	LinkToken     []linkTokenVec     `json:"linkToken"`
	FileAddress   []fileAddressVec   `json:"fileAddress"`
	BlindIndex    []blindIndexVec    `json:"blindIndex"`
	StrictJSON    []strictJSONVec    `json:"strictJSON"`
	Envelope      []envelopeVec      `json:"envelope"`
	Base64URL     []base64Vec        `json:"base64url"`
	Chain         []chainVec         `json:"chain"`
	Approval      []approvalVec      `json:"approval"`
	Keyring       []keyringVec       `json:"keyring"`
}

type encVec struct {
	Name   string   `json:"name"`
	Fields []string `json:"fields"`
	Want   string   `json:"want"`
}

type deriveVec struct {
	Label  string   `json:"label"`
	IKM    string   `json:"ikm"`
	Salt   string   `json:"salt"`
	Fields []string `json:"fields"`
	Want   string   `json:"want"`
}

type argon2ParamsVec struct {
	Alg     string `json:"alg"`
	Memory  uint32 `json:"m"`
	Time    uint32 `json:"t"`
	Threads uint8  `json:"p"`
	Salt    string `json:"salt"`
}

type argon2Vec struct {
	Name      string          `json:"name"`
	Password  string          `json:"password"`
	Email     string          `json:"email"`
	Params    argon2ParamsVec `json:"params"`
	ArgonSalt string          `json:"argonSalt"`
	Stretched string          `json:"stretched"`
	AuthKey   string          `json:"authKey"`
	Kek       string          `json:"kek"`
	Negative  []negative      `json:"negative"`
}

type recoveryVec struct {
	Name     string     `json:"name"`
	Code     string     `json:"code"`
	Display  string     `json:"display"`
	Variants []string   `json:"variants"`
	Kek      string     `json:"kek"`
	Negative []negative `json:"negative"`
}

type apiKeyVec struct {
	Name       string     `json:"name"`
	Full       string     `json:"full"`
	KeyID      string     `json:"keyId"`
	AuthSecret string     `json:"authSecret"`
	KeySecret  string     `json:"keySecret"`
	Kek        string     `json:"kek"`
	AuthHash   string     `json:"authHash"`
	Negative   []negative `json:"negative"`
}

type akCommitVec struct {
	Name     string `json:"name"`
	Ak       string `json:"ak"`
	Artifact string `json:"artifact"`
	Epoch    uint64 `json:"epoch"`
	Want     string `json:"want"`
}

type rotationVec struct {
	Name     string     `json:"name"`
	OldSeed  string     `json:"oldSeed"`
	OldPub   string     `json:"oldPub"`
	NewSeed  string     `json:"newSeed"`
	NewPub   string     `json:"newPub"`
	Signer   string     `json:"signer"`
	Body     string     `json:"body"`
	Sig      string     `json:"sig"`
	NewSig   string     `json:"newSig"`
	Negative []negative `json:"negative"`
	// Refuse, when set, says why the entry as a whole must be refused as
	// malformed (ErrFormat, FormatError) even though both signatures verify.
	Refuse string `json:"refuse,omitempty"`
}

// ed25519StrictVec covers two different rejections under one name: a
// small-order public key (Purpose/Body/Sig empty, since the key alone must
// fail), and a genuine key with a non-canonical signature (Purpose, Body,
// and Sig all set).
type ed25519StrictVec struct {
	Name    string `json:"name"`
	Pub     string `json:"pub"`
	Purpose string `json:"purpose,omitempty"`
	Body    string `json:"body,omitempty"`
	Sig     string `json:"sig,omitempty"`
	Why     string `json:"why"`
}

// x25519StrictVec is an X25519 public key CheckPublicKeys must refuse on its
// own: non-canonical (high bit set, or u >= p) or low-order.
type x25519StrictVec struct {
	Name   string `json:"name"`
	Pub    string `json:"pub"`
	Accept bool   `json:"accept,omitempty"`
	Why    string `json:"why"`
}

// strictJSONVec is a raw body or envelope byte string DecodeStrict must
// refuse: Body is hex, since some entries are invalid UTF-8 and can't be
// written as a JSON string literal. Purpose names which BODY_SCHEMAS entry
// (Go: which body struct) to decode Body against.
type strictJSONVec struct {
	Name    string `json:"name"`
	Purpose string `json:"purpose"`
	Body    string `json:"body"`
	Why     string `json:"why"`
}

// base64Vec checks UnB64/unb64 both accept the canonical encoding of Bytes
// and refuse every Negative variant: a non-URL character, padding, or
// non-zero trailing bits in a partial group.
type base64Vec struct {
	Name     string     `json:"name"`
	Bytes    string     `json:"bytes"`
	Encoded  string     `json:"encoded"`
	Negative []negative `json:"negative"`
}

type sealVec struct {
	Name     string     `json:"name"`
	Key      string     `json:"key"`
	Fields   []string   `json:"fields"`
	Nonce    string     `json:"nonce"`
	Pt       string     `json:"pt"`
	Want     string     `json:"want"`
	Negative []negative `json:"negative"`
}

type blobCtxVec struct {
	Artifact string `json:"artifact"`
	Version  string `json:"version"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
}

// ptRule generates a large plaintext without storing it literally: byte i is
// i mod 251. Used only above a few KiB, to keep vectors.json small.
type ptRule struct {
	Rule string `json:"rule"`
	Len  int    `json:"len"`
}

type blobVec struct {
	Name     string     `json:"name"`
	Ak       string     `json:"ak"`
	Ctx      blobCtxVec `json:"ctx"`
	Salt     string     `json:"salt"`
	Pt       string     `json:"pt,omitempty"`
	PtRule   *ptRule    `json:"ptRule,omitempty"`
	Want     string     `json:"want"`
	Negative []negative `json:"negative,omitempty"`
}

type wrapCtxVec struct {
	Purpose      string `json:"purpose"`
	Artifact     string `json:"artifact"`
	Epoch        uint64 `json:"epoch"`
	RecipientID  string `json:"recipientId"`
	RecipientPub string `json:"recipientPub"`
}

type wrapVec struct {
	Name          string     `json:"name"`
	Ctx           wrapCtxVec `json:"ctx"`
	RecipientPriv string     `json:"recipientPriv"`
	EphPriv       string     `json:"ephPriv"`
	Key           string     `json:"key"`
	Want          string     `json:"want"`
	Negative      []negative `json:"negative"`
}

type sigVec struct {
	Name     string     `json:"name"`
	Purpose  string     `json:"purpose"`
	Seed     string     `json:"seed"`
	Pub      string     `json:"pub"`
	Body     string     `json:"body"`
	Signer   string     `json:"signer"`
	Want     string     `json:"want"`
	Negative []negative `json:"negative"`
}

type fingerprintVec struct {
	Name       string `json:"name"`
	X25519Pub  string `json:"x25519Pub"`
	Ed25519Pub string `json:"ed25519Pub"`
	Want       string `json:"want"`
	Display    string `json:"display"`
}

type linkTokenVec struct {
	Name     string `json:"name"`
	Ak       string `json:"ak"`
	Artifact string `json:"artifact"`
	Epoch    uint64 `json:"epoch"`
	Want     string `json:"want"`
	Hash     string `json:"hash"`
}

// fileAddressVec and blindIndexVec carry negatives whose key override is a
// wrong-length key: FileAddress/fileAddress and BlindIndex/blindIndex must
// refuse it (ErrFormat/FormatError) rather than MAC under it.
type fileAddressVec struct {
	Name     string     `json:"name"`
	FileKey  string     `json:"fileKey"`
	Path     string     `json:"path"`
	Want     string     `json:"want"`
	Negative []negative `json:"negative"`
}

type blindIndexVec struct {
	Name     string     `json:"name"`
	IndexKey string     `json:"indexKey"`
	Type     string     `json:"type"`
	Value    string     `json:"value"`
	Want     string     `json:"want"`
	Negative []negative `json:"negative"`
}

// nonCanonicalEphWrapped wraps key to the recipient under the ephemeral
// public key spelled as ephPub, a non-canonical encoding of canonicalU: the
// shared secret comes from canonicalU, and the wrap key binds the ephPub
// bytes exactly as sent, so only a canonical-encoding check on ephPub can
// refuse the result.
func nonCanonicalEphWrapped(t testing.TB, recipientPriv []byte, ctx WrapContext, key, ephPub, canonicalU []byte) string {
	t.Helper()
	if !isNonCanonicalX25519(ephPub) {
		t.Fatalf("%x is a canonical X25519 encoding", ephPub)
	}
	shared, zero := x25519Shared(recipientPriv, canonicalU)
	if zero {
		t.Fatal("all-zero shared secret")
	}
	gcm, err := newGCM(wrapKey(shared, ctx, ephPub))
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte{wrapVersion}, ephPub...)
	return hexEnc(gcm.Seal(out, make([]byte, gcmNonceSize), key, nil))
}

// wrongKeyLenNegatives overrides the key with one too short or too long.
func wrongKeyLenNegatives() []negative {
	var out []negative
	for _, n := range []int{16, 31, 33} {
		out = append(out, negative{Why: fmt.Sprintf("%d-byte key", n), Key: hexEnc(fillBytes(n))})
	}
	return out
}

func vectorsPath() string {
	return filepath.Join("testdata", "vectors.json")
}

// generateVectors builds the full vector file deterministically.
func generateVectors(t testing.TB) vectorFile {
	t.Helper()
	var vf vectorFile

	// enc
	vf.Enc = []encVec{
		{Name: "two-fields", Fields: []string{hexEnc([]byte("ab")), hexEnc([]byte("c"))}, Want: hexEnc(Enc([]byte("ab"), []byte("c")))},
		{Name: "empty", Fields: nil, Want: hexEnc(Enc())},
		{Name: "empty-field", Fields: []string{hexEnc([]byte("a")), hexEnc([]byte(""))}, Want: hexEnc(Enc([]byte("a"), []byte("")))},
	}

	// derive: one entry per label, with sample ikm/salt/fields
	ikm := []byte("sample-input-key-material-32byte")
	salt := []byte("sample-salt-16-b")
	fieldsByLabel := map[string][][]byte{
		LabelAuth:        nil,
		LabelKEK:         nil,
		LabelRecovery:    nil,
		LabelAPIKey:      {[]byte("deadbeefcafebabe")},
		LabelMKSeal:      nil,
		LabelIndex:       nil,
		LabelEKSeal:      nil,
		LabelLinkToken:   {[]byte("artifact-1"), []byte("3")},
		LabelFileKey:     {[]byte("artifact-1"), []byte("3")},
		LabelBlob:        {[]byte("artifact-1"), []byte("v1"), []byte("content"), []byte("index.html")},
		LabelWrap:        {[]byte("ak"), []byte("artifact-1"), []byte("3"), []byte("user-1"), bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)},
		LabelSeal:        {[]byte("mk")},
		LabelSig:         {[]byte("manifest"), []byte("body-bytes")},
		LabelFingerprint: {bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32)},
		LabelBlind:       {[]byte("session"), []byte("abc123")},
		LabelAKCommit:    {[]byte("artifact-1"), []byte("3")},
		LabelSalt:        {[]byte("ada@example.com"), bytes.Repeat([]byte{5}, 16)},
	}
	for _, label := range Labels() {
		fields := fieldsByLabel[label]
		var fieldHex []string
		for _, f := range fields {
			fieldHex = append(fieldHex, hexEnc(f))
		}
		want := Derive(ikm, salt, label, fields...)
		vf.Derive = append(vf.Derive, deriveVec{
			Label: label, IKM: hexEnc(ikm), Salt: hexEnc(salt), Fields: fieldHex, Want: hexEnc(want),
		})
	}

	// argon2 at floor. Every negative carries a complete, standalone params
	// object (its own salt too), not a partial override merged over the
	// positive one, so each case is self-contained.
	{
		password := []byte("correct horse battery staple")
		email := "  Alice@Example.COM "
		p := Params{Alg: "argon2id", Memory: floorMemory, Time: floorTime, Threads: 1, Salt: make([]byte, 16)}
		newDRBG("vector-argon2-salt").Read(p.Salt)
		stretched, err := Stretch(password, email, p)
		if err != nil {
			t.Fatal(err)
		}
		authKey, kek := PasswordKeys(stretched)
		complete := func(alg string, m, tm uint32, pl uint8, saltLen int) *argon2ParamsVec {
			s := make([]byte, saltLen)
			newDRBG("vector-argon2-negative-salt").Read(s)
			return &argon2ParamsVec{Alg: alg, Memory: m, Time: tm, Threads: pl, Salt: hexEnc(s)}
		}
		vf.Argon2 = []argon2Vec{{
			Name:     "floor",
			Password: hexEnc(password),
			Email:    email,
			Params: argon2ParamsVec{
				Alg: p.Alg, Memory: p.Memory, Time: p.Time, Threads: p.Threads, Salt: hexEnc(p.Salt),
			},
			ArgonSalt: hexEnc(ArgonSalt(email, p.Salt)),
			Stretched: hexEnc(stretched),
			AuthKey:   hexEnc(authKey),
			Kek:       hexEnc(kek),
			Negative: []negative{
				{Why: "memory one below the floor", Params: complete("argon2id", floorMemory-1, floorTime, 1, 16)},
				{Why: "time one below the floor", Params: complete("argon2id", floorMemory, floorTime-1, 1, 16)},
				{Why: "wrong algorithm", Params: complete("argon2i", floorMemory, floorTime, 1, 16)},
				{Why: "threads zero", Params: complete("argon2id", floorMemory, floorTime, 0, 16)},
				{Why: "threads above range", Params: complete("argon2id", floorMemory, floorTime, 5, 16)},
				{Why: "salt one byte below the floor", Params: complete("argon2id", floorMemory, floorTime, 1, 15)},
				{Why: "salt one byte above the ceiling", Params: complete("argon2id", floorMemory, floorTime, 1, 65)},
				{Why: "memory one above the ceiling", Params: complete("argon2id", ceilingMemory+1, floorTime, 1, 16)},
				{Why: "time one above the ceiling", Params: complete("argon2id", floorMemory, ceilingTime+1, 1, 16)},
			},
		}}
	}

	// akCommit
	{
		ak := testKey("vector-akcommit-ak")
		commit, err := AKCommit(ak, "artifact-1", 3)
		if err != nil {
			t.Fatal(err)
		}
		vf.AKCommit = []akCommitVec{{
			Name: "sample", Ak: hexEnc(ak), Artifact: "artifact-1", Epoch: 3, Want: commit,
		}}
	}

	// recovery code
	{
		code, display, err := NewRecoveryCode(newDRBG("vector-recovery"))
		if err != nil {
			t.Fatal(err)
		}
		kek := RecoveryKEK(code)
		vf.RecoveryCode = []recoveryVec{{
			Name:    "sample",
			Code:    hexEnc(code),
			Display: display,
			Variants: []string{
				strings.ToLower(display),
				strings.ReplaceAll(display, "-", " "),
				strings.ToLower(strings.ReplaceAll(display, "-", " ")),
			},
			Kek: hexEnc(kek),
			Negative: []negative{
				{Why: "too short", Input: display[:len(display)-5]},
				{Why: "invalid character", Input: "!" + display[1:]},
				{Why: "empty", Input: ""},
				{Why: "non-ASCII letter (long s)", Input: "ſ" + display[1:]},
				{Why: "non-ASCII letter (dotless i)", Input: "ı" + display[1:]},
				{Why: "disallowed digit 0", Input: "0" + display[1:]},
				{Why: "disallowed digit 1", Input: "1" + display[1:]},
				{Why: "disallowed digit 8", Input: "8" + display[1:]},
				{Why: "non-zero trailing bits", Input: display[:len(display)-1] + nonZeroTrailingBitsChar(display[len(display)-1])},
			},
		}}
	}

	// API key
	{
		full, keyID, authSecret, keySecret, err := NewAPIKey(newDRBG("vector-apikey"))
		if err != nil {
			t.Fatal(err)
		}
		kek := APIKeyKEK(keySecret, keyID)
		vf.APIKey = []apiKeyVec{{
			Name: "sample", Full: full, KeyID: keyID, AuthSecret: authSecret, KeySecret: hexEnc(keySecret), Kek: hexEnc(kek),
			AuthHash: APIKeyAuthHash(authSecret),
			Negative: []negative{
				{Why: "missing prefix", Input: strings.TrimPrefix(full, "cairn_")},
				{Why: "wrong number of parts", Input: full + "_extra"},
				{Why: "empty", Input: ""},
				{Why: "uppercase hex", Input: "cairn_" + strings.ToUpper(strings.TrimPrefix(full, "cairn_"))},
			},
		}}
	}

	// seal: one entry per row of the spec's sealed-value table
	sealCases := []struct {
		name   string
		key    []byte
		fields [][]byte
		pt     []byte
	}{
		{"mk-under-password", testKey("vec-kek"), [][]byte{[]byte("mk")}, []byte("master-key-material-32-bytes!!!!")},
		{"mk-under-recovery", testKey("vec-recovery-kek"), [][]byte{[]byte("mk")}, []byte("master-key-material-32-bytes!!!!")},
		{"mk-under-apikey", testKey("vec-apikey-kek"), [][]byte{[]byte("mk"), []byte("keyid-abc123")}, []byte("master-key-material-32-bytes!!!!")},
		{"x25519-private", testKey("vec-mkseal"), [][]byte{[]byte("x25519")}, bytes.Repeat([]byte{7}, 32)},
		{"ed25519-seed", testKey("vec-mkseal"), [][]byte{[]byte("ed25519")}, bytes.Repeat([]byte{8}, 32)},
		{"ek", testKey("vec-mkseal"), [][]byte{[]byte("ek")}, bytes.Repeat([]byte{9}, 32)},
		{"keyring", testKey("vec-mkseal"), [][]byte{[]byte("keyring")}, []byte(`{"pins":[]}`)},
		{"ak-estate-copy", testKey("vec-ekseal"), [][]byte{[]byte("estate"), []byte("artifact-1"), []byte("3")}, bytes.Repeat([]byte{10}, 32)},
	}
	for _, c := range sealCases {
		seed := newDRBG("vector-seal-" + c.name)
		sealed, err := Seal(seed, c.key, c.fields, c.pt)
		if err != nil {
			t.Fatal(err)
		}
		var fieldHex []string
		for _, f := range c.fields {
			fieldHex = append(fieldHex, hexEnc(f))
		}
		flipped := append([]byte(nil), sealed...)
		flipped[len(flipped)-1] ^= 0x01
		vf.Seal = append(vf.Seal, sealVec{
			Name: c.name, Key: hexEnc(c.key), Fields: fieldHex, Nonce: hexEnc(sealed[1:13]), Pt: hexEnc(c.pt), Want: hexEnc(sealed),
			Negative: []negative{
				{Why: "flipped last bit", Input: hexEnc(flipped)},
				{Why: "wrong key", Key: hexEnc(testKey("vector-seal-wrong-key"))},
				{Why: "wrong fields", Fields: append(append([]string{}, fieldHex...), hexEnc([]byte("extra-field")))},
			},
		})
	}

	// blobs
	blobCases := []struct {
		name      string
		n         int
		negatives []negative
	}{
		{"size-0", 0, []negative{
			{Why: "flipped bit in the only chunk", Transform: &transform{Op: "flip", Offset: blobHeaderSize}},
			{Why: "truncated to header only", Transform: &transform{Op: "truncate", Chunks: 0}},
		}},
		{"size-1", 1, nil},
		{"size-65535", 65535, nil},
		{"size-65536", 65536, nil},
		{"size-65537", 65537, nil},
		// Two full chunks plus a short tail: exercises drop/swap/truncate at
		// a real chunk boundary.
		{"size-two-chunks-plus-tail", 2*BlobChunkSize + 1000, []negative{
			{Why: "truncated after one chunk", Transform: &transform{Op: "truncate", Chunks: 1}},
			{Why: "truncated after two chunks", Transform: &transform{Op: "truncate", Chunks: 2}},
			{Why: "dropped chunk 1", Transform: &transform{Op: "drop", Chunk: 1}},
			{Why: "swapped chunks 0 and 1", Transform: &transform{Op: "swap", Chunks: []int{0, 1}}},
			{Why: "appended an extra chunk", Transform: &transform{Op: "append", Bytes: hexEnc(make([]byte, blobTagSize+16))}},
			{Why: "flipped a salt byte", Transform: &transform{Op: "flip", Offset: 5}},
			{Why: "flipped the magic", Transform: &transform{Op: "flip", Offset: 0}},
			{Why: "wrong artifact", Ctx: map[string]any{"artifact": "other-artifact"}},
			{Why: "wrong version", Ctx: map[string]any{"version": "other-version"}},
			{Why: "wrong kind", Ctx: map[string]any{"kind": "other-kind"}},
			{Why: "wrong name", Ctx: map[string]any{"name": "other-name"}},
		}},
		// An exact multiple of the chunk size: no short tail chunk at all.
		{"size-exact-multiple", 131072, []negative{
			{Why: "truncated after one chunk", Transform: &transform{Op: "truncate", Chunks: 1}},
		}},
		{"size-204800", 204800, nil},
	}
	ak := testKey("vector-blob-ak")
	ctx := BlobContext{Artifact: "artifact-1", Version: "version-1", Kind: "content", Name: "index.html"}
	ctxVec := blobCtxVec(ctx)
	// Keep vectors.json small: only sizes up to one chunk carry a literal
	// plaintext; above that a ptRule stands in. Literal plaintext up to and
	// including one full chunk is kept so the exact chunk-boundary byte
	// counts are pinned at least once.
	const literalPtLimit = BlobChunkSize
	for _, c := range blobCases {
		pt := fillBytes(c.n)
		blob, err := SealBlob(newDRBG("vector-blob-"+c.name), ak, ctx, pt)
		if err != nil {
			t.Fatal(err)
		}
		v := blobVec{
			Name: c.name, Ak: hexEnc(ak), Ctx: ctxVec, Salt: hexEnc(blob[len(blobMagic)+1 : blobHeaderSize]),
			Want: hexEnc(blob), Negative: c.negatives,
		}
		if c.n > literalPtLimit {
			v.PtRule = &ptRule{Rule: "i mod 251", Len: c.n}
		} else {
			v.Pt = hexEnc(pt)
		}
		vf.Blob = append(vf.Blob, v)
	}

	// wrap. The two low-order ephemeral public keys are the Curve25519
	// all-zero u-coordinate and a u-coordinate of order 8, computed from the
	// birational map u=(1+y)/(1-y) over the Ed25519 small-order points in
	// sign.go and confirmed separately: any clamped X25519 scalar times a
	// point of order dividing 8 yields the all-zero shared secret, which
	// crypto/ecdh and curve25519.X25519 both refuse.
	order8EphPub, err := hex.DecodeString("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")
	if err != nil {
		t.Fatal(err)
	}
	// Two non-canonical spellings of a genuine ephemeral key: one with the
	// high bit set, and the base point u = 9 spelled as p+9. X25519 reduces
	// both to the canonical u, so each wrap below decrypts unless Unwrap
	// refuses the spelling itself.
	basePointU := make([]byte, 32)
	basePointU[0] = 9
	basePointPlusP := encodeLE255(new(big.Int).Add(edwards25519P, big.NewInt(9)), false)
	lowOrderWrapped := func(ephPub []byte) string {
		b := make([]byte, wrapSize)
		b[0] = wrapVersion
		copy(b[1:1+wrapPubSize], ephPub)
		return hexEnc(b)
	}
	for _, purpose := range []string{"ak", "ek"} {
		recipientPriv, recipientPub, err := GenerateX25519(newDRBG("vector-wrap-recipient-" + purpose))
		if err != nil {
			t.Fatal(err)
		}
		wctx := WrapContext{Purpose: purpose, Artifact: "artifact-1", Epoch: 3, RecipientID: "user-1", RecipientPub: recipientPub}
		if purpose == "ek" {
			wctx.Artifact = "user-owner-1"
			wctx.Epoch = 0
		}
		key := testKey("vector-wrap-key-" + purpose)
		rnd := newDRBG("vector-wrap-eph-" + purpose)
		wrapped, err := Wrap(rnd, wctx, key)
		if err != nil {
			t.Fatal(err)
		}
		ephPriv, _, err := GenerateX25519(newDRBG("vector-wrap-eph-" + purpose))
		if err != nil {
			t.Fatal(err)
		}
		otherRecipientPriv, _, err := GenerateX25519(newDRBG("vector-wrap-other-recipient-" + purpose))
		if err != nil {
			t.Fatal(err)
		}
		otherPurpose := "ek"
		if purpose == "ek" {
			otherPurpose = "ak"
		}
		mutated := append([]byte(nil), wrapped...)
		mutated[len(mutated)-1] ^= 0x01
		highBitEph := append([]byte(nil), wrapped[1:1+wrapPubSize]...)
		highBitEph[31] |= 0x80
		vf.Wrap = append(vf.Wrap, wrapVec{
			Name: purpose,
			Ctx: wrapCtxVec{
				Purpose: wctx.Purpose, Artifact: wctx.Artifact, Epoch: wctx.Epoch,
				RecipientID: wctx.RecipientID, RecipientPub: hexEnc(wctx.RecipientPub),
			},
			RecipientPriv: hexEnc(recipientPriv),
			EphPriv:       hexEnc(ephPriv),
			Key:           hexEnc(key),
			Want:          hexEnc(wrapped),
			Negative: []negative{
				{Why: "flipped last bit", Input: hexEnc(mutated)},
				{Why: "wrong purpose", Ctx: map[string]any{"purpose": otherPurpose}},
				{Why: "wrong artifact", Ctx: map[string]any{"artifact": wctx.Artifact + "-other"}},
				{Why: "wrong epoch", Ctx: map[string]any{"epoch": wctx.Epoch + 1}},
				{Why: "wrong recipientId", Ctx: map[string]any{"recipientId": wctx.RecipientID + "-other"}},
				{Why: "wrong recipient private key", Key: hexEnc(otherRecipientPriv)},
				{Why: "all-zero ephemeral public key", Input: lowOrderWrapped(make([]byte, 32))},
				{Why: "order-8 ephemeral public key", Input: lowOrderWrapped(order8EphPub)},
				{Why: "ephemeral public key with the high bit set", Input: nonCanonicalEphWrapped(t, recipientPriv, wctx, key, highBitEph, wrapped[1:1+wrapPubSize])},
				{Why: "ephemeral public key u = p+9, the base point", Input: nonCanonicalEphWrapped(t, recipientPriv, wctx, key, basePointPlusP[:], basePointU)},
			},
		})
	}

	// signatures: one per purpose in the spec's table
	sigSeed, sigPub, err := GenerateEd25519(newDRBG("vector-sig-key"))
	if err != nil {
		t.Fatal(err)
	}
	fullFP := hexEnc(bytes.Repeat([]byte{0xaa}, 32))
	sigCases := []struct {
		purpose string
		body    string
	}{
		{"membership", `{"v":1,"artifact":"artifact-1","epoch":3,"seq":1,"owner":"user-1","ownerFp":"` + fullFP + `","akCommit":"` + fullFP + `","members":[{"user":"user-1","role":"editor","fp":"` + fullFP + `"}],"excluded":[{"user":"user-2","fp":"` + fullFP + `","email":"user2@example.com"}],"team":"none","public":false,"publicWrites":false,"prev":"","transfer":"","handover":""}`},
		{"transfer", `{"v":1,"artifact":"artifact-1","from":"user-1","to":"user-2","toFp":"` + fullFP + `","prev":"` + fullFP + `"}`},
		{"approval", `{"v":1,"artifact":"artifact-1","epoch":3,"user":"user-2","fp":"` + fullFP + `"}`},
		{"manifest", `{"v":1,"artifact":"artifact-1","version":"version-1","epoch":3,"files":[{"path":"index.html","blob":"blob-1","size":12,"sha256":"deadbeef"}]}`},
		{"revision", `{"v":1,"artifact":"artifact-1","version":"version-1","revision":4,"epoch":3,"sha256":"deadbeef"}`},
		{"vouch", `{"v":1,"artifact":"artifact-1","version":"version-1","manifest":"deadbeef"}`},
		{"successor", `{"v":1,"user":"user-1","seq":2,"successor":"user-2","successorFp":"` + fullFP + `","action":"nominate"}`},
		{"reset", `{"v":1,"user":"user-1","token":"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"}`},
		{"record", `{"v":1,"artifact":"artifact-1","version":"version-1","kind":"file","name":"path/to/file","epoch":3,"sha256":"deadbeef"}`},
	}
	_, otherPub, err := GenerateEd25519(newDRBG("vector-sig-other-key"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range sigCases {
		body := []byte(c.body)
		sig, err := Sign(sigSeed, c.purpose, body)
		if err != nil {
			t.Fatal(err)
		}
		otherPurpose := "manifest"
		if c.purpose == "manifest" {
			otherPurpose = "revision"
		}
		vf.Signature = append(vf.Signature, sigVec{
			Name: c.purpose, Purpose: c.purpose, Seed: hexEnc(sigSeed), Pub: hexEnc(sigPub), Body: hexEnc(body), Signer: "user-1", Want: hexEnc(sig),
			Negative: []negative{
				{Why: "wrong purpose", Purpose: otherPurpose},
				{Why: "wrong pub", Pub: hexEnc(otherPub)},
			},
		})
	}

	// rotation: signed by the old key, and the same body signed again
	// (Envelope.NewSig) by the new key. The "missing newSig" negative is
	// exercised directly in envelope_test.go instead of through this file,
	// since the schema's newSig override has no way to say "absent" as
	// opposed to "not overridden".
	{
		oldSeed, oldPub, err := GenerateEd25519(newDRBG("vector-rotation-old"))
		if err != nil {
			t.Fatal(err)
		}
		newSeed, newPub, err := GenerateEd25519(newDRBG("vector-rotation-new"))
		if err != nil {
			t.Fatal(err)
		}
		_, x25519Pub, err := GenerateX25519(newDRBG("vector-rotation-x25519"))
		if err != nil {
			t.Fatal(err)
		}
		body := RotationBody{
			V: 1, User: "user-1", Seq: 2,
			Old: KeyPair{X25519: B64(x25519Pub), Ed25519: B64(oldPub)},
			New: KeyPair{X25519: B64(x25519Pub), Ed25519: B64(newPub)},
		}
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		env, err := SignRotation(oldSeed, newSeed, bodyBytes, "user-1")
		if err != nil {
			t.Fatal(err)
		}
		wrongSeed, _, err := GenerateEd25519(newDRBG("vector-rotation-wrong"))
		if err != nil {
			t.Fatal(err)
		}
		wrongNewSig, err := Sign(wrongSeed, "rotation", bodyBytes)
		if err != nil {
			t.Fatal(err)
		}
		vf.Rotation = []rotationVec{{
			Name: "sample", OldSeed: hexEnc(oldSeed), OldPub: hexEnc(oldPub),
			NewSeed: hexEnc(newSeed), NewPub: hexEnc(newPub), Signer: "user-1",
			Body: hexEnc(bodyBytes), Sig: hexEnc(env.Sig), NewSig: hexEnc(env.NewSig),
			Negative: []negative{
				{Why: "newSig by a wrong key", NewSig: hexEnc(wrongNewSig)},
			},
		}}

		// Both signatures valid, but the new X25519 key is the all-zero
		// low-order point: only the key check can refuse it.
		body.New.X25519 = B64(make([]byte, 32))
		badBody, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		badEnv, err := SignRotation(oldSeed, newSeed, badBody, "user-1")
		if err != nil {
			t.Fatal(err)
		}
		vf.Rotation = append(vf.Rotation, rotationVec{
			Name: "low-order-new-x25519", OldSeed: hexEnc(oldSeed), OldPub: hexEnc(oldPub),
			NewSeed: hexEnc(newSeed), NewPub: hexEnc(newPub), Signer: "user-1",
			Body: hexEnc(badBody), Sig: hexEnc(badEnv.Sig), NewSig: hexEnc(badEnv.NewSig),
			Refuse: "the new X25519 key is low-order; both signatures are valid",
		})
		vf.Rotation = append(vf.Rotation, mixedOrderRotation(t, oldSeed, oldPub, x25519Pub))
	}

	// ed25519Strict: every hardcoded small-order public key, plus every known
	// non-canonical encoding of one, must fail CheckPublicKeys and Verify,
	// and a genuine signature with its S component replaced by S+L (still
	// congruent mod L, so a cofactored or otherwise non-strict verifier might
	// accept it) must fail too.
	allBadEd25519 := append(append([][32]byte{}, smallOrderEd25519...), nonCanonicalEd25519()...)
	for i, p := range allBadEd25519 {
		vf.Ed25519Strict = append(vf.Ed25519Strict, ed25519StrictVec{
			Name: fmt.Sprintf("small-order-%d", i), Pub: hexEnc(p[:]), Why: "small-order or non-canonical Ed25519 public key",
		})
	}
	{
		strictSeed, strictPub, err := GenerateEd25519(newDRBG("vector-ed25519-strict-s"))
		if err != nil {
			t.Fatal(err)
		}
		body := []byte("body for non-canonical S test")
		sig, err := Sign(strictSeed, "manifest", body)
		if err != nil {
			t.Fatal(err)
		}
		nonCanonical := nonCanonicalS(sig)
		vf.Ed25519Strict = append(vf.Ed25519Strict, ed25519StrictVec{
			Name: "non-canonical-s", Pub: hexEnc(strictPub), Purpose: "manifest", Body: hexEnc(body),
			Sig: hexEnc(nonCanonical), Why: "non-canonical S (S + L)",
		})
	}
	vf.Ed25519Strict = append(vf.Ed25519Strict, ed25519StrictTorsionVectors(t)...)

	// x25519Strict: a non-canonical (high bit set, or u >= p) or low-order
	// X25519 public key must fail CheckPublicKeys on its own.
	{
		_, genuinePub, err := GenerateX25519(newDRBG("vector-x25519-strict-genuine"))
		if err != nil {
			t.Fatal(err)
		}
		highBitSet := append([]byte(nil), genuinePub...)
		highBitSet[31] |= 0x80
		uEqualsP := encodeLE255(edwards25519P, false)
		uAboveP := encodeLE255(new(big.Int).Add(edwards25519P, big.NewInt(5)), false)
		vf.X25519Strict = []x25519StrictVec{
			{Name: "high-bit-set", Pub: hexEnc(highBitSet), Why: "the high bit of the last byte is set"},
			{Name: "u-equals-p", Pub: hexEnc(uEqualsP[:]), Why: "u equals the field prime (non-canonical encoding of 0)"},
			{Name: "u-above-p", Pub: hexEnc(uAboveP[:]), Why: "u is a few values above the field prime, high bit clear"},
			{Name: "low-order-order8", Pub: hexEnc(order8EphPub), Why: "a low-order point reaching the X25519 branch directly"},
			{Name: "mixed-order", Pub: hexEnc(mixedOrderX25519(t)), Accept: true, Why: "canonical, with a torsion component: the clamped scalar is a multiple of the cofactor, so no torsion check applies"},
		}
	}

	// strictJSON: a raw body or envelope byte string DecodeStrict/decodeStrict
	// must refuse. Body is hex, since some entries are invalid UTF-8 and some
	// (the escaped duplicate key) rely on the exact raw escape spelling.
	{
		invalidUTF8Body := append([]byte(`{"v":1,"artifact":"a1","version":"v1","manifest":"`), 0xff)
		invalidUTF8Body = append(invalidUTF8Body, []byte(`"}`)...)
		bomBody := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"v":1,"artifact":"a1","version":"v1","manifest":"m"}`)...)
		vf.StrictJSON = []strictJSONVec{
			{
				Name: "escaped-duplicate-key", Purpose: "vouch", Why: "duplicate key, one spelled with a unicode escape",
				Body: hexEnc([]byte(`{"v":1,"artifact":"a1","version":"v1","manifest":"m","ma` + "\\u006e" + `ifest":"x"}`)),
			},
			{
				Name: "number-fraction", Purpose: "revision", Why: "number has a fraction",
				Body: hexEnc([]byte(`{"v":1,"artifact":"a1","version":"v1","revision":1.0,"epoch":3,"sha256":"deadbeef"}`)),
			},
			{
				Name: "number-exponent", Purpose: "revision", Why: "number has an exponent",
				Body: hexEnc([]byte(`{"v":1,"artifact":"a1","version":"v1","revision":1e0,"epoch":3,"sha256":"deadbeef"}`)),
			},
			{
				Name: "number-fraction-nonzero", Purpose: "revision", Why: "number has a nonzero fraction",
				Body: hexEnc([]byte(`{"v":1,"artifact":"a1","version":"v1","revision":1.5,"epoch":3,"sha256":"deadbeef"}`)),
			},
			{
				Name: "number-negative", Purpose: "revision", Why: "number is negative",
				Body: hexEnc([]byte(`{"v":1,"artifact":"a1","version":"v1","revision":-1,"epoch":3,"sha256":"deadbeef"}`)),
			},
			{
				Name: "number-too-large", Purpose: "revision", Why: "number exceeds 2^53-1",
				Body: hexEnc([]byte(`{"v":1,"artifact":"a1","version":"v1","revision":9007199254740993,"epoch":3,"sha256":"deadbeef"}`)),
			},
			{
				Name: "invalid-utf8", Purpose: "vouch", Why: "invalid UTF-8 byte in a string",
				Body: hexEnc(invalidUTF8Body),
			},
			{
				Name: "utf8-bom", Purpose: "vouch", Why: "a UTF-8 BOM before the JSON value",
				Body: hexEnc(bomBody),
			},
			{
				Name: "unpaired-surrogate", Purpose: "vouch", Why: "an unpaired UTF-16 surrogate escape",
				Body: hexEnc([]byte(`{"v":1,"artifact":"a1","version":"v1","manifest":"` + `\ud800` + `"}`)),
			},
			{
				Name: "lone-low-surrogate", Purpose: "vouch", Why: "a low surrogate escape with no high surrogate before it",
				Body: hexEnc([]byte(`{"v":1,"artifact":"a1","version":"v1","manifest":"` + `\udc00` + `"}`)),
			},
			{
				Name: "high-surrogate-then-char", Purpose: "vouch", Why: "a high surrogate escape followed by a plain character",
				Body: hexEnc([]byte(`{"v":1,"artifact":"a1","version":"v1","manifest":"` + `\ud800A` + `"}`)),
			},
			{
				Name: "high-surrogate-twice", Purpose: "vouch", Why: "a high surrogate escape followed by another high surrogate escape",
				Body: hexEnc([]byte(`{"v":1,"artifact":"a1","version":"v1","manifest":"` + `\ud800\ud800` + `"}`)),
			},
		}
	}

	// base64url: strict decoding accepts only the URL-safe alphabet, no
	// padding, zero padding bits in a partial group, and no whitespace at all
	// (Go's decoder silently skips CR and LF unless told not to); see
	// UnB64/unb64. len-4 gives a full group plus a partial one, so an
	// embedded line break can sit between them.
	for _, n := range []int{1, 2, 4} {
		b := fillBytes(n)
		encoded := B64(b)
		mid := len(encoded) / 2
		vf.Base64URL = append(vf.Base64URL, base64Vec{
			Name: fmt.Sprintf("len-%d", n), Bytes: hexEnc(b), Encoded: encoded,
			Negative: []negative{
				{Why: "non-zero trailing bits", Input: mutateBase64TrailingBits(t, encoded)},
				{Why: "contains a plus sign", Input: "+" + encoded[1:]},
				{Why: "contains a slash", Input: "/" + encoded[1:]},
				{Why: "padded with equals", Input: encoded + "="},
				{Why: "leading line feed", Input: "\n" + encoded},
				{Why: "trailing line feed", Input: encoded + "\n"},
				{Why: "embedded line feed", Input: encoded[:mid] + "\n" + encoded[mid:]},
				{Why: "embedded carriage return and line feed", Input: encoded[:mid] + "\r\n" + encoded[mid:]},
				{Why: "trailing carriage return", Input: encoded + "\r"},
			},
		})
	}

	// fingerprint
	{
		x25519Pub := bytes.Repeat([]byte{0xAB}, 32)
		ed25519Pub := bytes.Repeat([]byte{0xCD}, 32)
		fp := Fingerprint(x25519Pub, ed25519Pub)
		vf.Fingerprint = []fingerprintVec{{
			Name: "sample", X25519Pub: hexEnc(x25519Pub), Ed25519Pub: hexEnc(ed25519Pub), Want: hexEnc(fp), Display: FormatFingerprint(fp),
		}}
	}

	// linkToken
	{
		lak := testKey("vector-linktoken-ak")
		token, err := LinkToken(lak, "artifact-1", 3)
		if err != nil {
			t.Fatal(err)
		}
		vf.LinkToken = []linkTokenVec{{
			Name: "sample", Ak: hexEnc(lak), Artifact: "artifact-1", Epoch: 3, Want: hexEnc(token), Hash: LinkTokenHash(token),
		}}
	}

	// fileAddress
	{
		fk := testKey("vector-filekey")
		want, err := FileAddress(fk, "/images/logo.png")
		if err != nil {
			t.Fatal(err)
		}
		vf.FileAddress = []fileAddressVec{{
			Name: "sample", FileKey: hexEnc(fk), Path: "/images/logo.png", Want: want,
			Negative: wrongKeyLenNegatives(),
		}}
	}

	// blindIndex
	{
		ik := testKey("vector-indexkey")
		want, err := BlindIndex(ik, "session", "abc123")
		if err != nil {
			t.Fatal(err)
		}
		vf.BlindIndex = []blindIndexVec{{
			Name: "sample", IndexKey: hexEnc(ik), Type: "session", Value: "abc123", Want: want,
			Negative: wrongKeyLenNegatives(),
		}}
	}

	vf.Envelope = envelopeVectors()
	vf.Chain = chainVectors(t)
	vf.Approval = approvalVectors(t)
	vf.Keyring = keyringVectors(t)

	return vf
}

func TestVectors(t *testing.T) {
	vf := generateVectors(t)
	got, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	path := vectorsPath()
	if *updateVectors {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(got))
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run with -update to generate it)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: regenerated output differs from the file; run with -update", path)
	}

	checkVectors(t, vf)
}

// checkVectors independently verifies every entry in vf: decrypts, verifies,
// and re-derives, and confirms every negative case fails.
func checkVectors(t *testing.T, vf vectorFile) {
	t.Run("enc", func(t *testing.T) {
		for _, v := range vf.Enc {
			var fields [][]byte
			for _, f := range v.Fields {
				fields = append(fields, hexDec(t, f))
			}
			if got := hexEnc(Enc(fields...)); got != v.Want {
				t.Errorf("%s: Enc = %s, want %s", v.Name, got, v.Want)
			}
		}
	})

	t.Run("derive", func(t *testing.T) {
		for _, v := range vf.Derive {
			var fields [][]byte
			for _, f := range v.Fields {
				fields = append(fields, hexDec(t, f))
			}
			got := Derive(hexDec(t, v.IKM), hexDec(t, v.Salt), v.Label, fields...)
			if hexEnc(got) != v.Want {
				t.Errorf("label %s: Derive mismatch", v.Label)
			}
		}
	})

	t.Run("argon2", func(t *testing.T) {
		for _, v := range vf.Argon2 {
			p := Params{Alg: v.Params.Alg, Memory: v.Params.Memory, Time: v.Params.Time, Threads: v.Params.Threads, Salt: hexDec(t, v.Params.Salt)}
			if hexEnc(ArgonSalt(v.Email, p.Salt)) != v.ArgonSalt {
				t.Errorf("%s: ArgonSalt mismatch", v.Name)
			}
			stretched, err := Stretch(hexDec(t, v.Password), v.Email, p)
			if err != nil {
				t.Fatalf("%s: Stretch: %v", v.Name, err)
			}
			if hexEnc(stretched) != v.Stretched {
				t.Errorf("%s: stretched mismatch", v.Name)
			}
			authKey, kek := PasswordKeys(stretched)
			if hexEnc(authKey) != v.AuthKey || hexEnc(kek) != v.Kek {
				t.Errorf("%s: authKey/kek mismatch", v.Name)
			}
			// Every negative carries its own complete params object; none of
			// it is merged with the positive entry's salt or other fields.
			for _, neg := range v.Negative {
				if neg.Params == nil {
					t.Errorf("%s negative %q: missing params", v.Name, neg.Why)
					continue
				}
				np := Params{Alg: neg.Params.Alg, Memory: neg.Params.Memory, Time: neg.Params.Time, Threads: neg.Params.Threads, Salt: hexDec(t, neg.Params.Salt)}
				if err := np.CheckFloor(); err == nil {
					t.Errorf("%s negative %q: floor check accepted it", v.Name, neg.Why)
				}
			}
		}
	})

	t.Run("akCommit", func(t *testing.T) {
		for _, v := range vf.AKCommit {
			got, err := AKCommit(hexDec(t, v.Ak), v.Artifact, v.Epoch)
			if err != nil {
				t.Fatalf("%s: AKCommit: %v", v.Name, err)
			}
			if got != v.Want {
				t.Errorf("%s: AKCommit mismatch", v.Name)
			}
		}
	})

	t.Run("recoveryCode", func(t *testing.T) {
		for _, v := range vf.RecoveryCode {
			code := hexDec(t, v.Code)
			if got := FormatRecoveryCode(code); got != v.Display {
				t.Errorf("%s: FormatRecoveryCode = %q, want %q", v.Name, got, v.Display)
			}
			got, err := ParseRecoveryCode(v.Display)
			if err != nil || !bytes.Equal(got, code) {
				t.Errorf("%s: ParseRecoveryCode(display) failed: %v", v.Name, err)
			}
			for _, variant := range v.Variants {
				got, err := ParseRecoveryCode(variant)
				if err != nil || !bytes.Equal(got, code) {
					t.Errorf("%s: ParseRecoveryCode(%q) failed: %v", v.Name, variant, err)
				}
			}
			if hexEnc(RecoveryKEK(code)) != v.Kek {
				t.Errorf("%s: RecoveryKEK mismatch", v.Name)
			}
			for _, neg := range v.Negative {
				if _, err := ParseRecoveryCode(neg.Input); err == nil {
					t.Errorf("%s negative %q: parsed without error", v.Name, neg.Why)
				}
			}
		}
	})

	t.Run("apiKey", func(t *testing.T) {
		for _, v := range vf.APIKey {
			parsed, err := ParseAPIKey(v.Full)
			if err != nil {
				t.Fatalf("%s: ParseAPIKey: %v", v.Name, err)
			}
			if parsed.KeyID != v.KeyID || parsed.AuthSecret != v.AuthSecret || hexEnc(parsed.KeySecret) != v.KeySecret {
				t.Errorf("%s: parsed parts mismatch", v.Name)
			}
			if hexEnc(APIKeyKEK(parsed.KeySecret, parsed.KeyID)) != v.Kek {
				t.Errorf("%s: APIKeyKEK mismatch", v.Name)
			}
			for _, neg := range v.Negative {
				if _, err := ParseAPIKey(neg.Input); err == nil {
					t.Errorf("%s negative %q: parsed without error", v.Name, neg.Why)
				}
			}
		}
	})

	t.Run("seal", func(t *testing.T) {
		for _, v := range vf.Seal {
			key := hexDec(t, v.Key)
			var fields [][]byte
			for _, f := range v.Fields {
				fields = append(fields, hexDec(t, f))
			}
			sealed := hexDec(t, v.Want)
			got, err := Open(key, fields, sealed)
			if err != nil || hexEnc(got) != v.Pt {
				t.Errorf("%s: Open failed: %v", v.Name, err)
			}
			// Every row but the keyring seals a 32-byte key, which OpenKey
			// opens; the keyring is not 61 bytes, so OpenKey refuses it.
			gotKey, err := OpenKey(key, fields, sealed)
			if string(fields[0]) == "keyring" {
				if !errors.Is(err, ErrDecrypt) {
					t.Errorf("%s: OpenKey = %v, want ErrDecrypt", v.Name, err)
				}
			} else if err != nil || hexEnc(gotKey) != v.Pt {
				t.Errorf("%s: OpenKey failed: %v", v.Name, err)
			}
			for _, neg := range v.Negative {
				input := sealed
				if neg.Input != "" {
					input = hexDec(t, neg.Input)
				}
				useKey := key
				if neg.Key != "" {
					useKey = hexDec(t, neg.Key)
				}
				useFields := fields
				if neg.Fields != nil {
					useFields = nil
					for _, f := range neg.Fields {
						useFields = append(useFields, hexDec(t, f))
					}
				}
				if _, err := Open(useKey, useFields, input); err == nil {
					t.Errorf("%s negative %q: Open succeeded", v.Name, neg.Why)
				}
			}
		}
	})

	t.Run("blob", func(t *testing.T) {
		for _, v := range vf.Blob {
			ak := hexDec(t, v.Ak)
			ctx := BlobContext{Artifact: v.Ctx.Artifact, Version: v.Ctx.Version, Kind: v.Ctx.Kind, Name: v.Ctx.Name}
			blob := hexDec(t, v.Want)
			got, err := OpenBlob(ak, ctx, blob)
			if err != nil {
				t.Errorf("%s: OpenBlob failed: %v", v.Name, err)
				continue
			}
			wantPt := hexDec(t, v.Pt)
			if v.PtRule != nil {
				wantPt = fillBytes(v.PtRule.Len)
			}
			if !bytes.Equal(got, wantPt) {
				t.Errorf("%s: OpenBlob plaintext mismatch", v.Name)
			}
			for _, neg := range v.Negative {
				useCtx := ctx
				if neg.Ctx != nil {
					useCtx = applyBlobCtxOverride(t, ctx, neg.Ctx)
				}
				input := blob
				if neg.Transform != nil {
					input = applyBlobTransform(t, blob, *neg.Transform)
				} else if neg.Input != "" {
					input = hexDec(t, neg.Input)
				}
				if _, err := OpenBlob(ak, useCtx, input); err == nil {
					t.Errorf("%s negative %q: OpenBlob succeeded", v.Name, neg.Why)
				}
			}
		}
	})

	t.Run("wrap", func(t *testing.T) {
		for _, v := range vf.Wrap {
			ctx := WrapContext{
				Purpose: v.Ctx.Purpose, Artifact: v.Ctx.Artifact, Epoch: v.Ctx.Epoch,
				RecipientID: v.Ctx.RecipientID, RecipientPub: hexDec(t, v.Ctx.RecipientPub),
			}
			wrapped := hexDec(t, v.Want)
			got, err := Unwrap(hexDec(t, v.RecipientPriv), ctx, wrapped)
			if err != nil || hexEnc(got) != v.Key {
				t.Errorf("%s: Unwrap failed: %v", v.Name, err)
			}
			for _, neg := range v.Negative {
				useCtx := ctx
				if neg.Ctx != nil {
					useCtx = applyWrapCtxOverride(t, ctx, neg.Ctx)
				}
				usePriv := hexDec(t, v.RecipientPriv)
				if neg.Key != "" {
					usePriv = hexDec(t, neg.Key)
				}
				input := wrapped
				if neg.Input != "" {
					input = hexDec(t, neg.Input)
				}
				if _, err := Unwrap(usePriv, useCtx, input); err == nil {
					t.Errorf("%s negative %q: Unwrap succeeded", v.Name, neg.Why)
				}
			}
		}
	})

	t.Run("signature", func(t *testing.T) {
		for _, v := range vf.Signature {
			pub := hexDec(t, v.Pub)
			body := hexDec(t, v.Body)
			sig := hexDec(t, v.Want)
			if !Verify(pub, v.Purpose, body, sig) {
				t.Errorf("%s: Verify failed", v.Name)
			}
			env := Envelope{Body: body, Sig: sig, Signer: v.Signer}
			if !env.Verify(pub, v.Purpose) {
				t.Errorf("%s: Envelope.Verify failed", v.Name)
			}
			for _, neg := range v.Negative {
				usePurpose := v.Purpose
				if neg.Purpose != "" {
					usePurpose = neg.Purpose
				}
				usePub := pub
				if neg.Pub != "" {
					usePub = hexDec(t, neg.Pub)
				}
				if Verify(usePub, usePurpose, body, sig) {
					t.Errorf("%s negative %q: Verify succeeded", v.Name, neg.Why)
				}
			}
		}
	})

	t.Run("rotation", func(t *testing.T) {
		for _, v := range vf.Rotation {
			body := hexDec(t, v.Body)
			env := Envelope{Body: body, Sig: hexDec(t, v.Sig), Signer: v.Signer, NewSig: hexDec(t, v.NewSig)}
			var out RotationBody
			err := OpenRotation(env, hexDec(t, v.OldPub), &out)
			if v.Refuse != "" {
				if !errors.Is(err, ErrFormat) {
					t.Errorf("%s (%s): OpenRotation = %v, want ErrFormat", v.Name, v.Refuse, err)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s: OpenRotation failed: %v", v.Name, err)
			}
			for _, neg := range v.Negative {
				useEnv := env
				if neg.NewSig != "" {
					useEnv.NewSig = hexDec(t, neg.NewSig)
				}
				var negOut RotationBody
				if err := OpenRotation(useEnv, hexDec(t, v.OldPub), &negOut); err == nil {
					t.Errorf("%s negative %q: OpenRotation succeeded", v.Name, neg.Why)
				}
			}
		}
	})

	t.Run("ed25519Strict", func(t *testing.T) {
		// edwards25519BasePoint is the standard compressed encoding of the
		// Ed25519 base point B (y = 4/5 mod p, x even). Paired with S=1, R=B
		// satisfies the cofactored verification equation [8][1]B = [8]B +
		// [8]h*A for ANY message whenever A has order dividing 8 — a
		// universal forgery against any verifier that doesn't itself refuse
		// a small-order or non-canonical A before running the curve math.
		edwards25519BasePoint := hexDec(t, "5866666666666666666666666666666666666666666666666666666666666666")
		forgedS := make([]byte, 32)
		forgedS[0] = 1
		forgedSig := append(append([]byte{}, edwards25519BasePoint...), forgedS...)

		for _, v := range vf.Ed25519Strict {
			pub := hexDec(t, v.Pub)
			if len(pub) != 32 {
				t.Fatalf("%s: pub is %d bytes, want 32", v.Name, len(pub))
			}
			if v.Sig != "" {
				// A signature some verifier accepts, which Verify must
				// refuse, and must refuse before the curve equation: Go's
				// cofactorless equation alone already fails several of
				// these, so only the encoding checks prove each rejection.
				sig := hexDec(t, v.Sig)
				if Verify(pub, v.Purpose, hexDec(t, v.Body), sig) {
					t.Errorf("%s (%s): Verify accepted it", v.Name, v.Why)
				}
				if signatureEncodingOK(pub, sig) {
					t.Errorf("%s (%s): signatureEncodingOK accepted it", v.Name, v.Why)
				}
				continue
			}
			// A bad key must fail on its own, for any purpose, body, and
			// signature — including the R=B,S=1 forgery. The X25519 key is
			// genuine, so only the Ed25519 key can be the reason.
			_, x25519Pub, err := GenerateX25519(newDRBG("ed25519-strict-x25519"))
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckPublicKeys(x25519Pub, pub); err == nil {
				t.Errorf("%s (%s): CheckPublicKeys accepted a bad Ed25519 key", v.Name, v.Why)
			}
			for _, body := range [][]byte{[]byte("body"), []byte("a different message")} {
				if Verify(pub, "manifest", body, forgedSig) {
					t.Errorf("%s (%s): Verify accepted the R=B,S=1 forgery", v.Name, v.Why)
				}
			}
		}
	})

	t.Run("x25519Strict", func(t *testing.T) {
		_, genuineEd25519Pub, err := GenerateEd25519(newDRBG("x25519-strict-ed25519"))
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range vf.X25519Strict {
			pub := hexDec(t, v.Pub)
			err := CheckPublicKeys(pub, genuineEd25519Pub)
			if v.Accept && err != nil {
				t.Errorf("%s (%s): CheckPublicKeys refused it: %v", v.Name, v.Why, err)
			}
			if !v.Accept && err == nil {
				t.Errorf("%s (%s): CheckPublicKeys accepted it", v.Name, v.Why)
			}
		}
	})

	t.Run("envelope", func(t *testing.T) { checkEnvelopeVectors(t, vf.Envelope) })
	t.Run("chain", func(t *testing.T) { checkChainVectors(t, vf.Chain) })
	t.Run("approval", func(t *testing.T) { checkApprovalVectors(t, vf.Approval) })
	t.Run("keyring", func(t *testing.T) { checkKeyringVectors(t, vf.Keyring) })

	t.Run("strictJSON", func(t *testing.T) {
		for _, v := range vf.StrictJSON {
			body := hexDec(t, v.Body)
			var err error
			switch v.Purpose {
			case "vouch":
				var out VouchBody
				err = DecodeStrict(body, &out)
			case "revision":
				var out RevisionBody
				err = DecodeStrict(body, &out)
			default:
				t.Fatalf("%s: unknown purpose %q", v.Name, v.Purpose)
			}
			if err == nil {
				t.Errorf("%s (%s): DecodeStrict accepted it", v.Name, v.Why)
			}
		}
	})

	t.Run("base64url", func(t *testing.T) {
		for _, v := range vf.Base64URL {
			got, err := UnB64(v.Encoded)
			if err != nil || hexEnc(got) != v.Bytes {
				t.Errorf("%s: UnB64 failed: %v", v.Name, err)
			}
			for _, neg := range v.Negative {
				if _, err := UnB64(neg.Input); err == nil {
					t.Errorf("%s negative %q: UnB64 succeeded", v.Name, neg.Why)
				}
			}
		}
	})

	t.Run("fingerprint", func(t *testing.T) {
		for _, v := range vf.Fingerprint {
			got := Fingerprint(hexDec(t, v.X25519Pub), hexDec(t, v.Ed25519Pub))
			if hexEnc(got) != v.Want {
				t.Errorf("%s: Fingerprint mismatch", v.Name)
			}
			if FormatFingerprint(got) != v.Display {
				t.Errorf("%s: FormatFingerprint mismatch", v.Name)
			}
		}
	})

	t.Run("linkToken", func(t *testing.T) {
		for _, v := range vf.LinkToken {
			got, err := LinkToken(hexDec(t, v.Ak), v.Artifact, v.Epoch)
			if err != nil {
				t.Fatalf("%s: LinkToken: %v", v.Name, err)
			}
			if hexEnc(got) != v.Want {
				t.Errorf("%s: LinkToken mismatch", v.Name)
			}
			if LinkTokenHash(got) != v.Hash {
				t.Errorf("%s: LinkTokenHash mismatch", v.Name)
			}
		}
	})

	t.Run("fileAddress", func(t *testing.T) {
		for _, v := range vf.FileAddress {
			if got, err := FileAddress(hexDec(t, v.FileKey), v.Path); err != nil || got != v.Want {
				t.Errorf("%s: FileAddress mismatch (%v)", v.Name, err)
			}
			for _, neg := range v.Negative {
				if _, err := FileAddress(hexDec(t, neg.Key), v.Path); !errors.Is(err, ErrFormat) {
					t.Errorf("%s negative %q: got %v, want ErrFormat", v.Name, neg.Why, err)
				}
			}
		}
	})

	t.Run("blindIndex", func(t *testing.T) {
		for _, v := range vf.BlindIndex {
			if got, err := BlindIndex(hexDec(t, v.IndexKey), v.Type, v.Value); err != nil || got != v.Want {
				t.Errorf("%s: BlindIndex mismatch (%v)", v.Name, err)
			}
			for _, neg := range v.Negative {
				if _, err := BlindIndex(hexDec(t, neg.Key), v.Type, v.Value); !errors.Is(err, ErrFormat) {
					t.Errorf("%s negative %q: got %v, want ErrFormat", v.Name, neg.Why, err)
				}
			}
		}
	})
}
