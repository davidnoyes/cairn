package e2e

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
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

func hexDec(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

type negative struct {
	Why   string `json:"why"`
	Input string `json:"input"`
}

type vectorFile struct {
	Enc          []encVec         `json:"enc"`
	Derive       []deriveVec      `json:"derive"`
	Argon2       []argon2Vec      `json:"argon2"`
	RecoveryCode []recoveryVec    `json:"recoveryCode"`
	APIKey       []apiKeyVec      `json:"apiKey"`
	Seal         []sealVec        `json:"seal"`
	Blob         []blobVec        `json:"blob"`
	Wrap         []wrapVec        `json:"wrap"`
	Signature    []sigVec         `json:"signature"`
	Fingerprint  []fingerprintVec `json:"fingerprint"`
	LinkToken    []linkTokenVec   `json:"linkToken"`
	FileAddress  []fileAddressVec `json:"fileAddress"`
	BlindIndex   []blindIndexVec  `json:"blindIndex"`
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
	Params    argon2ParamsVec `json:"params"`
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
	Negative   []negative `json:"negative"`
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

type fileAddressVec struct {
	Name    string `json:"name"`
	FileKey string `json:"fileKey"`
	Path    string `json:"path"`
	Want    string `json:"want"`
}

type blindIndexVec struct {
	Name     string `json:"name"`
	IndexKey string `json:"indexKey"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Want     string `json:"want"`
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

	// argon2 at floor
	{
		password := []byte("correct horse battery staple")
		p := Params{Alg: "argon2id", Memory: floorMemory, Time: floorTime, Threads: 1, Salt: make([]byte, 16)}
		newDRBG("vector-argon2-salt").Read(p.Salt)
		stretched, err := Stretch(password, p)
		if err != nil {
			t.Fatal(err)
		}
		authKey, kek := PasswordKeys(stretched)
		vf.Argon2 = []argon2Vec{{
			Name:     "floor",
			Password: hexEnc(password),
			Params: argon2ParamsVec{
				Alg: p.Alg, Memory: p.Memory, Time: p.Time, Threads: p.Threads, Salt: hexEnc(p.Salt),
			},
			Stretched: hexEnc(stretched),
			AuthKey:   hexEnc(authKey),
			Kek:       hexEnc(kek),
			Negative: []negative{
				{Why: "memory one below the floor", Input: `{"alg":"argon2id","m":65535,"t":3,"p":1}`},
				{Why: "time one below the floor", Input: `{"alg":"argon2id","m":65536,"t":2,"p":1}`},
				{Why: "wrong algorithm", Input: `{"alg":"argon2i","m":65536,"t":3,"p":1}`},
			},
		}}
	}

	// recovery code
	{
		code, display := NewRecoveryCode(newDRBG("vector-recovery"))
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
			},
		}}
	}

	// API key
	{
		full, keyID, authSecret, keySecret := NewAPIKey(newDRBG("vector-apikey"))
		kek := APIKeyKEK(keySecret, keyID)
		vf.APIKey = []apiKeyVec{{
			Name: "sample", Full: full, KeyID: keyID, AuthSecret: authSecret, KeySecret: hexEnc(keySecret), Kek: hexEnc(kek),
			Negative: []negative{
				{Why: "missing prefix", Input: strings.TrimPrefix(full, "cairn_")},
				{Why: "wrong number of parts", Input: full + "_extra"},
				{Why: "empty", Input: ""},
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
		{"mk-under-password", testKey("vec-kek"), [][]byte{[]byte("mk")}, []byte("master-key-material-32-bytes!!!")},
		{"mk-under-recovery", testKey("vec-recovery-kek"), [][]byte{[]byte("mk")}, []byte("master-key-material-32-bytes!!!")},
		{"mk-under-apikey", testKey("vec-apikey-kek"), [][]byte{[]byte("mk"), []byte("keyid-abc123")}, []byte("master-key-material-32-bytes!!!")},
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
				{Why: "wrong key", Input: hexEnc(sealed)}, // paired with a different key in the Go/Node test
			},
		})
	}

	// blobs
	blobCases := []struct {
		name string
		n    int
	}{
		{"size-0", 0},
		{"size-1", 1},
		{"size-65536", 65536},
		{"size-65537", 65537},
		{"size-204800", 204800},
	}
	ak := testKey("vector-blob-ak")
	ctx := BlobContext{Artifact: "artifact-1", Version: "version-1", Kind: "content", Name: "index.html"}
	ctxVec := blobCtxVec(ctx)
	// Keep vectors.json small: only the two tiny sizes carry literal
	// negative copies of their ciphertext. The 64 KiB-ish sizes keep a
	// literal plaintext (required, to pin the chunk-boundary byte counts)
	// but skip negatives; the ~200 KB size uses a plaintext rule instead of
	// literal bytes and skips negatives too. Every negative case Go itself
	// checks (flipped bit, truncation, dropped/reordered chunk, wrong
	// context) is already exercised byte-for-byte in blob_test.go.
	const negativeSizeLimit = 1
	const literalPtLimit = 65537
	for _, c := range blobCases {
		pt := fillBytes(c.n)
		blob, err := SealBlob(newDRBG("vector-blob-"+c.name), ak, ctx, pt)
		if err != nil {
			t.Fatal(err)
		}
		v := blobVec{
			Name: c.name, Ak: hexEnc(ak), Ctx: ctxVec, Salt: hexEnc(blob[len(blobMagic)+1 : blobHeaderSize]),
			Want: hexEnc(blob),
		}
		if c.n > literalPtLimit {
			v.PtRule = &ptRule{Rule: "i mod 251", Len: c.n}
		} else {
			v.Pt = hexEnc(pt)
		}
		if c.n <= negativeSizeLimit {
			mutated := append([]byte(nil), blob...)
			mutated[blobHeaderSize] ^= 0x01
			truncated := blob[:len(blob)-1]
			v.Negative = []negative{
				{Why: "flipped bit in first chunk", Input: hexEnc(mutated)},
				{Why: "truncated by one byte", Input: hexEnc(truncated)},
			}
		}
		vf.Blob = append(vf.Blob, v)
	}

	// wrap
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
		mutated := append([]byte(nil), wrapped...)
		mutated[len(mutated)-1] ^= 0x01
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
				{Why: "wrong epoch", Input: hexEnc(wrapped)}, // paired with ctx.Epoch+1 in the Go/Node test
			},
		})
	}

	// signatures: one per purpose in the spec's table
	sigSeed, sigPub, err := GenerateEd25519(newDRBG("vector-sig-key"))
	if err != nil {
		t.Fatal(err)
	}
	sigCases := []struct {
		purpose string
		body    string
	}{
		{"membership", `{"v":1,"artifact":"artifact-1","epoch":3,"owner":"user-1","members":[{"user":"user-1","role":"editor","fp":"aabbccdd"}],"team":"none","public":false,"publicWrites":false,"prev":""}`},
		{"manifest", `{"v":1,"artifact":"artifact-1","version":"version-1","epoch":3,"files":[{"path":"index.html","blob":"blob-1","size":12,"sha256":"deadbeef"}]}`},
		{"revision", `{"v":1,"artifact":"artifact-1","version":"version-1","revision":4,"epoch":3,"sha256":"deadbeef"}`},
		{"vouch", `{"v":1,"artifact":"artifact-1","version":"version-1","manifest":"deadbeef"}`},
		{"rotation", `{"v":1,"user":"user-1","old":{"x25519":"AAAA","ed25519":"BBBB"},"new":{"x25519":"CCCC","ed25519":"DDDD"}}`},
		{"successor", `{"v":1,"user":"user-1","successor":"user-2","action":"nominate"}`},
		{"reset", `{"v":1,"user":"user-1","token":"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"}`},
	}
	for _, c := range sigCases {
		body := []byte(c.body)
		sig := Sign(sigSeed, c.purpose, body)
		tampered := append([]byte(nil), body...)
		tampered[0] = '0'
		vf.Signature = append(vf.Signature, sigVec{
			Name: c.purpose, Purpose: c.purpose, Seed: hexEnc(sigSeed), Pub: hexEnc(sigPub), Body: hexEnc(body), Signer: "user-1", Want: hexEnc(sig),
			Negative: []negative{
				{Why: "tampered body", Input: hexEnc(tampered)},
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
		token := LinkToken(lak, "artifact-1", 3)
		vf.LinkToken = []linkTokenVec{{
			Name: "sample", Ak: hexEnc(lak), Artifact: "artifact-1", Epoch: 3, Want: hexEnc(token), Hash: LinkTokenHash(token),
		}}
	}

	// fileAddress
	{
		fk := testKey("vector-filekey")
		vf.FileAddress = []fileAddressVec{{
			Name: "sample", FileKey: hexEnc(fk), Path: "/images/logo.png", Want: FileAddress(fk, "/images/logo.png"),
		}}
	}

	// blindIndex
	{
		ik := testKey("vector-indexkey")
		vf.BlindIndex = []blindIndexVec{{
			Name: "sample", IndexKey: hexEnc(ik), Type: "session", Value: "abc123", Want: BlindIndex(ik, "session", "abc123"),
		}}
	}

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
			stretched, err := Stretch(hexDec(t, v.Password), p)
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
			for _, neg := range v.Negative {
				var np Params
				if err := json.Unmarshal([]byte(neg.Input), &np); err != nil {
					continue // malformed JSON is itself a valid failure case
				}
				np.Salt = p.Salt
				if err := np.CheckFloor(); err == nil {
					t.Errorf("%s negative %q: floor check accepted it", v.Name, neg.Why)
				}
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
			for _, neg := range v.Negative {
				input := hexDec(t, neg.Input)
				var err error
				if neg.Why == "wrong key" {
					_, err = Open(testKey("wrong-key-for-vectors"), fields, input)
				} else {
					_, err = Open(key, fields, input)
				}
				if err == nil {
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
				if _, err := OpenBlob(ak, ctx, hexDec(t, neg.Input)); err == nil {
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
				if neg.Why == "wrong epoch" {
					useCtx.Epoch++
				}
				if _, err := Unwrap(hexDec(t, v.RecipientPriv), useCtx, hexDec(t, neg.Input)); err == nil {
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
				if Verify(pub, v.Purpose, hexDec(t, neg.Input), sig) {
					t.Errorf("%s negative %q: Verify succeeded", v.Name, neg.Why)
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
			got := LinkToken(hexDec(t, v.Ak), v.Artifact, v.Epoch)
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
			if got := FileAddress(hexDec(t, v.FileKey), v.Path); got != v.Want {
				t.Errorf("%s: FileAddress mismatch", v.Name)
			}
		}
	})

	t.Run("blindIndex", func(t *testing.T) {
		for _, v := range vf.BlindIndex {
			if got := BlindIndex(hexDec(t, v.IndexKey), v.Type, v.Value); got != v.Want {
				t.Errorf("%s: BlindIndex mismatch", v.Name)
			}
		}
	})
}
