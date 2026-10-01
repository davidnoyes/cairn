package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Cross-language agreement with real randomness, checked in both
// directions: Go checks fresh output from internal/server/web/e2e_interop.mjs
// (TestInteropGoChecksNodeEmit), and Node checks fresh output from this
// package (TestInteropNodeChecksGoEmit). The JSON shape is documented in
// testdata/README.md; every byte value is hex, except signature.envelope,
// which is embedded in its real b64 wire form.

type interopSeal struct {
	Key    string   `json:"key"`
	Fields []string `json:"fields"`
	Pt     string   `json:"pt"`
	Sealed string   `json:"sealed"`
}

type interopBlob struct {
	Ak   string     `json:"ak"`
	Ctx  blobCtxVec `json:"ctx"`
	Pt   string     `json:"pt"`
	Blob string     `json:"blob"`
}

type interopWrapCtx struct {
	Purpose      string `json:"purpose"`
	Artifact     string `json:"artifact"`
	Epoch        uint64 `json:"epoch"`
	RecipientID  string `json:"recipientId"`
	RecipientPub string `json:"recipientPub"`
}

type interopWrap struct {
	Ctx           interopWrapCtx `json:"ctx"`
	RecipientPriv string         `json:"recipientPriv"`
	Key           string         `json:"key"`
	Wrapped       string         `json:"wrapped"`
}

type interopEnvelope struct {
	Body   string `json:"body"`
	Sig    string `json:"sig"`
	Signer string `json:"signer"`
}

type interopSignature struct {
	Purpose  string          `json:"purpose"`
	Seed     string          `json:"seed"`
	Pub      string          `json:"pub"`
	Body     string          `json:"body"`
	Signer   string          `json:"signer"`
	Sig      string          `json:"sig"`
	Envelope interopEnvelope `json:"envelope"`
}

type interopRecoveryCode struct {
	Code    string `json:"code"`
	Display string `json:"display"`
	Kek     string `json:"kek"`
}

type interopAPIKey struct {
	Full       string `json:"full"`
	KeyID      string `json:"keyId"`
	AuthSecret string `json:"authSecret"`
	KeySecret  string `json:"keySecret"`
	Kek        string `json:"kek"`
}

type interopAKCommit struct {
	Ak       string `json:"ak"`
	Artifact string `json:"artifact"`
	Epoch    uint64 `json:"epoch"`
	Want     string `json:"want"`
}

type interopRotation struct {
	OldSeed string `json:"oldSeed"`
	OldPub  string `json:"oldPub"`
	NewSeed string `json:"newSeed"`
	NewPub  string `json:"newPub"`
	Signer  string `json:"signer"`
	Body    string `json:"body"`
	Sig     string `json:"sig"`
	NewSig  string `json:"newSig"`
}

type interopStretchParams struct {
	Alg    string `json:"alg"`
	Memory uint32 `json:"m"`
	Time   uint32 `json:"t"`
	Thread uint8  `json:"p"`
	Salt   string `json:"salt"`
}

type interopStretch struct {
	Email     string               `json:"email"`
	Password  string               `json:"password"`
	Params    interopStretchParams `json:"params"`
	ArgonSalt string               `json:"argonSalt"`
	Stretched string               `json:"stretched"`
	AuthKey   string               `json:"authKey"`
	Kek       string               `json:"kek"`
}

type interopFile struct {
	Seal           interopSeal         `json:"seal"`
	Blob           interopBlob         `json:"blob"`
	BlobMultiChunk interopBlob         `json:"blobMultiChunk"`
	Wrap           interopWrap         `json:"wrap"`
	Signature      interopSignature    `json:"signature"`
	RecoveryCode   interopRecoveryCode `json:"recoveryCode"`
	APIKey         interopAPIKey       `json:"apiKey"`
	AKCommit       interopAKCommit     `json:"akCommit"`
	Rotation       interopRotation     `json:"rotation"`
	Stretch        interopStretch      `json:"stretch"`
}

// interopScriptPath finds e2e_interop.mjs relative to this test file, so it
// works regardless of the test runner's working directory.
func interopScriptPath(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "server", "web", "e2e_interop.mjs")
}

// requireNode skips locally when node isn't on PATH, but fails outright in
// CI, where it must always be available (the workflow sets up Node before
// running go test).
func requireNode(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("node not found in CI: %v", err)
		}
		t.Skip("node not found on PATH; skipping interop test")
	}
	return path
}

func TestInteropGoChecksNodeEmit(t *testing.T) {
	node := requireNode(t)
	out, err := exec.Command(node, interopScriptPath(t), "emit").Output()
	if err != nil {
		t.Fatalf("node emit: %v", err)
	}
	var data interopFile
	if err := json.Unmarshal(out, &data); err != nil {
		t.Fatalf("unmarshal emit output: %v\n%s", err, out)
	}
	checkInteropFile(t, data)
}

func TestInteropNodeChecksGoEmit(t *testing.T) {
	node := requireNode(t)
	data := buildGoInteropFile(t)
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "interop.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(node, interopScriptPath(t), "check", path).CombinedOutput(); err != nil {
		t.Fatalf("node check: %v\n%s", err, out)
	}
}

// checkInteropFile independently verifies every item in data with this
// package, regardless of which side produced it.
func checkInteropFile(t *testing.T, data interopFile) {
	t.Helper()

	t.Run("seal", func(t *testing.T) {
		var fields [][]byte
		for _, f := range data.Seal.Fields {
			fields = append(fields, hexDec(t, f))
		}
		pt, err := Open(hexDec(t, data.Seal.Key), fields, hexDec(t, data.Seal.Sealed))
		if err != nil || hexEnc(pt) != data.Seal.Pt {
			t.Errorf("Open: %v", err)
		}
	})

	for _, b := range []struct {
		name string
		v    interopBlob
	}{{"blob", data.Blob}, {"blobMultiChunk", data.BlobMultiChunk}} {
		t.Run(b.name, func(t *testing.T) {
			ctx := BlobContext(b.v.Ctx)
			pt, err := OpenBlob(hexDec(t, b.v.Ak), ctx, hexDec(t, b.v.Blob))
			if err != nil || hexEnc(pt) != b.v.Pt {
				t.Errorf("OpenBlob: %v", err)
			}
		})
	}

	t.Run("wrap", func(t *testing.T) {
		w := data.Wrap
		ctx := WrapContext{
			Purpose: w.Ctx.Purpose, Artifact: w.Ctx.Artifact, Epoch: w.Ctx.Epoch,
			RecipientID: w.Ctx.RecipientID, RecipientPub: hexDec(t, w.Ctx.RecipientPub),
		}
		got, err := Unwrap(hexDec(t, w.RecipientPriv), ctx, hexDec(t, w.Wrapped))
		if err != nil || hexEnc(got) != w.Key {
			t.Errorf("Unwrap: %v", err)
		}
	})

	t.Run("signature", func(t *testing.T) {
		s := data.Signature
		pub, body, sig := hexDec(t, s.Pub), hexDec(t, s.Body), hexDec(t, s.Sig)
		if !Verify(pub, s.Purpose, body, sig) {
			t.Error("Verify failed")
		}
		envBody, err := UnB64(s.Envelope.Body)
		if err != nil {
			t.Fatalf("envelope body: %v", err)
		}
		envSig, err := UnB64(s.Envelope.Sig)
		if err != nil {
			t.Fatalf("envelope sig: %v", err)
		}
		env := Envelope{Body: envBody, Sig: envSig, Signer: s.Envelope.Signer}
		if !env.Verify(pub, s.Purpose) {
			t.Error("Envelope.Verify failed")
		}
	})

	t.Run("recoveryCode", func(t *testing.T) {
		r := data.RecoveryCode
		code := hexDec(t, r.Code)
		got, err := ParseRecoveryCode(r.Display)
		if err != nil || !bytes.Equal(got, code) {
			t.Errorf("ParseRecoveryCode: %v", err)
		}
		if hexEnc(RecoveryKEK(code)) != r.Kek {
			t.Error("RecoveryKEK mismatch")
		}
	})

	t.Run("apiKey", func(t *testing.T) {
		a := data.APIKey
		parsed, err := ParseAPIKey(a.Full)
		if err != nil {
			t.Fatalf("ParseAPIKey: %v", err)
		}
		if parsed.KeyID != a.KeyID || parsed.AuthSecret != a.AuthSecret || hexEnc(parsed.KeySecret) != a.KeySecret {
			t.Error("parsed parts mismatch")
		}
		if hexEnc(APIKeyKEK(parsed.KeySecret, parsed.KeyID)) != a.Kek {
			t.Error("APIKeyKEK mismatch")
		}
	})

	t.Run("akCommit", func(t *testing.T) {
		c := data.AKCommit
		got, err := AKCommit(hexDec(t, c.Ak), c.Artifact, c.Epoch)
		if err != nil || got != c.Want {
			t.Errorf("AKCommit: got %q, %v, want %q", got, err, c.Want)
		}
	})

	t.Run("rotation", func(t *testing.T) {
		r := data.Rotation
		env := Envelope{
			Body: hexDec(t, r.Body), Sig: hexDec(t, r.Sig), Signer: r.Signer, NewSig: hexDec(t, r.NewSig),
		}
		var out RotationBody
		if err := OpenRotation(env, hexDec(t, r.OldPub), &out); err != nil {
			t.Errorf("OpenRotation: %v", err)
		}
	})

	t.Run("stretch", func(t *testing.T) {
		s := data.Stretch
		p := Params{
			Alg: s.Params.Alg, Memory: s.Params.Memory, Time: s.Params.Time, Threads: s.Params.Thread,
			Salt: hexDec(t, s.Params.Salt),
		}
		if hexEnc(ArgonSalt(s.Email, p.Salt)) != s.ArgonSalt {
			t.Error("ArgonSalt mismatch")
		}
		stretched, err := Stretch(hexDec(t, s.Password), s.Email, p)
		if err != nil {
			t.Fatalf("Stretch: %v", err)
		}
		if hexEnc(stretched) != s.Stretched {
			t.Error("stretched mismatch")
		}
		authKey, kek := PasswordKeys(stretched)
		if hexEnc(authKey) != s.AuthKey || hexEnc(kek) != s.Kek {
			t.Error("authKey/kek mismatch")
		}
	})
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func hexEncAll(fields [][]byte) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = hexEnc(f)
	}
	return out
}

// buildGoInteropFile builds a fresh interopFile with real randomness, for
// e2e_interop.mjs's "check" command to verify.
func buildGoInteropFile(t *testing.T) interopFile {
	t.Helper()
	ctx := BlobContext{Artifact: "interop-artifact", Version: "interop-version", Kind: "content", Name: "interop.txt"}

	sealKey := randBytes(t, 32)
	sealFields := [][]byte{[]byte("mk")}
	sealPt := randBytes(t, 40)
	sealed, err := Seal(rand.Reader, sealKey, sealFields, sealPt)
	if err != nil {
		t.Fatal(err)
	}

	blobAk := randBytes(t, 32)
	blobPt := randBytes(t, 200)
	blob, err := SealBlob(rand.Reader, blobAk, ctx, blobPt)
	if err != nil {
		t.Fatal(err)
	}

	multiAk := randBytes(t, 32)
	multiPt := randBytes(t, 2*BlobChunkSize+1000) // several chunks
	multiBlob, err := SealBlob(rand.Reader, multiAk, ctx, multiPt)
	if err != nil {
		t.Fatal(err)
	}

	recipientPriv, recipientPub, err := GenerateX25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrapKey := randBytes(t, 32)
	wctx := WrapContext{Purpose: "ak", Artifact: "interop-artifact", Epoch: 7, RecipientID: "interop-user", RecipientPub: recipientPub}
	wrapped, err := Wrap(rand.Reader, wctx, wrapKey)
	if err != nil {
		t.Fatal(err)
	}

	seed, pub, err := GenerateEd25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sigBody := []byte(`{"v":1,"artifact":"interop-artifact"}`)
	sig, err := Sign(seed, "manifest", sigBody)
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnvelope(seed, "interop-user", "manifest", sigBody)
	if err != nil {
		t.Fatal(err)
	}

	code, display, err := NewRecoveryCode(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recoveryKek := RecoveryKEK(code)

	full, keyID, authSecret, keySecret, err := NewAPIKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	apiKeyKek := APIKeyKEK(keySecret, keyID)

	akCommitAk := randBytes(t, 32)
	akCommitWant, err := AKCommit(akCommitAk, "interop-artifact", 9)
	if err != nil {
		t.Fatal(err)
	}

	rotation := buildGoInteropRotation(t)

	stretch := buildGoInteropStretch(t)

	return interopFile{
		Seal: interopSeal{Key: hexEnc(sealKey), Fields: hexEncAll(sealFields), Pt: hexEnc(sealPt), Sealed: hexEnc(sealed)},
		Blob: interopBlob{Ak: hexEnc(blobAk), Ctx: blobCtxVec(ctx), Pt: hexEnc(blobPt), Blob: hexEnc(blob)},
		BlobMultiChunk: interopBlob{
			Ak: hexEnc(multiAk), Ctx: blobCtxVec(ctx), Pt: hexEnc(multiPt), Blob: hexEnc(multiBlob),
		},
		Wrap: interopWrap{
			Ctx: interopWrapCtx{
				Purpose: wctx.Purpose, Artifact: wctx.Artifact, Epoch: wctx.Epoch,
				RecipientID: wctx.RecipientID, RecipientPub: hexEnc(recipientPub),
			},
			RecipientPriv: hexEnc(recipientPriv), Key: hexEnc(wrapKey), Wrapped: hexEnc(wrapped),
		},
		Signature: interopSignature{
			Purpose: "manifest", Seed: hexEnc(seed), Pub: hexEnc(pub), Body: hexEnc(sigBody),
			Signer: "interop-user", Sig: hexEnc(sig),
			Envelope: interopEnvelope{Body: B64(env.Body), Sig: B64(env.Sig), Signer: env.Signer},
		},
		RecoveryCode: interopRecoveryCode{Code: hexEnc(code), Display: display, Kek: hexEnc(recoveryKek)},
		APIKey: interopAPIKey{
			Full: full, KeyID: keyID, AuthSecret: authSecret, KeySecret: hexEnc(keySecret), Kek: hexEnc(apiKeyKek),
		},
		AKCommit: interopAKCommit{Ak: hexEnc(akCommitAk), Artifact: "interop-artifact", Epoch: 9, Want: akCommitWant},
		Rotation: rotation,
		Stretch:  stretch,
	}
}

// buildGoInteropRotation builds a rotation envelope signed by a fresh old key
// and a fresh new key, matching RotationBody.
func buildGoInteropRotation(t *testing.T) interopRotation {
	t.Helper()
	oldSeed, oldPub, err := GenerateEd25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newSeed, newPub, err := GenerateEd25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, x25519Pub, err := GenerateX25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := RotationBody{
		V: 1, User: "interop-user", Seq: 3,
		Old: KeyPair{X25519: B64(x25519Pub), Ed25519: B64(oldPub)},
		New: KeyPair{X25519: B64(x25519Pub), Ed25519: B64(newPub)},
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	env, err := SignRotation(oldSeed, newSeed, bodyBytes, "interop-user")
	if err != nil {
		t.Fatal(err)
	}
	return interopRotation{
		OldSeed: hexEnc(oldSeed), OldPub: hexEnc(oldPub), NewSeed: hexEnc(newSeed), NewPub: hexEnc(newPub),
		Signer: "interop-user", Body: hexEnc(bodyBytes), Sig: hexEnc(env.Sig), NewSig: hexEnc(env.NewSig),
	}
}

// buildGoInteropStretch runs Stretch with an email, at floor parameters so
// the Node side's Argon2id-under-WebAssembly run stays fast.
func buildGoInteropStretch(t *testing.T) interopStretch {
	t.Helper()
	email := "  Interop@Example.COM "
	password := randBytes(t, 24)
	p := Params{Alg: "argon2id", Memory: floorMemory, Time: floorTime, Threads: 1, Salt: randBytes(t, 16)}
	stretched, err := Stretch(password, email, p)
	if err != nil {
		t.Fatal(err)
	}
	authKey, kek := PasswordKeys(stretched)
	return interopStretch{
		Email: email, Password: hexEnc(password),
		Params: interopStretchParams{
			Alg: p.Alg, Memory: p.Memory, Time: p.Time, Thread: p.Threads, Salt: hexEnc(p.Salt),
		},
		ArgonSalt: hexEnc(ArgonSalt(email, p.Salt)), Stretched: hexEnc(stretched),
		AuthKey: hexEnc(authKey), Kek: hexEnc(kek),
	}
}
