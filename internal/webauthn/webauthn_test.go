package webauthn_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/webauthn"
	"github.com/aloisdeniel/cairn/internal/webauthn/webauthntest"
)

var algs = []struct {
	name string
	alg  int
}{
	{"EdDSA", webauthn.AlgEdDSA},
	{"ES256", webauthn.AlgES256},
	{"RS256", webauthn.AlgRS256},
}

func testExpect() webauthn.Expect {
	return webauthn.Expect{
		RPID:      "cairn.example.com",
		Origin:    "https://cairn.example.com",
		Challenge: bytes.Repeat([]byte{0xfb, 0xef, 0xbe, 0x01}, 8),
	}
}

func credFor(a *webauthntest.Authenticator, signCount uint32) webauthn.Credential {
	return webauthn.Credential{PublicKey: a.SPKI(), Alg: a.Alg(), SignCount: signCount}
}

func TestVerifyAcceptsValidAssertion(t *testing.T) {
	for _, tc := range algs {
		t.Run(tc.name, func(t *testing.T) {
			a := webauthntest.New(tc.alg)
			exp := testExpect()
			for want := uint32(1); want <= 2; want++ {
				got, err := webauthn.Verify(a.Assert(exp), credFor(a, want-1), exp)
				if err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Fatalf("counter = %d, want %d", got, want)
				}
			}
		})
	}
}

func TestVerifyRefuses(t *testing.T) {
	a := webauthntest.New(webauthn.AlgES256)
	exp := testExpect()
	tests := []struct {
		name string
		want error
		opts []webauthntest.Option
	}{
		{"type", webauthn.ErrType, []webauthntest.Option{webauthntest.WithType("webauthn.create")}},
		{"challenge", webauthn.ErrChallenge, []webauthntest.Option{webauthntest.WithChallenge([]byte("another challenge"))}},
		{"origin", webauthn.ErrOrigin, []webauthntest.Option{webauthntest.WithOrigin("https://evil.example.com")}},
		{"crossOrigin", webauthn.ErrOrigin, []webauthntest.Option{webauthntest.WithCrossOrigin()}},
		{"rpid", webauthn.ErrRPID, []webauthntest.Option{webauthntest.WithRPID("evil.example.com")}},
		{"user-present", webauthn.ErrUserPresent, []webauthntest.Option{webauthntest.WithFlags(0x04)}},
		{"user-verified", webauthn.ErrUserVerified, []webauthntest.Option{webauthntest.WithFlags(0x01)}},
		{"signature", webauthn.ErrSignature, []webauthntest.Option{webauthntest.WithBadSignature()}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := webauthn.Verify(a.Assert(exp, tc.opts...), credFor(a, 0), exp)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifySignatureAllAlgorithms(t *testing.T) {
	for _, tc := range algs {
		t.Run(tc.name, func(t *testing.T) {
			a := webauthntest.New(tc.alg)
			exp := testExpect()
			_, err := webauthn.Verify(a.Assert(exp, webauthntest.WithBadSignature()), credFor(a, 0), exp)
			if !errors.Is(err, webauthn.ErrSignature) {
				t.Fatalf("err = %v, want ErrSignature", err)
			}
			// A valid signature from a different key is refused too.
			other := webauthntest.New(tc.alg)
			_, err = webauthn.Verify(other.Assert(exp), credFor(a, 0), exp)
			if !errors.Is(err, webauthn.ErrSignature) {
				t.Fatalf("other key: err = %v, want ErrSignature", err)
			}
		})
	}
}

func TestVerifyMalformed(t *testing.T) {
	a := webauthntest.New(webauthn.AlgEdDSA)
	exp := testExpect()
	good := a.Assert(exp)
	tests := []struct {
		name string
		mod  func(*webauthn.Assertion, *webauthn.Credential)
	}{
		{"client data not JSON", func(as *webauthn.Assertion, _ *webauthn.Credential) { as.ClientDataJSON = []byte("{nope") }},
		{"client data empty", func(as *webauthn.Assertion, _ *webauthn.Credential) { as.ClientDataJSON = nil }},
		{"authenticator data short", func(as *webauthn.Assertion, _ *webauthn.Credential) {
			as.AuthenticatorData = as.AuthenticatorData[:36]
		}},
		{"public key garbage", func(_ *webauthn.Assertion, c *webauthn.Credential) { c.PublicKey = []byte("garbage") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			as := good
			cred := credFor(a, 0)
			tc.mod(&as, &cred)
			_, err := webauthn.Verify(as, cred, exp)
			if !errors.Is(err, webauthn.ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestVerifyAlgorithm(t *testing.T) {
	a := webauthntest.New(webauthn.AlgEdDSA)
	exp := testExpect()
	for _, alg := range []int{webauthn.AlgES256, webauthn.AlgRS256, 0, -35} {
		cred := credFor(a, 0)
		cred.Alg = alg
		_, err := webauthn.Verify(a.Assert(exp), cred, exp)
		if !errors.Is(err, webauthn.ErrAlgorithm) {
			t.Fatalf("alg %d: err = %v, want ErrAlgorithm", alg, err)
		}
	}
}

func TestVerifyCounter(t *testing.T) {
	tests := []struct {
		name         string
		stored, next uint32
		ok           bool
	}{
		{"zero and zero", 0, 0, true},
		{"equal", 5, 5, false},
		{"increase", 5, 6, true},
		{"from zero", 0, 3, true},
		{"decrease", 5, 4, false},
		{"reset to zero", 5, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := webauthntest.New(webauthn.AlgEdDSA)
			exp := testExpect()
			got, err := webauthn.Verify(a.Assert(exp, webauthntest.WithCounter(tc.next)), credFor(a, tc.stored), exp)
			if tc.ok {
				if err != nil || got != tc.next {
					t.Fatalf("got %d, %v; want %d, nil", got, err, tc.next)
				}
				return
			}
			if !errors.Is(err, webauthn.ErrCounter) {
				t.Fatalf("err = %v, want ErrCounter", err)
			}
		})
	}
	t.Run("zero repeatedly", func(t *testing.T) {
		a := webauthntest.New(webauthn.AlgEdDSA)
		exp := testExpect()
		for i := 0; i < 3; i++ {
			if _, err := webauthn.Verify(a.Assert(exp, webauthntest.WithCounter(0)), credFor(a, 0), exp); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestVerifyChallengeEncoding(t *testing.T) {
	a := webauthntest.New(webauthn.AlgEdDSA)
	exp := webauthn.Expect{RPID: "cairn.example.com", Origin: "https://cairn.example.com", Challenge: testExpect().Challenge[:16]}
	good := a.Assert(exp)
	url := base64.RawURLEncoding.EncodeToString(exp.Challenge)
	if !strings.Contains(url, "-") {
		t.Fatal("test challenge must use the URL alphabet's - character")
	}
	variants := map[string]string{
		"padded":          base64.URLEncoding.EncodeToString(exp.Challenge),
		"standard":        base64.RawStdEncoding.EncodeToString(exp.Challenge),
		"standard padded": base64.StdEncoding.EncodeToString(exp.Challenge),
	}
	for name, enc := range variants {
		t.Run(name, func(t *testing.T) {
			if enc == url {
				t.Fatal("variant equals the valid encoding")
			}
			as := good
			as.ClientDataJSON = []byte(strings.Replace(string(good.ClientDataJSON), url, enc, 1))
			if bytes.Equal(as.ClientDataJSON, good.ClientDataJSON) {
				t.Fatal("variant not applied")
			}
			_, err := webauthn.Verify(as, credFor(a, 0), exp)
			if !errors.Is(err, webauthn.ErrChallenge) {
				t.Fatalf("err = %v, want ErrChallenge", err)
			}
		})
	}
}

func TestVerifyIgnoresUnknownClientDataFields(t *testing.T) {
	a := webauthntest.New(webauthn.AlgEdDSA)
	exp := testExpect()
	as := a.Assert(exp)
	// The edit invalidates the signature, so it is checked through the
	// challenge: reaching ErrSignature means every earlier check passed.
	as.ClientDataJSON = bytes.Replace(as.ClientDataJSON, []byte("{"), []byte(`{"extra":{"a":[1]},"other_keys_can_be_added_here":"x",`), 1)
	_, err := webauthn.Verify(as, credFor(a, 0), exp)
	if !errors.Is(err, webauthn.ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

func TestCheckPublicKey(t *testing.T) {
	for _, tc := range algs {
		if err := webauthn.CheckPublicKey(webauthntest.New(tc.alg).SPKI(), tc.alg); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// Every pairing of a key type with a different alg is refused.
	for _, key := range algs {
		spki := webauthntest.New(key.alg).SPKI()
		for _, alg := range algs {
			if alg.alg == key.alg {
				continue
			}
			if err := webauthn.CheckPublicKey(spki, alg.alg); !errors.Is(err, webauthn.ErrAlgorithm) {
				t.Errorf("%s key as %s: err = %v, want ErrAlgorithm", key.name, alg.name, err)
			}
		}
	}
	if err := webauthn.CheckPublicKey(webauthntest.New(webauthn.AlgEdDSA).SPKI(), 99); !errors.Is(err, webauthn.ErrAlgorithm) {
		t.Errorf("unsupported alg: err = %v, want ErrAlgorithm", err)
	}

	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&small.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := webauthn.CheckPublicKey(spki, webauthn.AlgRS256); !errors.Is(err, webauthn.ErrAlgorithm) {
		t.Errorf("RSA 1024: err = %v, want ErrAlgorithm", err)
	}

	for _, alg := range []int{webauthn.AlgEdDSA, webauthn.AlgES256, webauthn.AlgRS256} {
		if err := webauthn.CheckPublicKey([]byte("garbage"), alg); !errors.Is(err, webauthn.ErrMalformed) {
			t.Errorf("garbage alg %d: err = %v, want ErrMalformed", alg, err)
		}
	}
}

// FuzzVerify checks Verify never panics on arbitrary client data,
// authenticator data, and signature bytes, whatever the key type.
func FuzzVerify(f *testing.F) {
	exp := testExpect()
	auths := make([]*webauthntest.Authenticator, len(algs))
	creds := make([]webauthn.Credential, len(algs))
	for i, tc := range algs {
		auths[i] = webauthntest.New(tc.alg)
		creds[i] = credFor(auths[i], 0)
		as := auths[i].Assert(exp)
		f.Add(as.ClientDataJSON, as.AuthenticatorData, as.Signature)
	}
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add([]byte("{}"), make([]byte, 37), []byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, cd, ad, sig []byte) {
		for _, cred := range creds {
			webauthn.Verify(webauthn.Assertion{ClientDataJSON: cd, AuthenticatorData: ad, Signature: sig}, cred, exp)
		}
	})
}
