package release

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

func testKey(t *testing.T) (seed, pub []byte) {
	t.Helper()
	seed, pub, err := e2e.GenerateEd25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return seed, pub
}

func sampleManifest() Manifest {
	return Manifest{
		V:       1,
		Version: "v1.2.3",
		Assets: []Asset{
			{Origin: OriginApp, Path: "/app.mjs", SHA256: strings.Repeat("a", 64)},
			{Origin: OriginContent, Path: "/_cairn/boot.js", SHA256: strings.Repeat("b", 64)},
		},
		Templates: []Template{{Name: "login.html", Source: "<p>{{.Next}}</p>"}},
	}
}

func TestSignOpenRoundTrip(t *testing.T) {
	seed, pub := testKey(t)
	_, other := testKey(t)
	signed, err := Sign(seed, sampleManifest())
	if err != nil {
		t.Fatal(err)
	}
	m, err := Open(signed, [][]byte{other, pub})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if m.Version != "v1.2.3" || len(m.Assets) != 2 || m.Templates[0].Source != "<p>{{.Next}}</p>" {
		t.Errorf("round trip changed the manifest: %+v", m)
	}
}

func TestOpenRefusesAnUntrustedKey(t *testing.T) {
	seed, _ := testKey(t)
	_, other := testKey(t)
	signed, err := Sign(seed, sampleManifest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(signed, [][]byte{other}); !errors.Is(err, ErrUntrusted) {
		t.Errorf("Open with another key: %v, want ErrUntrusted", err)
	}
	if _, err := Open(signed, nil); !errors.Is(err, ErrNoKeys) {
		t.Errorf("Open with no keys: %v, want ErrNoKeys", err)
	}
}

func TestOpenRefusesAnotherPurpose(t *testing.T) {
	seed, pub := testKey(t)
	body, err := json.Marshal(sampleManifest())
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(seed, "release", "manifest", body)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(data, [][]byte{pub}); !errors.Is(err, ErrUntrusted) {
		t.Errorf("Open of a manifest-purpose signature: %v, want ErrUntrusted", err)
	}
}

func TestOpenRefusesATamperedBody(t *testing.T) {
	seed, pub := testKey(t)
	signed, err := Sign(seed, sampleManifest())
	if err != nil {
		t.Fatal(err)
	}
	var env e2e.Envelope
	if err := json.Unmarshal(signed, &env); err != nil {
		t.Fatal(err)
	}
	env.Body = bytes.Replace(env.Body, []byte("v1.2.3"), []byte("v1.2.4"), 1)
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(data, [][]byte{pub}); !errors.Is(err, ErrUntrusted) {
		t.Errorf("Open of a changed body: %v, want ErrUntrusted", err)
	}
}

func TestOpenRefusesAMalformedManifest(t *testing.T) {
	seed, pub := testKey(t)
	cases := map[string]func(m *Manifest){
		"version 2":        func(m *Manifest) { m.V = 2 },
		"no version name":  func(m *Manifest) { m.Version = "" },
		"no assets":        func(m *Manifest) { m.Assets = nil },
		"unknown origin":   func(m *Manifest) { m.Assets[0].Origin = "admin" },
		"relative path":    func(m *Manifest) { m.Assets[0].Path = "app.mjs" },
		"short hash":       func(m *Manifest) { m.Assets[0].SHA256 = "abc" },
		"uppercase hash":   func(m *Manifest) { m.Assets[0].SHA256 = strings.Repeat("A", 64) },
		"duplicate asset":  func(m *Manifest) { m.Assets[1] = m.Assets[0] },
		"unnamed template": func(m *Manifest) { m.Templates[0].Name = "" },
		"duplicate template": func(m *Manifest) {
			m.Templates = append(m.Templates, m.Templates[0])
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			m := sampleManifest()
			change(&m)
			body, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			env, err := e2e.NewEnvelope(seed, "release", Purpose, body)
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Open(data, [][]byte{pub}); !errors.Is(err, e2e.ErrFormat) {
				t.Errorf("Open: %v, want ErrFormat", err)
			}
		})
	}
}

func TestOpenRefusesAnUnknownField(t *testing.T) {
	seed, pub := testKey(t)
	body := []byte(`{"v":1,"version":"v1","assets":[{"origin":"app","path":"/a","sha256":"` + strings.Repeat("a", 64) + `"}],"templates":[],"extra":1}`)
	env, err := e2e.NewEnvelope(seed, "release", Purpose, body)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(data, [][]byte{pub}); !errors.Is(err, e2e.ErrFormat) {
		t.Errorf("Open: %v, want ErrFormat", err)
	}
}

func TestSignRefusesAMalformedManifest(t *testing.T) {
	seed, _ := testKey(t)
	for name, change := range map[string]func(m *Manifest){
		"relative path": func(m *Manifest) { m.Assets[0].Path = "app.mjs" },
		"version 2":     func(m *Manifest) { m.V = 2 },
	} {
		m := sampleManifest()
		change(&m)
		if _, err := Sign(seed, m); !errors.Is(err, e2e.ErrFormat) {
			t.Errorf("%s: Sign: %v, want ErrFormat", name, err)
		}
	}
}

func TestParseKeys(t *testing.T) {
	_, pub := testKey(t)
	keys, err := ParseKeys([]string{e2e.B64(pub)})
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0], pub) {
		t.Fatalf("ParseKeys: %v, %v", keys, err)
	}
	for _, bad := range []string{"", "not base64!", e2e.B64(pub[:31]), e2e.B64(make([]byte, 32))} {
		if _, err := ParseKeys([]string{bad}); err == nil {
			t.Errorf("ParseKeys(%q) accepted a bad key", bad)
		}
	}
}

func TestEmbeddedKeysParse(t *testing.T) {
	if _, err := ParseKeys(trustedKeys); err != nil {
		t.Errorf("a compiled-in release key does not parse: %v", err)
	}
}
