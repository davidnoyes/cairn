package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/release"
)

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

// keygen runs keygen and returns the secret and the public key it prints.
func keygen(t *testing.T) (secret, pub string) {
	t.Helper()
	var out bytes.Buffer
	if err := run([]string{"keygen"}, &out, env(nil)); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if v, ok := strings.CutPrefix(line, "CAIRN_RELEASE_KEY="); ok {
			secret = v
		}
		if v, ok := strings.CutPrefix(line, "public key: "); ok {
			pub = v
		}
	}
	if secret == "" || pub == "" {
		t.Fatalf("keygen printed no secret or public key:\n%s", out.String())
	}
	return secret, pub
}

func TestKeygenPrintsAMatchingPair(t *testing.T) {
	secret, pub := keygen(t)
	var out bytes.Buffer
	if err := run([]string{"public"}, &out, env(map[string]string{"CAIRN_RELEASE_KEY": secret})); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != pub {
		t.Errorf("public = %q, keygen said %q", got, pub)
	}
	if _, err := release.ParseKeys([]string{pub}); err != nil {
		t.Errorf("the public key does not parse as a release key: %v", err)
	}
	if other, _ := keygen(t); other == secret {
		t.Error("two keygen runs printed the same secret")
	}
}

func TestPublicNeedsTheKey(t *testing.T) {
	err := run([]string{"public"}, &bytes.Buffer{}, env(nil))
	if err == nil || !strings.Contains(err.Error(), "CAIRN_RELEASE_KEY") {
		t.Errorf("public with no key: %v, want an error naming CAIRN_RELEASE_KEY", err)
	}
}

func TestPublicRefusesAMalformedKey(t *testing.T) {
	short := e2e.B64(make([]byte, 31))
	for _, v := range []string{"not base64!", short} {
		err := run([]string{"public"}, &bytes.Buffer{}, env(map[string]string{"CAIRN_RELEASE_KEY": v}))
		if !errors.Is(err, e2e.ErrFormat) {
			t.Errorf("public with key %q: %v, want ErrFormat", v, err)
		}
	}
}

func TestSignWritesAManifestThePublicKeyOpens(t *testing.T) {
	secret, pub := keygen(t)
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := run([]string{"sign", "-version", "v1.2.3", "-out", path}, &bytes.Buffer{}, env(map[string]string{"CAIRN_RELEASE_KEY": secret})); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := release.ParseKeys([]string{pub})
	if err != nil {
		t.Fatal(err)
	}
	m, err := release.Open(data, keys)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if m.Version != "v1.2.3" || len(m.Assets) == 0 || len(m.Templates) == 0 {
		t.Errorf("manifest = version %q, %d assets, %d templates", m.Version, len(m.Assets), len(m.Templates))
	}
}

func TestSignNeedsAVersionAndAKey(t *testing.T) {
	secret, _ := keygen(t)
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := run([]string{"sign", "-out", path}, &bytes.Buffer{}, env(map[string]string{"CAIRN_RELEASE_KEY": secret})); err == nil {
		t.Error("sign with no -version succeeded")
	}
	if err := run([]string{"sign", "-version", "v1", "-out", path}, &bytes.Buffer{}, env(nil)); err == nil {
		t.Error("sign with no CAIRN_RELEASE_KEY succeeded")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused sign wrote %s", path)
	}
}

func TestUnknownCommand(t *testing.T) {
	if err := run([]string{"frobnicate"}, &bytes.Buffer{}, env(nil)); err == nil {
		t.Error("an unknown command succeeded")
	}
	if err := run(nil, &bytes.Buffer{}, env(nil)); err == nil {
		t.Error("no command succeeded")
	}
}
