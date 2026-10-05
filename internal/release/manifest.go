// Package release signs and checks the release manifest: the SHA-256 of
// every embedded file the server sends a browser, and the source of every
// HTML template it renders. CI signs it with the release key and embeds it in
// the binary; cairn verify fetches what a server serves and compares.
package release

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// Purpose is the signature purpose of a release manifest. See
// design/e2e-wire-formats.md "Signatures".
const Purpose = "release"

// The origins an asset is served from.
const (
	OriginApp     = "app"
	OriginContent = "content"
)

// Manifest is the signed body.
type Manifest struct {
	V         int        `json:"v"`
	Version   string     `json:"version"`
	Assets    []Asset    `json:"assets"`
	Templates []Template `json:"templates"`
}

// Asset is one file served as it is embedded: on which origin, at which
// path, and the lowercase hex SHA-256 of its bytes.
type Asset struct {
	Origin string `json:"origin"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Template is one HTML template, by file name, with its source.
type Template struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

var (
	// ErrNoKeys means there was no release key to check a manifest against.
	ErrNoKeys = errors.New("release: no release key to check the manifest against")
	// ErrUntrusted means no trusted release key signed the manifest.
	ErrUntrusted = errors.New("release: the manifest is not signed by a trusted release key")
)

// trustedKeys are the release public keys this binary trusts, base64url
// without padding. A maintainer adds theirs here; see deploy/gcp/README.md.
var trustedKeys = []string{}

// Signed is the signed manifest the release build embeds. It is empty in
// every other build, which then serves none.
//
//go:embed manifest.json
var Signed []byte

// TrustedKeys returns the compiled-in release keys.
func TrustedKeys() ([][]byte, error) {
	return ParseKeys(trustedKeys)
}

// ParseKeys decodes base64url release public keys, refusing any that is not
// a canonical Ed25519 point of prime order.
func ParseKeys(encoded []string) ([][]byte, error) {
	keys := make([][]byte, 0, len(encoded))
	for _, s := range encoded {
		k, err := e2e.UnB64(s)
		if err == nil {
			err = e2e.CheckSigningKey(k)
		}
		if err != nil {
			return nil, fmt.Errorf("release key %q: %w", s, err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// Sign checks m and signs it with the release key's seed, returning the
// envelope's JSON.
func Sign(seed []byte, m Manifest) ([]byte, error) {
	if err := m.check(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	env, err := e2e.NewEnvelope(seed, "release", Purpose, body)
	if err != nil {
		return nil, err
	}
	return json.Marshal(env)
}

// Open checks that one of keys signed data, then decodes and checks the
// manifest. The envelope's signer field is not trusted for anything.
func Open(data []byte, keys [][]byte) (*Manifest, error) {
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	var env e2e.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", e2e.ErrFormat, err)
	}
	var m Manifest
	for _, k := range keys {
		err := e2e.OpenEnvelope(env, k, Purpose, &m)
		if errors.Is(err, e2e.ErrDecrypt) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err = m.check(); err != nil {
			return nil, err
		}
		return &m, nil
	}
	return nil, ErrUntrusted
}

// check refuses a manifest a verifier could misread: anything but version 1,
// no assets, an asset on an unknown origin, a path that is not absolute, a
// hash that is not 64 lowercase hex digits, or the same asset or template
// listed twice.
func (m Manifest) check() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: release manifest: %s", e2e.ErrFormat, fmt.Sprintf(format, args...))
	}
	if m.V != 1 {
		return bad("version %d, want 1", m.V)
	}
	if m.Version == "" {
		return bad("no release version")
	}
	if len(m.Assets) == 0 {
		return bad("no assets")
	}
	seen := map[string]bool{}
	for _, a := range m.Assets {
		if a.Origin != OriginApp && a.Origin != OriginContent {
			return bad("asset %s: unknown origin %q", a.Path, a.Origin)
		}
		if !strings.HasPrefix(a.Path, "/") {
			return bad("asset path %q is not absolute", a.Path)
		}
		if b, err := hex.DecodeString(a.SHA256); err != nil || len(b) != 32 || hex.EncodeToString(b) != a.SHA256 {
			return bad("asset %s: sha256 %q is not 64 lowercase hex digits", a.Path, a.SHA256)
		}
		key := a.Origin + " " + a.Path
		if seen[key] {
			return bad("asset %s listed twice", key)
		}
		seen[key] = true
	}
	names := map[string]bool{}
	for _, t := range m.Templates {
		if t.Name == "" {
			return bad("a template has no name")
		}
		if names[t.Name] {
			return bad("template %s listed twice", t.Name)
		}
		names[t.Name] = true
	}
	return nil
}
