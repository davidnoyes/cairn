package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/release"
	"github.com/aloisdeniel/cairn/internal/server/web"
)

func hexSum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestReleaseManifestCoversEveryEmbeddedFile: everything the web package
// embeds for a browser is in the manifest, so a file added to an embed list
// cannot ship unchecked.
func TestReleaseManifestCoversEveryEmbeddedFile(t *testing.T) {
	m, err := ReleaseManifest("v0.0.0-test")
	if err != nil {
		t.Fatal(err)
	}
	hashes := map[string]bool{}
	for _, a := range m.Assets {
		hashes[a.SHA256] = true
	}
	want := map[string][]byte{
		"cairn.js": web.CairnJS, "mermaid.js": web.MermaidJS, "sql-wasm.js": web.SqlJS,
		"sql-wasm.wasm": web.SqlWasm, "argon2.wasm": web.Argon2Wasm, "wasm_exec.js": web.WasmExecJS,
	}
	for _, embedded := range []fs.FS{web.Assets, web.ContentAssets} {
		err := fs.WalkDir(embedded, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := fs.ReadFile(embedded, p)
			want[p] = b
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for name, b := range want {
		if !hashes[hexSum(b)] {
			t.Errorf("%s is embedded but not in the release manifest", name)
		}
	}
	sources := map[string]string{}
	for _, tm := range m.Templates {
		sources[tm.Name] = tm.Source
	}
	pages, err := fs.Glob(web.Templates, "*.html")
	if err != nil || len(pages) == 0 {
		t.Fatalf("no templates: %v", err)
	}
	for _, name := range pages {
		b, _ := fs.ReadFile(web.Templates, name)
		if sources[name] != string(b) {
			t.Errorf("template %s is missing from the manifest or differs", name)
		}
	}
	if len(m.Templates) != len(pages) {
		t.Errorf("manifest lists %d templates, the binary embeds %d", len(m.Templates), len(pages))
	}
}

// TestReleaseManifestAssetsAreServed: every asset in the manifest is served,
// on its origin and at its path, as exactly the bytes the manifest hashes.
func TestReleaseManifestAssetsAreServed(t *testing.T) {
	w := newHostWorld(t)
	m, err := ReleaseManifest("v0.0.0-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.Sign(make([]byte, 32), m); err != nil {
		t.Fatalf("the manifest does not pass its own checks: %v", err)
	}
	for _, a := range m.Assets {
		host := "127.0.0.1:" + w.port
		path := a.Path
		if a.Origin == release.OriginContent {
			host = w.host(w.art.id)
			if path == "/_cairn/sw.js" {
				path += "?app=" + w.appOrigin()
			}
		}
		resp := w.viaHost(t, host, http.MethodGet, path, nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s %s: HTTP %d", a.Origin, a.Path, resp.StatusCode)
			continue
		}
		if got := hexSum([]byte(resp.body)); got != a.SHA256 {
			t.Errorf("%s %s: served sha256 %s, manifest %s", a.Origin, a.Path, got, a.SHA256)
		}
	}
}

func TestWellKnownReleaseWithoutASignedManifest(t *testing.T) {
	w := newHostWorld(t)
	old := release.Signed
	release.Signed = nil
	t.Cleanup(func() { release.Signed = old })

	resp := w.viaHost(t, "127.0.0.1:"+w.port, http.MethodGet, "/.well-known/cairn-release", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Manifest      json.RawMessage `json:"manifest"`
		AppOrigin     string          `json:"appOrigin"`
		ContentOrigin string          `json:"contentOrigin"`
	}
	if err := json.Unmarshal([]byte(resp.body), &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc.Manifest) != "null" {
		t.Errorf("manifest = %s, want null in a build with none", doc.Manifest)
	}
	if doc.AppOrigin != w.appOrigin() {
		t.Errorf("appOrigin = %q, want %q", doc.AppOrigin, w.appOrigin())
	}
	if want := "http://*.localhost:" + w.port; doc.ContentOrigin != want {
		t.Errorf("contentOrigin = %q, want %q", doc.ContentOrigin, want)
	}
}

func TestWellKnownReleaseServesTheEmbeddedManifest(t *testing.T) {
	w := newHostWorld(t)
	signed := []byte(`{"body":"e30","sig":"AA","signer":"release"}`)
	old := release.Signed
	release.Signed = signed
	t.Cleanup(func() { release.Signed = old })

	resp := w.viaHost(t, "127.0.0.1:"+w.port, http.MethodGet, "/.well-known/cairn-release", nil, nil)
	var doc struct {
		Manifest json.RawMessage `json:"manifest"`
	}
	if err := json.Unmarshal([]byte(resp.body), &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc.Manifest) != string(signed) {
		t.Errorf("manifest = %s, want the embedded bytes %s", doc.Manifest, signed)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
}

// TestWellKnownReleaseIsAppOriginOnly: a content host does not answer it,
// like every other app route.
func TestWellKnownReleaseIsAppOriginOnly(t *testing.T) {
	w := newHostWorld(t)
	resp := w.onContent(t, http.MethodGet, "/.well-known/cairn-release", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("content host: HTTP %d, want 404", resp.StatusCode)
	}
}
