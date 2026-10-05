// Package client is the Go client for the Cairn API, used by the CLI.
package client

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/google/uuid"
)

type Client struct {
	Host  string // e.g. http://localhost:8787
	Token string // JWT or API key bearer
	HTTP  *http.Client
	// Key is the full device API key, set by NewWithKey. Only it can unlock
	// the account's keys; a client without one can still call the API.
	Key *e2e.APIKey
	// Anchors keeps the keyring anchor across sign-outs. Reading or
	// writing the keyring without one is an error.
	Anchors AnchorStore
	// LinkToken, when set, is sent as X-Cairn-Link-Token (base64), which
	// opens a public artifact to its link's holder.
	LinkToken string
	// AcceptNewOwner says the person confirmed an administrator's handover of
	// an artifact with the people involved. A function that writes to such an
	// artifact then records the acknowledgement in the keyring and goes
	// ahead; without it, the function refuses with *HandoverNotAckedError.
	AcceptNewOwner bool
	// OnHandover, when set, is called each time VerifyArtifact finds an
	// administrator's handover in an artifact's chain, acknowledged or not,
	// so a command can show the notice.
	OnHandover func(artifactID string, n HandoverNotice)
}

func New(host, token string) *Client {
	return &Client{Host: strings.TrimSuffix(host, "/"), Token: token, HTTP: http.DefaultClient}
}

// NewWithKey builds a client from a full four-part API key: its bearer goes
// on the wire, and the key is kept to unlock the account's keys.
func NewWithKey(host string, key e2e.APIKey) *Client {
	c := New(host, apiKeyBearer(key.KeyID, key.AuthSecret))
	c.Key = &key
	return c
}

// APIError is a non-2xx response from the server.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s (%d)", e.Message, e.Status)
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

type apiError struct {
	Error string `json:"error"`
}

func (c *Client) do(method, path string, body io.Reader, contentType string, out any) error {
	return c.doWithHeaders(method, path, body, contentType, nil, out)
}

// doWithHeaders is do with extra request headers.
func (c *Client) doWithHeaders(method, path string, body io.Reader, contentType string, headers http.Header, out any) error {
	req, err := http.NewRequest(method, c.Host+path, body)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header[k] = v
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if c.LinkToken != "" {
		req.Header.Set("X-Cairn-Link-Token", c.LinkToken)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return errorFromResponse(method, path, resp)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// errorFromResponse is the APIError for a response with a status of 400 or
// more: the server's JSON error message, or a plain one naming the request.
func errorFromResponse(method, path string, resp *http.Response) *APIError {
	var apiErr apiError
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	json.Unmarshal(data, &apiErr)
	if apiErr.Error == "" {
		apiErr.Error = method + " " + path + " failed"
	}
	return &APIError{Status: resp.StatusCode, Message: apiErr.Error}
}

func (c *Client) doJSON(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	return c.do(method, path, body, "application/json", out)
}

// Auth. Signup, Login, Logout, password reset, and API key management live
// in account.go.

func (c *Client) Me() (*store.User, error) {
	var u store.User
	return &u, c.doJSON("GET", "/api/me", nil, &u)
}

func (c *Client) Users() ([]map[string]any, error) {
	var out []map[string]any
	return out, c.doJSON("GET", "/api/users", nil, &out)
}

// Artifacts

func (c *Client) ListArtifacts() ([]*store.Artifact, error) {
	var out []*store.Artifact
	return out, c.doJSON("GET", "/api/artifacts", nil, &out)
}

func (c *Client) GetArtifact(id string) (*store.Artifact, error) {
	var out store.Artifact
	return &out, c.doJSON("GET", "/api/artifacts/"+id, nil, &out)
}

func (c *Client) UpdateArtifact(id string, fields map[string]any) (*store.Artifact, error) {
	var out store.Artifact
	return &out, c.doJSON("PATCH", "/api/artifacts/"+id, fields, &out)
}

func (c *Client) DeleteArtifact(id string) error {
	return c.doJSON("DELETE", "/api/artifacts/"+id, nil, nil)
}

func (c *Client) AddResource(artifactID, typ, value string) error {
	return c.doJSON("POST", "/api/artifacts/"+artifactID+"/resources", map[string]string{"type": typ, "value": value}, nil)
}

// ResolveArtifact accepts an artifact id, a resource reference (e.g. a
// Claude session id — resolved server-side, ambiguity is an error) or an
// exact artifact name, and returns the artifact.
func (c *Client) ResolveArtifact(idOrName string) (*store.Artifact, error) {
	a, err := c.GetArtifact(idOrName)
	if err == nil {
		return a, nil
	}
	var apiErr *APIError
	// Fall through to name lookup only on plain not-found; an ambiguous
	// resource reference (409) or any other failure surfaces as-is.
	if !errors.As(err, &apiErr) || apiErr.Status != 404 {
		return nil, err
	}
	all, err := c.ListArtifacts()
	if err != nil {
		return nil, err
	}
	var matches []*store.Artifact
	for _, a := range all {
		if a.Name == idOrName {
			matches = append(matches, a)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no artifact with id or name %q", idOrName)
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("%d artifacts named %q — use the id", len(matches), idOrName)
	}
}

// Versions

func (c *Client) ListVersions(artifactID string) ([]*store.Version, error) {
	var out []*store.Version
	return out, c.doJSON("GET", "/api/artifacts/"+artifactID+"/versions", nil, &out)
}

// ErrEpochMoved means the artifact's epoch changed while the command ran, so
// the server refused the write.
var ErrEpochMoved = errors.New("the artifact moved to a new epoch; run the command again")

// ErrCannotPush means the verified chain lists the caller as neither the
// owner nor an editor, under their current keys.
var ErrCannotPush = errors.New("only the artifact's owner or an editor can push a version")

// Push seals dir's files and uploads them as a new version, or as a
// replacement of versionID when non-empty. It verifies the artifact's
// membership chain first, refuses a caller the chain does not list as owner
// or editor, and seals under the chain's current epoch, which the upload
// declares so the server refuses it if the epoch has moved since; it refuses
// itself when that epoch is below the one the keyring pins. Each file is a
// blob under a random ID, and the manifest listing them is signed with the
// caller's key and sealed the same way, so the server holds ciphertext only.
func (c *Client) Push(artifactID, versionID, dir, name, changelog string) (*store.Version, error) {
	files, err := pushFiles(dir)
	if err != nil {
		return nil, err
	}
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return nil, err
	}
	if err := c.checkHandover(k, artifactID, va); err != nil {
		return nil, err
	}
	if !approverOf(va.Chain.Latest, k) {
		return nil, ErrCannotPush
	}
	epoch := va.Chain.Latest.Epoch
	if err := e2e.CheckEncryptEpoch(va.Keyring.EpochPin(artifactID), epoch); err != nil {
		return nil, err
	}
	aks, err := c.callerAKs(k, artifactID, va.Chain)
	if err != nil {
		return nil, err
	}
	ak := aks[epoch]

	replace := versionID != ""
	if !replace {
		versionID = uuid.NewString()
	}
	contents := make(map[string][]byte, len(files))
	for _, f := range files {
		data, err := os.ReadFile(f.abs)
		if err != nil {
			return nil, err
		}
		contents[f.rel] = data
	}
	return c.uploadVersion(k, artifactID, versionID, replace, epoch, ak, contents, name, changelog)
}

// uploadVersion seals files, a map of slash path to content, under ak, the AK
// of epoch, signs the manifest listing them with k's key, and uploads them as
// versionID: a replacement when replace is set, else a new version. The upload
// declares epoch, so the server refuses it if the epoch has moved since.
func (c *Client) uploadVersion(k *UnlockedKeys, artifactID, versionID string, replace bool, epoch int, ak []byte, files map[string][]byte, name, changelog string) (*store.Version, error) {
	method, path := "POST", "/api/artifacts/"+artifactID+"/versions"
	if replace {
		method, path = "PUT", path+"/"+versionID
	}

	tmp, err := os.CreateTemp("", "cairn-push-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	mw := multipart.NewWriter(tmp)
	manifest := e2e.ManifestBody{V: 1, Artifact: artifactID, Version: versionID, Epoch: epoch, Files: make([]e2e.ManifestFile, 0, len(files))}
	paths := make([]string, 0, len(files))
	for rel := range files {
		paths = append(paths, rel)
	}
	slices.Sort(paths)
	for _, rel := range paths {
		data := files[rel]
		blob, err := e2e.SealBlob(rand.Reader, ak, e2e.BlobContext{Artifact: artifactID, Version: versionID, Kind: "content", Name: rel}, data)
		if err != nil {
			return nil, err
		}
		id, err := newBlobID()
		if err != nil {
			return nil, err
		}
		w, err := mw.CreateFormFile("blob", id)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(blob); err != nil {
			return nil, err
		}
		manifest.Files = append(manifest.Files, e2e.ManifestFile{Path: rel, Blob: id, Size: int64(len(data)), SHA256: e2e.BodyHash(blob)})
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "manifest", body)
	if err != nil {
		return nil, err
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	sealed, err := e2e.SealBlob(rand.Reader, ak, e2e.BlobContext{Artifact: artifactID, Version: versionID, Kind: "manifest"}, envJSON)
	if err != nil {
		return nil, err
	}
	w, err := mw.CreateFormFile("manifest", "manifest")
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(sealed); err != nil {
		return nil, err
	}
	meta, err := json.Marshal(map[string]any{
		"id": versionID, "epoch": epoch, "manifestHash": e2e.BodyHash(body), "name": name, "changelog": changelog,
	})
	if err != nil {
		return nil, err
	}
	if err := mw.WriteField("version", string(meta)); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	var out store.Version
	err = c.do(method, path, tmp, mw.FormDataContentType(), &out)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict && strings.Contains(apiErr.Message, "moved to a new epoch") {
		return nil, ErrEpochMoved
	}
	// The client cannot learn the server's limit, so it reports the server's
	// refusal rather than checking the size first.
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusRequestEntityTooLarge {
		return nil, fmt.Errorf("the upload is larger than the server's limit (--max-upload-mb on the server): %w", err)
	}
	return &out, err
}

// newBlobID is a blob ID: 32 lowercase hex characters from crypto/rand.
func newBlobID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CheckTree reports why dir cannot be pushed as a version, without
// contacting the server, so a caller can refuse before it creates anything.
func CheckTree(dir string) error {
	_, err := pushFiles(dir)
	return err
}

// pushFile is one file of a tree to push: its slash path in the version and
// where it is on disk.
type pushFile struct{ rel, abs string }

// checkUTF8Path refuses a path that is not valid UTF-8: json.Marshal would
// rewrite its bytes in the manifest while the blob is sealed under the name
// as it is on disk.
func checkUTF8Path(rel string) error {
	if !utf8.ValidString(rel) {
		return fmt.Errorf("%q is not valid UTF-8, so it cannot be a path in a version", rel)
	}
	return nil
}

// checkRelPaths refuses the first of rels, the slash paths of a tree's
// files, that is not a valid path in a version.
func checkRelPaths(rels []string) error {
	for _, rel := range rels {
		// First, because fs.ValidPath refuses invalid UTF-8 too, with a
		// message that does not say why.
		if err := checkUTF8Path(rel); err != nil {
			return err
		}
		if !fs.ValidPath(rel) || strings.Contains(rel, `\`) {
			return fmt.Errorf("%q is not a valid path in a version", rel)
		}
	}
	return nil
}

// pushFiles lists the regular files under dir and refuses a tree the server
// would not take as a version: no index.html at the root, a symlink or other
// special file, or a name that is not a valid slash path.
func pushFiles(dir string) ([]pushFile, error) {
	var files []pushFile
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !d.Type().IsRegular() {
			return fmt.Errorf("%q is not a regular file; symlinks and special files cannot be pushed", rel)
		}
		files = append(files, pushFile{rel: rel, abs: p})
		return nil
	})
	if err != nil {
		return nil, err
	}
	rels := make([]string, len(files))
	for i, f := range files {
		rels[i] = f.rel
	}
	if err := checkRelPaths(rels); err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(files, func(f pushFile) bool { return f.rel == "index.html" }) {
		return nil, errors.New("the directory must contain an index.html at its root")
	}
	return files, nil
}
