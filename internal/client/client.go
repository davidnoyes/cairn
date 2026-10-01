// Package client is the Go client for the Cairn API, used by the CLI.
package client

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/aloisdeniel/cairn/internal/versiondb"
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
		var apiErr apiError
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		json.Unmarshal(data, &apiErr)
		if apiErr.Error == "" {
			apiErr.Error = method + " " + path + " failed"
		}
		return &APIError{Status: resp.StatusCode, Message: apiErr.Error}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
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

// Push zips dir and uploads it as a new version, or replaces versionID when
// non-empty. It verifies the artifact's membership chain first and declares
// the chain's epoch on the write, so the server refuses it if the epoch has
// moved since; it refuses itself when that epoch is below the one the
// keyring pins.
func (c *Client) Push(artifactID, versionID, dir, name, changelog string) (*store.Version, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return nil, err
	}
	epoch := va.Chain.Latest.Epoch
	if err := e2e.CheckEncryptEpoch(va.Keyring.EpochPin(artifactID), epoch); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp("", "cairn-push-*.zip")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	mw := multipart.NewWriter(tmp)
	mw.WriteField("name", name)
	mw.WriteField("changelog", changelog)
	fw, err := mw.CreateFormFile("archive", "artifact.zip")
	if err != nil {
		return nil, err
	}
	if err := zipDir(fw, dir); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	method, path := "POST", "/api/artifacts/"+artifactID+"/versions"
	if versionID != "" {
		method, path = "PUT", path+"/"+versionID
	}
	var out store.Version
	hdr := http.Header{"X-Cairn-Epoch": {strconv.Itoa(epoch)}}
	err = c.doWithHeaders(method, path, tmp, mw.FormDataContentType(), hdr, &out)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict {
		return nil, ErrEpochMoved
	}
	return &out, err
}

// zipDir writes dir's regular files into a zip stream, preserving relative
// slash paths.
func zipDir(w io.Writer, dir string) error {
	zw := zip.NewWriter(w)
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // skip symlinks and specials; the server rejects them anyway
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		f, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		src, err := os.Open(p)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(f, src)
		return err
	})
	if err != nil {
		return err
	}
	return zw.Close()
}

// Shared database

func (c *Client) Query(artifactID, versionID, sqlText string, params []any) (*versiondb.Result, error) {
	var out versiondb.Result
	err := c.doJSON("POST", "/api/artifacts/"+artifactID+"/versions/"+versionID+"/db/query",
		versiondb.Statement{SQL: sqlText, Params: params}, &out)
	return &out, err
}

func (c *Client) Batch(artifactID, versionID string, stmts []versiondb.Statement) ([]*versiondb.Result, error) {
	var out []*versiondb.Result
	err := c.doJSON("POST", "/api/artifacts/"+artifactID+"/versions/"+versionID+"/db/batch",
		map[string]any{"statements": stmts}, &out)
	return out, err
}

// File storage

// FileInfo describes one file in a version's storage.
type FileInfo struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	ModifiedAt string `json:"modifiedAt"`
}

// filePath builds the API path for a stored file, escaping each segment.
func filePath(artifactID, versionID, name string) string {
	segs := strings.Split(name, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return "/api/artifacts/" + artifactID + "/versions/" + versionID + "/files/" + strings.Join(segs, "/")
}

func (c *Client) ListFiles(artifactID, versionID string) ([]FileInfo, error) {
	var out []FileInfo
	return out, c.doJSON("GET", "/api/artifacts/"+artifactID+"/versions/"+versionID+"/files", nil, &out)
}

func (c *Client) UploadFile(artifactID, versionID, name string, r io.Reader) (*FileInfo, error) {
	var out FileInfo
	return &out, c.do("PUT", filePath(artifactID, versionID, name), r, "application/octet-stream", &out)
}

// DownloadFile streams a stored file; the caller must close the reader.
func (c *Client) DownloadFile(artifactID, versionID, name string) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", c.Host+filePath(artifactID, versionID, name), nil)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		var apiErr apiError
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		json.Unmarshal(data, &apiErr)
		if apiErr.Error == "" {
			apiErr.Error = "download " + name + " failed"
		}
		return nil, &APIError{Status: resp.StatusCode, Message: apiErr.Error}
	}
	return resp.Body, nil
}

func (c *Client) DeleteFile(artifactID, versionID, name string) error {
	return c.doJSON("DELETE", filePath(artifactID, versionID, name), nil, nil)
}
