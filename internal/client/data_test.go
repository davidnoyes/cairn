package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/server"
	"github.com/aloisdeniel/cairn/internal/sqlrun"
)

// dataEnv is a sharing world with one pushed version, which ada owns.
type dataEnv struct {
	*sharing
	version string
}

func newDataEnv(t *testing.T) *dataEnv {
	t.Helper()
	s := newSharing(t)
	v, err := s.ada.Push(s.artifact, "", siteDir(t), "v1", "")
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	return &dataEnv{sharing: s, version: v.ID}
}

func (e *dataEnv) open(t *testing.T, c *Client, write bool) *Data {
	t.Helper()
	d, err := c.OpenData(e.artifact, e.version, write)
	if err != nil {
		t.Fatalf("OpenData: %v", err)
	}
	return d
}

// exec runs one statement and returns its result.
func exec(t *testing.T, d *Data, sql string, params ...any) *sqlrun.Result {
	t.Helper()
	res, err := d.Exec([]sqlrun.Statement{{SQL: sql, Params: params}})
	if err != nil {
		t.Fatalf("Exec(%q): %v", sql, err)
	}
	return res[0]
}

// tamper wraps c's transport. before may answer a request itself, and after
// may change the response.
type tamper struct {
	base   http.RoundTripper
	before func(*http.Request) *http.Response
	after  func(*http.Request, *http.Response)
}

func (tp *tamper) RoundTrip(req *http.Request) (*http.Response, error) {
	if tp.before != nil {
		if resp := tp.before(req); resp != nil {
			return resp, nil
		}
	}
	resp, err := tp.base.RoundTrip(req)
	if err == nil && tp.after != nil {
		tp.after(req, resp)
	}
	return resp, err
}

func intercept(c *Client, tp *tamper) {
	tp.base = http.DefaultTransport
	c.HTTP = &http.Client{Transport: tp}
}

func replyJSON(req *http.Request, status int, header http.Header, body string) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header, Request: req, Body: io.NopCloser(strings.NewReader(body))}
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func setBody(resp *http.Response, b []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
}

func envelopeOf(t *testing.T, header string) e2e.Envelope {
	t.Helper()
	raw, err := e2e.UnB64(header)
	if err != nil {
		t.Fatal(err)
	}
	var env e2e.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	return env
}

func setEnvelope(t *testing.T, resp *http.Response, env e2e.Envelope) {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	resp.Header.Set("X-Cairn-Record", e2e.B64(b))
}

func signAs(t *testing.T, k *UnlockedKeys, purpose string, body any) e2e.Envelope {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, purpose, b)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// isDB says whether req reads the latest revision.
func isDB(req *http.Request) bool {
	return req.Method == "GET" && strings.HasSuffix(req.URL.Path, "/db")
}

// resignRevision re-signs the revision in resp with k, after mutate changed
// its body. The body starts as the revision's own, with the hash of the blob
// as it now is.
func resignRevision(t *testing.T, k *UnlockedKeys, resp *http.Response, blob []byte, mutate func(*e2e.RevisionBody)) {
	t.Helper()
	var b e2e.RevisionBody
	if err := e2e.DecodeStrict(envelopeOf(t, resp.Header.Get("X-Cairn-Record")).Body, &b); err != nil {
		t.Fatal(err)
	}
	b.SHA256 = e2e.BodyHash(blob)
	mutate(&b)
	setEnvelope(t, resp, signAs(t, k, "revision", b))
	setBody(resp, blob)
}

func TestDataRevisionsRoundTrip(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	if _, _, err := d.Latest(); !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("Latest before any write: %v, want ErrNoDatabase", err)
	}
	if _, err := d.PutRevision([]byte("one"), 0); err != nil {
		t.Fatalf("PutRevision: %v", err)
	}
	if rev, err := d.PutRevision([]byte("two"), 1); err != nil || rev != 2 {
		t.Fatalf("PutRevision 2 = %d, %v", rev, err)
	}
	plain, rev, err := d.Latest()
	if err != nil || rev != 2 || string(plain) != "two" {
		t.Fatalf("Latest = %q, %d, %v", plain, rev, err)
	}
	revs, err := d.Revisions()
	if err != nil || len(revs) != 2 || revs[0].Revision != 2 || revs[1].Revision != 1 || revs[0].Epoch != 1 {
		t.Fatalf("Revisions = %+v, %v", revs, err)
	}
	var conflict *ConflictError
	if _, err := d.PutRevision([]byte("stale"), 1); !errors.As(err, &conflict) || conflict.Latest != 2 {
		t.Fatalf("a write on a stale base = %v, want a ConflictError at 2", err)
	}
	// A revision a reader of the artifact can open: a viewer reads it.
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if plain, _, err := e.open(t, e.bob, false).Latest(); err != nil || string(plain) != "two" {
		t.Fatalf("a viewer's Latest = %q, %v", plain, err)
	}
}

func TestOpenDataRefusals(t *testing.T) {
	e := newDataEnv(t)
	if _, err := e.ada.OpenData(e.artifact, "00000000-0000-4000-8000-000000000000", false); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("an unknown version: %v", err)
	}
	empty, err := e.ada.CreateArtifact("empty", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ada.OpenData(empty.ID, "", false); err == nil || !strings.Contains(err.Error(), "no versions") {
		t.Errorf("an artifact with no versions: %v", err)
	}
	d, err := e.ada.OpenData(e.artifact, "", false)
	if err != nil || d.Version().ID != e.version {
		t.Errorf("the latest version = %v, %v", d, err)
	}
}

// TestRevisionReadRefusals is the read side of the refusal matrix: each case
// has the server answer with a revision that fails exactly one check.
func TestRevisionReadRefusals(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	if _, err := d.PutRevision([]byte("the database"), 0); err != nil {
		t.Fatal(err)
	}
	adaKeys := mustUnlock(t, e.ada)
	bobKeys := mustUnlock(t, e.bob)

	cases := []struct {
		name string
		want string
		fn   func(t *testing.T, resp *http.Response, blob []byte)
	}{
		{"bad signature", "does not verify", func(t *testing.T, resp *http.Response, blob []byte) {
			env := envelopeOf(t, resp.Header.Get("X-Cairn-Record"))
			env.Sig[0] ^= 1
			setEnvelope(t, resp, env)
		}},
		{"signer not a writer", "may not write", func(t *testing.T, resp *http.Response, blob []byte) {
			resignRevision(t, bobKeys, resp, blob, func(*e2e.RevisionBody) {})
			resp.Header.Set("X-Cairn-Signer-Key", e2e.B64(bobKeys.Ed25519Pub))
		}},
		{"wrong key", "may not write", func(t *testing.T, resp *http.Response, blob []byte) {
			resp.Header.Set("X-Cairn-Signer-Key", e2e.B64(bytes.Repeat([]byte{7}, 32)))
		}},
		{"signer key not 32 bytes", "not 32 bytes", func(t *testing.T, resp *http.Response, blob []byte) {
			resp.Header.Set("X-Cairn-Signer-Key", e2e.B64([]byte{1, 2, 3}))
		}},
		{"another artifact", "another artifact", func(t *testing.T, resp *http.Response, blob []byte) {
			resignRevision(t, adaKeys, resp, blob, func(b *e2e.RevisionBody) { b.Artifact = e.version })
		}},
		{"another version", "another version", func(t *testing.T, resp *http.Response, blob []byte) {
			resignRevision(t, adaKeys, resp, blob, func(b *e2e.RevisionBody) { b.Version = e.artifact })
		}},
		{"another revision", "another revision", func(t *testing.T, resp *http.Response, blob []byte) {
			resignRevision(t, adaKeys, resp, blob, func(b *e2e.RevisionBody) { b.Revision = 9 })
		}},
		{"another epoch than the server named", "another epoch than the server named", func(t *testing.T, resp *http.Response, blob []byte) {
			resp.Header.Set("X-Cairn-Epoch", "2")
		}},
		{"no key for the epoch", "no key for epoch 7", func(t *testing.T, resp *http.Response, blob []byte) {
			resignRevision(t, adaKeys, resp, blob, func(b *e2e.RevisionBody) { b.Epoch = 7 })
			resp.Header.Set("X-Cairn-Epoch", "7")
		}},
		{"blob does not match", "does not match its signature", func(t *testing.T, resp *http.Response, blob []byte) {
			setBody(resp, append(bytes.Clone(blob[:len(blob)-1]), blob[len(blob)-1]^1))
		}},
		{"blob sealed for another revision", "does not open", func(t *testing.T, resp *http.Response, blob []byte) {
			// Valid signature over a blob the context does not open.
			other, err := e2e.SealBlob(bytes.NewReader(bytes.Repeat([]byte{1}, 4096)), d.aks[1], e2e.BlobContext{
				Artifact: e.artifact, Version: e.version, Kind: "database", Name: "5"}, []byte("x"))
			if err != nil {
				t.Fatal(err)
			}
			resignRevision(t, adaKeys, resp, other, func(*e2e.RevisionBody) {})
		}},
		{"revision header not a number", "revision is not a number", func(t *testing.T, resp *http.Response, blob []byte) {
			resp.Header.Set("X-Cairn-Revision", "01")
		}},
		{"epoch header not a number", "epoch is not a number", func(t *testing.T, resp *http.Response, blob []byte) {
			resp.Header.Set("X-Cairn-Epoch", "-1")
		}},
		{"record not an envelope", "not an envelope", func(t *testing.T, resp *http.Response, blob []byte) {
			resp.Header.Set("X-Cairn-Record", e2e.B64([]byte("{}")))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
			intercept(c, &tamper{after: func(req *http.Request, resp *http.Response) {
				if isDB(req) && resp.StatusCode == 200 {
					blob := readBody(t, resp)
					setBody(resp, blob)
					tc.fn(t, resp, blob)
				}
			}})
			dd := e.open(t, c, false)
			_, _, err := dd.Latest()
			if !errors.Is(err, ErrUnverified) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Latest = %v, want an ErrUnverified naming %q", err, tc.want)
			}
		})
	}
}

// mustAPIKeyOf is the full API key of c, so a second client can sign in as it.
func mustAPIKeyOf(t *testing.T, c *Client) string {
	t.Helper()
	return c.Key.Full
}

func TestRevisionBelowTheVersionsEpochIsRefused(t *testing.T) {
	e := newDataEnv(t)
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ada.Unshare(e.artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	// A version pushed under epoch 2; a revision signed under epoch 1 is below it.
	v, err := e.ada.Push(e.artifact, "", siteDir(t), "v2", "")
	if err != nil || v.Epoch != 2 {
		t.Fatalf("Push = %+v, %v", v, err)
	}
	e.version = v.ID
	d := e.open(t, e.ada, true)
	if _, err := d.PutRevision([]byte("data"), 0); err != nil {
		t.Fatal(err)
	}
	k := mustUnlock(t, e.ada)
	c := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	intercept(c, &tamper{after: func(req *http.Request, resp *http.Response) {
		if isDB(req) && resp.StatusCode == 200 {
			resignRevision(t, k, resp, readBody(t, resp), func(b *e2e.RevisionBody) { b.Epoch = 1 })
			resp.Header.Set("X-Cairn-Epoch", "1")
		}
	}})
	if _, _, err := e.open(t, c, false).Latest(); !errors.Is(err, ErrUnverified) || !strings.Contains(err.Error(), "before the version") {
		t.Fatalf("Latest = %v, want a refusal for an epoch before the version", err)
	}
}

func TestLatestRefusesARollback(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	d.PutRevision([]byte("one"), 0)
	d.PutRevision([]byte("two"), 1)
	// The server answers a read of the latest revision with revision 1.
	c := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	serveOld := false
	c.HTTP = &http.Client{Transport: rewritePath(func(req *http.Request) {
		if serveOld && isDB(req) {
			req.URL.Path += "/revisions/1"
		}
	})}
	dd := e.open(t, c, false)
	if plain, rev, err := dd.Latest(); err != nil || rev != 2 || string(plain) != "two" {
		t.Fatalf("Latest = %q, %d, %v", plain, rev, err)
	}
	serveOld = true
	if _, _, err := dd.Latest(); !errors.Is(err, ErrUnverified) || !strings.Contains(err.Error(), "already seen") {
		t.Fatalf("Latest after a rollback = %v, want a refusal", err)
	}
}

// rewritePath is a transport that lets fn change each request first.
type rewritePath func(*http.Request)

func (f rewritePath) RoundTrip(req *http.Request) (*http.Response, error) {
	f(req)
	return http.DefaultTransport.RoundTrip(req)
}

func TestFilesRoundTrip(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	if _, err := d.GetFile("none.txt"); !errors.Is(err, ErrFileNotFound) {
		t.Errorf("GetFile of a missing path = %v", err)
	}
	if err := d.DeleteFile("none.txt"); !errors.Is(err, ErrFileNotFound) {
		t.Errorf("DeleteFile of a missing path = %v", err)
	}
	for _, p := range []string{"", "a//b", "./a", "a/../b", `a\b`, "a/", "/a", "a\x00b", "\xff"} {
		if _, err := d.PutFile(p, nil); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("PutFile(%q) = %v, want ErrInvalidPath", p, err)
		}
		if _, err := d.GetFile(p); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("GetFile(%q) = %v, want ErrInvalidPath", p, err)
		}
		if err := d.DeleteFile(p); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("DeleteFile(%q) = %v, want ErrInvalidPath", p, err)
		}
	}
	info, err := d.PutFile("notes/hello.txt", []byte("hello file"))
	if err != nil || info.Size != 10 || info.Path != "notes/hello.txt" {
		t.Fatalf("PutFile = %+v, %v", info, err)
	}
	d.PutFile("a.txt", []byte("a"))
	d.PutFile("notes/hello.txt", []byte("hello again, longer"))
	files, err := d.ListFiles()
	if err != nil || len(files) != 2 || files[0].Path != "a.txt" || files[1].Path != "notes/hello.txt" || files[1].Size != 19 {
		t.Fatalf("ListFiles = %+v, %v", files, err)
	}
	got, err := d.GetFile("notes/hello.txt")
	if err != nil || string(got) != "hello again, longer" {
		t.Fatalf("GetFile = %q, %v", got, err)
	}
	if err := d.DeleteFile("notes/hello.txt"); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	if files, _ := d.ListFiles(); len(files) != 1 {
		t.Fatalf("ListFiles after delete = %+v", files)
	}
	// The server holds no name: its list shows addresses only.
	raw, err := d.entries()
	if err != nil || len(raw) != 1 || strings.Contains(raw[0].Address, "a.txt") || !addressRe.MatchString(raw[0].Address) {
		t.Fatalf("server list = %+v, %v", raw, err)
	}
}

// listTamper changes the file list the server answers.
func listTamper(t *testing.T, c *Client, fn func(items []map[string]any)) {
	t.Helper()
	intercept(c, &tamper{after: func(req *http.Request, resp *http.Response) {
		if req.Method == "GET" && strings.HasSuffix(req.URL.Path, "/files") && resp.StatusCode == 200 {
			var items []map[string]any
			if err := json.Unmarshal(readBody(t, resp), &items); err != nil {
				t.Fatal(err)
			}
			fn(items)
			b, _ := json.Marshal(items)
			setBody(resp, b)
		}
	}})
}

func envMap(t *testing.T, env e2e.Envelope) map[string]any {
	t.Helper()
	b, _ := json.Marshal(env)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func mapEnv(t *testing.T, v any) e2e.Envelope {
	t.Helper()
	b, _ := json.Marshal(v)
	var env e2e.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	return env
}

// TestFileListRefusals has the server list one file whose entry fails one
// check; the entry is left out, with a warning, and the other file stays.
func TestFileListRefusals(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	d.PutFile("good.txt", []byte("good"))
	d.PutFile("bad.txt", []byte("bad"))
	k := mustUnlock(t, e.ada)
	badAddr, _ := d.addressAt(1, "bad.txt")
	otherAddr, _ := d.addressAt(1, "good.txt")

	// recordFor builds a record body for the bad entry, changed by mutate.
	recordFor := func(kind string, blob []byte, mutate func(*e2e.RecordBody)) map[string]any {
		b := e2e.RecordBody{V: 1, Artifact: e.artifact, Version: e.version, Kind: kind, Name: badAddr, Epoch: 1, SHA256: e2e.BodyHash(blob)}
		mutate(&b)
		return envMap(t, signAs(t, k, "record", b))
	}
	cases := []struct {
		name string
		want string
		fn   func(t *testing.T, item map[string]any)
	}{
		{"bad signature", "does not verify", func(t *testing.T, item map[string]any) {
			env := mapEnv(t, item["record"])
			env.Sig[0] ^= 1
			item["record"] = envMap(t, env)
		}},
		{"signer not a writer", "may not write", func(t *testing.T, item map[string]any) {
			item["signerKey"] = e2e.B64(mustUnlock(t, e.bob).Ed25519Pub)
		}},
		{"another artifact", "another artifact", func(t *testing.T, item map[string]any) {
			item["record"] = recordFor("file", nil, func(b *e2e.RecordBody) { b.Artifact = e.version })
		}},
		{"another version", "another version", func(t *testing.T, item map[string]any) {
			item["record"] = recordFor("file", nil, func(b *e2e.RecordBody) { b.Version = e.artifact })
		}},
		{"another kind", "another kind", func(t *testing.T, item map[string]any) {
			item["record"] = recordFor("file-meta", nil, func(*e2e.RecordBody) {})
		}},
		{"another address", "another address", func(t *testing.T, item map[string]any) {
			item["record"] = recordFor("file", nil, func(b *e2e.RecordBody) { b.Name = otherAddr })
		}},
		{"no key for the epoch", "no key for epoch 6", func(t *testing.T, item map[string]any) {
			item["epoch"] = 6
			item["record"] = recordFor("file", nil, func(b *e2e.RecordBody) { b.Epoch = 6 })
		}},
		{"metadata does not match its signature", "does not match its signature", func(t *testing.T, item map[string]any) {
			meta, _ := e2e.UnB64(item["meta"].(string))
			meta[len(meta)-1] ^= 1
			item["meta"] = e2e.B64(meta)
		}},
		{"address not hex", "not 64 hex", func(t *testing.T, item map[string]any) {
			item["address"] = "bad"
		}},
		{"metadata moved to another file's address", "belongs to another file", func(t *testing.T, item map[string]any) {
			// A signer who seals the metadata of another path under this
			// address: every signature and context is right, the path is not.
			meta, err := e2e.SealBlob(bytes.NewReader(bytes.Repeat([]byte{2}, 4096)), d.aks[1], e2e.BlobContext{
				Artifact: e.artifact, Version: e.version, Kind: "file-meta", Name: badAddr},
				[]byte(`{"v":1,"path":"good.txt","size":4,"modifiedAt":"2026-01-01T00:00:00.000Z"}`))
			if err != nil {
				t.Fatal(err)
			}
			item["meta"] = e2e.B64(meta)
			item["metaRecord"] = recordFor("file-meta", meta, func(*e2e.RecordBody) {})
		}},
		{"metadata is not strict JSON", "does not decode", func(t *testing.T, item map[string]any) {
			meta, err := e2e.SealBlob(bytes.NewReader(bytes.Repeat([]byte{2}, 4096)), d.aks[1], e2e.BlobContext{
				Artifact: e.artifact, Version: e.version, Kind: "file-meta", Name: badAddr},
				[]byte(`{"v":1,"path":"bad.txt","size":3,"modifiedAt":"x","extra":1}`))
			if err != nil {
				t.Fatal(err)
			}
			item["meta"] = e2e.B64(meta)
			item["metaRecord"] = recordFor("file-meta", meta, func(*e2e.RecordBody) {})
		}},
		{"metadata path invalid", "path is not valid", func(t *testing.T, item map[string]any) {
			meta, err := e2e.SealBlob(bytes.NewReader(bytes.Repeat([]byte{2}, 4096)), d.aks[1], e2e.BlobContext{
				Artifact: e.artifact, Version: e.version, Kind: "file-meta", Name: badAddr},
				[]byte(`{"v":1,"path":"a/../b","size":3,"modifiedAt":"x"}`))
			if err != nil {
				t.Fatal(err)
			}
			item["meta"] = e2e.B64(meta)
			item["metaRecord"] = recordFor("file-meta", meta, func(*e2e.RecordBody) {})
		}},
		{"metadata version", "version unsupported", func(t *testing.T, item map[string]any) {
			meta, err := e2e.SealBlob(bytes.NewReader(bytes.Repeat([]byte{2}, 4096)), d.aks[1], e2e.BlobContext{
				Artifact: e.artifact, Version: e.version, Kind: "file-meta", Name: badAddr},
				[]byte(`{"v":2,"path":"bad.txt","size":3,"modifiedAt":"x"}`))
			if err != nil {
				t.Fatal(err)
			}
			item["meta"] = e2e.B64(meta)
			item["metaRecord"] = recordFor("file-meta", meta, func(*e2e.RecordBody) {})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var warned []string
			old := warnf
			warnf = func(format string, a ...any) { warned = append(warned, fmt.Sprintf(format, a...)) }
			defer func() { warnf = old }()
			c := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
			listTamper(t, c, func(items []map[string]any) {
				for _, item := range items {
					if item["address"] == badAddr {
						tc.fn(t, item)
					}
				}
			})
			files, err := e.open(t, c, false).ListFiles()
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 1 || files[0].Path != "good.txt" {
				t.Fatalf("ListFiles = %+v, want only good.txt", files)
			}
			if len(warned) != 1 || !strings.Contains(warned[0], tc.want) {
				t.Fatalf("warnings = %q, want one naming %q", warned, tc.want)
			}
		})
	}
}

// TestFileReadRefusals is the same matrix for reading one file.
func TestFileReadRefusals(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	d.PutFile("f.txt", []byte("contents"))
	k := mustUnlock(t, e.ada)
	addr, _ := d.addressAt(1, "f.txt")
	resign := func(t *testing.T, resp *http.Response, blob []byte, mutate func(*e2e.RecordBody)) {
		b := e2e.RecordBody{V: 1, Artifact: e.artifact, Version: e.version, Kind: "file", Name: addr, Epoch: 1, SHA256: e2e.BodyHash(blob)}
		mutate(&b)
		setEnvelope(t, resp, signAs(t, k, "record", b))
		setBody(resp, blob)
	}
	cases := []struct {
		name string
		want string
		fn   func(t *testing.T, resp *http.Response, blob []byte)
	}{
		{"stored under another epoch", "another epoch than its address", func(t *testing.T, resp *http.Response, blob []byte) {
			resp.Header.Set("X-Cairn-Epoch", "3")
		}},
		{"another kind", "another kind", func(t *testing.T, resp *http.Response, blob []byte) {
			resign(t, resp, blob, func(b *e2e.RecordBody) { b.Kind = "file-meta" })
		}},
		{"another address", "another address", func(t *testing.T, resp *http.Response, blob []byte) {
			resign(t, resp, blob, func(b *e2e.RecordBody) { b.Name = strings.Repeat("a", 64) })
		}},
		{"blob does not match", "does not match its signature", func(t *testing.T, resp *http.Response, blob []byte) {
			setBody(resp, append(bytes.Clone(blob[:len(blob)-1]), blob[len(blob)-1]^1))
		}},
		{"signer not a writer", "may not write", func(t *testing.T, resp *http.Response, blob []byte) {
			resp.Header.Set("X-Cairn-Signer-Key", e2e.B64(mustUnlock(t, e.bob).Ed25519Pub))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
			intercept(c, &tamper{after: func(req *http.Request, resp *http.Response) {
				if req.Method == "GET" && strings.HasSuffix(req.URL.Path, "/files/"+addr) && resp.StatusCode == 200 {
					blob := readBody(t, resp)
					setBody(resp, blob)
					tc.fn(t, resp, blob)
				}
			}})
			if _, err := e.open(t, c, false).GetFile("f.txt"); !errors.Is(err, ErrUnverified) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("GetFile = %v, want an ErrUnverified naming %q", err, tc.want)
			}
		})
	}
}

func TestPublicWritesAcceptAnySigner(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	d.PutRevision([]byte("data"), 0)
	if _, err := e.ada.Public(e.artifact, true, ptr(true)); err != nil {
		t.Fatal(err)
	}
	// With publicWrites on, a signer who is no writer is accepted as far as
	// the signature goes: the signature must still verify.
	bobKeys := mustUnlock(t, e.bob)
	c := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	intercept(c, &tamper{after: func(req *http.Request, resp *http.Response) {
		if isDB(req) && resp.StatusCode == 200 {
			resignRevision(t, bobKeys, resp, readBody(t, resp), func(*e2e.RevisionBody) {})
			resp.Header.Set("X-Cairn-Signer-Key", e2e.B64(bobKeys.Ed25519Pub))
		}
	}})
	plain, _, err := e.open(t, c, false).Latest()
	if err != nil || string(plain) != "data" {
		t.Fatalf("Latest = %q, %v, want the data from a public writer", plain, err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestRestoreAcceptsARevisionFromARemovedEditor(t *testing.T) {
	e := newDataEnv(t)
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	bob := e.open(t, e.bob, true)
	if _, err := bob.PutRevision([]byte("from bob"), 0); err != nil {
		t.Fatalf("an editor's write: %v", err)
	}
	if _, err := e.open(t, e.ada, true).PutRevision([]byte("from ada"), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ada.Unshare(e.artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	d := e.open(t, e.ada, true)
	// Revision 1 is bob's, and he is no longer a writer: it does not read.
	f, err := d.fetchRevision(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.openRevision(f, d.now); !errors.Is(err, ErrUnverified) || !strings.Contains(err.Error(), "may not write") {
		t.Fatalf("a removed editor's revision opened as a current writer's: %v", err)
	}
	rev, err := d.Restore(1)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	plain, got, err := d.Latest()
	if err != nil || got != rev || string(plain) != "from bob" {
		t.Fatalf("Latest after the restore = %q, %d, %v", plain, got, err)
	}
	// The restore is signed by the caller, a current writer: it reads as any.
	if plain, _, err := e.open(t, e.ada, false).Latest(); err != nil || string(plain) != "from bob" {
		t.Fatalf("a fresh read = %q, %v", plain, err)
	}
	// An editor may restore, not only the owner.
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.open(t, e.bob, true).Restore(1); err != nil {
		t.Fatalf("an editor's restore: %v", err)
	}
}

func TestRestoreRefusals(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	d.PutRevision([]byte("data"), 0)
	if _, err := d.Restore(5); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("Restore of a revision the server does not keep = %v", err)
	}
	// A revision signed by someone the chain never listed is refused.
	bobKeys := mustUnlock(t, e.bob)
	c := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	intercept(c, &tamper{after: func(req *http.Request, resp *http.Response) {
		if req.Method == "GET" && strings.Contains(req.URL.Path, "/db/revisions/") && resp.StatusCode == 200 {
			resignRevision(t, bobKeys, resp, readBody(t, resp), func(*e2e.RevisionBody) {})
			resp.Header.Set("X-Cairn-Signer-Key", e2e.B64(bobKeys.Ed25519Pub))
		}
	}})
	if _, err := e.open(t, c, true).Restore(1); !errors.Is(err, ErrUnverified) {
		t.Errorf("Restore of a stranger's revision = %v, want ErrUnverified", err)
	}
}

func TestRestoreFollowsA412(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	d.PutRevision([]byte("one"), 0)
	d.PutRevision([]byte("two"), 1)
	// Another writer lands a revision between the restore's list and its PUT.
	other := e.open(t, e.ada, true)
	c := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	once := sync.Once{}
	intercept(c, &tamper{before: func(req *http.Request) *http.Response {
		if req.Method == "PUT" {
			once.Do(func() { other.PutRevision([]byte("three"), 2) })
		}
		return nil
	}})
	rev, err := e.open(t, c, true).Restore(1)
	if err != nil || rev != 4 {
		t.Fatalf("Restore = %d, %v, want revision 4", rev, err)
	}
	if plain, _, _ := d.Latest(); string(plain) != "one" {
		t.Errorf("Latest = %q, want the restored \"one\"", plain)
	}
}

func TestRestoreGivesUpAfterFiveTries(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	d.PutRevision([]byte("one"), 0)
	puts := 0
	c := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	intercept(c, &tamper{before: func(req *http.Request) *http.Response {
		if req.Method == "PUT" {
			puts++
			return replyJSON(req, 412, http.Header{"Etag": {`"` + strconv.Itoa(puts+1) + `"`}}, `{"error":"no"}`)
		}
		return nil
	}})
	if _, err := e.open(t, c, true).Restore(1); err == nil || !strings.Contains(err.Error(), "gave up after 5") || puts != 5 {
		t.Fatalf("Restore = %v after %d PUTs, want to give up after 5", err, puts)
	}
}

func TestDatabaseOverTheServersCapIsRefused(t *testing.T) {
	host, m := newTestServerWith(t, func(c *server.Config) { c.MaxDBMB = 1 })
	signupVerify(t, host, m, "ada@example.com", testPassword)
	out, err := New(host, "").Login("ada@example.com", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	ada := keyedFor(t, host, out.APIKey)
	a, err := ada.CreateArtifact("big", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.Push(a.ID, "", siteDir(t), "v1", ""); err != nil {
		t.Fatal(err)
	}
	d, err := ada.OpenData(a.ID, "", true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec([]sqlrun.Statement{
		{SQL: "CREATE TABLE t (b BLOB)"},
		{SQL: "INSERT INTO t VALUES (zeroblob(2000000))"},
	})
	var api *APIError
	if !errors.As(err, &api) || api.Status != 413 || !strings.Contains(err.Error(), "--max-db-mb") {
		t.Fatalf("Exec = %v, want the 413 naming --max-db-mb", err)
	}
	if _, _, err := d.Latest(); !errors.Is(err, ErrNoDatabase) {
		t.Errorf("a refused database was stored: %v", err)
	}
}

// TestRevisionSignerMustOwnTheKey has the server name a writer as the signer
// but supply another writer's key: the key must be one the record lists for the
// named signer, or one a rotation chain links to it.
func TestRevisionSignerMustOwnTheKey(t *testing.T) {
	e := newDataEnv(t)
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	d := e.open(t, e.ada, true)
	if _, err := d.PutRevision([]byte("data"), 0); err != nil {
		t.Fatal(err)
	}
	adaKeys, bobKeys := mustUnlock(t, e.ada), mustUnlock(t, e.bob)
	c := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	intercept(c, &tamper{after: func(req *http.Request, resp *http.Response) {
		if isDB(req) && resp.StatusCode == 200 {
			// Signed by ada's key, under bob's name.
			blob := readBody(t, resp)
			var b e2e.RevisionBody
			if err := e2e.DecodeStrict(envelopeOf(t, resp.Header.Get("X-Cairn-Record")).Body, &b); err != nil {
				t.Fatal(err)
			}
			env := signAs(t, adaKeys, "revision", b)
			env.Signer = bobKeys.UserID
			setEnvelope(t, resp, env)
			setBody(resp, blob)
		}
	}})
	if _, _, err := e.open(t, c, false).Latest(); !errors.Is(err, ErrUnverified) || !strings.Contains(err.Error(), "may not write") {
		t.Fatalf("Latest = %v, want a refusal: ada's key is not bob's", err)
	}
}

func TestRevisionReadByNumberChecksTheNumber(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	d.PutRevision([]byte("one"), 0)
	d.PutRevision([]byte("two"), 1)
	c := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	c.HTTP = &http.Client{Transport: rewritePath(func(req *http.Request) {
		req.URL.Path = strings.Replace(req.URL.Path, "/db/revisions/1", "/db/revisions/2", 1)
	})}
	if _, err := e.open(t, c, false).fetchRevision(1); !errors.Is(err, ErrUnverified) || !strings.Contains(err.Error(), "answered revision 2 for revision 1") {
		t.Fatalf("fetchRevision(1) = %v, want a refusal for the wrong revision", err)
	}
}

// TestDataIsSealedUnderTheSpecifiedContexts opens what the CLI stored the way
// the wire formats prescribe, so a context both sides share by mistake shows.
func TestDataIsSealedUnderTheSpecifiedContexts(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	if _, err := d.PutRevision([]byte("the database"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutFile("dir/f.txt", []byte("the file")); err != nil {
		t.Fatal(err)
	}
	ak := d.aks[1]
	f, err := d.fetchRevision(0)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := e2e.OpenBlob(ak, e2e.BlobContext{Artifact: e.artifact, Version: e.version, Kind: "database", Name: "1"}, f.blob); err != nil || string(plain) != "the database" {
		t.Errorf("the revision under {database, 1} = %q, %v", plain, err)
	}
	fk, err := e2e.FileKey(ak, e.artifact, 1)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := e2e.FileAddress(fk, "dir/f.txt")
	if err != nil {
		t.Fatal(err)
	}
	items, err := d.entries()
	if err != nil || len(items) != 1 || items[0].Address != addr {
		t.Fatalf("stored files = %+v, %v, want one at HMAC(fileKey, path)", items, err)
	}
	var rec, metaRec e2e.Envelope
	if err := json.Unmarshal(items[0].Record, &rec); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(items[0].MetaRecord, &metaRec); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		env  e2e.Envelope
		kind string
	}{{rec, "file"}, {metaRec, "file-meta"}} {
		var b e2e.RecordBody
		if err := e2e.OpenEnvelope(c.env, mustUnlock(t, e.ada).Ed25519Pub, "record", &b); err != nil {
			t.Fatal(err)
		}
		if b.Kind != c.kind || b.Name != addr || b.Epoch != 1 {
			t.Errorf("%s record body = %+v", c.kind, b)
		}
	}
	meta, _ := e2e.UnB64(items[0].Meta)
	plain, err := e2e.OpenBlob(ak, e2e.BlobContext{Artifact: e.artifact, Version: e.version, Kind: "file-meta", Name: addr}, meta)
	if err != nil || !strings.HasPrefix(string(plain), `{"v":1,"path":"dir/f.txt","size":8,"modifiedAt":"`) {
		t.Errorf("the metadata under {file-meta, address} = %q, %v", plain, err)
	}
	resp, err := d.c.send("GET", d.path("files/"+addr), nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	blob := readBody(t, resp)
	if plain, err := e2e.OpenBlob(ak, e2e.BlobContext{Artifact: e.artifact, Version: e.version, Kind: "file", Name: addr}, blob); err != nil || string(plain) != "the file" {
		t.Errorf("the file under {file, address} = %q, %v", plain, err)
	}
}
