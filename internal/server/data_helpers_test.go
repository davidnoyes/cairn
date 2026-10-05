package server

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// A database revision or a stored file as the multipart request carries it.
// The server cannot read either, so these helpers seal real blobs and sign
// real records as an actor, and a test breaks one field to see a refusal.

type namedPart struct {
	name string
	data []byte
}

// multipartOf serializes parts in order.
func multipartOf(t *testing.T, parts ...namedPart) (contentType string, body []byte) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q`, p.name))
		w, err := mw.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(p.data)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return mw.FormDataContentType(), buf.Bytes()
}

// sendParts sends parts as method on path, with extra headers.
func (c *testClient) sendParts(method, path string, hdr map[string]string, parts ...namedPart) *http.Response {
	c.t.Helper()
	ct, body := multipartOf(c.t, parts...)
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", ct)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	c.setHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp
}

// sealFor seals plain as a blob in the given context under testAK.
func sealFor(t *testing.T, aid, vid, kind, name string, epoch int, plain []byte) []byte {
	t.Helper()
	blob, err := e2e.SealBlob(rand.Reader, testAK(aid, epoch), e2e.BlobContext{Artifact: aid, Version: vid, Kind: kind, Name: name}, plain)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

// signedBody signs body as signer with seed.
func signedBody(t *testing.T, seed []byte, signer, purpose string, body any) []byte {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(seed, signer, purpose, raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// revisionRequest is a well-formed PUT .../db that a test can alter.
type revisionRequest struct {
	a          actor
	aid, vid   string
	body       e2e.RevisionBody
	blob       []byte
	recordPart []byte // the record part; built from body when nil
	ifMatch    string
	seed       []byte // signs the record; the actor's own when nil
	signer     string // the record's signer; the actor's own when empty
}

// newRevision builds revision rev of version vid, sealed under epoch, naming
// ifMatch as the latest revision.
func newRevision(t *testing.T, a actor, aid, vid string, epoch, rev int, plain string) *revisionRequest {
	t.Helper()
	blob := sealFor(t, aid, vid, "database", strconv.Itoa(rev), epoch, []byte(plain))
	return &revisionRequest{
		a: a, aid: aid, vid: vid, blob: blob, ifMatch: fmt.Sprintf(`"%d"`, rev-1),
		body: e2e.RevisionBody{V: 1, Artifact: aid, Version: vid, Revision: rev, Epoch: epoch, SHA256: e2e.BodyHash(blob)},
	}
}

func (q *revisionRequest) record(t *testing.T) []byte {
	if q.recordPart != nil {
		return q.recordPart
	}
	seed, signer := q.seed, q.signer
	if seed == nil {
		seed = q.a.keys.seed
	}
	if signer == "" {
		signer = q.a.id
	}
	return signedBody(t, seed, signer, "revision", q.body)
}

// send issues the request.
func (q *revisionRequest) send(t *testing.T) *http.Response {
	t.Helper()
	hdr := map[string]string{}
	if q.ifMatch != "" {
		hdr["If-Match"] = q.ifMatch
	}
	return q.a.sendParts("PUT", "/api/artifacts/"+q.aid+"/versions/"+q.vid+"/db", hdr,
		namedPart{"record", q.record(t)}, namedPart{"blob", q.blob})
}

// writeDB writes the next revision of the version's database as a, at the
// artifact's current epoch, and returns the response.
func (a actor) writeDB(t *testing.T, aid, vid string) *http.Response {
	t.Helper()
	next := a.latestRevision(t, aid, vid) + 1
	return newRevision(t, a, aid, vid, a.currentEpoch(aid), next, "db "+strconv.Itoa(next)).send(t)
}

// mustWriteDB is writeDB, expecting it to land.
func (a actor) mustWriteDB(t *testing.T, aid, vid string) {
	t.Helper()
	resp := a.writeDB(t, aid, vid)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("write db: %d", resp.StatusCode)
	}
}

// latestRevision is the version's latest revision as a reads it, or 0.
func (a actor) latestRevision(t *testing.T, aid, vid string) int {
	t.Helper()
	resp := a.doRaw("GET", "/api/artifacts/"+aid+"/versions/"+vid+"/db", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0
	}
	n, _ := strconv.Atoi(resp.Header.Get("X-Cairn-Revision"))
	return n
}

// fileRequest is a well-formed PUT .../files/{address} that a test can alter.
type fileRequest struct {
	a            actor
	aid, vid     string
	address      string
	body, meta   e2e.RecordBody
	blob, metaBl []byte
	seed         []byte
	signer       string
	// recordPart and metaRecordPart replace the signed records when set.
	recordPart, metaRecordPart []byte
}

// testAddress derives a file's address from its path, as a client would.
func testAddress(t *testing.T, aid string, epoch int, path string) string {
	t.Helper()
	fk, err := e2e.FileKey(testAK(aid, epoch), aid, uint64(epoch))
	if err != nil {
		t.Fatal(err)
	}
	addr, err := e2e.FileAddress(fk, path)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

// newFile builds the file at path with content plain, sealed under epoch.
func newFile(t *testing.T, a actor, aid, vid string, epoch int, path, plain string) *fileRequest {
	t.Helper()
	addr := testAddress(t, aid, epoch, path)
	meta, err := json.Marshal(map[string]any{"v": 1, "path": path, "size": len(plain), "modifiedAt": time.Unix(0, 0).UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	blob := sealFor(t, aid, vid, "file", addr, epoch, []byte(plain))
	metaBlob := sealFor(t, aid, vid, "file-meta", addr, epoch, meta)
	return &fileRequest{
		a: a, aid: aid, vid: vid, address: addr, blob: blob, metaBl: metaBlob,
		body: e2e.RecordBody{V: 1, Artifact: aid, Version: vid, Kind: "file", Name: addr, Epoch: epoch, SHA256: e2e.BodyHash(blob)},
		meta: e2e.RecordBody{V: 1, Artifact: aid, Version: vid, Kind: "file-meta", Name: addr, Epoch: epoch, SHA256: e2e.BodyHash(metaBlob)},
	}
}

func (q *fileRequest) records(t *testing.T) (rec, metaRec []byte) {
	seed, signer := q.seed, q.signer
	if seed == nil {
		seed = q.a.keys.seed
	}
	if signer == "" {
		signer = q.a.id
	}
	rec, metaRec = q.recordPart, q.metaRecordPart
	if rec == nil {
		rec = signedBody(t, seed, signer, "record", q.body)
	}
	if metaRec == nil {
		metaRec = signedBody(t, seed, signer, "record", q.meta)
	}
	return rec, metaRec
}

func (q *fileRequest) path() string {
	return "/api/artifacts/" + q.aid + "/versions/" + q.vid + "/files/" + q.address
}

// send issues the request.
func (q *fileRequest) send(t *testing.T) *http.Response {
	t.Helper()
	rec, metaRec := q.records(t)
	return q.a.sendParts("PUT", q.path(), nil,
		namedPart{"record", rec}, namedPart{"blob", q.blob}, namedPart{"metaRecord", metaRec}, namedPart{"meta", q.metaBl})
}

// writeFile stores path as a at the artifact's current epoch and returns the
// response.
func (a actor) writeFile(t *testing.T, aid, vid, path, plain string) *http.Response {
	t.Helper()
	return newFile(t, a, aid, vid, a.currentEpoch(aid), path, plain).send(t)
}

// mustWriteFile is writeFile, expecting it to land; it returns the address.
func (a actor) mustWriteFile(t *testing.T, aid, vid, path, plain string) string {
	t.Helper()
	q := newFile(t, a, aid, vid, a.currentEpoch(aid), path, plain)
	resp := q.send(t)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("write file: %d", resp.StatusCode)
	}
	return q.address
}

// readBody returns the body of resp, closed.
func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// doRaw sends body as is, with no content type.
func (c *testClient) doRaw(method, path string, body []byte) *http.Response {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	c.setHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp
}
