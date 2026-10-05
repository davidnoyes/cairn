package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// A version's database is a series of revisions, each the whole SQLite file
// sealed by a client. The server cannot read one: it checks the signed record
// that covers the blob, and keeps the bytes under dbs/{artifact}/{version}/.
// See design/e2e-api.md (Client-side database and files).

const (
	maxRecordBytes = 64 << 10 // a record envelope part
	maxMetaBytes   = 4 << 10  // a stored file's metadata blob
	// multipartSlack covers the boundaries and part headers around the
	// parts whose own sizes are capped.
	multipartSlack = 64 << 10
)

var (
	// An If-Match value is one quoted revision number: "0" for none.
	ifMatchPattern = regexp.MustCompile(`^"(0|[1-9][0-9]{0,8})"$`)
	// An address is hex(HMAC-SHA256), lowercase.
	addressPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func (s *Server) maxDBBytes() int64 { return s.cfg.MaxDBMB << 20 }

// dataRefusal is a write the server refuses, with the status to answer.
type dataRefusal struct {
	status int
	msg    string
}

func (e *dataRefusal) Error() string { return e.msg }

func refuse(status int, msg string) error { return &dataRefusal{status, msg} }

// writeRefusal answers err: a dataRefusal as its status, a store epoch
// refusal as 409, anything else as an internal error.
func (s *Server) writeRefusal(w http.ResponseWriter, err error) {
	var ref *dataRefusal
	if errors.As(err, &ref) {
		writeError(w, ref.status, ref.msg)
		return
	}
	s.writeStoreError(w, err, "artifact")
}

// bodyErr maps an error from reading the request body: a size refusal is
// 413, a failure of ours stays as is, anything else is a malformed request.
func bodyErr(err error) error {
	var perr *os.PathError
	switch {
	case isBodyError(err):
		return refuse(http.StatusRequestEntityTooLarge, "the request is over the maximum size")
	case errors.As(err, &perr):
		return err
	}
	return refuse(http.StatusBadRequest, "invalid multipart request: "+err.Error())
}

// nextPart returns the next part, as sent, which must be named name.
func nextPart(mr *multipart.Reader, name string) (*multipart.Part, error) {
	part, err := mr.NextRawPart()
	if err == io.EOF {
		return nil, refuse(http.StatusBadRequest, "the request has no '"+name+"' part")
	}
	if err != nil {
		return nil, bodyErr(err)
	}
	if part.FormName() != name {
		return nil, refuse(http.StatusBadRequest, fmt.Sprintf("expected the '%s' part, got '%s'", name, part.FormName()))
	}
	return part, nil
}

// noMoreParts refuses a request with a part after the last one it takes.
func noMoreParts(mr *multipart.Reader) error {
	part, err := mr.NextRawPart()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return bodyErr(err)
	}
	return refuse(http.StatusBadRequest, "unexpected part "+part.FormName())
}

// readSmall reads a part of at most limit bytes.
func readSmall(part io.Reader, limit int64, name string) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(part, limit+1))
	if err != nil {
		return nil, bodyErr(err)
	}
	if int64(len(b)) > limit {
		return nil, refuse(http.StatusRequestEntityTooLarge, fmt.Sprintf("the '%s' part is over %d bytes", name, limit))
	}
	return b, nil
}

// readEnvelope reads a record part: an envelope as JSON, decoded strictly.
func readEnvelope(part io.Reader, name string) (e2e.Envelope, error) {
	b, err := readSmall(part, maxRecordBytes, name)
	if err != nil {
		return e2e.Envelope{}, err
	}
	var env e2e.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return e2e.Envelope{}, refuse(http.StatusBadRequest, "invalid '"+name+"' part: "+err.Error())
	}
	return env, nil
}

// stagedBlob is a blob received into a temp file, awaiting its rename.
type stagedBlob struct {
	path string
	size int64
	sum  string // hex SHA-256 of the bytes
}

// receiveBlob copies a blob part into a temp file in dir, at most max bytes.
// It refuses one without the blob header. The caller removes the file unless
// it renames it into place.
func receiveBlob(part io.Reader, dir string, max int64, name string) (*stagedBlob, error) {
	notBlob := refuse(http.StatusBadRequest, "the '"+name+"' part "+errBlobShape.Error())
	head := make([]byte, 5) // magic and version byte
	if _, err := io.ReadFull(part, head); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, notBlob
		}
		return nil, bodyErr(err)
	}
	if !e2e.HasBlobHeader(head) {
		return nil, notBlob
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*stagedBlob, error) {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(io.MultiReader(bytes.NewReader(head), part), max+1))
	if err != nil {
		return fail(bodyErr(err))
	}
	if n > max {
		return fail(refuse(http.StatusRequestEntityTooLarge, fmt.Sprintf("the '%s' part is over %d MiB", name, max>>20)))
	}
	if n < int64(e2e.BlobMinSize) {
		return fail(notBlob)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return nil, err
	}
	return &stagedBlob{path: f.Name(), size: n, sum: hex.EncodeToString(h.Sum(nil))}, nil
}

// callerKey is the Ed25519 key the caller's records must verify under: the
// one in their current key bundle.
func (s *Server) callerKey(u *store.User) ([]byte, error) {
	b, err := s.store.BundleFor(u.ID)
	if err != nil {
		return nil, err
	}
	return b.Ed25519Pub, nil
}

// openRecord checks that env is signed by the caller under pub and decodes
// its body into out. A signer who is not the caller, or a signature that does
// not verify, is 403; a body that does not decode strictly is 400.
func openRecord(u *store.User, pub []byte, env e2e.Envelope, purpose string, out any) error {
	if env.Signer != u.ID {
		return refuse(http.StatusForbidden, "the record is not signed by you")
	}
	if err := e2e.OpenEnvelope(env, pub, purpose, out); err != nil {
		if errors.Is(err, e2e.ErrDecrypt) {
			return refuse(http.StatusForbidden, "the record's signature does not verify under your current key")
		}
		return refuse(http.StatusBadRequest, "invalid record: "+err.Error())
	}
	return nil
}

// setRecordHeaders adds the headers every revision and file answer carries.
func setRecordHeaders(w http.ResponseWriter, epoch int, record, signerKey []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Cairn-Epoch", strconv.Itoa(epoch))
	w.Header().Set("X-Cairn-Record", e2e.B64(record))
	w.Header().Set("X-Cairn-Signer-Key", e2e.B64(signerKey))
}

// serveBlobFile sends the stored blob at path.
func (s *Server) serveBlobFile(w http.ResponseWriter, r *http.Request, path string) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		s.log.Error("open stored data", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer f.Close()
	http.ServeContent(w, r, "", time.Time{}, f)
}

func revisionETag(rev int) string { return `"` + strconv.Itoa(rev) + `"` }

func (s *Server) revisionPath(aid, vid string, rev int) string {
	return filepath.Join(s.layout.VersionDBDir(aid, vid), strconv.Itoa(rev))
}

// serveRevision answers a read of revision rv.
func (s *Server) serveRevision(w http.ResponseWriter, r *http.Request, rv *store.DBRevision) {
	setRecordHeaders(w, rv.Epoch, rv.Record, rv.SignerKey)
	w.Header().Set("ETag", revisionETag(rv.Revision))
	w.Header().Set("X-Cairn-Revision", strconv.Itoa(rv.Revision))
	s.serveBlobFile(w, r, s.revisionPath(rv.ArtifactID, rv.VersionID, rv.Revision))
}

// handleGetDB returns the version's latest database revision.
func (s *Server) handleGetDB(w http.ResponseWriter, r *http.Request) {
	aid, vid := requestArtifact(r).ID, r.PathValue("vid")
	if _, err := s.store.VersionByID(aid, vid); err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	rv, err := s.store.LatestDBRevision(aid, vid)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "this version has no database yet")
		return
	}
	if err != nil {
		s.writeStoreError(w, err, "database")
		return
	}
	s.serveRevision(w, r, rv)
}

// handleGetDBRevision returns one revision still kept.
func (s *Server) handleGetDBRevision(w http.ResponseWriter, r *http.Request) {
	aid, vid := requestArtifact(r).ID, r.PathValue("vid")
	if _, err := s.store.VersionByID(aid, vid); err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	n, err := strconv.ParseUint(r.PathValue("rev"), 10, 31)
	if err != nil {
		writeError(w, http.StatusNotFound, "revision not found")
		return
	}
	rv, err := s.store.DBRevisionByNumber(aid, vid, int(n))
	if err != nil {
		s.writeStoreError(w, err, "revision")
		return
	}
	s.serveRevision(w, r, rv)
}

// handleListDBRevisions lists the revisions kept, newest first.
func (s *Server) handleListDBRevisions(w http.ResponseWriter, r *http.Request) {
	aid, vid := requestArtifact(r).ID, r.PathValue("vid")
	if _, err := s.store.VersionByID(aid, vid); err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	revs, err := s.store.ListDBRevisions(aid, vid)
	if err != nil {
		s.writeStoreError(w, err, "revisions")
		return
	}
	writeJSON(w, http.StatusOK, revs)
}

// latestRevisionNumber is the version's latest revision, or 0 for none.
func (s *Server) latestRevisionNumber(aid, vid string) (int, error) {
	rv, err := s.store.LatestDBRevision(aid, vid)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return rv.Revision, nil
}

// writePreconditionFailed answers 412 with the latest revision's ETag.
func writePreconditionFailed(w http.ResponseWriter, latest int) {
	w.Header().Set("ETag", revisionETag(latest))
	writeError(w, http.StatusPreconditionFailed, "If-Match does not name the latest revision")
}

// handlePutDB adds a database revision. See design/e2e-api.md (Database
// revisions) for the order of the refusals.
func (s *Server) handlePutDB(w http.ResponseWriter, r *http.Request) {
	aid, vid := requestArtifact(r).ID, r.PathValue("vid")
	if _, err := s.store.VersionByID(aid, vid); err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	m := ifMatchPattern.FindStringSubmatch(r.Header.Get("If-Match"))
	if m == nil {
		writeError(w, http.StatusPreconditionRequired, `If-Match must name the latest revision as a quoted number, or "0" for none`)
		return
	}
	ifMatch, _ := strconv.Atoi(m[1])
	latest, err := s.latestRevisionNumber(aid, vid)
	if err != nil {
		s.writeStoreError(w, err, "database")
		return
	}
	if latest != ifMatch {
		writePreconditionFailed(w, latest)
		return
	}
	u := requestUser(r)
	if u == nil {
		writeError(w, http.StatusForbidden, "sign in to write")
		return
	}
	pub, err := s.callerKey(u)
	if err != nil {
		s.writeStoreError(w, err, "key bundle")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.maxDBBytes()+maxRecordBytes+multipartSlack)
	mr, err := r.MultipartReader()
	if err != nil {
		s.writeRefusal(w, refuse(http.StatusBadRequest, "invalid multipart request: "+err.Error()))
		return
	}
	recordPart, err := nextPart(mr, "record")
	if err != nil {
		s.writeRefusal(w, err)
		return
	}
	env, err := readEnvelope(recordPart, "record")
	if err != nil {
		s.writeRefusal(w, err)
		return
	}
	blobPart, err := nextPart(mr, "blob")
	if err != nil {
		s.writeRefusal(w, err)
		return
	}
	staged, err := receiveBlob(blobPart, s.layout.VersionDBDir(aid, vid), s.maxDBBytes(), "blob")
	if err != nil {
		s.writeRefusal(w, err)
		return
	}
	defer os.Remove(staged.path) // fails harmlessly once renamed into place
	if err := noMoreParts(mr); err != nil {
		s.writeRefusal(w, err)
		return
	}
	var body e2e.RevisionBody
	if err := openRecord(u, pub, env, "revision", &body); err != nil {
		s.writeRefusal(w, err)
		return
	}
	recordJSON, err := json.Marshal(env)
	if err != nil {
		s.writeStoreError(w, err, "record")
		return
	}

	final := s.revisionPath(aid, vid, body.Revision)
	placed := false
	var writeErr error
	var pruned []int
	var current int
	// The epoch lock keeps the artifact from changing epoch while the
	// revision lands; the store checks If-Match in the same transaction as
	// the insert, so two writes naming one revision cannot both succeed.
	err = s.store.UnderEpoch(aid, body.Epoch, func() {
		switch {
		case body.Artifact != aid || body.Version != vid:
			writeErr = refuse(http.StatusBadRequest, "the record names another artifact or version")
		case body.Revision != ifMatch+1:
			writeErr = refuse(http.StatusBadRequest, "the record's revision is not the latest plus one")
		case body.SHA256 != staged.sum:
			writeErr = refuse(http.StatusBadRequest, "the record's sha256 is not the blob's")
		default:
			current, pruned, writeErr = s.store.AddDBRevision(store.DBRevision{
				ArtifactID: aid, VersionID: vid, Revision: body.Revision, Epoch: body.Epoch, Size: staged.size,
				Record: recordJSON, SignerKey: pub, WrittenBy: u.ID,
			}, ifMatch, func() error {
				err := os.Rename(staged.path, final)
				placed = err == nil
				return err
			})
		}
	})
	if err == nil {
		err = writeErr
	}
	if errors.Is(err, store.ErrRevisionMismatch) {
		writePreconditionFailed(w, current)
		return
	}
	if err != nil {
		if placed {
			os.Remove(final)
		}
		s.writeRefusal(w, err)
		return
	}
	for _, n := range pruned {
		os.Remove(s.revisionPath(aid, vid, n))
	}
	s.log.Info("database revision stored", "artifact", aid, "version", vid, "revision", body.Revision, "by", u.Email)
	w.Header().Set("ETag", revisionETag(body.Revision))
	writeJSON(w, http.StatusOK, map[string]int{"revision": body.Revision})
}
