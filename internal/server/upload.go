package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/google/uuid"
)

func (s *Server) maxUploadBytes() int64 { return s.cfg.MaxUploadMB << 20 }

// A pushed version is stored as content/{artifactID}/{contentDir}/manifest
// and content/{artifactID}/{contentDir}/blobs/{blobID}. The server cannot
// read any of it: it checks shape and size, and keeps the bytes.
const (
	manifestFile = "manifest"
	blobsDir     = "blobs"
)

var (
	// A blob ID is 32 lowercase hex characters, chosen by the client.
	blobIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// A manifest hash is hex(SHA-256).
	manifestHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// versionIDPattern is the canonical lowercase UUID form.
	versionIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// pushVersionPart is the JSON of a push's "version" part.
type pushVersionPart struct {
	ID           string `json:"id"`
	Epoch        int    `json:"epoch"`
	ManifestHash string `json:"manifestHash"`
	Name         string `json:"name"`
	Changelog    string `json:"changelog"`
}

// handleUploadVersion creates a version from a multipart push of encrypted
// blobs and a signed manifest. See design/e2e-api.md (Pushing a version).
func (s *Server) handleUploadVersion(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	p, contentDir, ok := s.receivePush(w, r, a.ID)
	if !ok {
		return
	}
	// The id the client chose goes in the manifest and every blob's context,
	// so the server never picks one: an id any version uses is a conflict.
	v, err := s.store.CreateVersion(a.ID, p.ID, p.Name, p.Changelog, contentDir, requestUser(r).ID, p.ManifestHash, p.Epoch)
	if err != nil {
		os.RemoveAll(s.layout.ContentDir(a.ID, contentDir))
		if errors.Is(err, store.ErrExists) {
			writeError(w, http.StatusConflict, "a version with this id already exists")
			return
		}
		s.writeStoreError(w, err, "version")
		return
	}
	s.log.Info("version uploaded", "artifact", a.ID, "version", v.ID, "seq", v.Seq, "by", requestUser(r).Email)
	writeJSON(w, http.StatusCreated, v)
}

// handleReplaceVersion re-uploads an existing version's content (allowed by
// design: Cairn trusts its users; iterating agents overwrite work-in-progress
// versions). The version's shared database is untouched, and its vouch goes:
// it covered the content the owner reviewed.
func (s *Server) handleReplaceVersion(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	v, err := s.store.VersionByID(a.ID, r.PathValue("vid"))
	if err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	p, contentDir, ok := s.receivePush(w, r, a.ID)
	if !ok {
		return
	}
	if p.ID != v.ID {
		os.RemoveAll(s.layout.ContentDir(a.ID, contentDir))
		writeError(w, http.StatusBadRequest, "the version id must be the id in the URL")
		return
	}
	name, changelog := p.Name, p.Changelog
	if name == "" {
		name = v.Name
	}
	if changelog == "" {
		changelog = v.Changelog
	}
	prev, err := s.store.SwapVersionContent(v.ArtifactID, v.ID, contentDir, name, changelog, requestUser(r).ID, p.ManifestHash, p.Epoch)
	if err != nil {
		os.RemoveAll(s.layout.ContentDir(v.ArtifactID, contentDir))
		s.writeStoreError(w, err, "version")
		return
	}
	// Open file handles on the old dir keep serving until closed (POSIX);
	// new requests resolve the new pointer.
	os.RemoveAll(s.layout.ContentDir(v.ArtifactID, prev))
	v, _ = s.store.VersionByID(v.ArtifactID, v.ID)
	s.log.Info("version replaced", "artifact", v.ArtifactID, "version", v.ID, "by", requestUser(r).Email)
	writeJSON(w, http.StatusOK, v)
}

// errBlobShape means a part is not a blob: it lacks the header, or is too
// short to hold one tagged chunk.
var errBlobShape = errors.New("is not a Cairn blob")

// receivePush reads the multipart request into a fresh content dir and
// returns its version part and the dir's name. It reports every refusal to
// the client itself, and leaves no dir behind when it refuses.
func (s *Server) receivePush(w http.ResponseWriter, r *http.Request, artifactID string) (p pushVersionPart, contentDir string, ok bool) {
	contentDir = uuid.NewString()
	dest := s.layout.ContentDir(artifactID, contentDir)
	refuse := func(status int, msg string) {
		os.RemoveAll(dest)
		writeError(w, status, msg)
	}
	// A body error is a size refusal or a malformed request; anything else is ours.
	readFailed := func(err error) {
		var tooBig *http.MaxBytesError
		switch {
		case errors.As(err, &tooBig):
			refuse(http.StatusRequestEntityTooLarge, fmt.Sprintf("the push exceeds the maximum size of %d MiB", s.cfg.MaxUploadMB))
		case errors.Is(err, errBlobShape):
			refuse(http.StatusBadRequest, err.Error())
		default:
			var perr *os.PathError
			if errors.As(err, &perr) {
				s.log.Error("store push", "err", err)
				refuse(http.StatusInternalServerError, "failed to store the push")
				return
			}
			refuse(http.StatusBadRequest, "invalid multipart push: "+err.Error())
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.maxUploadBytes())
	mr, err := r.MultipartReader()
	if err != nil {
		refuse(http.StatusBadRequest, "invalid multipart push: "+err.Error())
		return
	}
	if err := os.MkdirAll(filepath.Join(dest, blobsDir), 0o755); err != nil {
		s.log.Error("store push", "err", err)
		refuse(http.StatusInternalServerError, "failed to store the push")
		return
	}

	haveVersion, haveManifest := false, false
	blobs := map[string]bool{}
	for {
		// A raw part, so a Content-Transfer-Encoding header cannot make the
		// reader decode what the server stores: the bytes are as sent.
		part, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			readFailed(err)
			return
		}
		switch part.FormName() {
		case "name", "changelog", "archive", "file":
			// The fields of the zip push an older cairn tool sent, whichever
			// of them comes first.
			refuse(http.StatusBadRequest, "this server takes encrypted pushes, not zip archives: update the cairn tool")
			return
		case "version":
			if haveVersion {
				refuse(http.StatusBadRequest, "the push has two 'version' parts")
				return
			}
			haveVersion = true
			if err := decodeVersionPart(io.LimitReader(part, 1<<20), &p); err != nil {
				if isBodyError(err) {
					readFailed(err)
					return
				}
				refuse(http.StatusBadRequest, err.Error())
				return
			}
		case "manifest":
			if haveManifest {
				refuse(http.StatusBadRequest, "the push has two 'manifest' parts")
				return
			}
			haveManifest = true
			if err := writeBlob(filepath.Join(dest, manifestFile), part); err != nil {
				if errors.Is(err, errBlobShape) {
					err = fmt.Errorf("the manifest %w", err)
				}
				readFailed(err)
				return
			}
		case "blob":
			id := rawFilename(part.Header.Get("Content-Disposition"))
			if !blobIDPattern.MatchString(id) {
				refuse(http.StatusBadRequest, "a blob's filename must be its ID, 32 lowercase hex characters")
				return
			}
			if blobs[id] {
				refuse(http.StatusBadRequest, "blob "+id+" appears twice")
				return
			}
			blobs[id] = true
			if err := writeBlob(filepath.Join(dest, blobsDir, id), part); err != nil {
				if errors.Is(err, errBlobShape) {
					err = fmt.Errorf("blob %s %w", id, err)
				}
				readFailed(err)
				return
			}
		default:
			refuse(http.StatusBadRequest, "unexpected part "+part.FormName())
			return
		}
	}
	if !haveVersion || !haveManifest {
		refuse(http.StatusBadRequest, "a push needs 'version' and 'manifest' parts")
		return
	}
	if len(blobs) == 0 {
		refuse(http.StatusBadRequest, "a push needs at least one blob: every version has an index.html")
		return
	}
	switch {
	case !manifestHashPattern.MatchString(p.ManifestHash):
		refuse(http.StatusBadRequest, "manifestHash must be 64 lowercase hex characters")
	case !versionIDPattern.MatchString(p.ID):
		refuse(http.StatusConflict, "the version id must be a lowercase UUID")
	case p.Epoch < 1:
		// A declared epoch of 0 would skip the store's epoch check, and no
		// artifact that takes a push is at epoch 0. A missing epoch decodes
		// as 0, so this is a malformed push, not a stale one.
		refuse(http.StatusBadRequest, "the push names no epoch")
	default:
		return p, contentDir, true
	}
	return pushVersionPart{}, "", false
}

// decodeVersionPart reads the one JSON object of a push's "version" part. A
// read error from the request body comes back as is, for isBodyError.
func decodeVersionPart(r io.Reader, p *pushVersionPart) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return fmt.Errorf("invalid 'version' part: %w", err)
	}
	// More reports false before a closing bracket, so a stray } or ]
	// would pass it: the part must end after the one value.
	switch err := dec.Decode(&struct{}{}); {
	case err == io.EOF:
		return nil
	case isBodyError(err):
		return err
	}
	return errors.New("invalid 'version' part: trailing data")
}

// isBodyError reports whether err came from reading the request body rather
// than from decoding what was read.
func isBodyError(err error) bool {
	var tooBig *http.MaxBytesError
	return errors.As(err, &tooBig)
}

// rawFilename is the filename parameter of a Content-Disposition header, as
// sent: Part.FileName would drop any directory part, and a blob ID with one
// is not a blob ID.
func rawFilename(disposition string) string {
	_, params, err := mime.ParseMediaType(disposition)
	if err != nil {
		return ""
	}
	return params["filename"]
}

// writeBlob copies part to a new file at dest, refusing one that does not
// start with the blob header or is shorter than the header and one tagged
// chunk. The file is created exclusively, so a repeated ID cannot overwrite.
func writeBlob(dest string, part io.Reader) error {
	head := make([]byte, 5) // magic and version byte
	if _, err := io.ReadFull(part, head); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return errBlobShape
		}
		return err
	}
	if !e2e.HasBlobHeader(head) {
		return errBlobShape
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(head); err != nil {
		return err
	}
	n, err := io.Copy(f, part)
	if err != nil {
		return err
	}
	if int(n)+len(head) < e2e.BlobMinSize {
		return errBlobShape
	}
	return nil
}

// handleGetManifest and handleGetBlob serve a version's stored bytes: the
// manifest blob, and one file's blob by ID.
func (s *Server) handleGetManifest(w http.ResponseWriter, r *http.Request) {
	s.serveStored(w, r, manifestFile)
}

func (s *Server) handleGetBlob(w http.ResponseWriter, r *http.Request) {
	if !blobIDPattern.MatchString(r.PathValue("blob")) {
		writeError(w, http.StatusNotFound, "blob not found")
		return
	}
	s.serveStored(w, r, filepath.Join(blobsDir, r.PathValue("blob")))
}

// serveStored sends the file at rel in the version's content dir. rel is
// built from constants and a validated blob ID only.
func (s *Server) serveStored(w http.ResponseWriter, r *http.Request, rel string) {
	a := requestArtifact(r)
	v, err := s.store.VersionByID(a.ID, r.PathValue("vid"))
	if err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	f, err := os.Open(filepath.Join(s.layout.ContentDir(a.ID, v.ContentDir), rel))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		s.log.Error("open stored content", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "", time.Time{}, f)
}
