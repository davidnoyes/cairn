package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// A stored file is two sealed blobs under one address: the file, kept under
// files/{artifact}/{version}/{address}, and its metadata, kept in the row.
// The server never sees a path: it is inside the sealed metadata.

// fileInfo is the JSON shape of one stored file in a listing.
type fileInfo struct {
	Address    string          `json:"address"`
	Epoch      int             `json:"epoch"`
	Size       int64           `json:"size"`
	UpdatedAt  string          `json:"updatedAt"`
	Record     json.RawMessage `json:"record"`
	Meta       string          `json:"meta"`
	MetaRecord json.RawMessage `json:"metaRecord"`
	SignerKey  string          `json:"signerKey"`
}

func (s *Server) filePath(aid, vid, address string) string {
	return filepath.Join(s.layout.VersionFilesDir(aid, vid), address)
}

// fileAddress validates the {address} segment, answering 404 when it is not
// 64 lowercase hex characters.
func fileAddress(w http.ResponseWriter, r *http.Request) (string, bool) {
	a := r.PathValue("address")
	if !addressPattern.MatchString(a) {
		writeError(w, http.StatusNotFound, "file not found")
		return "", false
	}
	return a, true
}

// handleFileList lists a version's stored files; a version that was never
// written to lists as empty.
func (s *Server) handleFileList(w http.ResponseWriter, r *http.Request) {
	aid, vid := requestArtifact(r).ID, r.PathValue("vid")
	if _, err := s.store.VersionByID(aid, vid); err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	files, err := s.store.ListStoredFiles(aid, vid)
	if err != nil {
		s.writeStoreError(w, err, "files")
		return
	}
	out := make([]fileInfo, 0, len(files))
	for _, f := range files {
		out = append(out, fileInfo{
			Address: f.Address, Epoch: f.Epoch, Size: f.Size, UpdatedAt: f.UpdatedAt,
			Record: f.Record, Meta: e2e.B64(f.Meta), MetaRecord: f.MetaRecord, SignerKey: e2e.B64(f.SignerKey),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleFileGet returns one stored file's blob.
func (s *Server) handleFileGet(w http.ResponseWriter, r *http.Request) {
	aid, vid := requestArtifact(r).ID, r.PathValue("vid")
	address, ok := fileAddress(w, r)
	if !ok {
		return
	}
	if _, err := s.store.VersionByID(aid, vid); err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	f, err := s.store.StoredFileByAddress(aid, vid, address)
	if err != nil {
		s.writeStoreError(w, err, "file")
		return
	}
	setRecordHeaders(w, f.Epoch, f.Record, f.SignerKey)
	s.serveBlobFile(w, r, s.filePath(aid, vid, address))
}

// handleFilePut stores or replaces one file. See design/e2e-api.md (Stored
// files) for the refusals.
func (s *Server) handleFilePut(w http.ResponseWriter, r *http.Request) {
	aid, vid := requestArtifact(r).ID, r.PathValue("vid")
	address, ok := fileAddress(w, r)
	if !ok {
		return
	}
	if _, err := s.store.VersionByID(aid, vid); err != nil {
		s.writeStoreError(w, err, "version")
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

	r.Body = http.MaxBytesReader(w, r.Body, s.maxUploadBytes()+2*maxRecordBytes+maxMetaBytes+multipartSlack)
	mr, err := r.MultipartReader()
	if err != nil {
		s.writeRefusal(w, refuse(http.StatusBadRequest, "invalid multipart request: "+err.Error()))
		return
	}
	part, err := nextPart(mr, "record")
	if err != nil {
		s.writeRefusal(w, err)
		return
	}
	env, err := readEnvelope(part, "record")
	if err != nil {
		s.writeRefusal(w, err)
		return
	}
	if part, err = nextPart(mr, "blob"); err != nil {
		s.writeRefusal(w, err)
		return
	}
	staged, err := receiveBlob(part, s.layout.VersionFilesDir(aid, vid), s.maxUploadBytes(), "blob")
	if err != nil {
		s.writeRefusal(w, err)
		return
	}
	defer os.Remove(staged.path) // fails harmlessly once renamed into place
	if part, err = nextPart(mr, "metaRecord"); err != nil {
		s.writeRefusal(w, err)
		return
	}
	metaEnv, err := readEnvelope(part, "metaRecord")
	if err != nil {
		s.writeRefusal(w, err)
		return
	}
	if part, err = nextPart(mr, "meta"); err != nil {
		s.writeRefusal(w, err)
		return
	}
	meta, err := readSmall(part, maxMetaBytes, "meta")
	if err != nil {
		s.writeRefusal(w, err)
		return
	}
	if len(meta) < e2e.BlobMinSize || !e2e.HasBlobHeader(meta) {
		s.writeRefusal(w, refuse(http.StatusBadRequest, "the 'meta' part "+errBlobShape.Error()))
		return
	}
	if err := noMoreParts(mr); err != nil {
		s.writeRefusal(w, err)
		return
	}
	var body, metaBody e2e.RecordBody
	if err := openRecord(u, pub, env, "record", &body); err != nil {
		s.writeRefusal(w, err)
		return
	}
	if err := openRecord(u, pub, metaEnv, "record", &metaBody); err != nil {
		s.writeRefusal(w, err)
		return
	}
	recordJSON, err := json.Marshal(env)
	if err != nil {
		s.writeStoreError(w, err, "record")
		return
	}
	metaRecordJSON, err := json.Marshal(metaEnv)
	if err != nil {
		s.writeStoreError(w, err, "record")
		return
	}

	final := s.filePath(aid, vid, address)
	var undo, keep func()
	var writeErr error
	err = s.store.UnderEpoch(aid, body.Epoch, func() {
		switch {
		case metaBody.Epoch != body.Epoch:
			writeErr = refuse(http.StatusConflict, "the two records name different epochs")
		case body.Artifact != aid || body.Version != vid || metaBody.Artifact != aid || metaBody.Version != vid:
			writeErr = refuse(http.StatusBadRequest, "a record names another artifact or version")
		case body.Kind != "file" || metaBody.Kind != "file-meta":
			writeErr = refuse(http.StatusBadRequest, "the records must have kinds 'file' and 'file-meta'")
		case body.Name != address || metaBody.Name != address:
			writeErr = refuse(http.StatusBadRequest, "a record's name is not the file's address")
		case body.SHA256 != staged.sum || metaBody.SHA256 != e2e.BodyHash(meta):
			writeErr = refuse(http.StatusBadRequest, "a record's sha256 is not its blob's")
		default:
			writeErr = s.store.PutStoredFile(store.StoredFile{
				ArtifactID: aid, VersionID: vid, Address: address, Epoch: body.Epoch, Size: staged.size,
				Record: recordJSON, Meta: meta, MetaRecord: metaRecordJSON, SignerKey: pub, WrittenBy: u.ID,
			}, func() (err error) {
				undo, keep, err = placeFile(staged.path, final)
				return err
			})
		}
	})
	if err == nil {
		err = writeErr
	}
	if err != nil {
		if undo != nil {
			undo()
		}
		s.writeRefusal(w, err)
		return
	}
	keep()
	s.log.Info("file stored", "artifact", aid, "version", vid, "address", address, "by", u.Email)
	writeJSON(w, http.StatusOK, map[string]string{"address": address})
}

// handleFileDelete deletes one stored file. A delete carries no signature.
func (s *Server) handleFileDelete(w http.ResponseWriter, r *http.Request) {
	aid, vid := requestArtifact(r).ID, r.PathValue("vid")
	address, ok := fileAddress(w, r)
	if !ok {
		return
	}
	if _, err := s.store.VersionByID(aid, vid); err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	err := s.store.DeleteStoredFile(aid, vid, address, func() error {
		if err := os.Remove(s.filePath(aid, vid, address)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	})
	if err != nil {
		s.writeStoreError(w, err, "file")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// placeFile moves staged over final. A file already at final is linked to a
// backup first, so readers never find the address empty: undo puts it back,
// for a write whose commit fails, and keep drops the backup once it lands.
func placeFile(staged, final string) (undo, keep func(), err error) {
	backup := final + ".old"
	os.Remove(backup) // left by a crash part way through an earlier write
	kept := true
	if err := os.Link(final, backup); errors.Is(err, os.ErrNotExist) {
		kept = false
	} else if err != nil {
		return nil, nil, err
	}
	if err := os.Rename(staged, final); err != nil {
		if kept {
			os.Remove(backup)
		}
		return nil, nil, err
	}
	undo = func() {
		if kept {
			os.Rename(backup, final)
		} else {
			os.Remove(final)
		}
	}
	keep = func() {
		if kept {
			os.Remove(backup)
		}
	}
	return undo, keep, nil
}
