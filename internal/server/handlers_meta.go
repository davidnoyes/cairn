package server

import (
	"encoding/json"
	"net/http"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// An artifact's name and description, and a version's name and changelog, are
// each one sealed blob covered by a signed record. The server cannot read
// one: it checks the record, and keeps the blob. See design/e2e-api.md
// (Encrypted metadata and the app UI).

// maxMetaBlob is the largest sealed blob of a field: the 16 KiB plaintext, the
// header and tag, and room to spare.
const maxMetaBlob = 17 << 10

// The fields each scope takes.
var (
	artifactMetaFields = map[string]bool{"name": true, "description": true}
	versionMetaFields  = map[string]bool{"name": true, "changelog": true}
)

// metaPutRequest is the body of a field write.
type metaPutRequest struct {
	Record e2e.Envelope `json:"record"`
	Blob   string       `json:"blob"`
}

// metaItemView is one field as a view carries it.
type metaItemView struct {
	Record    json.RawMessage `json:"record"`
	SignerKey string          `json:"signerKey"`
	Blob      string          `json:"blob"`
}

// metaViews groups an artifact's stored fields: its own by field name, and
// each version's by version ID, then field name. Neither map is nil.
func metaViews(fields []store.MetaField) (artifact map[string]metaItemView, versions map[string]map[string]metaItemView) {
	artifact, versions = map[string]metaItemView{}, map[string]map[string]metaItemView{}
	for _, f := range fields {
		item := metaItemView{Record: f.Record, SignerKey: e2e.B64(f.SignerKey), Blob: e2e.B64(f.Blob)}
		if f.VersionID == "" {
			artifact[f.Field] = item
			continue
		}
		if versions[f.VersionID] == nil {
			versions[f.VersionID] = map[string]metaItemView{}
		}
		versions[f.VersionID][f.Field] = item
	}
	return artifact, versions
}

func (s *Server) handlePutArtifactMeta(w http.ResponseWriter, r *http.Request) {
	s.putMeta(w, r, "")
}

func (s *Server) handlePutVersionMeta(w http.ResponseWriter, r *http.Request) {
	s.putMeta(w, r, r.PathValue("vid"))
}

// putMeta stores or replaces one field of the artifact, or of version vid when
// it is not empty.
func (s *Server) putMeta(w http.ResponseWriter, r *http.Request, vid string) {
	aid, field := requestArtifact(r).ID, r.PathValue("field")
	allowed := artifactMetaFields
	if vid != "" {
		if _, err := s.store.VersionByID(aid, vid); err != nil {
			s.writeStoreError(w, err, "version")
			return
		}
		allowed = versionMetaFields
	}
	if !allowed[field] {
		writeError(w, http.StatusBadRequest, "unknown field "+field)
		return
	}
	u := requestUser(r) // not nil: access.Rename is for the owner and editors
	pub, err := s.callerKey(u)
	if err != nil {
		s.writeStoreError(w, err, "key bundle")
		return
	}

	var req metaPutRequest
	r.Body = http.MaxBytesReader(w, r.Body, 2*maxMetaBlob+maxRecordBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if isBodyError(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "the request is over the maximum size")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid JSON body: trailing data")
		return
	}
	blob, err := e2e.UnB64(req.Blob)
	switch {
	case err != nil:
		writeError(w, http.StatusBadRequest, "the blob is not base64url")
		return
	case len(blob) > maxMetaBlob:
		writeError(w, http.StatusRequestEntityTooLarge, "the blob is over 17 KiB")
		return
	case len(blob) < e2e.BlobMinSize || !e2e.HasBlobHeader(blob):
		writeError(w, http.StatusBadRequest, "the 'blob' "+errBlobShape.Error())
		return
	}
	var body e2e.RecordBody
	if err := openRecord(u, pub, req.Record, "record", &body); err != nil {
		s.writeRefusal(w, err)
		return
	}
	switch {
	case body.Artifact != aid || body.Version != vid:
		writeError(w, http.StatusBadRequest, "the record names another artifact or version")
		return
	case body.Kind != "meta":
		writeError(w, http.StatusBadRequest, "the record's kind must be 'meta'")
		return
	case body.Name != field:
		writeError(w, http.StatusBadRequest, "the record's name is not the field")
		return
	case body.SHA256 != e2e.BodyHash(blob):
		writeError(w, http.StatusBadRequest, "the record's sha256 is not the blob's")
		return
	}
	record, err := json.Marshal(req.Record)
	if err != nil {
		s.writeStoreError(w, err, "record")
		return
	}
	var writeErr error
	err = s.store.UnderEpoch(aid, body.Epoch, func() {
		writeErr = s.store.PutMetaField(store.MetaField{
			ArtifactID: aid, VersionID: vid, Field: field, Record: record, SignerKey: pub, Blob: blob,
		})
	})
	if err == nil {
		err = writeErr
	}
	if err != nil {
		s.writeRefusal(w, err)
		return
	}
	s.log.Info("meta field stored", "artifact", aid, "version", vid, "field", field, "by", u.Email)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
