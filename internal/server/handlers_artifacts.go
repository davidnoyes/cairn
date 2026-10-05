package server

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"

	"github.com/aloisdeniel/cairn/internal/access"
	"github.com/aloisdeniel/cairn/internal/store"
)

// errAmbiguousResource is returned when a resource reference matches several
// artifacts the caller can read.
type errAmbiguousResource struct {
	ref   string
	count int
}

func (e errAmbiguousResource) Error() string {
	return fmt.Sprintf("resource %q is associated with %d artifacts; use the artifact id", e.ref, e.count)
}

// requestArtifact returns the artifact attached by artifactRoute (never nil
// inside wrapped handlers).
func requestArtifact(r *http.Request) *store.Artifact {
	a, _ := r.Context().Value(artifactCtxKey).(*store.Artifact)
	return a
}

// Artifact CRUD. Creating one lives in sharing.go, with the membership
// endpoints whose first record it writes.

// handleListArtifacts lists the artifacts the caller can read without a
// link token.
func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request) {
	as, err := s.store.ListArtifacts()
	if err != nil {
		s.writeStoreError(w, err, "artifacts")
		return
	}
	c, err := s.callerFor(requestUser(r), requestAPIKey(r), requestTokenScope(r))
	if err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	out := []*artifactView{}
	for _, a := range as {
		a, req, err := s.accessRequest(c, a.ID, nil)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			s.writeStoreError(w, err, "artifacts")
			return
		}
		level := access.LevelOf(req)
		if level == access.LevelNone {
			continue
		}
		v, err := s.viewOf(a, level)
		if err != nil {
			s.writeStoreError(w, err, "artifacts")
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, paginate(r, out))
}

func (s *Server) handleGetArtifact(w http.ResponseWriter, r *http.Request) {
	v, err := s.viewOf(requestArtifact(r), access.LevelOf(requestAccess(r)))
	if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleDeleteArtifact(w http.ResponseWriter, r *http.Request) {
	s.deleteArtifact(w, requestArtifact(r), requestUser(r).Email, s.store.DeleteArtifact)
}

// deleteArtifact removes a's row with del, then its content, databases, and
// files, and answers the request. by is who asked, for the log.
func (s *Server) deleteArtifact(w http.ResponseWriter, a *store.Artifact, by string, del func(id string) error) {
	if err := del(a.ID); errors.Is(err, store.ErrOwnerActive) {
		writeError(w, http.StatusConflict, err.Error())
		return
	} else if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	os.RemoveAll(s.layout.ArtifactContentRoot(a.ID))
	os.RemoveAll(s.layout.ArtifactDBRoot(a.ID))
	os.RemoveAll(s.layout.ArtifactFilesRoot(a.ID))
	s.log.Info("artifact deleted", "id", a.ID, "by", by)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Resources

// blindIndexPattern is a resource value: hex(HMAC-SHA256) under the caller's
// index key, so the server never holds the reference itself.
var blindIndexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type resourceRequest struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (s *Server) handleAddResource(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	var req resourceRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Type == "" {
		writeError(w, http.StatusBadRequest, "type is required")
		return
	}
	if !blindIndexPattern.MatchString(req.Value) {
		writeError(w, http.StatusBadRequest, "value must be a blind index: 64 lowercase hex characters")
		return
	}
	res, err := s.store.AddResource(a.ID, req.Type, req.Value)
	if err != nil {
		s.writeStoreError(w, err, "resource")
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *Server) handleDeleteResource(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteResource(requestArtifact(r).ID, r.PathValue("rid")); err != nil {
		s.writeStoreError(w, err, "resource")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Versions (metadata; uploads live in upload.go)

func (s *Server) handleListVersions(w http.ResponseWriter, r *http.Request) {
	id := requestArtifact(r).ID
	vs, err := s.store.ListVersions(id)
	if err != nil {
		s.writeStoreError(w, err, "versions")
		return
	}
	vouches, err := s.store.Vouches(id)
	if err != nil {
		s.writeStoreError(w, err, "versions")
		return
	}
	fields, err := s.store.ListMetaFields(id)
	if err != nil {
		s.writeStoreError(w, err, "versions")
		return
	}
	_, meta := metaViews(fields)
	writeJSON(w, http.StatusOK, viewVersions(vs, vouches, meta))
}

func (s *Server) handleGetVersion(w http.ResponseWriter, r *http.Request) {
	id := requestArtifact(r).ID
	v, err := s.store.VersionByID(id, r.PathValue("vid"))
	if err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	vouches, err := s.store.Vouches(id)
	if err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	fields, err := s.store.ListMetaFields(id)
	if err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	_, meta := metaViews(fields)
	writeJSON(w, http.StatusOK, viewVersions([]*store.Version{v}, vouches, meta)[0])
}

func (s *Server) handleDeleteVersion(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.VersionByID(requestArtifact(r).ID, r.PathValue("vid"))
	if err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	if err := s.store.DeleteVersion(v.ArtifactID, v.ID); err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	os.RemoveAll(s.layout.VersionDBDir(v.ArtifactID, v.ID))
	os.RemoveAll(s.layout.ContentDir(v.ArtifactID, v.ContentDir))
	os.RemoveAll(s.layout.VersionFilesDir(v.ArtifactID, v.ID))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
