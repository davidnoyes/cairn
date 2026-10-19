package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/aloisdeniel/cairn/internal/access"
	"github.com/aloisdeniel/cairn/internal/store"
)

// Folders. See "Folders" in design/e2e-api.md.

// errFolderNoContent is the 409 answer to a content route aimed at a folder.
const errFolderNoContent = "a folder holds no content"

// errFolderShared is the 409 answer to sharing a folder or offering one to a
// new owner, which F1 does not allow.
const errFolderShared = "folders cannot be shared yet"

// refuseFolder wraps a content handler: a folder has no versions, database,
// or files, so it answers 409 before the handler runs. It runs behind
// artifactRoute, so a caller with no access still gets the 404.
func refuseFolder(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requestArtifact(r).Kind == store.KindFolder {
			writeError(w, http.StatusConflict, errFolderNoContent)
			return
		}
		next(w, r)
	}
}

// parentRefusal checks that c may put an item in the folder parent: it must
// exist and be readable (else 404), and be owned by c (else 403). It returns 0
// when the placement may go ahead; the store refuses a parent that is not a
// folder. A missing folder, and any other store failure, is returned as err.
func (s *Server) parentRefusal(c access.Caller, parent string) (status int, msg string, err error) {
	_, req, err := s.accessRequest(c, parent, nil)
	if err != nil {
		return 0, "", err
	}
	switch level := access.LevelOf(req); {
	case level == access.LevelNone:
		return http.StatusNotFound, "folder not found", nil
	case level != access.LevelOwner:
		return http.StatusForbidden, "you do not own the folder", nil
	}
	return 0, "", nil
}

// writePlacementError answers a create or move that the store refused for the
// shape of the tree.
func (s *Server) writePlacementError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, store.ErrNotFolder), errors.Is(err, store.ErrCycle), errors.Is(err, store.ErrTooDeep):
		writeError(w, http.StatusConflict, err.Error())
	default:
		return false
	}
	return true
}

// readable reports whether c has any access to artifact id.
func (s *Server) readable(c access.Caller, id string) (bool, error) {
	_, req, err := s.accessRequest(c, id, nil)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil && access.LevelOf(req) != access.LevelNone, err
}

// showParent sets v's parent to the folder a sits in, when c can read that
// folder, and leaves it null otherwise, so a reader of a shared item does not
// learn where its owner keeps it.
func (s *Server) showParent(v *artifactView, a *store.Artifact, c access.Caller) error {
	if a.ParentID == "" {
		return nil
	}
	ok, err := s.readable(c, a.ParentID)
	if ok {
		v.Parent = &a.ParentID
	}
	return err
}

type moveRequest struct {
	// Parent is a folder ID, or null for the top level. The key is required,
	// so a body without it is not read as a move to the top level.
	Parent json.RawMessage `json:"parent"`
}

// handlePutParent moves the item into a folder, or to the top level.
func (s *Server) handlePutParent(w http.ResponseWriter, r *http.Request) {
	a, u := requestArtifact(r), requestUser(r)
	var req moveRequest
	if !readJSON(w, r, &req) {
		return
	}
	var parent string
	switch {
	case req.Parent == nil:
		writeError(w, http.StatusBadRequest, "parent is required: a folder ID, or null for the top level")
		return
	case string(req.Parent) != "null":
		if json.Unmarshal(req.Parent, &parent) != nil || parent == "" {
			writeError(w, http.StatusBadRequest, "parent must be a folder ID, or null")
			return
		}
	}
	if parent != "" {
		c := requestAccess(r).Caller
		status, msg, err := s.parentRefusal(c, parent)
		if err != nil {
			s.writeStoreError(w, err, "folder")
			return
		}
		if status != 0 {
			writeError(w, status, msg)
			return
		}
	}
	if err := s.store.MoveItem(a.ID, parent); err != nil {
		if !s.writePlacementError(w, err) {
			s.writeStoreError(w, err, "artifact")
		}
		return
	}
	moved, err := s.store.ArtifactByID(a.ID)
	if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	v, err := s.viewOf(moved, access.LevelOwner)
	if err == nil {
		err = s.showParent(v, moved, requestAccess(r).Caller)
	}
	if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	s.log.Info("artifact moved", "id", a.ID, "parent", parent, "by", u.Email)
	writeJSON(w, http.StatusOK, v)
}
