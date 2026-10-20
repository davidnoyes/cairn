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
// exist and be readable (else 404), and c must have editor access to it, or
// manager or owner (else 403). It returns 0 when the placement may go ahead;
// the store refuses a parent that is not a folder. A missing folder, and any
// other store failure, is returned as err.
func (s *Server) parentRefusal(c access.Caller, parent string) (status int, msg string, err error) {
	_, req, err := s.accessRequest(c, parent, nil)
	if err != nil {
		return 0, "", err
	}
	switch {
	case access.LevelOf(req) == access.LevelNone:
		return http.StatusNotFound, "folder not found", nil
	case access.Check(req, access.Rename) != access.Allow:
		return http.StatusForbidden, "you need editor access to the folder", nil
	}
	return 0, "", nil
}

// leaveRefusal checks that c may take the item a out of the folder it sits
// in: its owner may always take it back, and anyone else needs editor access
// to the folder, which sends the item to its owner's top level. It returns 0
// when the move may go ahead, and 404 when c does not know of the item
// (itemSeen), so a stranger learns of neither.
func (s *Server) leaveRefusal(c access.Caller, a *store.Artifact, owns, itemSeen bool) (status int, msg string, err error) {
	if owns {
		return 0, "", nil
	}
	_, req, err := s.accessRequest(c, a.ParentID, nil)
	switch {
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return 0, "", err
	case err == nil && access.Check(req, access.Rename) == access.Allow:
		return 0, "", nil
	case !itemSeen:
		return http.StatusNotFound, "artifact not found", nil
	}
	return http.StatusForbidden, "you need editor access to the folder the item sits in", nil
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

// readableBy is readable for c, as showParent takes it.
func (s *Server) readableBy(c access.Caller) func(id string) (bool, error) {
	return func(id string) (bool, error) { return s.readable(c, id) }
}

// showParent sets v's parent to the folder a sits in, when readable reports
// the caller can read that folder, and leaves it null otherwise, so a reader
// of a shared item does not learn where its owner keeps it.
func (s *Server) showParent(v *artifactView, a *store.Artifact, readable func(id string) (bool, error)) error {
	if a.ParentID == "" {
		return nil
	}
	ok, err := readable(a.ParentID)
	if ok {
		v.Parent = &a.ParentID
	}
	return err
}

// stubView is an item the caller cannot read, as GET /api/artifacts lists it
// inside a folder the caller can read: who owns it, what it is, and that its
// owner has yet to apply the folder's sharing to it. It carries no name, no
// key, and no member list, and the parent is a folder the caller reads.
type stubView struct {
	ID      string       `json:"id"`
	Kind    string       `json:"kind"`
	Owner   string       `json:"owner"`
	Parent  *string      `json:"parent"`
	Inherit string       `json:"inherit"`
	Access  access.Level `json:"access"`
}

// stubOf is the stub of a, which sits in a folder the caller can read, or at
// the top level.
func stubOf(a *store.Artifact) *stubView {
	v := &stubView{ID: a.ID, Kind: a.Kind, Owner: a.OwnerID, Inherit: inheritPending, Access: access.LevelNone}
	if a.ParentID != "" {
		v.Parent = &a.ParentID
	}
	return v
}

type moveRequest struct {
	// Parent is a folder ID, or null for the top level. The key is required,
	// so a body without it is not read as a move to the top level.
	Parent json.RawMessage `json:"parent"`
}

// handlePutParent moves the item into a folder, or to the top level. Entering
// a folder needs the right to manage the item and editor access to the
// folder; leaving one needs editor access to the folder, or ownership of the
// item, and a folder's editor who does not manage the item may only remove
// it. The route does not check the action, because that editor may not be
// able to read the item.
func (s *Server) handlePutParent(w http.ResponseWriter, r *http.Request) {
	a, u := requestArtifact(r), requestUser(r)
	itemReq := requestAccess(r)
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
	c := itemReq.Caller
	// The caller knows of the item when they read it, or read the folder it
	// sits in, which lists it as a stub.
	itemSeen := access.LevelOf(itemReq) != access.LevelNone
	if !itemSeen && a.ParentID != "" {
		var err error
		if itemSeen, err = s.readable(c, a.ParentID); err != nil {
			s.writeStoreError(w, err, "folder")
			return
		}
	}
	manages := access.Check(itemReq, access.Move) == access.Allow
	entering := parent != "" && parent != a.ParentID
	leaving := a.ParentID != "" && parent != a.ParentID
	// Only one who manages the item places it, or confirms its place; a
	// folder's editor alone may take it out.
	if !manages && (entering || !leaving) {
		if !itemSeen {
			writeError(w, http.StatusNotFound, "artifact not found")
		} else {
			writeError(w, http.StatusForbidden, "only the item's owner or a manager places it in a folder")
		}
		return
	}
	if leaving {
		status, msg, err := s.leaveRefusal(c, a, access.LevelOf(itemReq) == access.LevelOwner, itemSeen)
		if err != nil {
			s.writeStoreError(w, err, "folder")
			return
		}
		if status != 0 {
			writeError(w, status, msg)
			return
		}
	}
	if entering {
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
	// What the caller reads of the item is judged after the move: a folder's
	// editor who removes an item they could read only through the folder
	// gets the stub of it.
	_, after, err := s.accessRequest(c, a.ID, nil)
	if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	var v any
	if level := access.LevelOf(after); level == access.LevelNone {
		v = stubOf(moved)
	} else {
		view, err := s.viewOf(moved, level)
		if err == nil {
			err = s.showParent(view, moved, s.readableBy(c))
		}
		if err != nil {
			s.writeStoreError(w, err, "artifact")
			return
		}
		v = view
	}
	s.log.Info("artifact moved", "id", a.ID, "parent", parent, "by", u.Email)
	writeJSON(w, http.StatusOK, v)
}
