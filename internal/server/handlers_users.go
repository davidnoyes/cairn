package server

import (
	"errors"
	"net/http"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// directoryUser is a user as listed in the directory: enough for clients to
// compute fingerprints and address them, never the auth hash or bundle.
type directoryUser struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	X25519Pub  string `json:"x25519Pub"`
	Ed25519Pub string `json:"ed25519Pub"`
	ResetAt    string `json:"resetAt,omitempty"`
}

func (s *Server) toDirectoryUser(u *store.User) (directoryUser, error) {
	b, err := s.store.BundleFor(u.ID)
	if err != nil {
		return directoryUser{}, err
	}
	return directoryUser{
		ID: u.ID, Name: u.Name, Email: u.Email, Role: u.Role,
		X25519Pub: e2e.B64(b.X25519Pub), Ed25519Pub: e2e.B64(b.Ed25519Pub),
		ResetAt: u.ResetAt,
	}, nil
}

// handleUsers lists verified, active users. Clients compute fingerprints
// themselves from the public keys here.
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(false)
	if err != nil {
		s.writeStoreError(w, err, "users")
		return
	}
	out := make([]directoryUser, 0, len(users))
	for _, u := range users {
		if u.Disabled {
			continue
		}
		d, err := s.toDirectoryUser(u)
		if err != nil {
			s.writeStoreError(w, err, "users")
			return
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, paginate(r, out))
}

func (s *Server) handleUserByID(w http.ResponseWriter, r *http.Request) {
	// A content-origin token reads only the owner and members its artifact's
	// latest record lists.
	if scope := requestTokenScope(r); scope.Artifact != "" {
		if err := s.tokenMayReadUser(r, scope, r.PathValue("id")); err != nil {
			s.writeStoreError(w, err, "user")
			return
		}
	}
	u, err := s.store.UserByID(r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	// The same accounts the directory lists, and no others.
	if u.Disabled || u.VerifiedAt == "" {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	d, err := s.toDirectoryUser(u)
	if err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// adminDirectoryUser adds the account-management fields an administrator
// sees, and includes unverified accounts.
type adminDirectoryUser struct {
	directoryUser
	IsAdmin   bool   `json:"isAdmin"`
	Disabled  bool   `json:"disabled"`
	Verified  bool   `json:"verified"`
	CreatedAt string `json:"createdAt"`
}

func (s *Server) toAdminDirectoryUser(u *store.User) (adminDirectoryUser, error) {
	d, err := s.toDirectoryUser(u)
	if err != nil {
		return adminDirectoryUser{}, err
	}
	return adminDirectoryUser{directoryUser: d, IsAdmin: u.IsAdmin, Disabled: u.Disabled, Verified: u.VerifiedAt != "", CreatedAt: u.CreatedAt}, nil
}

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(true)
	if err != nil {
		s.writeStoreError(w, err, "users")
		return
	}
	out := make([]adminDirectoryUser, 0, len(users))
	for _, u := range users {
		d, err := s.toAdminDirectoryUser(u)
		if err != nil {
			s.writeStoreError(w, err, "users")
			return
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, out)
}

type adminUpdateUserRequest struct {
	Role *string `json:"role"`
	// IsAdmin is the legacy form of Role: true is admin, false is member.
	IsAdmin  *bool `json:"isAdmin"`
	Disabled *bool `json:"disabled"`
}

// validRole reports whether role is one of the three server roles.
func validRole(role string) bool {
	return role == store.RoleAdmin || role == store.RoleMember || role == store.RoleViewer
}

// newRole is the role the request asks for, or "" when it asks for none. A
// legacy isAdmin that already holds changes nothing, so isAdmin:false never
// turns a viewer account into a member.
func (req adminUpdateUserRequest) newRole(u *store.User) string {
	switch {
	case req.Role != nil:
		return *req.Role
	case req.IsAdmin != nil && *req.IsAdmin && !u.IsAdmin:
		return store.RoleAdmin
	case req.IsAdmin != nil && !*req.IsAdmin && u.IsAdmin:
		return store.RoleMember
	}
	return ""
}

// handleAdminUpdateUser sets an account's role, or deactivates it. It never
// sets a password or creates anything: there is no other administrator
// endpoint for users or keys.
func (s *Server) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := s.store.UserByID(id)
	if err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	var req adminUpdateUserRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Role != nil && req.IsAdmin != nil {
		writeError(w, http.StatusBadRequest, "send role or isAdmin, not both")
		return
	}
	if req.Role != nil && !validRole(*req.Role) {
		writeError(w, http.StatusBadRequest, "role must be admin, member, or viewer")
		return
	}
	if role := req.newRole(u); role != "" && role != u.Role {
		// An administrator who lost their own role could leave none.
		if u.IsAdmin && role != store.RoleAdmin && id == requestUser(r).ID {
			writeError(w, http.StatusBadRequest, "cannot remove your own administrator role")
			return
		}
		if err := s.store.SetUserRole(id, role); err != nil {
			s.writeStoreError(w, err, "user")
			return
		}
	}
	if req.Disabled != nil && *req.Disabled != u.Disabled {
		if id == requestUser(r).ID {
			writeError(w, http.StatusBadRequest, "cannot disable your own account")
			return
		}
		// A deactivation while a request is pending is on the record, so an
		// administrator cannot hide it from the refusal page.
		var err error
		if *req.Disabled {
			err = s.store.DeactivateUser(id, s.clk.Now())
		} else {
			err = s.store.SetUserDisabled(id, false)
		}
		if err != nil {
			s.writeStoreError(w, err, "user")
			return
		}
	}
	u, err = s.store.UserByID(id)
	if err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	d, err := s.toAdminDirectoryUser(u)
	if err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == requestUser(r).ID {
		writeError(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}
	if err := s.store.DeleteUser(id); err != nil {
		if errors.Is(err, store.ErrOwnsArtifacts) {
			writeError(w, http.StatusConflict, "user owns artifacts; disable the account instead")
			return
		}
		s.writeStoreError(w, err, "user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
