package server

import (
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
		ID: u.ID, Name: u.Name, Email: u.Email,
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
	u, err := s.store.UserByID(r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err, "user")
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
	IsAdmin  *bool `json:"isAdmin"`
	Disabled *bool `json:"disabled"`
}

// handleAdminUpdateUser grants or removes the admin role, or deactivates an
// account. It never sets a password or creates anything: there is no other
// administrator endpoint for users or keys.
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
	if req.IsAdmin != nil && *req.IsAdmin != u.IsAdmin {
		if err := s.store.SetUserAdmin(id, *req.IsAdmin); err != nil {
			s.writeStoreError(w, err, "user")
			return
		}
	}
	if req.Disabled != nil && *req.Disabled != u.Disabled {
		if id == requestUser(r).ID {
			writeError(w, http.StatusBadRequest, "cannot disable your own account")
			return
		}
		if err := s.store.SetUserDisabled(id, *req.Disabled); err != nil {
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
		s.writeStoreError(w, err, "user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
