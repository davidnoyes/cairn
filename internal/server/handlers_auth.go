package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/aloisdeniel/artifacts/internal/auth"
	"github.com/aloisdeniel/artifacts/internal/store"
)

const minPasswordLen = 8

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	// Confirm is required only when claiming an account at first login, as a
	// guard against typos becoming the password.
	Confirm string `json:"confirm,omitempty"`
}

type loginResponse struct {
	Token string      `json:"token"`
	User  *store.User `json:"user"`
	// FirstLogin signals the UI that this login claimed the account.
	FirstLogin bool `json:"firstLogin,omitempty"`
}

// handleLogin implements email/password login. Cairn's trust model: accounts
// are created by admins without a password, and the first login sets it.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !readJSON(w, r, &req) {
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	u, err := s.store.UserByEmail(req.Email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid email or password")
			return
		}
		s.writeStoreError(w, err, "user")
		return
	}
	if u.Disabled {
		writeError(w, http.StatusForbidden, "account disabled")
		return
	}
	firstLogin := u.PasswordHash == ""
	if firstLogin {
		if len(req.Password) < minPasswordLen {
			writeError(w, http.StatusBadRequest, "first login: choose a password of at least 8 characters")
			return
		}
		if req.Confirm != req.Password {
			writeError(w, http.StatusBadRequest, "first login: password confirmation does not match")
			return
		}
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			s.writeStoreError(w, err, "password")
			return
		}
		if err := s.store.SetPassword(u.ID, hash, false); err != nil {
			s.writeStoreError(w, err, "user")
			return
		}
		s.log.Info("account claimed at first login", "email", u.Email)
	} else if !auth.CheckPassword(u.PasswordHash, req.Password) {
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	token, err := s.issueToken(u)
	if err != nil {
		s.writeStoreError(w, err, "token")
		return
	}
	s.setSessionCookie(w, token, s.cfg.TokenTTL)
	writeJSON(w, http.StatusOK, loginResponse{Token: token, User: u, FirstLogin: firstLogin})
}

func (s *Server) issueToken(u *store.User) (string, error) {
	nowT := time.Now()
	return auth.SignJWT(s.secret, auth.Claims{
		UserID:       u.ID,
		IsAdmin:      u.IsAdmin,
		TokenVersion: u.TokenVersion,
		IssuedAt:     nowT.Unix(),
		ExpiresAt:    nowT.Add(s.cfg.TokenTTL).Unix(),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, requestUser(r))
}

// publicUser is the user-directory projection every authenticated user may
// see.
type publicUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func toPublicUser(u *store.User) publicUser {
	return publicUser{ID: u.ID, Name: u.Name, Email: u.Email}
}

// handleUsers serves the global user directory: id, name and email of every
// user, readable by any authenticated user (deliberately unrestricted so
// artifacts can attribute shared data).
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		s.writeStoreError(w, err, "users")
		return
	}
	out := make([]publicUser, 0, len(users))
	for _, u := range users {
		out = append(out, toPublicUser(u))
	}
	writeJSON(w, http.StatusOK, paginate(r, out))
}

func (s *Server) handleUserByID(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.UserByID(r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	writeJSON(w, http.StatusOK, toPublicUser(u))
}

// Admin: user management

type createUserRequest struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	IsAdmin bool   `json:"isAdmin"`
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if !readJSON(w, r, &req) {
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "a valid email is required")
		return
	}
	u, err := s.store.CreateUser(req.Email, req.Name, req.IsAdmin)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusConflict, "a user with this email already exists")
			return
		}
		s.writeStoreError(w, err, "user")
		return
	}
	s.log.Info("user created", "email", u.Email, "by", requestUser(r).Email)
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		s.writeStoreError(w, err, "users")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

type updateUserRequest struct {
	Name     *string `json:"name"`
	IsAdmin  *bool   `json:"isAdmin"`
	Disabled *bool   `json:"disabled"`
}

func (s *Server) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := s.store.UserByID(id)
	if err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	var req updateUserRequest
	if !readJSON(w, r, &req) {
		return
	}
	name, isAdmin := u.Name, u.IsAdmin
	if req.Name != nil {
		name = *req.Name
	}
	if req.IsAdmin != nil {
		isAdmin = *req.IsAdmin
	}
	if err := s.store.UpdateUser(id, name, isAdmin); err != nil {
		s.writeStoreError(w, err, "user")
		return
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
	writeJSON(w, http.StatusOK, u)
}

// handleAdminResetPassword returns the account to the unclaimed state: the
// user chooses a new password at their next login.
func (s *Server) handleAdminResetPassword(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ClearPassword(r.PathValue("id")); err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
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

// Admin: API keys

type createKeyRequest struct {
	UserID string `json:"userId"`
	Name   string `json:"name"`
}

type createKeyResponse struct {
	Key *store.APIKey `json:"key"`
	// Token is shown exactly once; only its hash is stored.
	Token string `json:"token"`
}

func (s *Server) handleAdminCreateKey(w http.ResponseWriter, r *http.Request) {
	var req createKeyRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.UserID == "" {
		req.UserID = requestUser(r).ID
	}
	if _, err := s.store.UserByID(req.UserID); err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	id, token, secretHash, err := auth.NewAPIKey()
	if err != nil {
		s.writeStoreError(w, err, "key")
		return
	}
	key, err := s.store.CreateAPIKey(id, req.UserID, req.Name, secretHash)
	if err != nil {
		s.writeStoreError(w, err, "key")
		return
	}
	s.log.Info("api key created", "key", key.ID, "user", req.UserID, "by", requestUser(r).Email)
	writeJSON(w, http.StatusCreated, createKeyResponse{Key: key, Token: token})
}

func (s *Server) handleAdminListKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAPIKeys()
	if err != nil {
		s.writeStoreError(w, err, "keys")
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) handleAdminRevokeKey(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RevokeAPIKey(r.PathValue("id")); err != nil {
		s.writeStoreError(w, err, "key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
