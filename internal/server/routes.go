package server

import (
	"net/http"

	"github.com/aloisdeniel/cairn/internal/access"
)

func (s *Server) routes() {
	handle := func(pattern string, h http.HandlerFunc) {
		s.patterns = append(s.patterns, pattern)
		s.mux.HandleFunc(pattern, h)
	}

	handle("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Auth: sign-up, verification, sign-in and reset are all unauthenticated.
	handle("POST /api/auth/signup", s.handleSignup)
	handle("POST /api/auth/verify", s.handleVerify)
	handle("POST /api/auth/prelogin", s.handlePrelogin)
	handle("POST /api/auth/login", s.handleLogin)
	handle("POST /api/auth/logout", s.requireSession(s.handleLogout))
	handle("POST /api/auth/forgot", s.handleForgot)
	handle("POST /api/auth/reset/begin", s.handleResetBegin)
	handle("POST /api/auth/reset/complete", s.handleResetComplete)

	// Signed-in account
	handle("GET /api/me", s.requireAuth(s.handleMe))
	handle("GET /api/me/bundle", s.requireAuth(s.handleMeBundle))
	handle("PUT /api/me/password", s.requireSession(s.handleMePassword))
	handle("PUT /api/me/recovery", s.requireSession(s.handleMeRecovery))
	handle("GET /api/me/archives", s.requireAuth(s.handleMeArchives))
	handle("GET /api/me/keyring", s.requireAuth(s.handleGetKeyring))
	handle("PUT /api/me/keyring", s.requireAuth(s.handlePutKeyring))
	handle("POST /api/me/rotate", s.requireSession(s.handleMeRotate))

	// API keys: the user's own only.
	handle("GET /api/keys", s.requireAuth(s.handleListKeys))
	handle("POST /api/keys", s.requireSession(s.handleCreateKey))
	handle("DELETE /api/keys/{id}", s.requireAuth(s.handleRevokeKey))

	// User directory (any authenticated user)
	handle("GET /api/users", s.requireAuth(s.handleUsers))
	handle("GET /api/users/{id}", s.requireAuth(s.handleUserByID))
	handle("GET /api/users/{id}/rotations", s.requireAuth(s.handleUserRotations))

	// Admin: grant or remove a role, deactivate, or delete. No endpoint here
	// sets a password, creates an account, or creates an API key for someone
	// else.
	handle("GET /api/admin/users", s.requireAdmin(s.handleAdminListUsers))
	handle("PATCH /api/admin/users/{id}", s.requireAdmin(s.handleAdminUpdateUser))
	handle("DELETE /api/admin/users/{id}", s.requireAdmin(s.handleAdminDeleteUser))
	handle("GET /api/admin/users/{id}/artifacts", s.requireAdmin(s.handleAdminUserArtifacts))
	handle("POST /api/admin/artifacts/{id}/transfer", s.requireAdmin(s.handleAdminOfferTransfer))
	handle("DELETE /api/admin/artifacts/{id}", s.requireAdmin(s.handleAdminDeleteArtifact))

	// Artifacts. Every route under /api/artifacts/{id} resolves the {id}
	// segment (artifact id, else resource reference) among the artifacts the
	// caller can read, then checks one access action; no access is a 404,
	// administrators included. See artifactRoute in sharing.go.
	handle("GET /api/artifacts", s.requireAuth(s.handleListArtifacts))
	handle("POST /api/artifacts", s.requireAuth(s.handleCreateArtifact))
	handle("GET /api/artifacts/{id}", s.artifactRoute(access.ReadContent, s.handleGetArtifact))
	handle("PATCH /api/artifacts/{id}", s.artifactRoute(access.Rename, s.handleUpdateArtifact))
	handle("DELETE /api/artifacts/{id}", s.artifactRoute(access.Delete, s.handleDeleteArtifact))
	handle("GET /api/artifacts/{id}/membership", s.artifactRoute(access.ReadMembership, s.handleGetMembership))
	handle("PUT /api/artifacts/{id}/membership", s.artifactRoute(access.Share, s.handlePutMembership))
	handle("POST /api/artifacts/{id}/content-token", s.requireSession(s.artifactRoute(access.ReadContent, s.handleContentToken)))
	handle("POST /api/artifacts/{id}/transfer", s.artifactRoute(access.Transfer, s.handleOfferTransfer))
	handle("DELETE /api/artifacts/{id}/transfer", s.artifactRoute(access.AnswerTransfer, s.handleCloseTransfer))
	handle("POST /api/artifacts/{id}/transfer/accept", s.artifactRoute(access.AnswerTransfer, s.handleAcceptTransfer))
	handle("GET /api/artifacts/{id}/keys", s.artifactRoute(access.ReadKeys, s.handleGetKeys))
	handle("POST /api/artifacts/{id}/keys", s.artifactRoute(access.ApproveMember, s.handleApprove))
	handle("GET /api/artifacts/{id}/pending", s.artifactRoute(access.ListPending, s.handlePending))
	handle("GET /api/artifacts/{id}/review", s.artifactRoute(access.ReviewVersions, s.handleReview))
	handle("PUT /api/artifacts/{id}/versions/{vid}/vouch", s.artifactRoute(access.ReviewVersions, s.handleVouch))
	handle("POST /api/artifacts/{id}/resources", s.artifactRoute(access.Rename, s.handleAddResource))
	handle("DELETE /api/artifacts/{id}/resources/{rid}", s.artifactRoute(access.Rename, s.handleDeleteResource))
	handle("GET /api/artifacts/{id}/versions", s.artifactRoute(access.ReadContent, s.handleListVersions))
	handle("POST /api/artifacts/{id}/versions", s.artifactRoute(access.PushVersion, s.handleUploadVersion))
	handle("GET /api/artifacts/{id}/versions/{vid}", s.artifactRoute(access.ReadContent, s.handleGetVersion))
	handle("PUT /api/artifacts/{id}/versions/{vid}", s.artifactRoute(access.PushVersion, s.handleReplaceVersion))
	handle("PATCH /api/artifacts/{id}/versions/{vid}", s.artifactRoute(access.Rename, s.handleUpdateVersionMeta))
	handle("DELETE /api/artifacts/{id}/versions/{vid}", s.artifactRoute(access.Delete, s.handleDeleteVersion))

	// Shared per-version database (raw SQL proxy). A query runs on the
	// read-write pool only for a caller who may write data.
	handle("POST /api/artifacts/{id}/versions/{vid}/db/query", s.artifactRoute(access.ReadContent, s.handleDBQuery))
	handle("POST /api/artifacts/{id}/versions/{vid}/db/batch", s.artifactRoute(access.WriteData, s.handleDBBatch))
	handle("GET /api/artifacts/{id}/versions/{vid}/db/download", s.artifactRoute(access.ReadContent, s.handleDBDownload))

	// Per-version file storage
	handle("GET /api/artifacts/{id}/versions/{vid}/files", s.artifactRoute(access.ReadContent, s.handleFileList))
	handle("GET /api/artifacts/{id}/versions/{vid}/files/{path...}", s.artifactRoute(access.ReadContent, s.handleFileDownload))
	handle("PUT /api/artifacts/{id}/versions/{vid}/files/{path...}", s.artifactRoute(access.WriteData, s.handleFileUpload))
	handle("DELETE /api/artifacts/{id}/versions/{vid}/files/{path...}", s.artifactRoute(access.WriteData, s.handleFileDelete))

	// Pages. Account pages send the app CSP: scripts load only from files.
	handle("GET /", s.handleRoot)
	handle("GET /login", withAppCSP(s.handleLoginPage))
	for _, page := range []string{"signup", "verify", "forgot", "reset"} {
		handle("GET /"+page, withAppCSP(s.handleStaticPage(page+".html")))
	}
	handle("GET /admin", withAppCSP(s.handleAdminPage))
	handle("GET /logout", s.handleLogoutPage)
	handle("GET /cairn.js", s.serveCairnJS)
	handle("GET /mermaid.js", s.serveMermaidJS)
	handle("GET /sql-wasm.js", s.serveSqlJS)
	handle("GET /sql-wasm.wasm", s.serveSqlJS)
	handle("GET /shell.js", s.serveShellJS)
	for path, file := range appAssets {
		handle("GET "+path, serveAppAsset(file))
	}
	handle("GET /argon2.wasm", s.serveArgon2Wasm)
	handle("GET /wasm_exec.js", s.serveWasmExecJS)
	handle("GET /artifacts/{id}", s.handleArtifactRedirect)
	handle("GET /artifacts/{id}/{vid}", s.handleArtifactRedirect)
	handle("GET /artifacts/{id}/{vid}/{path...}", s.handleArtifactRedirect)
	handle("GET /shared/{id}", s.withShellCSP(s.handleShared))
	handle("GET /shared/{id}/{vid}", s.withShellCSP(s.handleShared))
	handle("GET /shared/{id}/{vid}/{path...}", s.withShellCSP(s.handleShared))
}
