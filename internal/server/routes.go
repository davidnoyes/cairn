package server

import "net/http"

func (s *Server) routes() {
	mux := s.mux

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Auth: sign-up, verification, sign-in and reset are all unauthenticated.
	mux.HandleFunc("POST /api/auth/signup", s.handleSignup)
	mux.HandleFunc("POST /api/auth/verify", s.handleVerify)
	mux.HandleFunc("POST /api/auth/prelogin", s.handlePrelogin)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.requireSession(s.handleLogout))
	mux.HandleFunc("POST /api/auth/forgot", s.handleForgot)
	mux.HandleFunc("POST /api/auth/reset/begin", s.handleResetBegin)
	mux.HandleFunc("POST /api/auth/reset/complete", s.handleResetComplete)

	// Signed-in account
	mux.HandleFunc("GET /api/me", s.requireAuth(s.handleMe))
	mux.HandleFunc("GET /api/me/bundle", s.requireAuth(s.handleMeBundle))
	mux.HandleFunc("PUT /api/me/password", s.requireSession(s.handleMePassword))
	mux.HandleFunc("PUT /api/me/recovery", s.requireSession(s.handleMeRecovery))
	mux.HandleFunc("GET /api/me/archives", s.requireAuth(s.handleMeArchives))

	// API keys: the user's own only.
	mux.HandleFunc("GET /api/keys", s.requireAuth(s.handleListKeys))
	mux.HandleFunc("POST /api/keys", s.requireSession(s.handleCreateKey))
	mux.HandleFunc("DELETE /api/keys/{id}", s.requireAuth(s.handleRevokeKey))

	// User directory (any authenticated user)
	mux.HandleFunc("GET /api/users", s.requireAuth(s.handleUsers))
	mux.HandleFunc("GET /api/users/{id}", s.requireAuth(s.handleUserByID))

	// Admin: grant or remove a role, deactivate, or delete. No endpoint here
	// sets a password, creates an account, or creates an API key for someone
	// else.
	mux.HandleFunc("GET /api/admin/users", s.requireAdmin(s.handleAdminListUsers))
	mux.HandleFunc("PATCH /api/admin/users/{id}", s.requireAdmin(s.handleAdminUpdateUser))
	mux.HandleFunc("DELETE /api/admin/users/{id}", s.requireAdmin(s.handleAdminDeleteUser))

	// Artifacts: reads follow the public/private flag, writes need auth.
	// The {id} segment accepts an artifact id or a resource reference
	// (resolved by withArtifact/publicAware; ambiguous references are a 409).
	mux.HandleFunc("GET /api/artifacts", s.requireAuth(s.handleListArtifacts))
	mux.HandleFunc("POST /api/artifacts", s.requireAuth(s.handleCreateArtifact))
	mux.HandleFunc("GET /api/artifacts/{id}", s.publicAware(s.handleGetArtifact))
	mux.HandleFunc("PATCH /api/artifacts/{id}", s.requireAuth(s.withArtifact(s.handleUpdateArtifact)))
	mux.HandleFunc("DELETE /api/artifacts/{id}", s.requireAuth(s.withArtifact(s.handleDeleteArtifact)))
	mux.HandleFunc("POST /api/artifacts/{id}/resources", s.requireAuth(s.withArtifact(s.handleAddResource)))
	mux.HandleFunc("DELETE /api/artifacts/{id}/resources/{rid}", s.requireAuth(s.withArtifact(s.handleDeleteResource)))
	mux.HandleFunc("GET /api/artifacts/{id}/versions", s.publicAware(s.handleListVersions))
	mux.HandleFunc("POST /api/artifacts/{id}/versions", s.requireAuth(s.withArtifact(s.handleUploadVersion)))
	mux.HandleFunc("GET /api/artifacts/{id}/versions/{vid}", s.publicAware(s.handleGetVersion))
	mux.HandleFunc("PUT /api/artifacts/{id}/versions/{vid}", s.requireAuth(s.withArtifact(s.handleReplaceVersion)))
	mux.HandleFunc("PATCH /api/artifacts/{id}/versions/{vid}", s.requireAuth(s.withArtifact(s.handleUpdateVersionMeta)))
	mux.HandleFunc("DELETE /api/artifacts/{id}/versions/{vid}", s.requireAuth(s.withArtifact(s.handleDeleteVersion)))

	// Shared per-version database (raw SQL proxy)
	mux.HandleFunc("POST /api/artifacts/{id}/versions/{vid}/db/query", s.publicAware(s.handleDBQuery))
	mux.HandleFunc("POST /api/artifacts/{id}/versions/{vid}/db/batch", s.requireAuth(s.withArtifact(s.handleDBBatch)))
	mux.HandleFunc("GET /api/artifacts/{id}/versions/{vid}/db/download", s.publicAware(s.handleDBDownload))

	// Per-version file storage
	mux.HandleFunc("GET /api/artifacts/{id}/versions/{vid}/files", s.publicAware(s.handleFileList))
	mux.HandleFunc("GET /api/artifacts/{id}/versions/{vid}/files/{path...}", s.publicAware(s.handleFileDownload))
	mux.HandleFunc("PUT /api/artifacts/{id}/versions/{vid}/files/{path...}", s.requireAuth(s.withArtifact(s.handleFileUpload)))
	mux.HandleFunc("DELETE /api/artifacts/{id}/versions/{vid}/files/{path...}", s.requireAuth(s.withArtifact(s.handleFileDelete)))

	// Pages. Account pages send the app CSP: scripts load only from files.
	mux.HandleFunc("GET /", s.handleRoot)
	mux.HandleFunc("GET /login", withAppCSP(s.handleLoginPage))
	mux.HandleFunc("GET /admin", withAppCSP(s.handleAdminPage))
	mux.HandleFunc("GET /logout", s.handleLogoutPage)
	mux.HandleFunc("GET /cairn.js", s.serveCairnJS)
	mux.HandleFunc("GET /mermaid.js", s.serveMermaidJS)
	mux.HandleFunc("GET /sql-wasm.js", s.serveSqlJS)
	mux.HandleFunc("GET /sql-wasm.wasm", s.serveSqlJS)
	mux.HandleFunc("GET /shell.js", s.serveShellJS)
	mux.HandleFunc("GET /argon2.wasm", s.serveArgon2Wasm)
	mux.HandleFunc("GET /wasm_exec.js", s.serveWasmExecJS)
	mux.HandleFunc("GET /artifacts/{id}", s.handleArtifactRedirect)
	mux.HandleFunc("GET /artifacts/{id}/{vid}", s.handleVersionNoSlash)
	mux.HandleFunc("GET /artifacts/{id}/{vid}/{path...}", s.handleVersionPage)
	mux.HandleFunc("GET /shared/{id}", s.handleShared)
	mux.HandleFunc("GET /shared/{id}/{vid}", s.handleShared)
}
