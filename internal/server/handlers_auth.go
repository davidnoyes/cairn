package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
	"github.com/aloisdeniel/cairn/internal/store"
)

// maxNameLen is signup's limit on a display name.
const maxNameLen = 200

// normalizeEmail lowercases and trims an address the way every lookup,
// comparison, mail, and the prelogin salt expects it.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// dummyAuthHash is bcrypt of a fixed, never-presented value. Sign-in for an
// unknown account still runs bcrypt against it, so the response time doesn't
// reveal whether the address has one.
var dummyAuthHash = mustHashPassword("cairn/v1/no-such-account")

func mustHashPassword(s string) string {
	h, err := auth.HashPassword(s)
	if err != nil {
		panic(err)
	}
	return h
}

// domainAllowed reports whether email may sign up: its domain is one of
// cfg.SignupDomains, or it is exactly cfg.AdminEmail.
func (s *Server) domainAllowed(email string) bool {
	if email == s.cfg.AdminEmail {
		return true
	}
	i := strings.LastIndex(email, "@")
	if i < 0 {
		return false
	}
	domain := email[i+1:]
	for _, d := range s.cfg.SignupDomains {
		if domain == d {
			return true
		}
	}
	return false
}

// newLinkToken generates a 32-byte random token for a verification or reset
// link, returning the raw bytes (shown once, in the link) and the hex-SHA-256
// hash the store keeps.
func newLinkToken() (raw []byte, hash string, err error) {
	raw = make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return nil, "", err
	}
	return raw, hashToken(raw), nil
}

func hashToken(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// sendMail delivers an email unless the per-address rate limit (three an
// hour, across sign-up, verification, and reset) is already spent, in which
// case the caller's "answer as if it succeeded" response is unaffected and
// the message is simply dropped.
func (s *Server) sendMail(to, subject, body string) {
	if !s.mailLimit.take(to) {
		return
	}
	s.deliverMail(to, subject, body)
}

// deliverMail sends without the per-address limit, for mail only a token
// holder can trigger.
func (s *Server) deliverMail(to, subject, body string) {
	if err := s.mail.Send(context.Background(), mail.Message{To: to, Subject: subject, Body: body}); err != nil {
		s.log.Error("send mail", "to", to, "err", err)
	}
}

func (s *Server) sendVerifyLink(u *store.User) {
	if err := s.store.DeleteTokens(u.ID, "verify"); err != nil {
		s.log.Error("delete old verify tokens", "err", err)
	}
	raw, hash, err := newLinkToken()
	if err != nil {
		s.log.Error("generate verify token", "err", err)
		return
	}
	if err := s.store.CreateToken(hash, u.ID, "verify", s.clk.Now().Add(24*time.Hour)); err != nil {
		s.log.Error("store verify token", "err", err)
		return
	}
	link := s.cfg.PublicURL + "/verify#token=" + e2e.B64(raw)
	s.sendMail(u.Email, "Verify your Cairn account", "Follow this link to verify your account:\n\n"+link+"\n\nThis link expires in 24 hours.")
}

func (s *Server) sendResetLink(u *store.User) {
	if err := s.store.DeleteTokens(u.ID, "reset"); err != nil {
		s.log.Error("delete old reset tokens", "err", err)
	}
	raw, hash, err := newLinkToken()
	if err != nil {
		s.log.Error("generate reset token", "err", err)
		return
	}
	if err := s.store.CreateToken(hash, u.ID, "reset", s.clk.Now().Add(30*time.Minute)); err != nil {
		s.log.Error("store reset token", "err", err)
		return
	}
	link := s.cfg.PublicURL + "/reset#token=" + e2e.B64(raw)
	s.sendMail(u.Email, "Reset your Cairn password", "Follow this link to reset your password:\n\n"+link+"\n\nThis link expires in 30 minutes.")
}

// sendResetNotice bypasses the mail limit: anyone can spend an address's
// budget with forgot requests, and this notice is the user's only signal
// that their password changed.
func (s *Server) sendResetNotice(u *store.User) {
	s.deliverMail(u.Email, "Your Cairn password was reset", "Your password was just reset. If this wasn't you, contact your administrator.")
}

// issueToken signs a session JWT for u, carrying its current token version so
// a password change or account disable revokes it instantly.
func (s *Server) issueToken(u *store.User) (string, error) {
	nowT := s.clk.Now()
	return auth.SignJWT(s.secret, auth.Claims{
		UserID:       u.ID,
		IsAdmin:      u.IsAdmin,
		TokenVersion: u.TokenVersion,
		IssuedAt:     nowT.Unix(),
		ExpiresAt:    nowT.Add(s.cfg.TokenTTL).Unix(),
	})
}

// checkSignInLimits reports whether email or the client IP has already
// failed enough times in the last 15 minutes that even a correct key must be
// refused.
func (s *Server) checkSignInLimits(email, ip string) (time.Duration, bool) {
	if ra, blocked := s.signIn.account.blocked(email); blocked {
		return ra, true
	}
	if ra, blocked := s.signIn.ip.blocked(ip); blocked {
		return ra, true
	}
	return 0, false
}

func (s *Server) recordSignInFailure(email, ip string) {
	s.signIn.account.record(email)
	s.signIn.ip.record(ip)
}

// meView is the projection of a user returned at /api/me and after login.
type meView struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	IsAdmin   bool   `json:"isAdmin"`
	CreatedAt string `json:"createdAt"`
	ResetAt   string `json:"resetAt,omitempty"`
}

func toMeView(u *store.User) meView {
	return meView{ID: u.ID, Email: u.Email, Name: u.Name, IsAdmin: u.IsAdmin, CreatedAt: u.CreatedAt, ResetAt: u.ResetAt}
}

// Sign-up and verification

type signupRequest struct {
	Email   string     `json:"email"`
	Name    string     `json:"name"`
	AuthKey string     `json:"authKey"`
	Bundle  bundleWire `json:"bundle"`
}

// handleSignup creates an unverified account, or re-sends a link for one
// that is still unverified. A verified account at the address changes
// nothing; its owner is mailed instead. The response is always 202, so
// sign-up never reveals which addresses already have an account.
func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	var req signupRequest
	if !readJSON(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	if len(req.Name) > maxNameLen {
		writeError(w, http.StatusBadRequest, "name is too long")
		return
	}
	if !s.domainAllowed(email) {
		writeError(w, http.StatusForbidden, "this email domain may not sign up")
		return
	}
	bundle, err := decodeBundle(req.Bundle)
	if err != nil || validateBundle(bundle) != nil {
		writeError(w, http.StatusBadRequest, "malformed key bundle")
		return
	}
	authKey, err := e2e.UnB64(req.AuthKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed authKey")
		return
	}
	authHash, err := auth.HashPassword(string(authKey))
	if err != nil {
		s.writeStoreError(w, err, "account")
		return
	}

	// CreateAccount decides new, unverified, or verified in one transaction,
	// so a verification landing mid-request can't change the answer.
	u, err := s.store.CreateAccount(email, req.Name, authHash, bundle, email == s.cfg.AdminEmail)
	switch {
	case errors.Is(err, store.ErrExists):
		s.sendMail(email, "Someone tried to sign up with your email",
			fmt.Sprintf("Someone tried to create a Cairn account with %s, which already has one. If this wasn't you, you can ignore this message.", email))
	case err != nil:
		s.writeStoreError(w, err, "account")
		return
	default:
		s.sendVerifyLink(u)
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "check-email"})
}

type verifyRequest struct {
	Token string `json:"token"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if !readJSON(w, r, &req) {
		return
	}
	raw, err := e2e.UnB64(req.Token)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired token")
		return
	}
	tok, err := s.store.UseToken(hashToken(raw), "verify", s.clk.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired token")
		return
	}
	if err := s.store.MarkVerified(tok.UserID, s.clk.Now()); err != nil {
		s.writeStoreError(w, err, "account")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Sign-in

type preloginRequest struct {
	Email string `json:"email"`
}

// handlePrelogin returns the kdf parameters a verified account registered,
// or a stable fake salt under the current defaults for anything else, so the
// response never reveals whether the address has a verified account.
func (s *Server) handlePrelogin(w http.ResponseWriter, r *http.Request) {
	var req preloginRequest
	if !readJSON(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	if u, err := s.store.UserByEmail(email); err == nil && u.VerifiedAt != "" {
		if b, err := s.store.BundleFor(u.ID); err == nil {
			writeJSON(w, http.StatusOK, b.KDF)
			return
		}
	}
	params := e2e.Params{Alg: "argon2id", Memory: 65536, Time: 3, Threads: 1, Salt: e2e.PreloginSalt(s.preloginSecret, email)}
	writeJSON(w, http.StatusOK, params)
}

type loginRequest struct {
	Email   string `json:"email"`
	AuthKey string `json:"authKey"`
	Client  string `json:"client"`
}

type loginResponse struct {
	User   meView     `json:"user"`
	Bundle bundleWire `json:"bundle"`
	Token  string     `json:"token,omitempty"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !readJSON(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	ip := clientIP(r)
	if retryAfter, blocked := s.checkSignInLimits(email, ip); blocked {
		writeRateLimited(w, retryAfter)
		return
	}
	authKey, err := e2e.UnB64(req.AuthKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed authKey")
		return
	}
	u, err := s.store.UserByEmail(email)
	if err != nil {
		auth.CheckPassword(dummyAuthHash, string(authKey)) // timing only; result unused
		s.recordSignInFailure(email, ip)
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	if !auth.CheckPassword(u.AuthHash, string(authKey)) {
		s.recordSignInFailure(email, ip)
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	if u.VerifiedAt == "" {
		writeError(w, http.StatusForbidden, "verify your email first")
		return
	}
	if u.Disabled {
		writeError(w, http.StatusForbidden, "account deactivated")
		return
	}
	bundle, err := s.store.BundleFor(u.ID)
	if err != nil {
		s.writeStoreError(w, err, "bundle")
		return
	}
	token, err := s.issueToken(u)
	if err != nil {
		s.writeStoreError(w, err, "token")
		return
	}
	s.setSessionCookie(w, token, s.cfg.TokenTTL)
	resp := loginResponse{User: toMeView(u), Bundle: encodeBundle(*bundle)}
	if req.Client == "cli" {
		resp.Token = token
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Password reset

type forgotRequest struct {
	Email string `json:"email"`
}

func (s *Server) handleForgot(w http.ResponseWriter, r *http.Request) {
	var req forgotRequest
	if !readJSON(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	if u, err := s.store.UserByEmail(email); err == nil && u.VerifiedAt != "" {
		s.sendResetLink(u)
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "check-email"})
}

type resetBeginRequest struct {
	Token string `json:"token"`
}

type resetBeginResponse struct {
	Email      string `json:"email"`
	MKRecovery string `json:"mkRecovery"`
	X25519Pub  string `json:"x25519Pub"`
	Ed25519Pub string `json:"ed25519Pub"`
}

// handleResetBegin reads what a reset needs without consuming the token;
// reset/complete still has to use it.
func (s *Server) handleResetBegin(w http.ResponseWriter, r *http.Request) {
	var req resetBeginRequest
	if !readJSON(w, r, &req) {
		return
	}
	raw, err := e2e.UnB64(req.Token)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired token")
		return
	}
	tok, err := s.store.PeekToken(hashToken(raw), "reset", s.clk.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired token")
		return
	}
	u, err := s.store.UserByID(tok.UserID)
	if err != nil {
		s.writeStoreError(w, err, "account")
		return
	}
	b, err := s.store.BundleFor(u.ID)
	if err != nil {
		s.writeStoreError(w, err, "bundle")
		return
	}
	writeJSON(w, http.StatusOK, resetBeginResponse{
		Email:      u.Email,
		MKRecovery: e2e.B64(b.MKRecovery),
		X25519Pub:  e2e.B64(b.X25519Pub),
		Ed25519Pub: e2e.B64(b.Ed25519Pub),
	})
}

// resetCompleteRequest covers both reset modes; a field only one of them
// uses is simply absent from the other's body, which strict decoding allows.
type resetCompleteRequest struct {
	Token      string          `json:"token"`
	Mode       string          `json:"mode"`
	AuthKey    string          `json:"authKey"`
	KDF        json.RawMessage `json:"kdf,omitempty"`
	MKPassword string          `json:"mkPassword,omitempty"`
	Proof      string          `json:"proof,omitempty"`
	Bundle     *bundleWire     `json:"bundle,omitempty"`
}

// resetProofBody is the body a reset proof signs over, exactly
// {"v":1,"user","token"} from design/e2e-wire-formats.md; token is
// hex(SHA-256(the reset token)), so the proof can't be replayed with another
// link.
type resetProofBody struct {
	V     int    `json:"v"`
	User  string `json:"user"`
	Token string `json:"token"`
}

func (s *Server) handleResetComplete(w http.ResponseWriter, r *http.Request) {
	var req resetCompleteRequest
	if !readJSON(w, r, &req) {
		return
	}
	raw, err := e2e.UnB64(req.Token)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired token")
		return
	}
	tokenHash := hashToken(raw)
	tok, err := s.store.PeekToken(tokenHash, "reset", s.clk.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired token")
		return
	}
	u, err := s.store.UserByID(tok.UserID)
	if err != nil {
		s.writeStoreError(w, err, "account")
		return
	}
	authKey, err := e2e.UnB64(req.AuthKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed authKey")
		return
	}
	authHash, err := auth.HashPassword(string(authKey))
	if err != nil {
		s.writeStoreError(w, err, "account")
		return
	}

	var apply func() error
	var ok bool
	switch req.Mode {
	case "recovery":
		apply, ok = s.prepareResetRecovery(w, req, u, tokenHash, authHash)
	case "new":
		apply, ok = s.prepareResetNew(w, req, u, authHash)
	default:
		writeError(w, http.StatusBadRequest, "unknown reset mode")
		return
	}
	if !ok {
		return
	}
	// The token is used only once the request is known to be good, so a
	// malformed attempt doesn't burn the link. UseToken is atomic, so of two
	// concurrent completions only one gets past here.
	if _, err := s.store.UseToken(tokenHash, "reset", s.clk.Now()); err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired token")
		return
	}
	if err := apply(); err != nil {
		s.writeStoreError(w, err, "account")
		return
	}
	s.sendResetNotice(u)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// prepareResetRecovery verifies the reset proof against the user's existing
// Ed25519 key, and returns the change that replaces authKey, kdf, and
// mkPassword. The key pairs, the recovery wrap, and API keys are untouched.
func (s *Server) prepareResetRecovery(w http.ResponseWriter, req resetCompleteRequest, u *store.User, tokenHash, authHash string) (func() error, bool) {
	if _, err := validateKDF(req.KDF); err != nil {
		writeError(w, http.StatusBadRequest, "malformed key bundle")
		return nil, false
	}
	mkPassword, err := e2e.UnB64(req.MKPassword)
	if err != nil || validateSealedLen(mkPassword) != nil {
		writeError(w, http.StatusBadRequest, "malformed key bundle")
		return nil, false
	}
	proof, err := e2e.UnB64(req.Proof)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid proof")
		return nil, false
	}
	b, err := s.store.BundleFor(u.ID)
	if err != nil {
		s.writeStoreError(w, err, "bundle")
		return nil, false
	}
	body, err := json.Marshal(resetProofBody{V: 1, User: u.ID, Token: tokenHash})
	if err != nil {
		s.writeStoreError(w, err, "proof")
		return nil, false
	}
	if !e2e.Verify(b.Ed25519Pub, "reset", body, proof) {
		writeError(w, http.StatusBadRequest, "invalid proof")
		return nil, false
	}
	return func() error { return s.store.SetPassword(u.ID, authHash, string(req.KDF), mkPassword) }, true
}

// prepareResetNew validates the new bundle, and returns the change that
// archives the current bundle and every API key's wrapped MK, revokes those
// keys, and stores the new bundle.
func (s *Server) prepareResetNew(w http.ResponseWriter, req resetCompleteRequest, u *store.User, authHash string) (func() error, bool) {
	if req.Bundle == nil {
		writeError(w, http.StatusBadRequest, "malformed key bundle")
		return nil, false
	}
	bundle, err := decodeBundle(*req.Bundle)
	if err != nil || validateBundle(bundle) != nil {
		writeError(w, http.StatusBadRequest, "malformed key bundle")
		return nil, false
	}
	return func() error { return s.store.ResetAccount(u.ID, authHash, bundle, s.clk.Now()) }, true
}
