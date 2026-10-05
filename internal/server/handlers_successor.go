package server

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	netmail "net/mail"
	"time"

	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// The successor. See "Successor" in design/e2e-api.md.

// ekWrapSize is the size of EK wrapped to the successor's key: the size of
// any wrap.
const ekWrapSize = rotateWrapSize

// maxNoticeEmailLen is the longest address a notice address may be.
const maxNoticeEmailLen = 254

// Notice headers on every authenticated response for a user whose successor
// has asked or been released.
const (
	noticeHeader              = "Cairn-Notice"
	noticeSuccessionRequested = "succession-requested"
	noticeRotateKeys          = "rotate-keys"
)

// mustRotateExempt are the writes a user whose successor was released may
// still make, as registered patterns: rotating keys, signing out, creating
// and revoking API keys, and asking for a content token.
var mustRotateExempt = map[string]bool{
	"POST /api/me/rotate":   true,
	"POST /api/auth/logout": true,
	"POST /api/keys":        true,
	"DELETE /api/keys/{id}": true,
	// A content token is a POST that only reads.
	"POST /api/artifacts/{id}/content-token": true,
}

// successionGate puts the notice header for u on the response and, for a
// write from a user whose successor was released, other than the few in
// mustRotateExempt, answers 409 itself and returns false. Every handler that
// authenticates a user calls it.
func (s *Server) successionGate(w http.ResponseWriter, r *http.Request, u *store.User) bool {
	sc, err := s.store.SuccessorOf(u.ID)
	if errors.Is(err, store.ErrNotFound) || err == nil && !sc.Requested() {
		return true
	}
	if err != nil {
		s.writeStoreError(w, err, "successor")
		return false
	}
	if !sc.Released(s.clk.Now()) {
		w.Header().Set(noticeHeader, noticeSuccessionRequested)
		return true
	}
	w.Header().Set(noticeHeader, noticeRotateKeys)
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if mustRotateExempt[r.Pattern] {
		return true
	}
	writeError(w, http.StatusConflict, "rotate your keys first: your successor was released, so no other change is allowed until you do")
	return false
}

// Views

// requestView is a request as the user and the successor see it.
type requestView struct {
	RequestedAt   string `json:"requestedAt"`
	ReleaseAt     string `json:"releaseAt"`
	Released      bool   `json:"released"`
	DeactivatedAt string `json:"deactivatedAt"`
}

// releaseAtOf is the release time of sc's request, empty when there is none.
func releaseAtOf(sc *store.Successor) string {
	if !sc.Requested() {
		return ""
	}
	return sc.ReleaseAt().UTC().Format(time.RFC3339)
}

func (s *Server) requestViewOf(sc *store.Successor) *requestView {
	if !sc.Requested() {
		return nil
	}
	return &requestView{RequestedAt: sc.RequestedAt, ReleaseAt: releaseAtOf(sc), Released: sc.Released(s.clk.Now()), DeactivatedAt: sc.DeactivatedAt}
}

type mySuccessorView struct {
	Successor   *directoryUser `json:"successor"`
	Record      *e2e.Envelope  `json:"record"`
	NominatedAt string         `json:"nominatedAt"`
	Seq         int            `json:"seq"`
	Request     *requestView   `json:"request"`
}

func (s *Server) handleGetSuccessor(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	v := mySuccessorView{}
	var err error
	if v.Seq, err = s.store.LastSuccessorSeq(u.ID); err != nil {
		s.writeStoreError(w, err, "successor")
		return
	}
	sc, err := s.store.SuccessorOf(u.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		s.writeStoreError(w, err, "successor")
		return
	default:
		to, err := s.store.UserByID(sc.SuccessorID)
		if err != nil {
			s.writeStoreError(w, err, "successor")
			return
		}
		d, err := s.toDirectoryUser(to)
		if err != nil {
			s.writeStoreError(w, err, "successor")
			return
		}
		env := envelopeOf(sc.Record)
		v.Successor, v.Record, v.NominatedAt, v.Request = &d, &env, sc.NominatedAt, s.requestViewOf(sc)
	}
	writeJSON(w, http.StatusOK, v)
}

// Nominating and removing

// fingerprintOf is the hex fingerprint of a bundle's public keys.
func fingerprintOf(b *store.Bundle) string {
	return hex.EncodeToString(e2e.Fingerprint(b.X25519Pub, b.Ed25519Pub))
}

// openSuccessorRecord verifies env as a successor record that u signed under
// their current Ed25519 key, and returns its body. A record that fails is a
// refusal, a message for a 400; err is only a failure to read the key.
func (s *Server) openSuccessorRecord(u *store.User, env e2e.Envelope) (body e2e.SuccessorBody, refusal string, err error) {
	b, err := s.store.BundleFor(u.ID)
	if err != nil {
		return body, "", err
	}
	switch {
	case env.Signer != u.ID:
		refusal = "the record is not signed by you"
	case e2e.OpenEnvelope(env, b.Ed25519Pub, "successor", &body) != nil:
		refusal = "the record does not verify under your current key"
	case body.User != u.ID:
		refusal = "the record is not for you"
	}
	return body, refusal, nil
}

// writeSeqConflict answers a successor record whose seq is not one more than
// the last the user signed.
func writeSeqConflict(w http.ResponseWriter, last int) {
	writeJSON(w, http.StatusConflict, map[string]any{"error": "seq must be one more than your last successor record; read it again", "seq": last})
}

type putSuccessorRequest struct {
	AuthKey   string       `json:"authKey"`
	Successor string       `json:"successor"`
	Record    e2e.Envelope `json:"record"`
	Wrapped   string       `json:"wrapped"`
}

// handlePutSuccessor nominates a successor, or replaces one. In one
// transaction it ends any pending request and stores the record.
func (s *Server) handlePutSuccessor(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	var req putSuccessorRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireFreshAuthKey(w, r, req.AuthKey) {
		return
	}
	to, err := s.store.UserByID(req.Successor)
	if errors.Is(err, store.ErrNotFound) || err == nil && (to.ID == u.ID || to.VerifiedAt == "" || to.Disabled) {
		writeError(w, http.StatusBadRequest, "the successor must be another verified, active user")
		return
	}
	if err != nil {
		s.writeStoreError(w, err, "successor")
		return
	}
	wrapped, err := e2e.UnB64(req.Wrapped)
	if err != nil || len(wrapped) != ekWrapSize {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("wrapped must be %d bytes in base64", ekWrapSize))
		return
	}
	body, refusal, err := s.openSuccessorRecord(u, req.Record)
	if err != nil {
		s.writeStoreError(w, err, "bundle")
		return
	}
	if refusal != "" {
		writeError(w, http.StatusBadRequest, refusal)
		return
	}
	b, err := s.store.BundleFor(to.ID)
	if err != nil {
		s.writeStoreError(w, err, "bundle")
		return
	}
	switch {
	case body.Successor != to.ID:
		writeError(w, http.StatusBadRequest, "the record names another successor")
	case body.Action != "nominate":
		writeError(w, http.StatusBadRequest, "the record's action must be nominate")
	case body.SuccessorFP != fingerprintOf(b):
		writeError(w, http.StatusBadRequest, "the record's successorFp is not the successor's current fingerprint")
	default:
		s.putSuccessor(w, u, to, body, req.Record, wrapped)
	}
}

// putSuccessor stores a checked nomination and tells a successor it replaced.
func (s *Server) putSuccessor(w http.ResponseWriter, u, to *store.User, body e2e.SuccessorBody, rec e2e.Envelope, wrapped []byte) {
	prev, last, err := s.store.Nominate(u.ID, to.ID, body.Seq, store.Envelope{Body: rec.Body, Sig: rec.Sig, Signer: rec.Signer}, wrapped, s.clk.Now())
	switch {
	case errors.Is(err, store.ErrStale):
		writeSeqConflict(w, last)
		return
	case errors.Is(err, store.ErrReleased):
		writeError(w, http.StatusConflict, "your successor was released; rotate your keys to end it")
		return
	case err != nil:
		s.writeStoreError(w, err, "successor")
		return
	}
	switch {
	case prev == nil || !prev.Requested():
	case prev.SuccessorID == to.ID:
		s.tellSuccessor(prev.SuccessorID, u, "nominated you again")
	default:
		s.tellSuccessor(prev.SuccessorID, u, "replaced you as their successor")
	}
	s.log.Info("successor nominated", "user", u.Email, "successor", to.Email, "seq", body.Seq)
	writeJSON(w, http.StatusOK, map[string]int{"seq": body.Seq})
}

type deleteSuccessorRequest struct {
	Record e2e.Envelope `json:"record"`
}

// handleDeleteSuccessor removes the successor with a signed remove record.
func (s *Server) handleDeleteSuccessor(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	var req deleteSuccessorRequest
	if !readJSON(w, r, &req) {
		return
	}
	sc, err := s.store.SuccessorOf(u.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusConflict, "you have no successor")
		return
	}
	if err != nil {
		s.writeStoreError(w, err, "successor")
		return
	}
	body, refusal, err := s.openSuccessorRecord(u, req.Record)
	if err != nil {
		s.writeStoreError(w, err, "bundle")
		return
	}
	switch {
	case refusal != "":
		writeError(w, http.StatusBadRequest, refusal)
		return
	case body.Action != "remove" || body.Successor != sc.SuccessorID || body.SuccessorFP != "":
		writeError(w, http.StatusBadRequest, "the record must remove the current successor, with an empty successorFp")
		return
	}
	prev, last, err := s.store.RemoveSuccessor(u.ID, body.Seq, store.Envelope{Body: req.Record.Body, Sig: req.Record.Sig, Signer: req.Record.Signer}, s.clk.Now())
	switch {
	case errors.Is(err, store.ErrStale):
		writeSeqConflict(w, last)
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusConflict, "you have no successor")
		return
	case errors.Is(err, store.ErrReleased):
		writeError(w, http.StatusConflict, "your successor was released; rotate your keys to end it")
		return
	case err != nil:
		s.writeStoreError(w, err, "successor")
		return
	}
	if prev.Requested() {
		s.tellSuccessor(prev.SuccessorID, u, "removed you as their successor")
	}
	s.log.Info("successor removed", "user", u.Email, "seq", body.Seq)
	writeJSON(w, http.StatusOK, map[string]int{"seq": body.Seq})
}

// Refusing

// handleRefuseRequest refuses a pending request from a signed-in session or
// API key. The nomination stays.
func (s *Server) handleRefuseRequest(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	prev, err := s.store.RefuseSuccession(u.ID, s.clk.Now())
	if !s.refusable(w, err) {
		return
	}
	s.tellSuccessor(prev.SuccessorID, u, "refused your request")
	s.log.Info("succession request refused", "user", u.Email)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// refusable answers a failed refusal and reports whether RefuseSuccession
// succeeded. A release is told apart from no request: the user has no
// refusal left, and must rotate their keys instead.
func (s *Server) refusable(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusConflict, "no request is pending")
	case errors.Is(err, store.ErrReleased):
		writeError(w, http.StatusConflict, "the request was already released; rotate your keys to end your successor's access")
	case err != nil:
		s.writeStoreError(w, err, "successor")
	default:
		return true
	}
	return false
}

// tellSuccessor emails a successor that their request ended. It is sent
// without the per-address limit: it is the successor's only word of it.
func (s *Server) tellSuccessor(successorID string, u *store.User, what string) {
	to, err := s.store.UserByID(successorID)
	if err != nil {
		s.log.Error("find the successor to tell", "err", err)
		return
	}
	s.deliverMail(to.Email, "Your request for access to "+u.Email+"'s artifacts ended",
		fmt.Sprintf("%s %s, so your request for access to the artifacts they own ended. You have no access.\n", u.Email, what))
}

// The successor asks

type successionView struct {
	User        directoryUser `json:"user"`
	Record      e2e.Envelope  `json:"record"`
	NominatedAt string        `json:"nominatedAt"`
	RequestedAt string        `json:"requestedAt"`
	ReleaseAt   string        `json:"releaseAt"`
	Released    bool          `json:"released"`
	Wrapped     string        `json:"wrapped,omitempty"`
}

// handleSuccessions lists the users whose nomination names the caller,
// deactivated or not. Only a released one carries the wrapped EK.
func (s *Server) handleSuccessions(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.SuccessionsTo(requestUser(r).ID)
	if err != nil {
		s.writeStoreError(w, err, "successions")
		return
	}
	out := []successionView{}
	for _, sc := range list {
		from, err := s.store.UserByID(sc.UserID)
		if err != nil {
			s.writeStoreError(w, err, "user")
			return
		}
		d, err := s.toDirectoryUser(from)
		if err != nil {
			s.writeStoreError(w, err, "user")
			return
		}
		v := successionView{User: d, Record: envelopeOf(sc.Record), NominatedAt: sc.NominatedAt,
			RequestedAt: sc.RequestedAt, ReleaseAt: releaseAtOf(sc), Released: sc.Released(s.clk.Now())}
		if v.Released {
			v.Wrapped = e2e.B64(sc.Wrapped)
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSuccessionRequest records the successor's request and tells the user.
func (s *Server) handleSuccessionRequest(w http.ResponseWriter, r *http.Request) {
	successor, userID := requestUser(r), r.PathValue("user")
	sc, err := s.store.SuccessorOf(userID)
	if errors.Is(err, store.ErrNotFound) || err == nil && sc.SuccessorID != successor.ID {
		writeError(w, http.StatusNotFound, "that user has not nominated you")
		return
	}
	if err != nil {
		s.writeStoreError(w, err, "successor")
		return
	}
	// A successor who rotated or reset since the nomination cannot open its
	// wrapped copy, so a release would hand over nothing.
	b, err := s.store.BundleFor(successor.ID)
	if err != nil {
		s.writeStoreError(w, err, "bundle")
		return
	}
	var body e2e.SuccessorBody
	if e2e.DecodeStrict(sc.Record.Body, &body) != nil || body.SuccessorFP != fingerprintOf(b) {
		writeError(w, http.StatusConflict, "your keys changed since this user nominated you; ask them to nominate you again")
		return
	}
	switch err := s.store.RequestSuccession(userID, successor.ID, s.clk.Now()); {
	case errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, "a request is already pending, or was released")
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "that user has not nominated you")
		return
	case err != nil:
		s.writeStoreError(w, err, "successor")
		return
	}
	if sc, err = s.store.SuccessorOf(userID); err != nil {
		s.writeStoreError(w, err, "successor")
		return
	}
	user, err := s.store.UserByID(userID)
	if err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	s.tellUserOfRequest(user, successor, sc)
	s.log.Info("succession requested", "user", user.Email, "successor", successor.Email)
	writeJSON(w, http.StatusOK, map[string]string{"requestedAt": sc.RequestedAt, "releaseAt": releaseAtOf(sc)})
}

// tellUserOfRequest emails the account address and any verified notice
// address. It is sent without the per-address limit: anyone can spend an
// address's budget with reset requests, and this is the user's only chance to
// refuse in time.
func (s *Server) tellUserOfRequest(user, successor *store.User, sc *store.Successor) {
	body := fmt.Sprintf("%s (%s), whom you nominated as your successor, asked for access to the artifacts you own.\n\n"+
		"Access starts on %s unless you refuse first. To refuse, sign in and run `cairn successor refuse`, or open:\n\n%s/refuse\n",
		successor.Name, successor.Email, sc.ReleaseAt().UTC().Format("2006-01-02"), s.cfg.PublicURL)
	for _, to := range []string{user.Email, user.NoticeEmail} {
		if to != "" {
			s.deliverMail(to, "Your successor asked for access to your Cairn artifacts", body)
		}
	}
}

// The notice address

type noticeEmailRequest struct {
	Email string `json:"email"`
}

// handlePutNoticeEmail sets a personal address for notices, once its
// verification link is followed, or clears it with an empty string.
func (s *Server) handlePutNoticeEmail(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	var req noticeEmailRequest
	if !readJSON(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	if addr, err := netmail.ParseAddress(email); req.Email != "" && (err != nil || addr.Address != email || len(email) > maxNoticeEmailLen) {
		writeError(w, http.StatusBadRequest, "malformed email address")
		return
	}
	if err := s.store.DeleteTokens(u.ID, "notice"); err != nil {
		s.writeStoreError(w, err, "account")
		return
	}
	if req.Email == "" {
		if err := s.store.ClearNoticeEmail(u.ID); err != nil {
			s.writeStoreError(w, err, "account")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	raw, hash, err := newLinkToken()
	if err != nil {
		s.writeStoreError(w, err, "token")
		return
	}
	if err := s.store.SetNoticeEmailPending(u.ID, email); err != nil {
		s.writeStoreError(w, err, "account")
		return
	}
	if err := s.store.CreateToken(hash, u.ID, "notice", s.clk.Now().Add(24*time.Hour)); err != nil {
		s.writeStoreError(w, err, "token")
		return
	}
	link := s.cfg.PublicURL + "/verify#token=" + e2e.B64(raw)
	s.sendMail(email, "Verify your Cairn notice address", "Follow this link to receive notices about your Cairn account here:\n\n"+link+"\n\nThis link expires in 24 hours.")
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "check-email"})
}

// The refusal page

type refuseBeginRequest struct {
	Email string `json:"email"`
}

type refuseBeginResponse struct {
	ID          string `json:"id"`
	MKRecovery  string `json:"mkRecovery"`
	Ed25519Priv string `json:"ed25519Priv"`
	RequestedAt string `json:"requestedAt"`
}

// handleRefuseBegin returns what a refusal with the recovery code needs: the
// account's sealed signing key and the request's requestedAt while a request
// is pending, and otherwise a fake of the same shape, so the answer does not
// reveal whether one is.
func (s *Server) handleRefuseBegin(w http.ResponseWriter, r *http.Request) {
	var req refuseBeginRequest
	if !readJSON(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	if u, err := s.store.UserByEmail(email); err == nil {
		if sc, err := s.store.SuccessorOf(u.ID); err == nil && sc.Requested() && !sc.Released(s.clk.Now()) {
			b, err := s.store.BundleFor(u.ID)
			if err != nil {
				s.writeStoreError(w, err, "bundle")
				return
			}
			writeJSON(w, http.StatusOK, refuseBeginResponse{ID: u.ID, MKRecovery: e2e.B64(b.MKRecovery), Ed25519Priv: e2e.B64(b.Ed25519Priv), RequestedAt: sc.RequestedAt})
			return
		}
	}
	id, mk, priv := e2e.RefuseFake(s.preloginSecret, email)
	at := e2e.RefuseFakeRequestedAt(s.preloginSecret, email, s.clk.Now(), store.SuccessionWait)
	writeJSON(w, http.StatusOK, refuseBeginResponse{ID: id, MKRecovery: e2e.B64(mk), Ed25519Priv: e2e.B64(priv), RequestedAt: at.Format(time.RFC3339)})
}

// dummyRefusalKey is a fixed public key whose private key is never used. A
// proof for an unknown address is checked against it, so the answer takes as
// long as one for an account.
var dummyRefusalKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)

type refuseRequest struct {
	Email   string        `json:"email"`
	AuthKey string        `json:"authKey"`
	Proof   *e2e.Envelope `json:"proof"`
}

type refusedView struct {
	Refused       bool             `json:"refused"`
	Successor     refusedSuccessor `json:"successor"`
	RequestedAt   string           `json:"requestedAt"`
	DeactivatedAt string           `json:"deactivatedAt"`
}

type refusedSuccessor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// refusalProof reports whether env is u's refusal: signed under their current
// Ed25519 key, naming them, and, while a request is pending, naming its
// requestedAt exactly as the server sent it, so it cannot be replayed against
// a later request. With nothing pending any authentic proof passes, and the
// answer is 409.
func (s *Server) refusalProof(u *store.User, env e2e.Envelope) bool {
	b, err := s.store.BundleFor(u.ID)
	if err != nil {
		return false
	}
	var body e2e.RefusalBody
	if env.Signer != u.ID || e2e.OpenEnvelope(env, b.Ed25519Pub, "refusal", &body) != nil || body.User != u.ID {
		return false
	}
	if sc, err := s.store.SuccessorOf(u.ID); err == nil && sc.Requested() {
		return body.RequestedAt == sc.RequestedAt
	}
	return true
}

// handleRefuse refuses a request from the refusal page, with the account's
// key or with a proof signed by the recovery code's key. It works for a
// deactivated account. A wrong key or proof is a failed sign-in for the rate
// limits.
func (s *Server) handleRefuse(w http.ResponseWriter, r *http.Request) {
	var req refuseRequest
	if !readJSON(w, r, &req) {
		return
	}
	email, ip := normalizeEmail(req.Email), clientIP(r)
	if retryAfter, blocked := s.checkSignInLimits(email, ip); blocked {
		writeRateLimited(w, retryAfter)
		return
	}
	if (req.AuthKey == "") == (req.Proof == nil) {
		writeError(w, http.StatusBadRequest, "send either authKey or proof")
		return
	}
	u, err := s.store.UserByEmail(email)
	known := err == nil
	valid := false
	if req.Proof == nil {
		authKey, err := e2e.UnB64(req.AuthKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "malformed authKey")
			return
		}
		hash := dummyAuthHash
		if known {
			hash = u.AuthHash
		}
		valid = auth.CheckPassword(hash, string(authKey)) && known
	} else if known {
		valid = s.refusalProof(u, *req.Proof)
	} else {
		var body e2e.RefusalBody
		_ = e2e.OpenEnvelope(*req.Proof, dummyRefusalKey, "refusal", &body) // timing only; result unused
	}
	if !valid {
		s.recordSignInFailure(email, ip)
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	prev, err := s.store.RefuseSuccession(u.ID, s.clk.Now())
	if !s.refusable(w, err) {
		return
	}
	to, err := s.store.UserByID(prev.SuccessorID)
	if err != nil {
		s.writeStoreError(w, err, "successor")
		return
	}
	s.tellSuccessor(to.ID, u, "refused your request")
	s.log.Info("succession request refused on the page", "user", u.Email)
	writeJSON(w, http.StatusOK, refusedView{Refused: true, Successor: refusedSuccessor{Name: to.Name, Email: to.Email},
		RequestedAt: prev.RequestedAt, DeactivatedAt: prev.DeactivatedAt})
}
