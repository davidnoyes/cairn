package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/google/uuid"
)

// Groups. See "Groups" in design/e2e-api.md.

// groupView is a group as the endpoints answer: the latest record's name,
// its seq, the number of members, and the caller's role, empty when they are
// not a member. Records, oldest first, and Signers are present only in the
// answers that carry them.
type groupView struct {
	ID      string                 `json:"id"`
	Name    string                 `json:"name"`
	Seq     int                    `json:"seq"`
	Members int                    `json:"members"`
	Role    string                 `json:"role"`
	Records []e2e.Envelope         `json:"records,omitempty"`
	Signers map[string]groupSigner `json:"signers,omitempty"`
}

// groupSigner is a signer of a group record: their current public keys and
// their rotation records, oldest first.
type groupSigner struct {
	X25519    string         `json:"x25519"`
	Ed25519   string         `json:"ed25519"`
	Rotations []e2e.Envelope `json:"rotations"`
}

// groupRecordRequest is the body of POST /api/groups and PUT
// /api/groups/{id}.
type groupRecordRequest struct {
	Record e2e.Envelope `json:"record"`
}

// groupRefusal is a refused group record: the status to answer with, and why.
type groupRefusal struct {
	Status int
	Msg    string
}

func (e *groupRefusal) Error() string { return e.Msg }

func groupRefuse(status int, format string, args ...any) *groupRefusal {
	return &groupRefusal{Status: status, Msg: fmt.Sprintf(format, args...)}
}

// groupLatest is a group's stored chain: its records and the body of the
// last, with that body's hash.
type groupLatest struct {
	Records []store.Envelope
	Body    e2e.GroupBody
	Hash    string
}

// loadGroup reads a group's records and decodes the latest. The server
// checked every body it stored, so one that does not decode is a fault.
func (s *Server) loadGroup(id string) (*groupLatest, error) {
	recs, err := s.store.GroupRecords(id)
	if err != nil {
		return nil, err
	}
	g := &groupLatest{Records: recs}
	last := recs[len(recs)-1]
	if err := json.Unmarshal(last.Body, &g.Body); err != nil {
		return nil, fmt.Errorf("group %s: decoding its latest record: %w", id, err)
	}
	g.Hash = e2e.BodyHash(last.Body)
	return g, nil
}

// signers reads the keys and rotation records of everyone who signed a record
// of g, from the store, so a deactivated account is served too.
func (s *Server) signers(g *groupLatest) (map[string]groupSigner, error) {
	out := map[string]groupSigner{}
	for _, r := range g.Records {
		if _, ok := out[r.Signer]; ok {
			continue
		}
		u, err := s.store.KeyedUserByID(r.Signer)
		if err != nil {
			return nil, fmt.Errorf("group %s: the signer %s of a record: %w", g.Body.Group, r.Signer, err)
		}
		rows, err := s.store.Rotations(u.ID)
		if err != nil {
			return nil, err
		}
		rotations := []e2e.Envelope{}
		for _, row := range rows {
			rotations = append(rotations, rotationEnvelope(row))
		}
		out[u.ID] = groupSigner{X25519: e2e.B64(u.X25519Pub), Ed25519: e2e.B64(u.Ed25519Pub), Rotations: rotations}
	}
	return out, nil
}

// fullView is g.view with every record and the keys of the signers.
func (s *Server) fullView(g *groupLatest, caller string) (groupView, error) {
	v := g.view(caller, true)
	var err error
	v.Signers, err = s.signers(g)
	return v, err
}

// writeGroup answers status with g as fullView gives it.
func (s *Server) writeGroup(w http.ResponseWriter, status int, g *groupLatest, caller string) {
	v, err := s.fullView(g, caller)
	if err != nil {
		s.writeStoreError(w, err, "group")
		return
	}
	writeJSON(w, status, v)
}

// view is g as the endpoints answer it to caller. withRecords adds every
// record.
func (g *groupLatest) view(caller string, withRecords bool) groupView {
	v := groupView{ID: g.Body.Group, Name: g.Body.Name, Seq: g.Body.Seq, Members: len(g.Body.Members)}
	for _, m := range g.Body.Members {
		if m.User == caller {
			v.Role = m.Role
		}
	}
	if withRecords {
		for _, r := range g.Records {
			v.Records = append(v.Records, envelopeOf(r))
		}
	}
	return v
}

// groupWriter returns the caller of a write, or answers 403 and returns
// false for a viewer account, which changes nothing.
func groupWriter(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	caller := requestUser(r)
	if caller.Role == store.RoleViewer {
		writeError(w, http.StatusForbidden, errViewerAccount)
		return nil, false
	}
	return caller, true
}

// managerEntry returns the entry that lists user as a manager in members.
func managerEntry(members []e2e.GroupMember, user string) (e2e.GroupMember, bool) {
	for _, m := range members {
		if m.User == user && m.Role == "manager" {
			return m, true
		}
	}
	return e2e.GroupMember{}, false
}

// writeGroupError answers a refusal with its own status, and any other error
// as a store fault.
func (s *Server) writeGroupError(w http.ResponseWriter, err error) {
	var refusal *groupRefusal
	if errors.As(err, &refusal) {
		writeError(w, refusal.Status, refusal.Msg)
		return
	}
	s.writeStoreError(w, err, "group")
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	heads, err := s.store.Groups()
	if err != nil {
		s.writeStoreError(w, err, "group")
		return
	}
	out := make([]groupView, 0, len(heads))
	for _, h := range heads {
		g := &groupLatest{}
		if err := json.Unmarshal(h.Record.Body, &g.Body); err != nil {
			s.writeStoreError(w, fmt.Errorf("group %s: decoding its latest record: %w", h.ID, err), "group")
			return
		}
		out = append(out, g.view(requestUser(r).ID, false))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.loadGroup(r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err, "group")
		return
	}
	s.writeGroup(w, http.StatusOK, g, requestUser(r).ID)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	caller, ok := groupWriter(w, r)
	if !ok {
		return
	}
	var req groupRecordRequest
	if !readJSON(w, r, &req) {
		return
	}
	g, err := s.acceptGroupRecord(caller.ID, "", nil, req.Record)
	if err != nil {
		s.writeGroupError(w, err)
		return
	}
	s.writeGroup(w, http.StatusCreated, g, caller.ID)
}

func (s *Server) handlePutGroup(w http.ResponseWriter, r *http.Request) {
	caller, ok := groupWriter(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	cur, err := s.loadGroup(id)
	if err != nil {
		s.writeStoreError(w, err, "group")
		return
	}
	var req groupRecordRequest
	if !readJSON(w, r, &req) {
		return
	}
	g, err := s.acceptGroupRecord(caller.ID, id, cur, req.Record)
	if err != nil {
		s.writeGroupError(w, err)
		return
	}
	s.writeGroup(w, http.StatusOK, g, caller.ID)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	caller, ok := groupWriter(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	cur, err := s.loadGroup(id)
	if err != nil {
		s.writeStoreError(w, err, "group")
		return
	}
	if _, ok := managerEntry(cur.Body.Members, caller.ID); !ok && !caller.IsAdmin {
		writeError(w, http.StatusForbidden, "only a manager of the group, or an administrator, can delete it")
		return
	}
	if err := s.store.DeleteGroup(id); err != nil {
		s.writeStoreError(w, err, "group")
		return
	}
	s.log.Info("group deleted", "id", id, "by", caller.Email)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// acceptGroupRecord checks env as the next record of group id, which cur is
// the stored chain of, or as the first record when cur is nil and id is
// empty, and stores it. A refusal is a *groupRefusal.
func (s *Server) acceptGroupRecord(callerID, id string, cur *groupLatest, env e2e.Envelope) (*groupLatest, error) {
	caller, err := s.store.KeyedUserByID(callerID)
	if err != nil {
		return nil, err
	}
	// The envelope's signer is the caller, and the signature verifies under
	// their current key, which signerFp names.
	if env.Signer != caller.ID {
		return nil, groupRefuse(http.StatusBadRequest, "the envelope's signer is not you")
	}
	var body e2e.GroupBody
	if err := e2e.OpenEnvelope(env, caller.Ed25519Pub, "group", &body); err != nil {
		if errors.Is(err, e2e.ErrDecrypt) {
			return nil, groupRefuse(http.StatusBadRequest, "the record does not verify under your current key")
		}
		return nil, groupRefuse(http.StatusBadRequest, "the body does not parse: %v", err)
	}
	switch {
	case body.Signer != caller.ID:
		return nil, groupRefuse(http.StatusBadRequest, "the body's signer %q is not the envelope's signer %q", body.Signer, caller.ID)
	case body.SignerFP != caller.FP:
		return nil, groupRefuse(http.StatusBadRequest, "signerFp is not your current fingerprint")
	}

	var prev *e2e.GroupBody
	if cur == nil {
		if err := s.checkFirstGroupRecord(caller, body); err != nil {
			return nil, err
		}
	} else {
		prev = &cur.Body
		if err := s.checkNextGroupRecord(caller, id, cur, body); err != nil {
			return nil, err
		}
	}
	if err := e2e.CheckGroupBody(body); err != nil {
		return nil, groupRefuse(http.StatusBadRequest, "%v", err)
	}
	if err := s.checkGroupEntries(prev, body); err != nil {
		return nil, err
	}

	members := make([]store.GroupMember, 0, len(body.Members))
	for _, m := range body.Members {
		members = append(members, store.GroupMember{UserID: m.User, Role: m.Role, FP: m.FP})
	}
	if _, err := s.store.AddGroupRecord(body.Group, body.Seq, store.Envelope{Body: env.Body, Sig: env.Sig, Signer: env.Signer}, members, s.clk.Now()); errors.Is(err, store.ErrStale) {
		return nil, groupRefuse(http.StatusConflict, "another record was stored first; read the group again")
	} else if errors.Is(err, store.ErrGroupIDReused) {
		return nil, groupRefuse(http.StatusConflict, "group %s was deleted; a group ID is never used again", body.Group)
	} else if err != nil {
		return nil, err
	}
	return s.loadGroup(body.Group)
}

// checkFirstGroupRecord is the rule for a group's first record: a random
// lowercase UUID not already used, seq 1, no prev, and the caller listed as a
// manager under their current fingerprint.
func (s *Server) checkFirstGroupRecord(caller *store.KeyedUser, body e2e.GroupBody) error {
	if u, err := uuid.Parse(body.Group); err != nil || u.String() != body.Group {
		return groupRefuse(http.StatusBadRequest, "group %q is not a lowercase UUID", body.Group)
	}
	switch {
	case body.Seq != 1:
		return groupRefuse(http.StatusBadRequest, "the first record has seq %d, want 1", body.Seq)
	case body.Prev != "":
		return groupRefuse(http.StatusBadRequest, "the first record has a prev")
	}
	if m, ok := managerEntry(body.Members, caller.ID); !ok || m.FP != caller.FP {
		return groupRefuse(http.StatusBadRequest, "the first record must list you as a manager under your current fingerprint")
	}
	if _, err := s.store.GroupRecords(body.Group); err == nil {
		return groupRefuse(http.StatusConflict, "group %s already exists", body.Group)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// checkNextGroupRecord is the rule for a later record, against the stored
// chain cur of group id: the same group, seq one more than the latest and
// prev its hash, and the caller listed as a manager in the latest record
// under their current fingerprint or one their rotation records link to it.
// A seq or prev that is behind the stored chain lost a race, which is a 409.
func (s *Server) checkNextGroupRecord(caller *store.KeyedUser, id string, cur *groupLatest, body e2e.GroupBody) error {
	listed, ok := managerEntry(cur.Body.Members, caller.ID)
	if !ok {
		return groupRefuse(http.StatusForbidden, "only a manager of the group can change it")
	}
	if listed.FP != caller.FP {
		rows, err := s.store.Rotations(caller.ID)
		if err != nil {
			return err
		}
		if !rotationLinked(rows, listed.FP, caller.FP) {
			return groupRefuse(http.StatusForbidden, "the latest record lists you as a manager under a fingerprint your rotation records do not lead from")
		}
	}
	switch {
	case body.Group != id:
		return groupRefuse(http.StatusBadRequest, "group %q is not this group", body.Group)
	case body.Seq != cur.Body.Seq+1:
		return groupRefuse(http.StatusConflict, "seq %d, want %d; read the group again", body.Seq, cur.Body.Seq+1)
	case body.Prev != cur.Hash:
		return groupRefuse(http.StatusConflict, "prev is not the latest record's hash; read the group again")
	}
	return nil
}

// checkGroupEntries holds each entry body adds or changes against prev, the
// record before it, nil for a first record, to the directory: the user is
// verified and active, listed under their current fingerprint, and a viewer
// account is not newly made a manager. An entry carried over unchanged is
// not checked again.
func (s *Server) checkGroupEntries(prev *e2e.GroupBody, body e2e.GroupBody) error {
	was := map[string]e2e.GroupMember{}
	if prev != nil {
		for _, m := range prev.Members {
			was[m.User] = m
		}
	}
	for _, m := range body.Members {
		if w, ok := was[m.User]; ok && w == m {
			continue
		}
		u, err := s.store.KeyedUserByID(m.User)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return groupRefuse(http.StatusBadRequest, "member %s is not a user", m.User)
		case err != nil:
			return err
		case !u.Verified:
			return groupRefuse(http.StatusBadRequest, "member %s is not verified", m.User)
		case u.Disabled:
			return groupRefuse(http.StatusBadRequest, "member %s is not active", m.User)
		case m.FP != u.FP:
			return groupRefuse(http.StatusBadRequest, "member %s fp is not their current fingerprint", m.User)
		case m.Role == "manager" && u.Role == store.RoleViewer && was[m.User].Role != "manager":
			return groupRefuse(http.StatusBadRequest, "member %s is a viewer account and cannot be made a manager", m.User)
		}
	}
	return nil
}
