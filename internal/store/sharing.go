package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/google/uuid"
)

// Envelope is a signed structure as the client sent it: the body bytes, the
// signature over them, and the ID of the user who signed. The store keeps all
// three verbatim and verifies nothing.
type Envelope struct {
	Body   []byte
	Sig    []byte
	Signer string
}

// Record is one membership record. Envelope is authoritative; the other
// fields are copies of what the body says, parsed and checked by the caller,
// so the store can answer queries without parsing. Prev is hex(SHA-256) of
// the previous record's body, empty for the first. BodyHash and CreatedAt are
// set by the store.
type Record struct {
	Seq          int
	Prev         string
	BodyHash     string
	Epoch        int
	OwnerID      string
	OwnerFp      string
	AKCommit     []byte
	Team         string
	Public       bool
	PublicWrites bool
	Transfer     string
	Handover     string
	Envelope     Envelope
	CreatedAt    string
}

// Member is a user listed by the latest record.
type Member struct {
	UserID string
	Role   string
	FP     string
}

// Excluded is an entry of the latest record's excluded list.
type Excluded struct {
	UserID string
	FP     string
	Email  string
}

// Wrap is AK for one epoch, wrapped to one user. FP is the user's
// fingerprint when the wrap was stored.
type Wrap struct {
	UserID  string
	Epoch   int
	Wrapped []byte
	FP      string
}

// Estate is the owner's copy of one epoch's AK, sealed under their EK.
type Estate struct {
	Epoch  int
	Sealed []byte
}

// Approval is the signed approval stored with a team member's wraps.
type Approval struct {
	UserID    string
	FP        string
	Epoch     int
	Envelope  Envelope
	CreatedAt string
}

// Offer is an ownership offer. By is "owner" or "admin". Envelope and Hash
// are set for an owner's offer only. State is open, accepted, or closed.
type Offer struct {
	To        string
	By        string
	Hash      string
	Envelope  *Envelope
	State     string
	CreatedAt string
}

// AccessState is what the permission check needs about one caller and one
// artifact: the artifact, the caller's entry in the latest record (nil when
// not listed), every wrap the caller holds, and the artifact owner's
// nomination when it names the caller (nil otherwise).
type AccessState struct {
	Artifact       *Artifact
	Member         *Member
	Wraps          []Wrap
	OwnerSuccessor *Successor
}

// ArtifactTx is a transaction that holds the lock on one artifact. Approvals
// and membership changes run in one, so none can land between a check and an
// epoch change; database and file writes use UnderEpoch instead.
//
// The store uses a single connection, so a transaction excludes every other
// store call until it ends: a function passed to WithArtifact must use only
// the ArtifactTx, never the Store, or it deadlocks.
type ArtifactTx struct {
	tx *sql.Tx
	id string
}

// artifactLock returns artifact id's in-process lock. WithArtifact takes it
// exclusively, so an epoch only changes while it is held; UnderEpoch shares
// it, so writes run in parallel but never across an epoch change.
func (s *Store) artifactLock(id string) *sync.RWMutex {
	s.locksMu.Lock()
	defer s.locksMu.Unlock()
	if s.locks == nil {
		s.locks = map[string]*sync.RWMutex{}
	}
	l, ok := s.locks[id]
	if !ok {
		l = &sync.RWMutex{}
		s.locks[id] = l
	}
	return l
}

// UnderEpoch runs write if artifact id is at the declared epoch, and keeps
// the epoch from changing until write returns. Unlike WithArtifact it holds
// no database transaction, so write may be slow: it delays changes to this
// artifact only. A missing artifact is ErrNotFound, another epoch
// ErrEpochMoved. write must not call WithArtifact on this artifact.
func (s *Store) UnderEpoch(id string, declared int, write func()) error {
	l := s.artifactLock(id)
	l.RLock()
	defer l.RUnlock()
	var epoch int
	err := s.db.QueryRow(`SELECT epoch FROM artifacts WHERE id = ?`, id).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if epoch != declared {
		return ErrEpochMoved
	}
	write()
	return nil
}

// ArtifactID is the artifact this transaction locks.
func (t *ArtifactTx) ArtifactID() string { return t.id }

// WithArtifact runs fn in one transaction that locks artifact id, committing
// if fn returns nil. A missing artifact is ErrNotFound.
//
// The lock stalls every other store call, so fn must use only the ArtifactTx
// (a Store call inside it deadlocks) and stay short: extract uploads, copy
// files, and hash large bodies before calling WithArtifact, not inside fn.
func (s *Store) WithArtifact(id string, fn func(*ArtifactTx) error) error {
	l := s.artifactLock(id)
	l.Lock()
	defer l.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A no-op write takes SQLite's write lock now, not at the first real
	// write, and doubles as the existence check.
	res, err := tx.Exec(`UPDATE artifacts SET id = id WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	if err := fn(&ArtifactTx{tx: tx, id: id}); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateOwnedArtifact inserts an artifact with the given ID and owner, then
// runs fn (if not nil) in the same transaction, so the first record and its
// wraps land with the artifact or not at all. An ID in use is ErrExists. fn
// follows the same rules as in WithArtifact.
func (s *Store) CreateOwnedArtifact(id, ownerID string, fn func(*ArtifactTx) error) (*Artifact, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	t := now()
	if _, err := tx.Exec(`INSERT INTO artifacts (id, owner_id, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		id, ownerID, t, t); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrExists
		}
		return nil, err
	}
	if fn != nil {
		if err := fn(&ArtifactTx{tx: tx, id: id}); err != nil {
			return nil, err
		}
	}
	a, err := scanArtifact(tx.QueryRow(`SELECT `+artifactCols+` FROM artifacts WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return a, nil
}

// AccessState reads what the permission check needs for userID on an
// artifact. An empty userID (anonymous) has no member entry and no wraps. A
// missing artifact is ErrNotFound.
//
// The three reads share one transaction, so a membership change cannot land
// between them and pair a new epoch with old wraps.
func (s *Store) AccessState(artifactID, userID string) (*AccessState, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, err := scanArtifact(tx.QueryRow(`SELECT `+artifactCols+` FROM artifacts WHERE id = ?`, artifactID))
	if err != nil {
		return nil, err
	}
	st := &AccessState{Artifact: a}
	if userID == "" {
		return st, nil
	}
	var m Member
	err = tx.QueryRow(`SELECT user_id, role, fp FROM artifact_members WHERE artifact_id = ? AND user_id = ?`,
		artifactID, userID).Scan(&m.UserID, &m.Role, &m.FP)
	switch {
	case err == nil:
		st.Member = &m
	case !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}
	if st.Wraps, err = queryWraps(tx, `WHERE artifact_id = ? AND user_id = ? ORDER BY epoch`, artifactID, userID); err != nil {
		return nil, err
	}
	sc, err := scanSuccessor(tx.QueryRow(`SELECT `+successorCols+successorFrom+`WHERE s.user_id = ? AND s.successor_id = ?`, a.OwnerID, userID))
	switch {
	case err == nil:
		st.OwnerSuccessor = sc
	case !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}
	return st, nil
}

// WrapsFor returns the wraps userID holds on an artifact, oldest epoch first.
func (s *Store) WrapsFor(artifactID, userID string) ([]Wrap, error) {
	return queryWraps(s.db, `WHERE artifact_id = ? AND user_id = ? ORDER BY epoch`, artifactID, userID)
}

// EstateKeys returns the owner's estate copies, oldest epoch first.
func (s *Store) EstateKeys(artifactID string) ([]Estate, error) {
	return queryEstate(s.db, artifactID)
}

type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

func queryWraps(q querier, where string, args ...any) ([]Wrap, error) {
	rows, err := q.Query(`SELECT user_id, epoch, wrapped, fp FROM artifact_keys `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Wrap
	for rows.Next() {
		var w Wrap
		if err := rows.Scan(&w.UserID, &w.Epoch, &w.Wrapped, &w.FP); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func queryEstate(q querier, artifactID string) ([]Estate, error) {
	rows, err := q.Query(`SELECT epoch, sealed FROM artifact_estate_keys WHERE artifact_id = ? ORDER BY epoch`, artifactID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Estate
	for rows.Next() {
		var e Estate
		if err := rows.Scan(&e.Epoch, &e.Sealed); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Artifact re-reads the artifact row inside the transaction.
func (t *ArtifactTx) Artifact() (*Artifact, error) {
	return scanArtifact(t.tx.QueryRow(`SELECT `+artifactCols+` FROM artifacts WHERE id = ?`, t.id))
}

// SetOwner makes userID the artifact's owner. Nothing else changes.
func (t *ArtifactTx) SetOwner(userID string) error {
	_, err := t.tx.Exec(`UPDATE artifacts SET owner_id = ? WHERE id = ?`, userID, t.id)
	return err
}

// Membership records

const recordCols = `seq, prev, body_hash, epoch, owner_id, owner_fp, ak_commit, team, public, public_writes, transfer, handover, body, sig, signer, created_at`

func scanRecord(row interface{ Scan(...any) error }) (*Record, error) {
	var r Record
	if err := row.Scan(&r.Seq, &r.Prev, &r.BodyHash, &r.Epoch, &r.OwnerID, &r.OwnerFp, &r.AKCommit, &r.Team, &r.Public,
		&r.PublicWrites, &r.Transfer, &r.Handover, &r.Envelope.Body, &r.Envelope.Sig, &r.Envelope.Signer, &r.CreatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// LatestRecord returns the newest record, or ErrNotFound before the first.
func (t *ArtifactTx) LatestRecord() (*Record, error) {
	return scanRecord(t.tx.QueryRow(`SELECT `+recordCols+` FROM artifact_records WHERE artifact_id = ? ORDER BY seq DESC LIMIT 1`, t.id))
}

// Records returns the whole chain, oldest first.
func (t *ArtifactTx) Records() ([]*Record, error) {
	rows, err := t.tx.Query(`SELECT `+recordCols+` FROM artifact_records WHERE artifact_id = ? ORDER BY seq`, t.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AppendRecord stores r as the next record and copies its epoch, team, public
// settings, and owner onto the artifact. Seq must be one more than the latest
// (1 for the first) and Prev must be the latest record's body hash (empty for
// the first), otherwise the answer is ErrStale. A record that is not public
// deletes the public link's token hash. An empty r.OwnerID keeps the current
// owner. Signatures and every other rule are the caller's to check.
func (t *ArtifactTx) AppendRecord(r *Record) error {
	latest, err := t.LatestRecord()
	wantSeq, wantPrev := 1, ""
	switch {
	case err == nil:
		wantSeq, wantPrev = latest.Seq+1, latest.BodyHash
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	if r.Seq != wantSeq || r.Prev != wantPrev {
		return ErrStale
	}
	a, err := t.Artifact()
	if err != nil {
		return err
	}
	if r.OwnerID == "" {
		r.OwnerID = a.OwnerID
	}
	sum := sha256.Sum256(r.Envelope.Body)
	r.BodyHash = hex.EncodeToString(sum[:])
	r.CreatedAt = now()
	if _, err := t.tx.Exec(`INSERT INTO artifact_records (artifact_id, `+recordCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.id, r.Seq, r.Prev, r.BodyHash, r.Epoch, r.OwnerID, r.OwnerFp, r.AKCommit, r.Team, r.Public, r.PublicWrites,
		r.Transfer, r.Handover, r.Envelope.Body, r.Envelope.Sig, r.Envelope.Signer, r.CreatedAt); err != nil {
		return err
	}
	if _, err := t.tx.Exec(`UPDATE artifacts SET owner_id = ?, epoch = ?, team = ?, public = ?, public_writes = ?, updated_at = ? WHERE id = ?`,
		r.OwnerID, r.Epoch, r.Team, r.Public, r.PublicWrites, r.CreatedAt, t.id); err != nil {
		return err
	}
	if !r.Public {
		return t.SetPublicToken("", 0)
	}
	return nil
}

// SetPublicToken stores hex(SHA-256(linkToken)) and the epoch it belongs to.
// An empty hash deletes both.
func (t *ArtifactTx) SetPublicToken(hash string, epoch int) error {
	if hash == "" {
		_, err := t.tx.Exec(`UPDATE artifacts SET public_token_hash = NULL, public_epoch = NULL WHERE id = ?`, t.id)
		return err
	}
	_, err := t.tx.Exec(`UPDATE artifacts SET public_token_hash = ?, public_epoch = ? WHERE id = ?`, hash, epoch, t.id)
	return err
}

// Users and their current keys

// KeyedUser is a user with the public keys of their bundle. FP is the hex
// fingerprint of those keys, computed on each read and never stored.
type KeyedUser struct {
	ID         string
	Name       string
	Email      string
	X25519Pub  []byte
	Ed25519Pub []byte
	FP         string
	Verified   bool
	Disabled   bool
}

const keyedUserCols = `u.id, u.name, u.email, b.x25519_pub, b.ed25519_pub, u.verified_at IS NOT NULL, u.disabled`

func scanKeyedUser(row interface{ Scan(...any) error }) (*KeyedUser, error) {
	var u KeyedUser
	if err := row.Scan(&u.ID, &u.Name, &u.Email, &u.X25519Pub, &u.Ed25519Pub, &u.Verified, &u.Disabled); err != nil {
		return nil, err
	}
	u.FP = hex.EncodeToString(e2e.Fingerprint(u.X25519Pub, u.Ed25519Pub))
	return &u, nil
}

// UserByID reads a user and their current keys inside the transaction. A
// missing user is ErrNotFound.
func (t *ArtifactTx) UserByID(id string) (*KeyedUser, error) {
	return scanKeyedUser(t.tx.QueryRow(`SELECT `+keyedUserCols+` FROM users u JOIN key_bundles b ON b.user_id = u.id WHERE u.id = ?`, id))
}

// KeyedUsers returns every user who has a key bundle, ordered by ID,
// verified or not and active or not. Fingerprints are not stored, so each is
// computed from the user's keys.
func (t *ArtifactTx) KeyedUsers() ([]*KeyedUser, error) {
	rows, err := t.tx.Query(`SELECT ` + keyedUserCols + ` FROM users u JOIN key_bundles b ON b.user_id = u.id ORDER BY u.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*KeyedUser
	for rows.Next() {
		u, err := scanKeyedUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UsersSharing returns the IDs, sorted, of every user whose current
// fingerprint is fp or whose normalized email is email's.
func (t *ArtifactTx) UsersSharing(fp, email string) ([]string, error) {
	users, err := t.KeyedUsers()
	if err != nil {
		return nil, err
	}
	email = e2e.NormalizeEmail(email)
	var out []string
	for _, u := range users {
		if u.FP == fp || e2e.NormalizeEmail(u.Email) == email {
			out = append(out, u.ID)
		}
	}
	return out, nil
}

// Members and excluded entries

// SetMembers replaces the member list.
func (t *ArtifactTx) SetMembers(members []Member) error {
	if _, err := t.tx.Exec(`DELETE FROM artifact_members WHERE artifact_id = ?`, t.id); err != nil {
		return err
	}
	for _, m := range members {
		if _, err := t.tx.Exec(`INSERT INTO artifact_members (artifact_id, user_id, role, fp) VALUES (?, ?, ?, ?)`,
			t.id, m.UserID, m.Role, m.FP); err != nil {
			return err
		}
	}
	return nil
}

// Members returns the member list, ordered by user ID.
func (t *ArtifactTx) Members() ([]Member, error) {
	rows, err := t.tx.Query(`SELECT user_id, role, fp FROM artifact_members WHERE artifact_id = ? ORDER BY user_id`, t.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Role, &m.FP); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetExcluded replaces the excluded list.
func (t *ArtifactTx) SetExcluded(entries []Excluded) error {
	if _, err := t.tx.Exec(`DELETE FROM artifact_excluded WHERE artifact_id = ?`, t.id); err != nil {
		return err
	}
	for _, e := range entries {
		if _, err := t.tx.Exec(`INSERT INTO artifact_excluded (artifact_id, user_id, fp, email) VALUES (?, ?, ?, ?)`,
			t.id, e.UserID, e.FP, normalizeEmail(e.Email)); err != nil {
			return err
		}
	}
	return nil
}

// ExcludedEntries returns the excluded list, ordered by user ID.
func (t *ArtifactTx) ExcludedEntries() ([]Excluded, error) {
	rows, err := t.tx.Query(`SELECT user_id, fp, email FROM artifact_excluded WHERE artifact_id = ? ORDER BY user_id`, t.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Excluded
	for rows.Next() {
		var e Excluded
		if err := rows.Scan(&e.UserID, &e.FP, &e.Email); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Wraps, estate copies, approvals

// PutWrap stores a wrap. A wrap already held for that user and epoch is
// ErrExists.
func (t *ArtifactTx) PutWrap(w Wrap) error {
	_, err := t.tx.Exec(`INSERT INTO artifact_keys (artifact_id, epoch, user_id, wrapped, fp) VALUES (?, ?, ?, ?, ?)`,
		t.id, w.Epoch, w.UserID, w.Wrapped, w.FP)
	if isUniqueViolation(err) {
		return ErrExists
	}
	return err
}

// ReplaceWrap stores a wrap, replacing any the user holds for that epoch,
// as when a member whose key changed is wrapped to again.
func (t *ArtifactTx) ReplaceWrap(w Wrap) error {
	_, err := t.tx.Exec(`INSERT OR REPLACE INTO artifact_keys (artifact_id, epoch, user_id, wrapped, fp) VALUES (?, ?, ?, ?, ?)`,
		t.id, w.Epoch, w.UserID, w.Wrapped, w.FP)
	return err
}

// Wraps returns every wrap on the artifact, ordered by epoch then user.
func (t *ArtifactTx) Wraps() ([]Wrap, error) {
	return queryWraps(t.tx, `WHERE artifact_id = ? ORDER BY epoch, user_id`, t.id)
}

// DeleteWraps deletes every wrap held by one user.
func (t *ArtifactTx) DeleteWraps(userID string) error {
	_, err := t.tx.Exec(`DELETE FROM artifact_keys WHERE artifact_id = ? AND user_id = ?`, t.id, userID)
	return err
}

// DeleteWrapsExcept deletes every wrap held by a user not in keep.
func (t *ArtifactTx) DeleteWrapsExcept(keep []string) error {
	return t.deleteExcept(`artifact_keys`, keep)
}

// DeleteApprovalsExcept deletes every stored approval for a user not in keep.
func (t *ArtifactTx) DeleteApprovalsExcept(keep []string) error {
	return t.deleteExcept(`team_approvals`, keep)
}

func (t *ArtifactTx) deleteExcept(table string, keep []string) error {
	q := `DELETE FROM ` + table + ` WHERE artifact_id = ?`
	args := []any{t.id}
	for _, u := range keep {
		q += ` AND user_id != ?`
		args = append(args, u)
	}
	_, err := t.tx.Exec(q, args...)
	return err
}

// PutEstate stores the owner's sealed copy of an epoch's AK, replacing any
// copy of that epoch.
func (t *ArtifactTx) PutEstate(epoch int, sealed []byte) error {
	_, err := t.tx.Exec(`INSERT OR REPLACE INTO artifact_estate_keys (artifact_id, epoch, sealed) VALUES (?, ?, ?)`, t.id, epoch, sealed)
	return err
}

// Estates returns the estate copies, oldest epoch first.
func (t *ArtifactTx) Estates() ([]Estate, error) { return queryEstate(t.tx, t.id) }

// DeleteEstates deletes every estate copy.
func (t *ArtifactTx) DeleteEstates() error {
	_, err := t.tx.Exec(`DELETE FROM artifact_estate_keys WHERE artifact_id = ?`, t.id)
	return err
}

// PutApproval stores a team approval, replacing the user's earlier one.
func (t *ArtifactTx) PutApproval(a Approval) error {
	_, err := t.tx.Exec(`INSERT OR REPLACE INTO team_approvals (artifact_id, user_id, fp, epoch, body, sig, signer, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.id, a.UserID, a.FP, a.Epoch, a.Envelope.Body, a.Envelope.Sig, a.Envelope.Signer, now())
	return err
}

// Approvals returns the stored team approvals, ordered by user ID.
func (t *ArtifactTx) Approvals() ([]Approval, error) {
	rows, err := t.tx.Query(`SELECT user_id, fp, epoch, body, sig, signer, created_at FROM team_approvals WHERE artifact_id = ? ORDER BY user_id`, t.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.UserID, &a.FP, &a.Epoch, &a.Envelope.Body, &a.Envelope.Sig, &a.Envelope.Signer, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Ownership offers

// PutOffer opens an offer. An offer already open is ErrExists.
func (t *ArtifactTx) PutOffer(o Offer) error {
	var body, sig []byte
	var signer *string
	if o.Envelope != nil {
		body, sig, signer = o.Envelope.Body, o.Envelope.Sig, &o.Envelope.Signer
	}
	_, err := t.tx.Exec(`INSERT INTO artifact_offers (id, artifact_id, to_user, offered_by, hash, body, sig, signer, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)`,
		uuid.NewString(), t.id, o.To, o.By, o.Hash, body, sig, signer, now())
	if isUniqueViolation(err) {
		return ErrExists
	}
	return err
}

const offerCols = `to_user, offered_by, hash, body, sig, signer, state, created_at`

func scanOffer(row interface{ Scan(...any) error }) (*Offer, error) {
	var o Offer
	var body, sig []byte
	var signer sql.NullString
	if err := row.Scan(&o.To, &o.By, &o.Hash, &body, &sig, &signer, &o.State, &o.CreatedAt); err != nil {
		return nil, err
	}
	if signer.Valid {
		o.Envelope = &Envelope{Body: body, Sig: sig, Signer: signer.String}
	}
	return &o, nil
}

// OpenOffer returns the open offer, or ErrNotFound.
func (t *ArtifactTx) OpenOffer() (*Offer, error) {
	return scanOffer(t.tx.QueryRow(`SELECT `+offerCols+` FROM artifact_offers WHERE artifact_id = ? AND state = 'open'`, t.id))
}

// OpenOffer returns the artifact's open offer outside a transaction, or
// ErrNotFound.
func (s *Store) OpenOffer(artifactID string) (*Offer, error) {
	return scanOffer(s.db.QueryRow(`SELECT `+offerCols+` FROM artifact_offers WHERE artifact_id = ? AND state = 'open'`, artifactID))
}

// SetOfferState moves the open offer to accepted or closed. No open offer is
// ErrNotFound.
func (t *ArtifactTx) SetOfferState(state string) error {
	res, err := t.tx.Exec(`UPDATE artifact_offers SET state = ? WHERE artifact_id = ? AND state = 'open'`, state, t.id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AcceptedOffers maps the body hash of each accepted owner offer to it.
func (t *ArtifactTx) AcceptedOffers() (map[string]*Offer, error) {
	rows, err := t.tx.Query(`SELECT `+offerCols+` FROM artifact_offers WHERE artifact_id = ? AND state = 'accepted' AND hash != ''`, t.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*Offer{}
	for rows.Next() {
		o, err := scanOffer(rows)
		if err != nil {
			return nil, err
		}
		out[o.Hash] = o
	}
	return out, rows.Err()
}

// Vouches

// ReviewVersions returns the versions that need the owner's review: pushed
// by a user who is neither the owner nor an editor of the latest record, or
// by a deleted account (no pusher), and with no vouch. Ordered by seq.
func (t *ArtifactTx) ReviewVersions() ([]*Version, error) {
	rows, err := t.tx.Query(`SELECT `+versionCols+` FROM versions
		WHERE artifact_id = ? AND (pushed_by IS NULL
			OR (pushed_by IS NOT (SELECT owner_id FROM artifacts WHERE id = ?)
			AND pushed_by NOT IN (SELECT user_id FROM artifact_members WHERE artifact_id = ? AND role = 'editor')))
		AND id NOT IN (SELECT version_id FROM version_vouches)
		ORDER BY seq`, t.id, t.id, t.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// PutVouch stores the owner's vouch for a version, replacing an earlier one.
// A version that is not on this artifact is ErrNotFound.
func (t *ArtifactTx) PutVouch(versionID string, env Envelope) error {
	res, err := t.tx.Exec(`INSERT OR REPLACE INTO version_vouches (version_id, artifact_id, body, sig, signer, created_at)
		SELECT id, artifact_id, ?, ?, ?, ? FROM versions WHERE id = ? AND artifact_id = ?`,
		env.Body, env.Sig, env.Signer, now(), versionID, t.id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Vouches returns an artifact's stored vouches, keyed by version ID.
func (s *Store) Vouches(artifactID string) (map[string]Envelope, error) {
	rows, err := s.db.Query(`SELECT version_id, body, sig, signer FROM version_vouches WHERE artifact_id = ?`, artifactID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Envelope{}
	for rows.Next() {
		var id string
		var e Envelope
		if err := rows.Scan(&id, &e.Body, &e.Sig, &e.Signer); err != nil {
			return nil, err
		}
		out[id] = e
	}
	return out, rows.Err()
}

// Versions and the epoch of each write

// RecordWrite records the epoch a database revision (kind "db", key "") or a
// file (kind "file", key = path) of a version was last written under, and by
// whom. A later write to the same target replaces the earlier row. A version
// that is not on this artifact is ErrNotFound.
func (t *ArtifactTx) RecordWrite(versionID, kind, key string, epoch int, writer string) error {
	res, err := t.tx.Exec(`INSERT OR REPLACE INTO version_writes (version_id, kind, key, epoch, writer, written_at)
		SELECT id, ?, ?, ?, ?, ? FROM versions WHERE id = ? AND artifact_id = ?`,
		kind, key, epoch, writer, now(), versionID, t.id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}
