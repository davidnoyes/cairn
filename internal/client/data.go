// A version's database and stored files, which the server holds as sealed,
// signed blobs. The client opens them, checks each as "Checking data a client
// reads" in design/e2e-api.md says, and seals and signs what it writes. The
// browser does the same in internal/server/web/data.mjs; the checks here
// mirror it. As elsewhere in this package, every byte of cryptography is built
// with internal/e2e.
package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

var (
	// ErrUnverified wraps the refusal of every check a client makes on data
	// it reads: the data is not used.
	ErrUnverified = errors.New("could not be verified")
	// ErrNoDatabase means the version has no database yet.
	ErrNoDatabase = errors.New("this version has no database yet")
	// ErrFileNotFound means no stored file has the path.
	ErrFileNotFound = errors.New("file not found")
	// ErrNoWriteKey means the caller holds no AK for the artifact's current
	// epoch, so cannot seal a write.
	ErrNoWriteKey = errors.New("you hold no key for the artifact's current epoch")
	// ErrInvalidPath is a stored file path the rules refuse.
	ErrInvalidPath = errors.New("a stored file's path may not have an empty, \".\" or \"..\" segment, a backslash, or a NUL")
)

// ConflictError is the server's 412: the database changed since it was read.
// Latest is the revision the server now holds.
type ConflictError struct{ Latest int }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("the database changed since it was read; the latest revision is now %d", e.Latest)
}

// Revision is one entry of the server's list of the revisions it keeps.
type Revision struct {
	Revision  int    `json:"revision"`
	Epoch     int    `json:"epoch"`
	Size      int64  `json:"size"`
	WrittenBy string `json:"writtenBy"`
	CreatedAt string `json:"createdAt"`
}

// warnf reports an entry a listing left out. Tests replace it.
var warnf = func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }

// maxDataBlob caps what the client reads of a revision or a file, so a server
// cannot stream without end. It is far above any limit a server sets.
const maxDataBlob = 4 << 30

var (
	revisionRe = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	epochRe    = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)
	etagRe     = regexp.MustCompile(`^"(0|[1-9][0-9]{0,15})"$`)
	addressRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// seenRevisions is the highest revision read or written per version since the
// process started: a read of a lower one is a rollback.
var seenRevisions = struct {
	sync.Mutex
	m map[string]int
}{m: map[string]int{}}

// FileMetaBody is the plaintext of a stored file's file-meta blob, decoded
// strictly.
type FileMetaBody struct {
	V          int    `json:"v"`
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	ModifiedAt string `json:"modifiedAt"`
}

// validFilePath applies the upload rules to a stored file's path.
func validFilePath(p string) bool {
	if !utf8.ValidString(p) || strings.ContainsAny(p, "\\\x00") {
		return false
	}
	return !slices.ContainsFunc(strings.Split(p, "/"), func(s string) bool { return s == "" || s == "." || s == ".." })
}

// CheckFilePath reports whether path can be a stored file's path, by the rule
// PutFile applies, without contacting the server.
func CheckFilePath(path string) error {
	if !validFilePath(path) {
		return ErrInvalidPath
	}
	return nil
}

// dataChecker holds what steps 1 to 3 of "Checking data a client reads" are
// made against.
type dataChecker struct {
	artifact, version string
	versionEpoch      int
	aks               map[int][]byte
	// writers maps a user to the b64 Ed25519 keys they may sign under.
	writers map[string]map[string]bool
	// anyWriter is set while publicWrites is on: any signer is accepted.
	anyWriter bool
	// earlierEpochs lets a restore open a revision sealed before the
	// version's epoch: re-sealing the latest version raises that epoch past
	// the kept revisions.
	earlierEpochs bool
}

func unverified(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnverified, fmt.Sprintf(format, a...))
}

// open runs step 1 and 2: the envelope verifies under signerKey, which
// belongs to a writer.
func (d *dataChecker) open(purpose string, env e2e.Envelope, signerKey string, out any) error {
	key, err := e2e.UnB64(signerKey)
	if err != nil {
		return unverified("the signer key is not base64url")
	}
	if len(key) != ed25519.PublicKeySize {
		return unverified("the signer key is not 32 bytes")
	}
	if !d.anyWriter && !d.writers[env.Signer][e2e.B64(key)] {
		return unverified("signed by someone who may not write")
	}
	if err := e2e.OpenEnvelope(env, key, purpose, out); err != nil {
		return unverified("the envelope does not verify: %v", err)
	}
	return nil
}

// akFor is the AK of body's epoch, after the epoch checks.
func (d *dataChecker) akFor(named, epoch int) ([]byte, error) {
	if epoch != named {
		return nil, unverified("signed under another epoch than the server named")
	}
	if epoch < d.versionEpoch && !d.earlierEpochs {
		return nil, unverified("signed under an epoch before the version")
	}
	ak := d.aks[epoch]
	if ak == nil {
		return nil, unverified("no key for epoch %d", epoch)
	}
	return ak, nil
}

// checkRevision checks a revision envelope against what was asked for and the
// blob, and returns the AK of its epoch.
func (d *dataChecker) checkRevision(env e2e.Envelope, signerKey string, epoch, revision int, blob []byte) ([]byte, error) {
	var b e2e.RevisionBody
	if err := d.open("revision", env, signerKey, &b); err != nil {
		return nil, err
	}
	if err := d.checkScope(b.Artifact, b.Version); err != nil {
		return nil, err
	}
	ak, err := d.akFor(epoch, b.Epoch)
	if err != nil {
		return nil, err
	}
	if b.Revision != revision {
		return nil, unverified("signed for another revision")
	}
	if err := checkBlob(blob, b.SHA256); err != nil {
		return nil, err
	}
	return ak, nil
}

// checkScope checks that a body names this artifact and version.
func (d *dataChecker) checkScope(artifact, version string) error {
	if artifact != d.artifact {
		return unverified("signed for another artifact")
	}
	if version != d.version {
		return unverified("signed for another version")
	}
	return nil
}

// checkBlob checks the blob against the hash a body signs. A nil blob is one
// the caller does not hold yet.
func checkBlob(blob []byte, sha256 string) error {
	if blob != nil && e2e.BodyHash(blob) != sha256 {
		return unverified("the blob does not match its signature")
	}
	return nil
}

// checkRecord checks a file or file-meta envelope. blob is nil for a file
// whose blob the caller does not hold yet.
func (d *dataChecker) checkRecord(env e2e.Envelope, signerKey string, epoch int, kind, name string, blob []byte) ([]byte, error) {
	var b e2e.RecordBody
	if err := d.open("record", env, signerKey, &b); err != nil {
		return nil, err
	}
	if err := d.checkScope(b.Artifact, b.Version); err != nil {
		return nil, err
	}
	ak, err := d.akFor(epoch, b.Epoch)
	if err != nil {
		return nil, err
	}
	if b.Kind != kind {
		return nil, unverified("signed for another kind")
	}
	if b.Name != name {
		return nil, unverified("signed for another address")
	}
	if err := checkBlob(blob, b.SHA256); err != nil {
		return nil, err
	}
	return ak, nil
}

func (s signerKeys) fp() string { return hex.EncodeToString(e2e.Fingerprint(s.x25519, s.ed25519)) }

// candidateKeys are the key pairs offered for user: the caller's own, else the
// directory's, the owner keys the membership served, and the old and new pairs
// of the user's rotation records. A pair counts only once its fingerprint is
// checked, so where the keys come from does not matter.
func (c *Client) candidateKeys(k *UnlockedKeys, m *Membership, user string) ([]signerKeys, error) {
	var pairs []signerKeys
	if user == k.UserID {
		pairs = append(pairs, signerKeys{k.X25519Pub, k.Ed25519Pub})
	} else {
		u, err := c.DirectoryUser(user)
		switch {
		case isNotFound(err):
			// A deleted account's keys come from the records below.
		case err != nil:
			return nil, err
		default:
			pairs = append(pairs, signerKeys{u.X25519Pub, u.Ed25519Pub})
		}
	}
	for _, kp := range m.Owners {
		pairs = append(pairs, pairOf(kp))
	}
	for _, env := range m.Rotations[user] {
		var b e2e.RotationBody
		// Skipping a record that does not decode can only shrink the candidates.
		if e2e.DecodeStrict(env.Body, &b) != nil {
			continue
		}
		pairs = append(pairs, pairOf(b.Old), pairOf(b.New))
	}
	return slices.DeleteFunc(pairs, func(s signerKeys) bool { return len(s.x25519) != 32 || len(s.ed25519) != 32 }), nil
}

func pairOf(kp e2e.KeyPair) signerKeys {
	x, _ := e2e.UnB64(kp.X25519)
	ed, _ := e2e.UnB64(kp.Ed25519)
	return signerKeys{x, ed}
}

// writerKeys lists, for body's owner and each editor it lists, the Ed25519 keys
// a stored revision or file may be signed under: those of a candidate pair
// whose fingerprint is the one body lists, or one a rotation chain links to it.
func (c *Client) writerKeys(k *UnlockedKeys, m *Membership, body e2e.MembershipBody) (map[string]map[string]bool, error) {
	listed := map[string]string{body.Owner: body.OwnerFP}
	for _, mem := range body.Members {
		if mem.Role == "editor" {
			listed[mem.User] = mem.FP
		}
	}
	linked := e2e.RotationLinker(m.Rotations)
	out := map[string]map[string]bool{}
	for user, fp := range listed {
		out[user] = map[string]bool{}
		cands, err := c.candidateKeys(k, m, user)
		if err != nil {
			return nil, err
		}
		for _, kp := range cands {
			if linked(user, fp, kp.fp()) {
				out[user][e2e.B64(kp.ed25519)] = true
			}
		}
	}
	return out, nil
}

// everWriterKeys is writerKeys for every user the chain has ever listed as
// owner or editor, under any fingerprint it ever listed for them. A restore
// takes a revision from this set, because an old revision may predate a
// removal.
func (c *Client) everWriterKeys(k *UnlockedKeys, m *Membership, chain *e2e.Chain) (map[string]map[string]bool, error) {
	listed := map[string]map[string]bool{}
	add := func(user, fp string) {
		if listed[user] == nil {
			listed[user] = map[string]bool{}
		}
		listed[user][fp] = true
	}
	for _, b := range chain.Bodies {
		add(b.Owner, b.OwnerFP)
		for _, mem := range b.Members {
			if mem.Role == "editor" {
				add(mem.User, mem.FP)
			}
		}
	}
	out := map[string]map[string]bool{}
	for user, fps := range listed {
		out[user] = map[string]bool{}
		cands, err := c.candidateKeys(k, m, user)
		if err != nil {
			return nil, err
		}
		for _, kp := range cands {
			if fps[kp.fp()] {
				out[user][e2e.B64(kp.ed25519)] = true
			}
		}
	}
	return out, nil
}

// Data is one version's database and stored files, as the caller reads and
// writes them.
type Data struct {
	c        *Client
	k        *UnlockedKeys
	va       *VerifiedArtifact
	artifact string
	version  *store.Version
	aks      map[int][]byte
	// now checks against the latest record's writers.
	now *dataChecker
}

// OpenData verifies the artifact's chain and opens version versionID, or the
// latest version when it is empty, for reading; for write also refuses what
// Push refuses, an unacknowledged handover and an epoch below the one the
// keyring pins.
func (c *Client) OpenData(artifactID, versionID string, write bool) (*Data, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return nil, err
	}
	if write {
		if err := c.checkHandover(k, artifactID, va); err != nil {
			return nil, err
		}
		if err := e2e.CheckEncryptEpoch(va.Keyring.EpochPin(artifactID), va.Chain.Latest.Epoch); err != nil {
			return nil, err
		}
	}
	versions, err := c.storeVersions(artifactID)
	if err != nil {
		return nil, err
	}
	var v *store.Version
	switch {
	case versionID == "" && len(versions) == 0:
		return nil, errors.New("artifact has no versions yet")
	case versionID == "":
		v = versions[0]
	default:
		i := slices.IndexFunc(versions, func(x *store.Version) bool { return x.ID == versionID })
		if i < 0 {
			return nil, fmt.Errorf("version %s not found in artifact %s", versionID, artifactID)
		}
		v = versions[i]
	}
	aks, err := c.callerAKs(k, artifactID, va.Chain)
	if err != nil {
		return nil, err
	}
	writers, err := c.writerKeys(k, va.Membership, va.Chain.Latest)
	if err != nil {
		return nil, err
	}
	return newData(k, va, artifactID, v, aks, c, writers), nil
}

// newData is the data of version v, checked against the latest record's
// writers.
func newData(k *UnlockedKeys, va *VerifiedArtifact, artifactID string, v *store.Version, aks map[int][]byte, c *Client, writers map[string]map[string]bool) *Data {
	return &Data{
		c: c, k: k, va: va, artifact: artifactID, version: v, aks: aks,
		now: &dataChecker{
			artifact: artifactID, version: v.ID, versionEpoch: v.Epoch, aks: aks,
			writers: writers, anyWriter: va.Chain.Latest.PublicWrites,
		},
	}
}

// Version is the version the data belongs to.
func (d *Data) Version() *store.Version { return d.version }

func (d *Data) path(suffix string) string {
	return "/api/artifacts/" + d.artifact + "/versions/" + d.version.ID + "/" + suffix
}

// send makes a request and returns the response whatever its status.
func (c *Client) send(method, path string, body io.Reader, contentType string, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequest(method, c.Host+path, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header[k] = v
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if c.LinkToken != "" {
		req.Header.Set("X-Cairn-Link-Token", c.LinkToken)
	}
	return c.roundTrip(req)
}

// fetchRecord reads the blob a revision or file answer carries, and the
// envelope, epoch, and signer key in its headers.
type fetched struct {
	blob      []byte
	env       e2e.Envelope
	epoch     int
	signerKey string
	revision  int
}

func readFetched(resp *http.Response, withRevision bool) (*fetched, error) {
	f := &fetched{signerKey: resp.Header.Get("X-Cairn-Signer-Key")}
	epoch := resp.Header.Get("X-Cairn-Epoch")
	if !epochRe.MatchString(epoch) {
		return nil, unverified("the epoch is not a number")
	}
	f.epoch, _ = strconv.Atoi(epoch)
	if withRevision {
		rev := resp.Header.Get("X-Cairn-Revision")
		if !revisionRe.MatchString(rev) {
			return nil, unverified("the revision is not a number")
		}
		f.revision, _ = strconv.Atoi(rev)
	}
	rec, err := e2e.UnB64(resp.Header.Get("X-Cairn-Record"))
	if err != nil || json.Unmarshal(rec, &f.env) != nil {
		return nil, unverified("the record is not an envelope")
	}
	f.blob, err = io.ReadAll(io.LimitReader(resp.Body, maxDataBlob+1))
	if err != nil {
		return nil, err
	}
	if len(f.blob) > maxDataBlob {
		return nil, unverified("the blob is implausibly large")
	}
	return f, nil
}

func (d *Data) dbContext(revision int) e2e.BlobContext {
	return e2e.BlobContext{Artifact: d.artifact, Version: d.version.ID, Kind: "database", Name: strconv.Itoa(revision)}
}

func seenKey(c *Client, version string) string { return c.Host + "/" + version }

// fetchRevision reads the latest revision, or revision n when n is not zero,
// and checks nothing but the shape of the answer.
func (d *Data) fetchRevision(n int) (*fetched, error) {
	path := d.path("db")
	if n != 0 {
		path += "/revisions/" + strconv.Itoa(n)
	}
	resp, err := d.c.send("GET", path, nil, "", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound && n == 0 {
		return nil, ErrNoDatabase
	}
	if resp.StatusCode >= 400 {
		return nil, errorFromResponse("GET", path, resp)
	}
	f, err := readFetched(resp, true)
	if err != nil {
		return nil, err
	}
	if n != 0 && f.revision != n {
		return nil, unverified("the server answered revision %d for revision %d", f.revision, n)
	}
	return f, nil
}

// openRevision runs steps 1 to 4 on a fetched revision: it checks it against
// chk and opens it.
func (d *Data) openRevision(f *fetched, chk *dataChecker) ([]byte, error) {
	ak, err := chk.checkRevision(f.env, f.signerKey, f.epoch, f.revision, f.blob)
	if err != nil {
		return nil, err
	}
	plain, err := e2e.OpenBlob(ak, d.dbContext(f.revision), f.blob)
	if err != nil {
		return nil, unverified("the database does not open: %v", err)
	}
	return plain, nil
}

// noteLatest is step 6: a latest revision lower than the highest this process
// has seen for the version is a rollback. Otherwise it records revision.
func (d *Data) noteLatest(revision int) error {
	seenRevisions.Lock()
	defer seenRevisions.Unlock()
	key := seenKey(d.c, d.version.ID)
	if seen := seenRevisions.m[key]; revision < seen {
		return unverified("revision %d is older than revision %d, already seen", revision, seen)
	}
	seenRevisions.m[key] = revision
	return nil
}

// Latest returns the latest revision's plaintext and its number, or
// ErrNoDatabase.
func (d *Data) Latest() ([]byte, int, error) {
	f, err := d.fetchRevision(0)
	if err != nil {
		return nil, 0, err
	}
	plain, err := d.openRevision(f, d.now)
	if err != nil {
		return nil, 0, err
	}
	if err := d.noteLatest(f.revision); err != nil {
		return nil, 0, err
	}
	return plain, f.revision, nil
}

// Revisions lists the revisions the server keeps, newest first. The list is
// the server's word: each revision is checked when it is read.
func (d *Data) Revisions() ([]Revision, error) {
	var out []Revision
	return out, d.c.doJSON("GET", d.path("db/revisions"), nil, &out)
}

// PutRevision seals plain and signs it as revision base+1, and uploads it with
// If-Match naming base, or "0" for none. A server that holds a later revision
// answers with a *ConflictError.
func (d *Data) PutRevision(plain []byte, base int) (int, error) {
	epoch := d.va.Chain.Latest.Epoch
	ak := d.aks[epoch]
	if ak == nil {
		return 0, ErrNoWriteKey
	}
	revision := base + 1
	blob, err := e2e.SealBlob(rand.Reader, ak, d.dbContext(revision), plain)
	if err != nil {
		return 0, err
	}
	body, err := json.Marshal(e2e.RevisionBody{V: 1, Artifact: d.artifact, Version: d.version.ID, Revision: revision, Epoch: epoch, SHA256: e2e.BodyHash(blob)})
	if err != nil {
		return 0, err
	}
	env, err := e2e.NewEnvelope(d.k.Ed25519Seed, d.k.UserID, "revision", body)
	if err != nil {
		return 0, err
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := writeRecordPart(mw, "record", env); err != nil {
		return 0, err
	}
	if err := writeBlobPart(mw, "blob", blob); err != nil {
		return 0, err
	}
	if err := mw.Close(); err != nil {
		return 0, err
	}
	h := http.Header{"If-Match": {`"` + strconv.Itoa(base) + `"`}}
	resp, err := d.c.send("PUT", d.path("db"), &buf, mw.FormDataContentType(), h)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		apiErr := errorFromResponse("PUT", d.path("db"), resp)
		switch apiErr.Status {
		case http.StatusPreconditionFailed:
			latest := 0
			if m := etagRe.FindStringSubmatch(resp.Header.Get("ETag")); m != nil {
				latest, _ = strconv.Atoi(m[1])
			}
			return 0, &ConflictError{Latest: latest}
		case http.StatusRequestEntityTooLarge:
			return 0, fmt.Errorf("the database is larger than the server's limit (--max-db-mb on the server): %w", apiErr)
		case http.StatusConflict:
			return 0, fmt.Errorf("%w: %w", ErrEpochMoved, apiErr)
		}
		return 0, apiErr
	}
	seenRevisions.Lock()
	defer seenRevisions.Unlock()
	if key := seenKey(d.c, d.version.ID); seenRevisions.m[key] < revision {
		seenRevisions.m[key] = revision
	}
	return revision, nil
}

func writeRecordPart(mw *multipart.Writer, name string, env e2e.Envelope) error {
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return mw.WriteField(name, string(b))
}

func writeBlobPart(mw *multipart.Writer, name string, blob []byte) error {
	w, err := mw.CreateFormFile(name, name)
	if err != nil {
		return err
	}
	_, err = w.Write(blob)
	return err
}

// maxRestoreTries bounds how often a restore follows a 412.
const maxRestoreTries = 5

// Restore uploads revision n's plaintext as a new revision, signed by the
// caller. It accepts a revision signed by anyone the chain has ever listed as
// owner or editor, under any epoch the caller holds the AK of, and returns the
// new revision's number.
func (d *Data) Restore(n int) (int, error) {
	writers, err := d.c.everWriterKeys(d.k, d.va.Membership, d.va.Chain)
	if err != nil {
		return 0, err
	}
	chk := *d.now
	chk.writers, chk.earlierEpochs = writers, true
	f, err := d.fetchRevision(n)
	if err != nil {
		return 0, err
	}
	plain, err := d.openRevision(f, &chk)
	if err != nil {
		return 0, err
	}
	revs, err := d.Revisions()
	if err != nil {
		return 0, err
	}
	base := 0
	for _, r := range revs {
		base = max(base, r.Revision)
	}
	for range maxRestoreTries {
		rev, err := d.PutRevision(plain, base)
		var conflict *ConflictError
		if !errors.As(err, &conflict) {
			return rev, err
		}
		base = conflict.Latest
	}
	return 0, fmt.Errorf("the database kept changing; gave up after %d tries", maxRestoreTries)
}

// Stored files.

// FileInfo describes one file in a version's storage.
type FileInfo struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	ModifiedAt string `json:"modifiedAt"`
}

func (d *Data) fileCtx(kind, address string) e2e.BlobContext {
	return e2e.BlobContext{Artifact: d.artifact, Version: d.version.ID, Kind: kind, Name: address}
}

// epochsDown lists the epochs a file may be stored under, newest first: the
// current one down to the version's, those the caller holds an AK for.
func (d *Data) epochsDown() []int {
	var out []int
	for e := d.va.Chain.Latest.Epoch; e >= d.version.Epoch; e-- {
		if d.aks[e] != nil {
			out = append(out, e)
		}
	}
	return out
}

func (d *Data) addressAt(epoch int, path string) (string, error) {
	fk, err := e2e.FileKey(d.aks[epoch], d.artifact, uint64(epoch))
	if err != nil {
		return "", err
	}
	return e2e.FileAddress(fk, path)
}

// storedFile is a file list entry, as the server sends it.
type storedFile struct {
	Address    string          `json:"address"`
	Epoch      int             `json:"epoch"`
	Size       int64           `json:"size"`
	Record     json.RawMessage `json:"record"`
	Meta       string          `json:"meta"`
	MetaRecord json.RawMessage `json:"metaRecord"`
	SignerKey  string          `json:"signerKey"`
}

// openEntry checks one entry of the file list and opens its metadata, steps 1
// to 5. The file's own blob is checked when it is read.
func (d *Data) openEntry(chk *dataChecker, item storedFile) (*FileMetaBody, error) {
	if !addressRe.MatchString(item.Address) {
		return nil, unverified("the address is not 64 hex characters")
	}
	var rec, metaRec e2e.Envelope
	if json.Unmarshal(item.Record, &rec) != nil || json.Unmarshal(item.MetaRecord, &metaRec) != nil {
		return nil, unverified("a record is not an envelope")
	}
	meta, err := e2e.UnB64(item.Meta)
	if err != nil {
		return nil, unverified("the metadata is not base64url")
	}
	if _, err := chk.checkRecord(rec, item.SignerKey, item.Epoch, "file", item.Address, nil); err != nil {
		return nil, err
	}
	ak, err := chk.checkRecord(metaRec, item.SignerKey, item.Epoch, "file-meta", item.Address, meta)
	if err != nil {
		return nil, err
	}
	plain, err := e2e.OpenBlob(ak, d.fileCtx("file-meta", item.Address), meta)
	if err != nil {
		return nil, unverified("the metadata does not open: %v", err)
	}
	var m FileMetaBody
	if err := e2e.DecodeStrict(plain, &m); err != nil {
		return nil, unverified("the metadata does not decode: %v", err)
	}
	if m.V != 1 {
		return nil, unverified("metadata version unsupported")
	}
	if !validFilePath(m.Path) {
		return nil, unverified("the path is not valid")
	}
	if m.Size < 0 {
		return nil, unverified("the size is not valid")
	}
	fk, err := e2e.FileKey(ak, d.artifact, uint64(item.Epoch))
	if err != nil {
		return nil, err
	}
	if want, err := e2e.FileAddress(fk, m.Path); err != nil || want != item.Address {
		return nil, unverified("the metadata belongs to another file")
	}
	return &m, nil
}

// entries fetches the server's file list.
func (d *Data) entries() ([]storedFile, error) {
	var items []storedFile
	return items, d.c.doJSON("GET", d.path("files"), nil, &items)
}

// ListFiles lists the stored files, one per path, from the highest epoch that
// has it. An entry that fails a check is left out, with a warning.
func (d *Data) ListFiles() ([]FileInfo, error) {
	items, err := d.entries()
	if err != nil {
		return nil, err
	}
	type held struct {
		FileInfo
		epoch int
	}
	byPath := map[string]held{}
	for _, item := range items {
		m, err := d.openEntry(d.now, item)
		if err != nil {
			warnf("cairn: a stored file was left out: %v", err)
			continue
		}
		if h, ok := byPath[m.Path]; !ok || h.epoch < item.Epoch {
			byPath[m.Path] = held{FileInfo{m.Path, m.Size, m.ModifiedAt}, item.Epoch}
		}
	}
	out := make([]FileInfo, 0, len(byPath))
	for _, h := range byPath {
		out = append(out, h.FileInfo)
	}
	slices.SortFunc(out, func(a, b FileInfo) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

// readFile reads the file at address, stored under epoch, and checks it
// against chk. found is false when the server has none.
func (d *Data) readFile(chk *dataChecker, epoch int, address string) (plain []byte, found bool, err error) {
	path := d.path("files/" + address)
	resp, err := d.c.send("GET", path, nil, "", nil)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode >= 400 {
		return nil, false, errorFromResponse("GET", path, resp)
	}
	f, err := readFetched(resp, false)
	if err != nil {
		return nil, false, err
	}
	if f.epoch != epoch {
		return nil, false, unverified("the file is stored under another epoch than its address")
	}
	ak, err := chk.checkRecord(f.env, f.signerKey, epoch, "file", address, f.blob)
	if err != nil {
		return nil, false, err
	}
	plain, err = e2e.OpenBlob(ak, d.fileCtx("file", address), f.blob)
	if err != nil {
		return nil, false, unverified("the file does not open: %v", err)
	}
	return plain, true, nil
}

// GetFile returns the file at path: it looks up its address under each epoch
// from the current one down to the version's, and uses the first the server
// has.
func (d *Data) GetFile(path string) ([]byte, error) {
	if !validFilePath(path) {
		return nil, ErrInvalidPath
	}
	for _, epoch := range d.epochsDown() {
		address, err := d.addressAt(epoch, path)
		if err != nil {
			return nil, err
		}
		plain, found, err := d.readFile(d.now, epoch, address)
		if err != nil {
			return nil, err
		}
		if found {
			return plain, nil
		}
	}
	return nil, ErrFileNotFound
}

func (d *Data) deleteAddress(address string) (found bool, err error) {
	resp, err := d.c.send("DELETE", d.path("files/"+address), nil, "", nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	case resp.StatusCode >= 400:
		return false, errorFromResponse("DELETE", d.path("files/"+address), resp)
	}
	return true, nil
}

// putAt seals plain and its metadata for path under the current epoch, signs
// both, and stores them.
func (d *Data) putAt(path string, plain []byte, modifiedAt string) (*FileInfo, error) {
	epoch := d.va.Chain.Latest.Epoch
	ak := d.aks[epoch]
	if ak == nil {
		return nil, ErrNoWriteKey
	}
	address, err := d.addressAt(epoch, path)
	if err != nil {
		return nil, err
	}
	blob, err := e2e.SealBlob(rand.Reader, ak, d.fileCtx("file", address), plain)
	if err != nil {
		return nil, err
	}
	metaJSON, err := json.Marshal(FileMetaBody{V: 1, Path: path, Size: int64(len(plain)), ModifiedAt: modifiedAt})
	if err != nil {
		return nil, err
	}
	meta, err := e2e.SealBlob(rand.Reader, ak, d.fileCtx("file-meta", address), metaJSON)
	if err != nil {
		return nil, err
	}
	sign := func(kind string, b []byte) (e2e.Envelope, error) {
		body, err := json.Marshal(e2e.RecordBody{V: 1, Artifact: d.artifact, Version: d.version.ID, Kind: kind, Name: address, Epoch: epoch, SHA256: e2e.BodyHash(b)})
		if err != nil {
			return e2e.Envelope{}, err
		}
		return e2e.NewEnvelope(d.k.Ed25519Seed, d.k.UserID, "record", body)
	}
	rec, err := sign("file", blob)
	if err != nil {
		return nil, err
	}
	metaRec, err := sign("file-meta", meta)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, step := range []func() error{
		func() error { return writeRecordPart(mw, "record", rec) },
		func() error { return writeBlobPart(mw, "blob", blob) },
		func() error { return writeRecordPart(mw, "metaRecord", metaRec) },
		func() error { return writeBlobPart(mw, "meta", meta) },
		mw.Close,
	} {
		if err := step(); err != nil {
			return nil, err
		}
	}
	p := d.path("files/" + address)
	resp, err := d.c.send("PUT", p, &buf, mw.FormDataContentType(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		apiErr := errorFromResponse("PUT", p, resp)
		switch apiErr.Status {
		case http.StatusRequestEntityTooLarge:
			return nil, fmt.Errorf("the file is larger than the server's limit (--max-upload-mb on the server): %w", apiErr)
		case http.StatusConflict:
			return nil, fmt.Errorf("%w: %w", ErrEpochMoved, apiErr)
		}
		return nil, apiErr
	}
	return &FileInfo{Path: path, Size: int64(len(plain)), ModifiedAt: modifiedAt}, nil
}

// PutFile stores plain at path under the current epoch, then deletes the same
// path's addresses under earlier epochs. A failure of that cleanup is left:
// the newer copy is the one a reader takes.
func (d *Data) PutFile(path string, plain []byte) (*FileInfo, error) {
	if !validFilePath(path) {
		return nil, ErrInvalidPath
	}
	info, err := d.putAt(path, plain, time.Now().UTC().Format("2006-01-02T15:04:05.000Z"))
	if err != nil {
		return nil, err
	}
	d.removeOlder(path)
	return info, nil
}

func (d *Data) removeOlder(path string) {
	for _, epoch := range d.epochsDown() {
		if epoch == d.va.Chain.Latest.Epoch {
			continue
		}
		if address, err := d.addressAt(epoch, path); err == nil {
			d.deleteAddress(address)
		}
	}
}

// DeleteFile deletes path's address under every epoch, and returns
// ErrFileNotFound when none had it. It goes oldest first, so a delete that
// fails part way leaves the newest copy as the one a read finds.
func (d *Data) DeleteFile(path string) error {
	if !validFilePath(path) {
		return ErrInvalidPath
	}
	found := false
	epochs := d.epochsDown()
	slices.Reverse(epochs)
	for _, epoch := range epochs {
		address, err := d.addressAt(epoch, path)
		if err != nil {
			return err
		}
		ok, err := d.deleteAddress(address)
		if err != nil {
			return err
		}
		found = found || ok
	}
	if !found {
		return ErrFileNotFound
	}
	return nil
}
