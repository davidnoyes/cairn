package client

import (
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/server"
)

// managerWorld is the team world with bob listed as a manager by ada, who
// owns the artifact; cat and dan are not listed.
func managerWorld(t *testing.T) *team {
	t.Helper()
	w := newTeam(t)
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "manager", false); err != nil {
		t.Fatalf("Share bob as manager: %v", err)
	}
	return w
}

// recording is a copy of c, sharing its keys and anchor, that notes each
// request that is not a GET in *writes, and answers 500 to a PUT of an estate
// copy when failEstate is set.
func recording(c *Client, writes *[]string, failEstate bool) *Client {
	out := NewWithKey(c.Host, *c.Key)
	out.Anchors = c.Anchors
	base := http.DefaultTransport
	if c.HTTP != nil && c.HTTP.Transport != nil {
		base = c.HTTP.Transport
	}
	var mu sync.Mutex
	out.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			mu.Lock()
			*writes = append(*writes, r.Method+" "+r.URL.Path)
			mu.Unlock()
		}
		if failEstate && r.Method == "PUT" && strings.Contains(r.URL.Path, "/estate/") {
			return &http.Response{
				StatusCode: 500, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(`{"error":"disk on fire"}`)), Request: r,
			}, nil
		}
		return base.RoundTrip(r)
	})}
	return out
}

func userID(t *testing.T, c *Client) string {
	t.Helper()
	me, err := c.Me()
	if err != nil {
		t.Fatal(err)
	}
	return me.ID
}

// keyEpochs are the epochs c holds an estate copy and a wrap for, as the
// server serves them.
func keyEpochs(t *testing.T, c *Client, artifact string) (estate, wraps []int) {
	t.Helper()
	keys, err := c.Keys(artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range keys.Estate {
		estate = append(estate, e.Epoch)
	}
	for _, w := range keys.Wraps {
		wraps = append(wraps, w.Epoch)
	}
	return estate, wraps
}

func TestOwnerMakesAManagerAndSignsVersionOne(t *testing.T) {
	w := managerWorld(t)
	b := latestRecord(t, w.ada, w.artifact)
	if b.V != 1 || b.Signer != "" || b.SignerFP != "" {
		t.Errorf("the owner's record = v%d signer %q fp %q, want version 1 and neither", b.V, b.Signer, b.SignerFP)
	}
	for _, c := range []*Client{w.ada, w.bob} {
		if r := memberRows(t, c, w.artifact)["bob@example.com"]; r.Role != "manager" {
			t.Errorf("bob's row = %+v, want manager", r)
		}
	}
	if got := openWraps(t, w.bob, w.artifact); !slices.Equal(got, []int{1}) {
		t.Errorf("bob opens wraps of epochs %v, want [1]", got)
	}
}

func TestManagerSharesAndChangesRoles(t *testing.T) {
	w := managerWorld(t)
	bobID, bobFP := userID(t, w.bob), mustUnlock(t, w.bob).FP
	var shareWrites []string
	if _, err := recording(w.bob, &shareWrites, false).Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatalf("manager shares as viewer: %v", err)
	}
	// A manager reads the epochs through their wraps and writes no estate copy.
	for _, wr := range shareWrites {
		if strings.Contains(wr, "/estate/") {
			t.Errorf("the manager wrote %s", wr)
		}
	}
	b := latestRecord(t, w.bob, w.artifact)
	if b.V != 2 || b.Signer != bobID || b.SignerFP != bobFP {
		t.Errorf("the manager's record = v%d signer %q fp %q, want version 2 signed by bob", b.V, b.Signer, b.SignerFP)
	}
	// The owner's client and the new member's verify the manager's record.
	if r := memberRows(t, w.cat, w.artifact)["cat@example.com"]; r.Role != "viewer" {
		t.Errorf("cat's row as cat sees it = %+v, want viewer", r)
	}
	if got := openWraps(t, w.cat, w.artifact); !slices.Equal(got, []int{1}) {
		t.Errorf("cat opens wraps %v, want [1]", got)
	}
	if r := memberRows(t, w.ada, w.artifact)["cat@example.com"]; r.Role != "viewer" {
		t.Errorf("cat's row as ada sees it = %+v, want viewer", r)
	}

	res, err := w.bob.Share(w.artifact, "cat@example.com", "editor", false)
	if err != nil || !res.Promoted {
		t.Fatalf("manager promotes a viewer: %+v, %v", res, err)
	}
	if r := memberRows(t, w.ada, w.artifact)["cat@example.com"]; r.Role != "editor" {
		t.Errorf("cat's row = %+v, want editor", r)
	}
	// Unlisted users and the owner's own record stay as they were.
	if _, err := w.ada.Share(w.artifact, "dan@example.com", "viewer", false); err != nil {
		t.Fatalf("owner shares after a manager's record: %v", err)
	}
	if b := latestRecord(t, w.ada, w.artifact); b.V != 1 || b.Signer != "" {
		t.Errorf("the owner's record after a manager's = v%d signer %q, want version 1", b.V, b.Signer)
	}
}

func TestManagerSetsTeamAndPublic(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.bob.Team(w.artifact, "viewer"); err != nil {
		t.Fatalf("manager sets the team: %v", err)
	}
	if b := latestRecord(t, w.ada, w.artifact); b.Team != "viewer" || b.V != 2 {
		t.Errorf("latest = team %q v%d, want viewer, version 2", b.Team, b.V)
	}
	var publicWrites []string
	res, err := recording(w.bob, &publicWrites, false).Public(w.artifact, true, nil)
	if err != nil || res.Link == "" {
		t.Fatalf("manager makes it public: %+v, %v", res, err)
	}
	for _, wr := range publicWrites {
		if strings.Contains(wr, "/estate/") {
			t.Errorf("the manager wrote %s", wr)
		}
	}
	if b := latestRecord(t, w.ada, w.artifact); !b.Public || b.V != 2 {
		t.Errorf("latest = public %v v%d, want public, version 2", b.Public, b.V)
	}
	// Private again starts a new epoch, which the manager may.
	off, err := w.bob.Public(w.artifact, false, nil)
	if err != nil || !off.NewEpoch {
		t.Fatalf("manager makes it private: %+v, %v", off, err)
	}
}

func TestManagerStartsANewEpochAndTheOwnerCatchesUp(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.bob.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Share(w.artifact, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	putData(t, w.ada, w.artifact)

	res, err := w.bob.Unshare(w.artifact, "cat@example.com")
	if err != nil {
		t.Fatalf("manager unshares: %v", err)
	}
	if !res.NewEpoch || res.Epoch != 2 || res.ResealErr != nil || res.Resealed == nil ||
		res.Resealed.Databases != 1 || res.Resealed.Files != 1 || res.Resealed.Versions != 1 {
		t.Fatalf("Unshare = %+v, resealed %+v, %v: want epoch 2 and the version, database, and file re-sealed", res, res.Resealed, res.ResealErr)
	}
	b := latestRecord(t, w.bob, w.artifact)
	if b.V != 2 || b.Epoch != 2 || !slices.Contains(excludedEmails(b), "cat@example.com") {
		t.Errorf("latest = v%d epoch %d excluding %v", b.V, b.Epoch, excludedEmails(b))
	}

	// The server holds no estate copy of epoch 2, and the owner's wrap of it.
	estate, wraps := keyEpochs(t, w.ada, w.artifact)
	if !slices.Equal(estate, []int{1}) || !slices.Equal(wraps, []int{2}) {
		t.Fatalf("the owner holds estate copies %v and wraps %v, want [1] and [2]", estate, wraps)
	}
	// bob and dan read the new epoch through their wraps; cat does not.
	if _, danWraps := keyEpochs(t, w.dan, w.artifact); !slices.Equal(danWraps, []int{1, 2}) {
		t.Errorf("dan holds wraps of epochs %v, want [1 2]", danWraps)
	}
	if got, err := w.dan.VersionFiles(w.artifact, mustLatestVersion(t, w.bob, w.artifact)); err != nil || string(got["index.html"]) != "<html>hi</html>" {
		t.Errorf("dan reads the re-sealed version: %v, %v", got, err)
	}
	if _, err := w.cat.VersionFiles(w.artifact, mustLatestVersion(t, w.bob, w.artifact)); err == nil {
		t.Error("cat, who was removed, still reads the artifact")
	}

	// The owner reads before the catch-up, through the wrap, and it stores
	// the estate copy.
	d, err := w.ada.OpenData(w.artifact, "", false)
	if err != nil {
		t.Fatalf("the owner opens the artifact through the wrap: %v", err)
	}
	if plain, _, err := d.Latest(); err != nil || string(plain) != "db" {
		t.Errorf("Latest = %q, %v", plain, err)
	}
	estate, wraps = keyEpochs(t, w.ada, w.artifact)
	if !slices.Equal(estate, []int{1, 2}) {
		t.Errorf("after the owner opened it the estate copies are %v, want [1 2]", estate)
	}
	if !slices.Equal(wraps, []int{2}) {
		t.Errorf("the owner's wraps are %v, want [2] still", wraps)
	}
	// And reads after it, through the estate copy.
	if got, err := w.ada.VersionFiles(w.artifact, mustLatestVersion(t, w.bob, w.artifact)); err != nil || string(got["index.html"]) != "<html>hi</html>" {
		t.Errorf("VersionFiles after the catch-up = %v, %v", got, err)
	}
	// A manager's next epoch after that reads the epoch the owner added.
	if _, err := w.bob.Unshare(w.artifact, "dan@example.com"); err != nil {
		t.Fatalf("second manager epoch: %v", err)
	}
	if _, err := w.ada.VersionFiles(w.artifact, mustLatestVersion(t, w.bob, w.artifact)); err != nil {
		t.Errorf("the owner after a second manager epoch: %v", err)
	}
	if estate, _ := keyEpochs(t, w.ada, w.artifact); !slices.Equal(estate, []int{1, 2, 3}) {
		t.Errorf("estate copies %v, want [1 2 3]", estate)
	}
}

func mustLatestVersion(t *testing.T, c *Client, artifact string) string {
	t.Helper()
	vs, err := c.ListVersions(artifact)
	if err != nil || len(vs) == 0 {
		t.Fatalf("ListVersions = %v, %v", vs, err)
	}
	return vs[0].ID
}

func TestFailedCatchUpDoesNotStopTheOwnerReading(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.bob.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	putData(t, w.ada, w.artifact)
	if _, err := w.bob.Unshare(w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	var writes []string
	flaky := recording(w.ada, &writes, true)
	if _, err := flaky.VersionFiles(w.artifact, mustLatestVersion(t, w.bob, w.artifact)); err != nil {
		t.Fatalf("the owner reads while the estate copy cannot be stored: %v", err)
	}
	if !slices.Contains(writes, "PUT /api/artifacts/"+w.artifact+"/estate/2") {
		t.Errorf("writes = %v, want an attempt to store the estate copy of epoch 2", writes)
	}
	if estate, _ := keyEpochs(t, w.ada, w.artifact); !slices.Equal(estate, []int{1}) {
		t.Errorf("estate copies %v, want [1]: the failed PUT stored none", estate)
	}
	// The next read, with a working connection, adds it.
	if _, err := w.ada.VersionFiles(w.artifact, mustLatestVersion(t, w.bob, w.artifact)); err != nil {
		t.Fatal(err)
	}
	if estate, _ := keyEpochs(t, w.ada, w.artifact); !slices.Equal(estate, []int{1, 2}) {
		t.Errorf("estate copies %v, want [1 2]", estate)
	}
}

func TestManagerEpochWrapsToTheOwnerOnly(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.bob.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	var writes []string
	if _, err := recording(w.bob, &writes, false).Unshare(w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	// The record is the only thing sent to the estate route's neighbours: no
	// PUT of an estate copy, from the manager.
	for _, wr := range writes {
		if strings.Contains(wr, "/estate/") {
			t.Errorf("the manager wrote %s", wr)
		}
	}
	// The owner's wrap of epoch 2 opens under the owner's keys.
	k := mustUnlock(t, w.ada)
	va, err := w.ada.VerifyArtifact(k, w.artifact, "")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := w.ada.Keys(w.artifact)
	if err != nil || len(keys.Wraps) != 1 {
		t.Fatalf("owner's keys = %+v, %v", keys, err)
	}
	if _, err := openWrap(k, w.artifact, epochCommits(va.Chain), keys.Wraps[0]); err != nil {
		t.Errorf("the owner's wrap does not open: %v", err)
	}
}

// ownerOnlyRefused runs f as bob, a manager, and checks that it fails with
// want, that no request that writes was made, and that the chain did not move.
func ownerOnlyRefused(t *testing.T, w *team, name string, want error, f func(bob *Client) error) {
	t.Helper()
	before := recordCount(t, w.ada, w.artifact)
	var writes []string
	err := f(recording(w.bob, &writes, false))
	if !errors.Is(err, want) {
		t.Errorf("%s: %v, want %v", name, err, want)
	}
	if len(writes) != 0 {
		t.Errorf("%s: wrote %v before refusing", name, writes)
	}
	if got := recordCount(t, w.ada, w.artifact); got != before {
		t.Errorf("%s: %d records, was %d", name, got, before)
	}
}

func TestManagerCannotMakeOrChangeManagers(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.ada.Share(w.artifact, "cat@example.com", "manager", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Share(w.artifact, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	share := func(who, role string) func(*Client) error {
		return func(c *Client) error { _, err := c.Share(w.artifact, who, role, false); return err }
	}
	ownerOnlyRefused(t, w, "make dan a manager", ErrManagerOwnerOnly, share("dan@example.com", "manager"))
	ownerOnlyRefused(t, w, "demote the other manager to editor", ErrManagerOwnerOnly, share("cat@example.com", "editor"))
	ownerOnlyRefused(t, w, "demote the other manager to viewer", ErrManagerOwnerOnly, share("cat@example.com", "viewer"))
	ownerOnlyRefused(t, w, "re-share the other manager as manager", ErrManagerOwnerOnly, share("cat@example.com", "manager"))
	ownerOnlyRefused(t, w, "demote himself", ErrManagerOwnerOnly, share("bob@example.com", "editor"))
	ownerOnlyRefused(t, w, "remove the other manager", ErrManagerOwnerOnly, func(c *Client) error {
		_, err := c.Unshare(w.artifact, "cat@example.com")
		return err
	})
	ownerOnlyRefused(t, w, "remove himself", ErrManagerOwnerOnly, func(c *Client) error {
		_, err := c.Unshare(w.artifact, "bob@example.com")
		return err
	})
	ownerOnlyRefused(t, w, "share with the owner", ErrShareSelf, share("ada@example.com", "viewer"))
	ownerOnlyRefused(t, w, "offer ownership", ErrTransferNotOwner, func(c *Client) error {
		_, err := c.OfferTransfer(w.artifact, "dan@example.com", false)
		return err
	})
	putData(t, w.ada, w.artifact)
	ownerOnlyRefused(t, w, "vouch", ErrVouchNotOwner, func(c *Client) error {
		return c.Vouch(w.artifact, mustLatestVersion(t, w.bob, w.artifact))
	})
	// The owner may do each of them, so the refusal is the role's.
	if res, err := w.ada.Share(w.artifact, "cat@example.com", "editor", false); err != nil || !res.Lowered {
		t.Errorf("the owner changes a manager to editor: %+v, %v", res, err)
	}
	if _, err := w.ada.Unshare(w.artifact, "bob@example.com"); err != nil {
		t.Errorf("the owner removes a manager: %v", err)
	}
}

func TestOwnerRemovingAManagerStartsANewEpoch(t *testing.T) {
	w := managerWorld(t)
	res, err := w.ada.Share(w.artifact, "bob@example.com", "viewer", false)
	if err != nil || !res.Demoted || !res.NewEpoch {
		t.Fatalf("owner demotes a manager to viewer: %+v, %v, want a new epoch", res, err)
	}
	// The manager's own record signing is refused once they are not one.
	if _, err := w.bob.Share(w.artifact, "cat@example.com", "viewer", false); !errors.Is(err, ErrNotOwner) {
		t.Errorf("a demoted manager shares: %v, want ErrNotOwner", err)
	}
}

func TestManagerPushIsAcceptedByOthers(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.bob.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	putData(t, w.bob, w.artifact)
	for name, c := range map[string]*Client{"owner": w.ada, "viewer": w.cat} {
		d, err := c.OpenData(w.artifact, "", false)
		if err != nil {
			t.Fatalf("%s opens: %v", name, err)
		}
		if plain, _, err := d.Latest(); err != nil || string(plain) != "db" {
			t.Errorf("%s: Latest = %q, %v", name, plain, err)
		}
		if got, err := d.GetFile("f.txt"); err != nil || string(got) != "file" {
			t.Errorf("%s: GetFile = %q, %v", name, got, err)
		}
		if _, err := c.VersionFiles(w.artifact, mustLatestVersion(t, w.bob, w.artifact)); err != nil {
			t.Errorf("%s: VersionFiles: %v", name, err)
		}
	}
	// A new epoch by the owner reseals what the manager wrote.
	res, err := w.ada.Unshare(w.artifact, "cat@example.com")
	if err != nil || res.ResealErr != nil || res.Resealed == nil || res.Resealed.Databases != 1 || res.Resealed.Files != 1 ||
		res.Resealed.Versions != 1 || len(res.Resealed.Skipped) != 0 {
		t.Fatalf("Unshare = %+v, %v: the owner re-seals what the manager wrote", res, err)
	}
}

func TestManagerApprovesATeamMember(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.ada.Team(w.artifact, "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Approve(w.artifact, "cat@example.com", false); err != nil {
		t.Fatalf("manager approves: %v", err)
	}
	// The server shows an approved user to whoever signs member lists: the
	// owner and the manager.
	for _, c := range []*Client{w.ada, w.bob} {
		wantStates(t, pendingStates(t, c, w.artifact), map[string]string{"cat@example.com": PendingApproved, "dan@example.com": PendingNew})
	}
	// The owner's client lists the member a manager approved: the approval
	// passes e2e.CheckApproval with a manager as its signer.
	res, err := w.ada.Team(w.artifact, "viewer")
	if err != nil || len(res.Listed) != 1 || res.Listed[0].Email != "cat@example.com" || len(res.Unlisted) != 0 {
		t.Fatalf("owner's Team = %+v, %v, want cat listed", res, err)
	}
	if r := memberRows(t, w.ada, w.artifact)["cat@example.com"]; r.Role != "viewer" {
		t.Errorf("cat's row = %+v, want viewer", r)
	}
	if got := openWraps(t, w.cat, w.artifact); !slices.Equal(got, []int{1}) {
		t.Errorf("cat opens wraps %v, want [1]", got)
	}
}

// A manager's new epoch on a team artifact must list or exclude every
// approved team member, so the manager's client decides about them as the
// owner's does: removing dan lists cat, whom an approval admitted.
func TestManagerEpochListsApprovedTeamMembers(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.ada.Team(w.artifact, "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Share(w.artifact, "dan@example.com", "viewer", false); err != nil {
		t.Fatalf("manager shares with dan: %v", err)
	}
	if _, err := w.bob.Approve(w.artifact, "cat@example.com", false); err != nil {
		t.Fatalf("manager approves cat: %v", err)
	}
	if _, err := w.bob.Unshare(w.artifact, "dan@example.com"); err != nil {
		t.Fatalf("manager removes dan in a new epoch: %v", err)
	}
	b := latestRecord(t, w.ada, w.artifact)
	if b.V != 2 || b.Epoch != 2 {
		t.Fatalf("latest record: v%d epoch %d, want a manager's v2 at epoch 2", b.V, b.Epoch)
	}
	rows := memberRows(t, w.ada, w.artifact)
	if r, ok := rows["cat@example.com"]; !ok || r.Role != "viewer" {
		t.Errorf("cat's row = %+v (listed %v), want the approved team member listed as viewer", r, ok)
	}
	if _, ok := rows["dan@example.com"]; ok {
		t.Error("dan is still listed after the manager removed him")
	}
	// cat opens the new epoch's key, and it matches that epoch's commitment.
	k := mustUnlock(t, w.cat)
	keys, err := w.cat.Keys(w.artifact)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(keys.Wraps, func(x KeyWrap) bool { return x.Epoch == 2 })
	if i < 0 {
		t.Fatalf("cat holds no wrap for epoch 2: %+v", keys.Wraps)
	}
	ak, err := e2e.Unwrap(k.X25519Priv, e2e.WrapContext{
		Purpose: "ak", Artifact: w.artifact, Epoch: 2, RecipientID: k.UserID, RecipientPub: k.X25519Pub,
	}, keys.Wraps[i].Wrapped)
	if err != nil {
		t.Fatalf("Unwrap epoch 2: %v", err)
	}
	if commit, _ := e2e.AKCommit(ak, w.artifact, 2); commit != b.AKCommit {
		t.Error("cat's epoch 2 key does not match the record's akCommit")
	}
}

func TestOwnershipOfferToAManager(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.ada.OfferTransfer(w.artifact, "bob@example.com", false); err != nil {
		t.Fatalf("offer to a manager: %v", err)
	}
	if _, err := w.bob.AcceptTransfer(w.artifact, AcceptTransferOptions{}); err != nil {
		t.Fatalf("manager accepts: %v", err)
	}
	rows := memberRows(t, w.bob, w.artifact)
	if rows["bob@example.com"].Role != "owner" || rows["ada@example.com"].Role != "editor" {
		t.Errorf("rows after the transfer: bob %+v, ada %+v, want owner and editor", rows["bob@example.com"], rows["ada@example.com"])
	}
	if b := latestRecord(t, w.bob, w.artifact); b.V != 1 || b.Signer != "" {
		t.Errorf("the accepting record = v%d signer %q, want version 1", b.V, b.Signer)
	}
	// The new owner signs version 1, and ada, now an editor, cannot sign.
	if _, err := w.bob.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Share(w.artifact, "dan@example.com", "viewer", false); !errors.Is(err, ErrNotOwner) {
		t.Errorf("the previous owner shares: %v, want ErrNotOwner", err)
	}
}

// After a manager starts an epoch, the owner holds a wrap for it. A
// transfer that keeps the previous owner as an editor wraps every epoch to
// them; the one they already hold must not stop the accept.
func TestTransferAfterAManagersEpoch(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.bob.Share(w.artifact, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Unshare(w.artifact, "dan@example.com"); err != nil {
		t.Fatalf("manager starts epoch 2: %v", err)
	}
	if _, err := w.ada.OfferTransfer(w.artifact, "bob@example.com", false); err != nil {
		t.Fatalf("offer to the manager: %v", err)
	}
	if _, err := w.bob.AcceptTransfer(w.artifact, AcceptTransferOptions{}); err != nil {
		t.Fatalf("accept after a manager's epoch: %v", err)
	}
	rows := memberRows(t, w.bob, w.artifact)
	if rows["bob@example.com"].Role != "owner" || rows["ada@example.com"].Role != "editor" {
		t.Errorf("rows after the transfer: bob %+v, ada %+v, want owner and editor", rows["bob@example.com"], rows["ada@example.com"])
	}
	// ada, now an editor, still opens every epoch through her wraps.
	k := mustUnlock(t, w.ada)
	va, err := w.ada.VerifyArtifact(k, w.artifact, "")
	if err != nil {
		t.Fatal(err)
	}
	aks, err := w.ada.callerAKs(k, w.artifact, va.Chain)
	if err != nil || len(aks) != 2 {
		t.Errorf("ada's AKs after the transfer: %d epochs, %v; want 2", len(aks), err)
	}
}

func TestViewerAccountCannotBeMadeAManager(t *testing.T) {
	host, m := newTestServerWith(t, func(c *server.Config) {
		c.SignupDomains = []string{"example.com"}
		c.ViewerDomains = []string{"viewers.test"}
	})
	clients := map[string]*Client{}
	for _, email := range []string{"admin@example.com", "ada@example.com", "bob@example.com", "carol@viewers.test"} {
		signupVerify(t, host, m, email, testPassword)
		out, err := New(host, "").Login(email, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		clients[email] = keyedFor(t, host, out.APIKey)
	}
	admin, ada := clients["admin@example.com"], clients["ada@example.com"]
	a, err := ada.CreateArtifact("shared", "")
	if err != nil {
		t.Fatal(err)
	}
	var writes []string
	_, err = recording(ada, &writes, false).Share(a.ID, "carol@viewers.test", "manager", false)
	if !errors.Is(err, ErrViewerAccount) || err.Error() != "carol@viewers.test is a viewer account and can only be a viewer" {
		t.Fatalf("share as manager: %v", err)
	}
	if len(writes) != 0 {
		t.Errorf("wrote %v before refusing", writes)
	}
	if _, err := ada.Share(a.ID, "carol@viewers.test", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.Share(a.ID, "carol@viewers.test", "manager", false); !errors.Is(err, ErrViewerAccount) {
		t.Errorf("promote a listed viewer account to manager: %v, want ErrViewerAccount", err)
	}

	// A manager whose account became a viewer account keeps the entry, may
	// become an editor, and cannot be made a manager again.
	if _, err := ada.Share(a.ID, "bob@example.com", "manager", false); err != nil {
		t.Fatal(err)
	}
	bob := memberRows(t, ada, a.ID)["bob@example.com"]
	if err := admin.doJSON("PATCH", "/api/admin/users/"+bob.User, map[string]string{"role": "viewer"}, nil); err != nil {
		t.Fatalf("demote the account: %v", err)
	}
	if res, err := ada.Share(a.ID, "bob@example.com", "manager", false); err != nil || !res.Unchanged {
		t.Fatalf("re-share a demoted manager as manager: %+v, %v; want unchanged", res, err)
	}
	if res, err := ada.Share(a.ID, "bob@example.com", "editor", false); err != nil || !res.Lowered {
		t.Fatalf("make the demoted manager an editor: %+v, %v", res, err)
	}
	if _, err := ada.Share(a.ID, "bob@example.com", "manager", false); !errors.Is(err, ErrViewerAccount) {
		t.Errorf("make the viewer account a manager again: %v, want ErrViewerAccount", err)
	}
}

func TestRolesAreRefusedBelowViewerAndAboveManager(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.ada.Share(w.artifact, "cat@example.com", "owner", false); err == nil {
		t.Error("sharing as owner was accepted")
	}
}

func TestSignedByCaller(t *testing.T) {
	k := &UnlockedKeys{UserID: "u-bob", FP: "fp-bob"}
	for _, c := range []struct {
		name string
		b    e2e.MembershipBody
		want bool
	}{
		{"the owner's record under the caller's key", e2e.MembershipBody{V: 1, Owner: "u-bob", OwnerFP: "fp-bob"}, true},
		{"the owner's record under an older key", e2e.MembershipBody{V: 1, Owner: "u-bob", OwnerFP: "fp-old"}, false},
		{"another owner's record", e2e.MembershipBody{V: 1, Owner: "u-ada", OwnerFP: "fp-bob"}, false},
		{"a manager's record naming the caller", e2e.MembershipBody{V: 2, Owner: "u-ada", Signer: "u-bob", SignerFP: "fp-bob"}, true},
		{"a manager's record under another key", e2e.MembershipBody{V: 2, Owner: "u-ada", Signer: "u-bob", SignerFP: "fp-old"}, false},
		{"another manager's record", e2e.MembershipBody{V: 2, Owner: "u-ada", Signer: "u-cat", SignerFP: "fp-bob"}, false},
	} {
		if got := signedByCaller(c.b, k); got != c.want {
			t.Errorf("%s: signedByCaller = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestManagerWrapsToAnOwnerWhoseKeysDoNotFollow(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.bob.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	_, x, err := e2e.GenerateX25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := e2e.GenerateEd25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The directory serves the owner under keys no rotation record links to
	// the fingerprint the chain lists.
	c := rewritingList(t, w.bob, "/api/users", func(list []map[string]any) []map[string]any {
		for _, u := range list {
			if u["email"] == "ada@example.com" {
				u["x25519Pub"], u["ed25519Pub"] = e2e.B64(x), e2e.B64(ed)
			}
		}
		return list
	})
	var writes []string
	if _, err := recording(c, &writes, false).Unshare(w.artifact, "cat@example.com"); err == nil || !strings.Contains(err.Error(), "do not follow") {
		t.Errorf("Unshare with an unexplained owner key: %v, want a refusal", err)
	}
	if len(writes) != 0 {
		t.Errorf("wrote %v before refusing", writes)
	}
}

func TestReviewTreatsAManagerAsAWriter(t *testing.T) {
	w := managerWorld(t)
	vid := pushOne(t, w.bob, w.artifact)
	c := withReview(t, w.ada, w.artifact, map[string]any{"id": vid, "seq": 1, "pushedBy": userID(t, w.bob), "createdAt": "x"})
	if list, err := c.Review(w.artifact); !errors.Is(err, ErrReviewInconsistent) {
		t.Errorf("an entry pushed by a listed manager: %v, %v, want ErrReviewInconsistent", list, err)
	}
}

func TestRestoreAcceptsARevisionAFormerManagerSigned(t *testing.T) {
	w := managerWorld(t)
	putData(t, w.bob, w.artifact)
	if res, err := w.ada.Share(w.artifact, "bob@example.com", "viewer", false); err != nil || !res.NewEpoch {
		t.Fatalf("owner demotes the manager: %+v, %v", res, err)
	}
	d, err := w.ada.OpenData(w.artifact, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Restore(1); err != nil {
		t.Errorf("restoring a revision a manager signed: %v", err)
	}
}

// A manager's client decides about a listed member who rotated, as the
// owner's does: the server shows them as rotated, and the manager's client
// believes it once the rotation chain checks out, so a new epoch keeps them
// under their new keys.
func TestManagerSeesARotatedMemberAsRotated(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.ada.Share(w.artifact, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	rotateOK(t, w.dan, false)
	if got := pendingStates(t, w.bob, w.artifact); got["dan@example.com"] != PendingRotated {
		t.Fatalf("manager's pending = %v, want dan rotated", got)
	}
}
