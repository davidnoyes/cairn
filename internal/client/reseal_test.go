package client

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/sqlrun"
)

// seedData writes a database and two files as ada.
func seedData(t *testing.T, e *dataEnv) {
	t.Helper()
	d := e.open(t, e.ada, true)
	exec(t, d, "CREATE TABLE t (n INTEGER)")
	exec(t, d, "INSERT INTO t VALUES (42)")
	if _, err := d.PutFile("notes/a.txt", []byte("alpha")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutFile("b.txt", []byte("beta")); err != nil {
		t.Fatal(err)
	}
}

// rawRevisionEpoch is the epoch the server says the latest revision is sealed
// under.
func rawRevisionEpoch(t *testing.T, d *Data) int {
	t.Helper()
	f, err := d.fetchRevision(0)
	if err != nil {
		t.Fatal(err)
	}
	return f.epoch
}

func epochsOf(t *testing.T, d *Data) map[string]int {
	t.Helper()
	items, err := d.entries()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, it := range items {
		out[it.Address] = it.Epoch
	}
	return out
}

func checkData(t *testing.T, d *Data) {
	t.Helper()
	res, err := d.Exec([]sqlrun.Statement{{SQL: "SELECT n FROM t"}})
	if err != nil || len(res[0].Rows) != 1 || res[0].Rows[0][0].(int64) != 42 {
		t.Fatalf("the database = %+v, %v", res, err)
	}
	for path, want := range map[string]string{"notes/a.txt": "alpha", "b.txt": "beta"} {
		if got, err := d.GetFile(path); err != nil || string(got) != want {
			t.Fatalf("GetFile(%s) = %q, %v, want %q", path, got, err, want)
		}
	}
	files, err := d.ListFiles()
	if err != nil || len(files) != 2 {
		t.Fatalf("ListFiles = %+v, %v", files, err)
	}
}

func TestUnshareResealsTheData(t *testing.T) {
	e := newDataEnv(t)
	seedData(t, e)
	if _, err := e.ada.Public(e.artifact, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	before := e.open(t, e.ada, false)
	oldAK := before.aks[1]
	oldAddrs := epochsOf(t, before)
	oldBlob, err := before.fetchRevision(0)
	if err != nil {
		t.Fatal(err)
	}

	res, err := e.ada.Unshare(e.artifact, "bob@example.com")
	if err != nil {
		t.Fatalf("Unshare: %v", err)
	}
	if res.ResealErr != nil || res.Resealed == nil || res.Resealed.Databases != 1 || res.Resealed.Files != 2 || len(res.Resealed.Skipped) != 0 {
		t.Fatalf("Resealed = %+v, %v, want one database and two files", res.Resealed, res.ResealErr)
	}
	d := e.open(t, e.ada, true)
	// The database is a new revision under epoch 2; the old link's epoch
	// cannot open it and the new one can.
	if got := rawRevisionEpoch(t, d); got != 2 {
		t.Errorf("the latest revision is sealed under epoch %d, want 2", got)
	}
	f, err := d.fetchRevision(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx := d.dbContext(f.revision)
	if _, err := e2e.OpenBlob(oldAK, ctx, f.blob); err == nil {
		t.Error("the old epoch's AK opens the resealed revision")
	}
	if _, err := e2e.OpenBlob(d.aks[2], ctx, f.blob); err != nil {
		t.Errorf("the new epoch's AK does not open it: %v", err)
	}
	if f.revision != oldBlob.revision+1 {
		t.Errorf("revision %d after %d, want the next one", f.revision, oldBlob.revision)
	}
	// Every file is at a new address under epoch 2, and the old ones are gone.
	now := epochsOf(t, d)
	if len(now) != 2 {
		t.Fatalf("%d stored files, want 2: %v", len(now), now)
	}
	for addr, epoch := range now {
		if epoch != 2 {
			t.Errorf("file %s is under epoch %d, want 2", addr, epoch)
		}
		if _, was := oldAddrs[addr]; was {
			t.Errorf("file %s kept its old address", addr)
		}
	}
	for addr := range oldAddrs {
		resp, err := d.c.send("GET", d.path("files/"+addr), nil, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("the old address %s answers %d, want 404", addr, resp.StatusCode)
		}
	}
	checkData(t, d)

	// Run again: nothing left to do.
	again, err := e.ada.Reseal(e.artifact)
	if err != nil || again.Databases != 0 || again.Files != 0 || len(again.Skipped) != 0 {
		t.Fatalf("a second Reseal = %+v, %v, want nothing", again, err)
	}
	if revs, _ := d.Revisions(); revs[0].Revision != f.revision {
		t.Errorf("the second Reseal wrote revision %d", revs[0].Revision)
	}
}

func TestEveryEpochChangeReseals(t *testing.T) {
	cases := []struct {
		name   string
		change func(t *testing.T, e *dataEnv) (*ResealResult, error)
	}{
		{"public off", func(t *testing.T, e *dataEnv) (*ResealResult, error) {
			if _, err := e.ada.Public(e.artifact, true, nil); err != nil {
				t.Fatal(err)
			}
			res, err := e.ada.Public(e.artifact, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			return res.Resealed, res.ResealErr
		}},
		{"demoting an editor", func(t *testing.T, e *dataEnv) (*ResealResult, error) {
			if _, err := e.ada.Share(e.artifact, "bob@example.com", "editor", false); err != nil {
				t.Fatal(err)
			}
			res, err := e.ada.Share(e.artifact, "bob@example.com", "viewer", false)
			if err != nil {
				t.Fatal(err)
			}
			if !res.NewEpoch {
				t.Fatal("demoting an editor started no epoch")
			}
			return res.Resealed, res.ResealErr
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newDataEnv(t)
			seedData(t, e)
			resealed, err := tc.change(t, e)
			if err != nil || resealed == nil || resealed.Databases != 1 || resealed.Files != 2 {
				t.Fatalf("Resealed = %+v, %v, want one database and two files", resealed, err)
			}
			checkData(t, e.open(t, e.ada, true))
		})
	}
}

func TestResealInTheFirstEpochDoesNothing(t *testing.T) {
	e := newDataEnv(t)
	seedData(t, e)
	res, err := e.ada.Reseal(e.artifact)
	if err != nil || res.Databases != 0 || res.Files != 0 {
		t.Fatalf("Reseal = %+v, %v", res, err)
	}
}

func TestResealRefusesAReader(t *testing.T) {
	e := newDataEnv(t)
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.bob.Reseal(e.artifact); !errors.Is(err, ErrCannotReseal) {
		t.Errorf("a viewer's Reseal = %v, want ErrCannotReseal", err)
	}
}

// TestResealReportsAFailurePartWay has the deletes of the old addresses fail
// while the owner unshares: the command reports it, readers still take the
// newest copy, a write cleans up after itself, and Reseal finishes the rest.
func TestResealReportsAFailurePartWay(t *testing.T) {
	e := newDataEnv(t)
	seedData(t, e)
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	failing := true
	intercept(e.ada, &tamper{before: func(req *http.Request) *http.Response {
		if failing && req.Method == "DELETE" && strings.Contains(req.URL.Path, "/files/") {
			return replyJSON(req, 500, nil, `{"error":"disk on fire"}`)
		}
		return nil
	}})
	res, err := e.ada.Unshare(e.artifact, "bob@example.com")
	if err != nil {
		t.Fatalf("Unshare: %v", err)
	}
	if res.ResealErr == nil || !strings.Contains(res.ResealErr.Error(), "disk on fire") || res.Resealed == nil || res.Resealed.Databases != 1 {
		t.Fatalf("Resealed = %+v, %v, want the database done and the failure named", res.Resealed, res.ResealErr)
	}
	failing = false

	d := e.open(t, e.ada, true)
	if n := len(epochsOf(t, d)); n != 3 {
		t.Fatalf("%d stored files, want 3: two old, one already copied", n)
	}
	checkData(t, d) // the newest copy wins, and the list shows one entry per path
	// The one file the failed re-seal did copy is stored at both addresses;
	// writing it again removes the old.
	held := epochsOf(t, d)
	for path, want := range map[string]string{"notes/a.txt": "alpha", "b.txt": "beta"} {
		old, _ := d.addressAt(1, path)
		cur, _ := d.addressAt(2, path)
		_, hasOld := held[old]
		_, hasCur := held[cur]
		if hasOld && hasCur {
			if _, err := d.PutFile(path, []byte(want)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if n := len(epochsOf(t, d)); n != 2 {
		t.Errorf("%d stored files after rewriting one, want 2: the write removes the old address", n)
	}
	done, err := e.ada.Reseal(e.artifact)
	if err != nil || done.Files != 1 || done.Databases != 0 {
		t.Fatalf("Reseal = %+v, %v, want the one file left", done, err)
	}
	for addr, epoch := range epochsOf(t, d) {
		if epoch != 2 {
			t.Errorf("file %s is still under epoch %d", addr, epoch)
		}
	}
	checkData(t, d)
	if err := d.DeleteFile("b.txt"); err != nil {
		t.Fatal(err)
	}
}

// TestResealLeavesWhatAnEarlierRemovalLeft has two epoch changes, the first
// without a re-seal. The removed editor's revision does not verify under the
// record before the second, so it stays as it is, the database cannot be
// read, and a write makes it readable again.
func TestResealLeavesWhatAnEarlierRemovalLeft(t *testing.T) {
	e := newDataEnv(t)
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	bob := e.open(t, e.bob, true)
	if _, err := bob.PutRevision([]byte("from bob"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.PutFile("bob.txt", []byte("bob's file")); err != nil {
		t.Fatal(err)
	}
	// The first removal cannot re-seal: reading the database fails.
	broken := true
	adaBroken := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	intercept(adaBroken, &tamper{before: func(req *http.Request) *http.Response {
		if broken && req.Method == "GET" && strings.Contains(req.URL.Path, "/versions/") && (strings.HasSuffix(req.URL.Path, "/db") || strings.HasSuffix(req.URL.Path, "/files")) {
			return replyJSON(req, 500, nil, `{"error":"unavailable"}`)
		}
		return nil
	}})
	first, err := adaBroken.Unshare(e.artifact, "bob@example.com")
	if err != nil || first.ResealErr == nil {
		t.Fatalf("Unshare = %+v, %v, want a re-seal failure", first, err)
	}
	broken = false
	// The second change: public on, then off.
	if _, err := e.ada.Public(e.artifact, true, nil); err != nil {
		t.Fatal(err)
	}
	off, err := e.ada.Public(e.artifact, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if off.ResealErr != nil || off.Resealed.Databases != 0 || off.Resealed.Files != 0 || len(off.Resealed.Skipped) != 2 {
		t.Fatalf("Resealed = %+v, %v, want bob's database and file skipped", off.Resealed, off.ResealErr)
	}
	for _, s := range off.Resealed.Skipped {
		if !strings.Contains(s, "may not write") {
			t.Errorf("skipped %q, want it to say the signer may not write", s)
		}
	}
	d := e.open(t, e.ada, true)
	if _, _, err := d.Latest(); !errors.Is(err, ErrUnverified) {
		t.Fatalf("Latest = %v, want the removed editor's revision refused", err)
	}
	if _, err := d.Restore(1); err != nil {
		t.Fatalf("a restore of it: %v", err)
	}
	if plain, _, err := d.Latest(); err != nil || string(plain) != "from bob" {
		t.Fatalf("Latest after the restore = %q, %v", plain, err)
	}
}

// TestResealKeepsARemovedEditorsLastRevision: an editor wrote while they could,
// so their revision and file verify under the record before the change, and the
// owner who removes them seals them again.
func TestResealKeepsARemovedEditorsLastRevision(t *testing.T) {
	e := newDataEnv(t)
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	bob := e.open(t, e.bob, true)
	exec(t, bob, "CREATE TABLE t (n INTEGER)")
	exec(t, bob, "INSERT INTO t VALUES (42)")
	bob.PutFile("notes/a.txt", []byte("alpha"))
	bob.PutFile("b.txt", []byte("beta"))
	res, err := e.ada.Unshare(e.artifact, "bob@example.com")
	if err != nil || res.ResealErr != nil || res.Resealed.Databases != 1 || res.Resealed.Files != 2 || len(res.Resealed.Skipped) != 0 {
		t.Fatalf("Unshare = %+v, %v", res, err)
	}
	checkData(t, e.open(t, e.ada, true))
}
