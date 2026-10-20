package membership

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// A record's folder is the one the item sits in, and nothing else: a hostile
// client or server cannot make a record name a folder of its choosing.
func TestCheckPlacementIsSigned(t *testing.T) {
	cases := []struct {
		name   string
		parent string // the folder the item sits in
		folder string // the folder the record names
		ok     bool
	}{
		{"top level, names none", "", "", true},
		{"top level, names a folder", "", folderG, false},
		{"in a folder, names it", folderF, folderF, true},
		{"in a folder, names none", folderF, "", false},
		{"in a folder, names another", folderF, folderG, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			if c.parent != "" {
				f.inFolder(nil)
			}
			b := f.next()
			b.Folder = c.folder
			_, err := Check(f.cur, f.dir, f.change(t, b, nil, nil))
			if c.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			refused(t, err, 409, RulePlacement, "is not the folder the item sits in")
		})
	}
}

// The first record of a new item names the folder it is created in.
func TestCheckPlacementOfAFirstRecord(t *testing.T) {
	for _, c := range []struct {
		name, folder string
		ok           bool
	}{{"names the folder", folderF, true}, {"names none", "", false}, {"names another", folderG, false}} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.creation()
			f.cur.Parent = folderF
			f.cur.Folders = map[string]*e2e.MembershipBody{folderF: folderRecord(folderF, nil, nil)}
			b, wraps, est := f.first()
			b.Folder = c.folder
			_, err := Check(f.cur, f.dir, f.change(t, b, wraps, est))
			if c.ok != (err == nil) {
				t.Fatalf("folder %q: %v", c.folder, err)
			}
			if err != nil {
				refused(t, err, 409, RulePlacement, "is not the folder the item sits in")
			}
		})
	}
}

// A folder's own record names its parent in the same way.
func TestCheckPlacementOfAFolderInAFolder(t *testing.T) {
	f := newFixture(t)
	f.cur.Kind = store.KindFolder
	f.latestWith("none")
	f.inFolder(nil)
	if _, err := Check(f.cur, f.dir, f.change(t, f.next(), nil, nil)); err != nil {
		t.Fatalf("a folder that names its parent: %v", err)
	}
	b := f.next()
	b.Folder = ""
	_, err := Check(f.cur, f.dir, f.change(t, b, nil, nil))
	refused(t, err, 409, RulePlacement, "is not the folder the item sits in")
}

// Moving is the owner's: a manager's record keeps the folder the latest
// record names, and after a move, while the record still names the old
// folder, only the owner's record can name the new one.
func TestCheckManagerKeepsTheFolder(t *testing.T) {
	f, m := managerFixture(t)
	f.inFolder(nil)
	if _, err := Check(f.cur, f.dir, f.byManager(t, m, f.next(), nil, nil)); err != nil {
		t.Fatalf("a manager's record that keeps the folder: %v", err)
	}

	// The owner moved the item to the top level: the tree says top level and
	// the record names folder F.
	f.cur.Parent = ""
	_, err := Check(f.cur, f.dir, f.byManager(t, m, f.next(), nil, nil))
	refused(t, err, 409, RulePlacement, "is not the folder the item sits in")
	b := f.next()
	b.Folder = ""
	_, err = Check(f.cur, f.dir, f.byManager(t, m, b, nil, nil))
	refused(t, err, 400, RuleManagerChange, "changes the folder")
	if !strings.Contains(err.Error(), "only the owner moves an item") {
		t.Errorf("message %q", err)
	}
	b = f.next()
	b.Folder = ""
	if _, err := Check(f.cur, f.dir, f.change(t, b, nil, nil)); err != nil {
		t.Fatalf("the owner names the new folder: %v", err)
	}
}

// A folder is created with its first record, so a folder above an item with
// none is an error, not a folder to skip.
func TestLoadRefusesAnAncestorWithoutARecord(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "cairn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	o := account(t, s, "o@x.y")
	if _, err := s.CreateOwnedItem(folderF, o.ID, store.KindFolder, "", nil); err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateOwnedItem(artID, o.ID, store.KindArtifact, folderF, func(tx *store.ArtifactTx) error {
		_, err := Load(tx, TxDirectory(tx))
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "has no record") {
		t.Fatalf("Load with a folder that has no record: %v", err)
	}
}
