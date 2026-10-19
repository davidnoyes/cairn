package store

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

const (
	folderA   = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	itemC     = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	missingID = "99999999-9999-4999-8999-999999999999"
)

func TestFolderKindAndParentRoundTrip(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "o@x.y")
	f, err := s.CreateOwnedItem(folderA, u.ID, KindFolder, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != KindFolder || f.ParentID != "" {
		t.Fatalf("folder: %+v", f)
	}
	c, err := s.CreateOwnedItem(itemC, u.ID, KindArtifact, folderA, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != KindArtifact || c.ParentID != folderA {
		t.Fatalf("item: %+v", c)
	}
	got, err := s.ArtifactByID(itemC)
	if err != nil || got.ParentID != folderA || got.Kind != KindArtifact {
		t.Fatalf("ArtifactByID: %+v, %v", got, err)
	}
	all, err := s.ListArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	var listed *Artifact
	for _, a := range all {
		if a.ID == itemC {
			listed = a
		}
	}
	if listed == nil || listed.ParentID != folderA {
		t.Fatalf("ListArtifacts: %+v", listed)
	}
	plain := ownedArtifact(t, s, u)
	if plain.Kind != KindArtifact || plain.ParentID != "" {
		t.Fatalf("default artifact: %+v", plain)
	}
}

func TestDeletingAFolderRowSetsParentNull(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "o@x.y")
	if _, err := s.CreateOwnedItem(folderA, u.ID, KindFolder, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOwnedItem(itemC, u.ID, KindArtifact, folderA, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteArtifact(folderA); err != nil {
		t.Fatal(err)
	}
	got, err := s.ArtifactByID(itemC)
	if err != nil || got.ParentID != "" {
		t.Fatalf("after folder delete: %+v, %v", got, err)
	}
}

func TestKindCheckRejectsUnknownKind(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "o@x.y")
	if _, err := s.CreateOwnedItem(folderA, u.ID, "drawer", "", nil); err == nil {
		t.Fatal("an unknown kind was stored")
	}
}

func TestCreateItemParentRules(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "o@x.y")
	other := testAccount(t, s, "p@x.y")
	if _, err := s.CreateOwnedItem(folderA, u.ID, KindFolder, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOwnedItem(itemC, u.ID, KindArtifact, "", nil); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, owner, parent string }{
		{"parent is an artifact", u.ID, itemC},
		{"parent missing", u.ID, missingID},
		{"parent owned by another", other.ID, folderA},
	}
	for i, c := range cases {
		id := strings.Repeat(string(rune('d'+i)), 8) + "-dddd-4ddd-8ddd-dddddddddddd"
		if _, err := s.CreateOwnedItem(id, c.owner, KindArtifact, c.parent, nil); !errors.Is(err, ErrNotFolder) {
			t.Errorf("%s: got %v, want ErrNotFolder", c.name, err)
		}
		if _, err := s.ArtifactByID(id); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: a refused create left a row: %v", c.name, err)
		}
	}
}

// chain makes n nested folders owned by owner and returns their IDs, the
// first at the top level.
func chain(t *testing.T, s *Store, owner string, n int) []string {
	t.Helper()
	var ids []string
	parent := ""
	for i := 0; i < n; i++ {
		id := strings.Repeat(string(rune('a'+i)), 8) + "-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		if _, err := s.CreateOwnedItem(id, owner, KindFolder, parent, nil); err != nil {
			t.Fatalf("folder %d: %v", i+1, err)
		}
		ids = append(ids, id)
		parent = id
	}
	return ids
}

func TestFolderDepthLimit(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "o@x.y")
	ids := chain(t, s, u.ID, MaxFolderDepth)
	deepest := ids[len(ids)-1]
	if _, err := s.CreateOwnedItem(itemC, u.ID, KindArtifact, deepest, nil); err != nil {
		t.Fatalf("an artifact in the 16th folder: %v", err)
	}
	extra := "ffffffff-ffff-4fff-8fff-ffffffffffff"
	if _, err := s.CreateOwnedItem(extra, u.ID, KindFolder, deepest, nil); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("a 17th folder: %v", err)
	}
}

func TestMoveItemRules(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "o@x.y")
	x := chain(t, s, u.ID, 10)
	if _, err := s.CreateOwnedItem(itemC, u.ID, KindArtifact, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.MoveItem(itemC, x[9]); err != nil {
		t.Fatalf("move artifact: %v", err)
	}
	if got, _ := s.ArtifactByID(itemC); got.ParentID != x[9] {
		t.Fatalf("parent after move: %q", got.ParentID)
	}
	if err := s.MoveItem(itemC, ""); err != nil {
		t.Fatalf("move to top: %v", err)
	}
	if got, _ := s.ArtifactByID(itemC); got.ParentID != "" {
		t.Fatalf("parent after move to top: %q", got.ParentID)
	}
	if err := s.MoveItem(x[0], x[0]); !errors.Is(err, ErrCycle) {
		t.Fatalf("into itself: %v", err)
	}
	if err := s.MoveItem(x[0], x[5]); !errors.Is(err, ErrCycle) {
		t.Fatalf("into a descendant: %v", err)
	}
	// A subtree of 7 folders under the 10th makes 17; under the 9th, 16.
	var sub []string
	parent := ""
	for i := 0; i < 7; i++ {
		id := strings.Repeat(string(rune('0'+i)), 8) + "-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		if _, err := s.CreateOwnedItem(id, u.ID, KindFolder, parent, nil); err != nil {
			t.Fatal(err)
		}
		sub = append(sub, id)
		parent = id
	}
	if err := s.MoveItem(sub[0], x[9]); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("subtree past the limit: %v", err)
	}
	if err := s.MoveItem(sub[0], x[8]); err != nil {
		t.Fatalf("subtree to exactly 16: %v", err)
	}
	if err := s.MoveItem(missingID, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing item: %v", err)
	}
	if err := s.MoveItem(itemC, itemC); !errors.Is(err, ErrNotFolder) {
		t.Fatalf("into a non-folder: %v", err)
	}
}

func TestDeleteFolderIfEmpty(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "o@x.y")
	if _, err := s.CreateOwnedItem(folderA, u.ID, KindFolder, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOwnedItem(itemC, u.ID, KindArtifact, folderA, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteFolderIfEmpty(folderA); !errors.Is(err, ErrFolderNotEmpty) {
		t.Fatalf("a folder with an item: %v, want ErrFolderNotEmpty", err)
	}
	if _, err := s.ArtifactByID(folderA); err != nil {
		t.Fatalf("the refused folder was deleted: %v", err)
	}
	if err := s.DeleteArtifact(itemC); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteFolderIfEmpty(folderA); err != nil {
		t.Fatalf("an empty folder: %v", err)
	}
	if _, err := s.ArtifactByID(folderA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the folder after delete: %v, want ErrNotFound", err)
	}
	if err := s.DeleteFolderIfEmpty(folderA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a missing folder: %v, want ErrNotFound", err)
	}
}

// A create racing the delete either lands before it (the delete is refused)
// or is refused itself; it is never left pointing at a deleted folder.
func TestDeleteFolderIfEmptyRacesCreate(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "o@x.y")
	for i := 0; i < 20; i++ {
		folder, item := uuid.NewString(), uuid.NewString()
		if _, err := s.CreateOwnedItem(folder, u.ID, KindFolder, "", nil); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var delErr, addErr error
		wg.Add(2)
		go func() { defer wg.Done(); delErr = s.DeleteFolderIfEmpty(folder) }()
		go func() {
			defer wg.Done()
			_, addErr = s.CreateOwnedItem(item, u.ID, KindArtifact, folder, nil)
		}()
		wg.Wait()
		if delErr == nil && addErr == nil {
			t.Fatalf("round %d: the folder was deleted and the item was created in it", i)
		}
		if delErr != nil && !errors.Is(delErr, ErrFolderNotEmpty) {
			t.Fatalf("round %d: delete: %v", i, delErr)
		}
		if got, err := s.ArtifactByID(item); err == nil && got.ParentID != folder {
			t.Fatalf("round %d: the item sits in %q, want %q", i, got.ParentID, folder)
		}
	}
}

func TestSetOwnerMovesTheItemToTheTopLevel(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	n := testAccount(t, s, "n@x.y")
	if _, err := s.CreateOwnedItem(folderA, o.ID, KindFolder, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOwnedItem(itemC, o.ID, KindArtifact, folderA, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.WithArtifact(itemC, func(tx *ArtifactTx) error { return tx.SetOwner(n.ID) }); err != nil {
		t.Fatal(err)
	}
	got, err := s.ArtifactByID(itemC)
	if err != nil || got.OwnerID != n.ID || got.ParentID != "" {
		t.Fatalf("after SetOwner: owner %q parent %q (%v), want owner %q and no parent", got.OwnerID, got.ParentID, err, n.ID)
	}
}
