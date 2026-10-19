package membership

import (
	"testing"

	"github.com/aloisdeniel/cairn/internal/store"
)

const viewerMsg = "is a viewer account and can only be a viewer"

// TestViewerAccountIsNotANewEditor checks a record that lists a viewer
// account as editor is refused with 400 under RuleViewerAccount, whether the
// account is new to the list, was a viewer on it, or the record is the first.
func TestViewerAccountIsNotANewEditor(t *testing.T) {
	t.Run("new member", func(t *testing.T) {
		f := newFixture(t)
		f.c.Role = store.RoleViewer
		b := f.next()
		b.Members = append(b.Members, member(f.c, "editor"))
		_, err := Check(f.cur, f.dir, f.change(t, b, wrapsFor(f.c, 1, 2), nil))
		refused(t, err, 400, RuleViewerAccount, "member u-c "+viewerMsg)
	})
	t.Run("a listed viewer promoted to editor", func(t *testing.T) {
		f := newFixture(t)
		f.b.Role = store.RoleViewer
		b := f.next()
		b.Members[1].Role = "editor"
		_, err := Check(f.cur, f.dir, f.change(t, b, nil, nil))
		refused(t, err, 400, RuleViewerAccount, "member u-b "+viewerMsg)
	})
	t.Run("first record", func(t *testing.T) {
		f := newFixture(t)
		f.creation()
		f.a.Role = store.RoleViewer
		b, w, e := f.first()
		_, err := Check(f.cur, f.dir, f.change(t, b, w, e))
		refused(t, err, 400, RuleViewerAccount, "member u-a "+viewerMsg)
	})
}

// TestViewerAccountMayBeAViewer checks the rule is only about the editor
// role: a viewer account listed as viewer, and a member or administrator
// listed as editor, pass.
func TestViewerAccountMayBeAViewer(t *testing.T) {
	f := newFixture(t)
	f.c.Role = store.RoleViewer
	b := f.next()
	b.Members = append(b.Members, member(f.c, "viewer"))
	if _, err := Check(f.cur, f.dir, f.change(t, b, wrapsFor(f.c, 1, 2), nil)); err != nil {
		t.Fatalf("a viewer account as viewer: %v", err)
	}
	for _, role := range []string{store.RoleMember, store.RoleAdmin} {
		f := newFixture(t)
		f.c.Role = role
		b := f.next()
		b.Members = append(b.Members, member(f.c, "editor"))
		if _, err := Check(f.cur, f.dir, f.change(t, b, wrapsFor(f.c, 1, 2), nil)); err != nil {
			t.Fatalf("a %s as editor: %v", role, err)
		}
	}
}

// TestDemotedEditorIsLeftAsIs checks an editor the previous record lists
// stays editor after the account becomes a viewer account, through a record
// that changes nothing, and through a next-epoch record; and that once
// an owner lists them as viewer they cannot be made editor again.
func TestDemotedEditorIsLeftAsIs(t *testing.T) {
	f := newFixture(t)
	f.a.Role = store.RoleViewer
	b := f.next()
	if _, err := Check(f.cur, f.dir, f.change(t, b, nil, nil)); err != nil {
		t.Fatalf("a record that leaves the demoted editor alone: %v", err)
	}
	nb, w, e := f.nextEpoch()
	if _, err := Check(f.cur, f.dir, f.change(t, nb, w, e)); err != nil {
		t.Fatalf("a next-epoch record that keeps the demoted editor: %v", err)
	}

	// The owner lists them as viewer; the next record cannot restore editor.
	down := f.next()
	down.Members[0].Role = "viewer"
	f.setLatest(down)
	up := f.next()
	up.Members[0].Role = "editor"
	_, err := Check(f.cur, f.dir, f.change(t, up, nil, nil))
	refused(t, err, 400, RuleViewerAccount, "member u-a "+viewerMsg)
}

// TestDirectoryFillsRole checks the store-backed directory reports the
// account's server role.
func TestDirectoryFillsRole(t *testing.T) {
	s, err := store.Open(t.TempDir() + "/cairn.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	o := account(t, s, "o@x.y")
	v := account(t, s, "v@x.y")
	if err := s.SetUserRole(v.ID, store.RoleViewer); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	_, err = s.CreateOwnedArtifact(artID, o.ID, func(tx *store.ArtifactTx) error {
		for _, u := range []*tUser{o, v} {
			d, err := TxDirectory(tx).User(u.ID)
			if err != nil {
				return err
			}
			got[u.ID] = d.Role
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got[o.ID] != store.RoleMember || got[v.ID] != store.RoleViewer {
		t.Fatalf("roles %v", got)
	}
}
