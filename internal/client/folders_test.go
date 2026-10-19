package client

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/store"
)

func mustCreate(t *testing.T, c *Client, name string, opts ...CreateOption) *Artifact {
	t.Helper()
	a, err := c.CreateArtifact(name, "", opts...)
	if err != nil {
		t.Fatalf("CreateArtifact(%s): %v", name, err)
	}
	return a
}

func TestCreateFolderAndItemInIt(t *testing.T) {
	c := authedClient(t)
	f, err := c.CreateFolder("Work", "")
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != store.KindFolder || f.Name != "Work" || f.ParentID != "" {
		t.Fatalf("folder: %+v", f)
	}
	inner, err := c.CreateFolder("Plans", f.ID)
	if err != nil {
		t.Fatal(err)
	}
	item := mustCreate(t, c, "q3", InFolder(inner.ID))
	if item.Kind != store.KindArtifact || item.ParentID != inner.ID || inner.ParentID != f.ID {
		t.Fatalf("item %+v in folder %+v", item, inner)
	}
	got, err := c.GetArtifact(item.ID)
	if err != nil || got.ParentID != inner.ID || got.Name != "q3" {
		t.Fatalf("GetArtifact = %+v, %v", got, err)
	}
	// A plain create is still an artifact at the top level.
	if plain := mustCreate(t, c, "plain"); plain.Kind != store.KindArtifact || plain.ParentID != "" {
		t.Fatalf("plain: %+v", plain)
	}
	// The server's refusals reach the caller.
	if _, err := c.CreateArtifact("x", "", InFolder(item.ID)); err == nil || !strings.Contains(err.Error(), "not a folder") {
		t.Errorf("a parent that is an artifact: %v", err)
	}
}

func TestMoveAndMoveToTop(t *testing.T) {
	c := authedClient(t)
	f, _ := c.CreateFolder("Work", "")
	item := mustCreate(t, c, "doc")
	moved, err := c.Move(item.ID, f.ID)
	if err != nil || moved.ParentID != f.ID {
		t.Fatalf("Move = %+v, %v", moved, err)
	}
	if moved, err = c.Move(item.ID, ""); err != nil || moved.ParentID != "" {
		t.Fatalf("Move to top = %+v, %v", moved, err)
	}
	if _, err := c.Move(f.ID, f.ID); err == nil || !strings.Contains(err.Error(), "itself") {
		t.Errorf("a folder into itself: %v", err)
	}
}

func names(nodes []*TreeNode) []string {
	var out []string
	for _, n := range nodes {
		out = append(out, n.Title())
	}
	return out
}

func TestTreeOrdersFoldersFirstThenByName(t *testing.T) {
	c := authedClient(t)
	zeta, _ := c.CreateFolder("zeta", "")
	alpha, _ := c.CreateFolder("Alpha", "")
	mustCreate(t, c, "Beta")
	mustCreate(t, c, "aardvark")
	mustCreate(t, c, "inside-alpha", InFolder(alpha.ID))
	sub, _ := c.CreateFolder("sub", alpha.ID)
	mustCreate(t, c, "deep", InFolder(sub.ID))
	_ = zeta

	top, err := c.Tree("")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names(top), ","); got != "Alpha,zeta,aardvark,Beta" {
		t.Errorf("top level: %s", got)
	}
	if got := strings.Join(names(top[0].Children), ","); got != "sub,inside-alpha" {
		t.Errorf("inside Alpha: %s", got)
	}
	if got := names(top[0].Children[0].Children); len(got) != 1 || got[0] != "deep" {
		t.Errorf("inside sub: %v", got)
	}
	below, err := c.Tree(alpha.ID)
	if err != nil || strings.Join(names(below), ",") != "sub,inside-alpha" {
		t.Errorf("Tree(Alpha) = %v, %v", names(below), err)
	}
	if _, err := c.Tree(top[2].ID); err == nil {
		t.Errorf("Tree of an artifact: no error")
	}
}

func TestFolderPaths(t *testing.T) {
	c := authedClient(t)
	f, _ := c.CreateFolder("Work", "")
	g, _ := c.CreateFolder("Plans", f.ID)
	item := mustCreate(t, c, "q3", InFolder(g.ID))
	top := mustCreate(t, c, "top")
	all, err := c.ListArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	p := FolderPaths(all)
	if p[item.ID] != "Work/Plans" || p[g.ID] != "Work" || p[f.ID] != "" || p[top.ID] != "" {
		t.Errorf("paths: %v", p)
	}
}

func TestResolveFolderByName(t *testing.T) {
	c := authedClient(t)
	f, _ := c.CreateFolder("Work", "")
	for _, ref := range []string{"Work", f.ID} {
		a, err := c.ResolveArtifact(ref)
		if err != nil || a.ID != f.ID || a.Kind != store.KindFolder {
			t.Errorf("ResolveArtifact(%s) = %+v, %v", ref, a, err)
		}
	}
	// An artifact and a folder that share a name: the folder resolver picks
	// the folder, the general one is ambiguous.
	art := mustCreate(t, c, "Work")
	if _, err := c.ResolveArtifact("Work"); err == nil || !strings.Contains(err.Error(), "2 artifacts match") {
		t.Errorf("ResolveArtifact of a shared name: %v", err)
	}
	if a, err := c.ResolveFolder("Work"); err != nil || a.ID != f.ID {
		t.Errorf("ResolveFolder(Work) = %+v, %v", a, err)
	}
	if _, err := c.ResolveFolder(art.ID); err == nil || !strings.Contains(err.Error(), "not a folder") {
		t.Errorf("ResolveFolder of an artifact's ID: %v", err)
	}
	if _, err := c.ResolveFolder("nothing"); !errors.Is(err, ErrNoArtifact) {
		t.Errorf("ResolveFolder(nothing) = %v", err)
	}
}

// deleteWorld is a folder tree: root holds a, mid (holding b and leaf, which
// holds c), and the artifact outside stays.
func deleteWorld(t *testing.T, c *Client) (root *Artifact, outside *Artifact) {
	t.Helper()
	root, _ = c.CreateFolder("root", "")
	mid, _ := c.CreateFolder("mid", root.ID)
	leaf, _ := c.CreateFolder("leaf", mid.ID)
	mustCreate(t, c, "a", InFolder(root.ID))
	mustCreate(t, c, "b", InFolder(mid.ID))
	mustCreate(t, c, "c", InFolder(leaf.ID))
	return root, mustCreate(t, c, "outside")
}

func TestFolderContentsOrder(t *testing.T) {
	c := authedClient(t)
	root, _ := deleteWorld(t, c)
	fc, err := c.FolderContents(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(fc.Artifacts) != 3 || len(fc.Folders) != 3 {
		t.Fatalf("contents: %d artifacts, %d folders", len(fc.Artifacts), len(fc.Folders))
	}
	// Deepest first, the folder itself last.
	c.OpenNames(fc.Folders...)
	if got := names2(fc.Folders); got != "leaf,mid,root" {
		t.Errorf("folder order: %s", got)
	}
	if _, err := c.FolderContents(fc.Artifacts[0].ID); !errors.Is(err, ErrNoArtifact) {
		t.Errorf("contents of an artifact: %v", err)
	}
}

func names2(as []*Artifact) string {
	var out []string
	for _, a := range as {
		out = append(out, a.Title())
	}
	return strings.Join(out, ",")
}

func TestDeleteFolderRemovesTheSubtreeAndReportsProgress(t *testing.T) {
	c := authedClient(t)
	root, outside := deleteWorld(t, c)
	var ticks [][2]int
	counts, err := c.DeleteFolder(root.ID, func(done, total int) { ticks = append(ticks, [2]int{done, total}) })
	if err != nil {
		t.Fatal(err)
	}
	if counts != (DeleteCounts{Folders: 3, Artifacts: 3}) {
		t.Errorf("counts: %+v", counts)
	}
	if len(ticks) != 6 || ticks[0] != [2]int{1, 6} || ticks[5] != [2]int{6, 6} {
		t.Errorf("progress: %v", ticks)
	}
	left, err := c.ListArtifacts()
	if err != nil || len(left) != 1 || left[0].ID != outside.ID {
		t.Errorf("left after delete: %+v, %v", left, err)
	}
}

func TestDeleteFolderInterruptedThenFinished(t *testing.T) {
	c := authedClient(t)
	root, outside := deleteWorld(t, c)
	flaky := keyedFor(t, c.Host, mustAPIKeyOf(t, c))
	deletes := 0
	intercept(flaky, &tamper{before: func(req *http.Request) *http.Response {
		if req.Method == "DELETE" {
			deletes++
			if deletes == 5 {
				return replyJSON(req, 500, nil, `{"error":"boom"}`)
			}
		}
		return nil
	}})
	counts, err := flaky.DeleteFolder(root.ID, nil)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("interrupted run: %v", err)
	}
	if counts.Artifacts != 3 || counts.Folders != 1 {
		t.Errorf("first run removed %+v, want 3 artifacts and 1 folder", counts)
	}
	// The folder itself is still there, so the delete can be run again.
	if _, err := c.GetArtifact(root.ID); err != nil {
		t.Fatalf("the folder went before its contents: %v", err)
	}
	counts, err = c.DeleteFolder(root.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if counts != (DeleteCounts{Folders: 2}) {
		t.Errorf("second run removed %+v, want the 2 folders left", counts)
	}
	left, _ := c.ListArtifacts()
	if len(left) != 1 || left[0].ID != outside.ID {
		t.Errorf("left: %+v", left)
	}
}

func TestDeleteFolderSkipsAnItemAlreadyGone(t *testing.T) {
	c := authedClient(t)
	root, _ := deleteWorld(t, c)
	racing := keyedFor(t, c.Host, mustAPIKeyOf(t, c))
	first := true
	intercept(racing, &tamper{before: func(req *http.Request) *http.Response {
		// Another process deletes the item just before this run does.
		if req.Method == "DELETE" && first {
			first = false
			http.DefaultClient.Do(req.Clone(req.Context()))
		}
		return nil
	}})
	counts, err := racing.DeleteFolder(root.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Artifacts+counts.Folders != 5 {
		t.Errorf("counts: %+v, want 5 (one was already gone)", counts)
	}
}

func TestDeleteFolderRefusesAnArtifactAndAMissingFolder(t *testing.T) {
	c := authedClient(t)
	art := mustCreate(t, c, "x")
	if _, err := c.DeleteFolder(art.ID, nil); !errors.Is(err, ErrNoArtifact) {
		t.Errorf("DeleteFolder of an artifact: %v", err)
	}
	if _, err := c.GetArtifact(art.ID); err != nil {
		t.Errorf("the artifact was deleted: %v", err)
	}
}

// A tree is of the caller's own items: an artifact shared with them is not in
// it, and it does not appear to sit in a folder they cannot read.
func TestTreeLeavesOutWhatIsSharedWithYou(t *testing.T) {
	s := newSharing(t)
	f, err := s.ada.CreateFolder("Work", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.Move(s.artifact, f.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	mine, err := s.bob.CreateArtifact("bobs", "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.bob.GetArtifact(s.artifact)
	if err != nil || got.ParentID != "" {
		t.Fatalf("bob's view of the shared item: %+v, %v", got, err)
	}
	tree, err := s.bob.Tree("")
	if err != nil || len(tree) != 1 || tree[0].ID != mine.ID {
		t.Errorf("bob's tree: %v, %v", names(tree), err)
	}
	if tree, err = s.ada.Tree(""); err != nil || len(tree) != 1 || tree[0].ID != f.ID || len(tree[0].Children) != 1 {
		t.Errorf("ada's tree: %v, %v", names(tree), err)
	}
}
