package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
)

// printed runs a command and returns what it wrote to stdout.
func printed(t *testing.T, run func([]string) error, args ...string) string {
	t.Helper()
	done := captureStdout(t)
	err := run(args)
	out := done()
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out
}

func TestFolderCreateCommand(t *testing.T) {
	c := loggedIn(t)
	f := runJSON[client.Artifact](t, runFolder, "create", "Work", "--json")
	if f.Kind != "folder" || f.Name != "Work" || f.ParentID != "" {
		t.Fatalf("created %+v", f)
	}
	checkOwnedChain(t, c, f.ID)

	inner := runJSON[client.Artifact](t, runFolder, "create", "Plans", "--in", "Work", "--json")
	if inner.Kind != "folder" || inner.ParentID != f.ID {
		t.Errorf("--in by name: %+v", inner)
	}
	again := runJSON[client.Artifact](t, runFolder, "create", "Q3", "--in", inner.ID, "--json")
	if again.ParentID != inner.ID {
		t.Errorf("--in by ID: %+v", again)
	}
	if out := printed(t, runFolder, "create", "Plain"); !strings.Contains(out, "created folder Plain (") {
		t.Errorf("text output: %q", out)
	}
	if err := runFolder([]string{"create"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Errorf("no name: %v", err)
	}
	if err := runFolder([]string{"create", "X", "--in", "nowhere"}); err == nil {
		t.Errorf("--in a folder that does not exist: no error")
	}
	art := runJSON[client.Artifact](t, runArtifact, "create", "an-artifact", "--json")
	if err := runFolder([]string{"create", "X", "--in", art.ID}); err == nil || !strings.Contains(err.Error(), "not a folder") {
		t.Errorf("--in an artifact: %v", err)
	}
	if err := runFolder([]string{"bogus"}); err == nil {
		t.Errorf("an unknown subcommand: no error")
	}
}

func TestArtifactCreateAndPushIntoAFolder(t *testing.T) {
	c := loggedIn(t)
	f := runJSON[client.Artifact](t, runFolder, "create", "Work", "--json")

	a := runJSON[client.Artifact](t, runArtifact, "create", "notes", "--in", "Work", "--json")
	if a.Kind != "artifact" || a.ParentID != f.ID {
		t.Fatalf("artifact create --in: %+v", a)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<p>hi</p>"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := runJSON[struct {
		Artifact client.Artifact `json:"artifact"`
	}](t, runPush, dir, "--artifact", "fresh", "--create", "--in", "Work", "--json")
	if out.Artifact.ParentID != f.ID || out.Artifact.Kind != "artifact" {
		t.Errorf("push --create --in: %+v", out.Artifact)
	}
	// A second run with the same flags finds the artifact and pushes to it.
	again := runJSON[struct {
		Artifact client.Artifact `json:"artifact"`
	}](t, runPush, dir, "--artifact", "fresh", "--create", "--in", "Work", "--json")
	if again.Artifact.ID != out.Artifact.ID {
		t.Errorf("a repeat push made a second artifact: %s and %s", again.Artifact.ID, out.Artifact.ID)
	}
	got, err := c.GetArtifact(out.Artifact.ID)
	if err != nil || got.ParentID != f.ID {
		t.Errorf("stored: %+v, %v", got, err)
	}

	if err := runPush([]string{dir, "--artifact", "x", "--in", "Work"}); err == nil || !strings.Contains(err.Error(), "--in needs --create") {
		t.Errorf("--in without --create: %v", err)
	}
	if err := runPush([]string{dir, "--artifact", "Work"}); err == nil || !strings.Contains(err.Error(), "is a folder") {
		t.Errorf("push to a folder: %v", err)
	}
}

func TestArtifactListShowsFolderPathsAndJSONKindAndParent(t *testing.T) {
	loggedIn(t)
	f := runJSON[client.Artifact](t, runFolder, "create", "Work", "--json")
	g := runJSON[client.Artifact](t, runFolder, "create", "Plans", "--in", "Work", "--json")
	a := runJSON[client.Artifact](t, runArtifact, "create", "q3", "--in", "Plans", "--json")
	runJSON[client.Artifact](t, runArtifact, "create", "loose", "--json")

	text := printed(t, runArtifact, "list")
	for _, want := range []string{
		a.ID + "  Work/Plans/q3 ",
		g.ID + "  Work/Plans/ ",
		f.ID + "  Work/ ",
		" folder ",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("list output lacks %q:\n%s", want, text)
		}
	}
	var loose string
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "loose") {
			loose = line
		}
	}
	if strings.Contains(loose, "/") {
		t.Errorf("a top-level artifact shows a path: %q", loose)
	}

	list := runJSON[[]client.Artifact](t, runArtifact, "list", "--json")
	byID := map[string]client.Artifact{}
	for _, x := range list {
		byID[x.ID] = x
	}
	if x := byID[f.ID]; x.Kind != "folder" || x.ParentID != "" {
		t.Errorf("folder in JSON: %+v", x)
	}
	if x := byID[g.ID]; x.Kind != "folder" || x.ParentID != f.ID {
		t.Errorf("nested folder in JSON: %+v", x)
	}
	if x := byID[a.ID]; x.Kind != "artifact" || x.ParentID != g.ID {
		t.Errorf("artifact in JSON: %+v", x)
	}
	raw := printed(t, runArtifact, "list", "--json")
	if !strings.Contains(raw, `"kind": "folder"`) || !strings.Contains(raw, `"parent": "`+f.ID+`"`) {
		t.Errorf("JSON lacks kind or parent keys:\n%s", raw)
	}
}

func TestArtifactShowAFolder(t *testing.T) {
	loggedIn(t)
	runJSON[client.Artifact](t, runFolder, "create", "Work", "--json")
	out := printed(t, runArtifact, "show", "Work")
	if !strings.Contains(out, "folder") || strings.Contains(out, "versions (") {
		t.Errorf("show of a folder: %q", out)
	}
	j := runJSON[struct {
		Artifact client.Artifact  `json:"artifact"`
		Versions []client.Version `json:"versions"`
	}](t, runArtifact, "show", "Work", "--json")
	if j.Artifact.Kind != "folder" || len(j.Versions) != 0 {
		t.Errorf("show --json of a folder: %+v", j)
	}
	if raw := printed(t, runArtifact, "show", "Work", "--json"); !strings.Contains(raw, `"versions": []`) {
		t.Errorf("versions is not an empty list: %s", raw)
	}
}

func TestArtifactUpdateRenamesAFolder(t *testing.T) {
	loggedIn(t)
	runJSON[client.Artifact](t, runFolder, "create", "Work", "--json")
	got := runJSON[client.Artifact](t, runArtifact, "update", "Work", "--name", "Office", "--json")
	if got.Name != "Office" || got.Kind != "folder" {
		t.Errorf("renamed: %+v", got)
	}
}

func TestFolderListCommand(t *testing.T) {
	loggedIn(t)
	f := runJSON[client.Artifact](t, runFolder, "create", "Work", "--json")
	runJSON[client.Artifact](t, runFolder, "create", "Plans", "--in", "Work", "--json")
	runJSON[client.Artifact](t, runArtifact, "create", "q3", "--in", "Plans", "--json")
	runJSON[client.Artifact](t, runArtifact, "create", "loose", "--json")

	out := printed(t, runFolder, "list")
	want := []string{"Work/", "  Plans/", "    q3", "loose"}
	last := -1
	for _, w := range want {
		i := strings.Index(out, "\n"+w)
		if i == -1 && !strings.HasPrefix(out, w) {
			t.Fatalf("tree lacks %q:\n%s", w, out)
		}
		if i != -1 && i < last {
			t.Errorf("%q is out of order:\n%s", w, out)
		}
		last = i
	}
	if sub := printed(t, runFolder, "list", "Work"); !strings.HasPrefix(sub, "Plans/") || strings.Contains(sub, "loose") {
		t.Errorf("subtree:\n%s", sub)
	}

	tree := runJSON[[]client.TreeNode](t, runFolder, "list", "--json")
	if len(tree) != 2 || tree[0].ID != f.ID || tree[0].Kind != "folder" || len(tree[0].Children) != 1 ||
		tree[0].Children[0].Name != "Plans" || len(tree[0].Children[0].Children) != 1 || tree[1].Name != "loose" {
		t.Errorf("JSON tree: %+v", tree)
	}
	if raw := printed(t, runFolder, "list", "--json"); !strings.Contains(raw, `"children": []`) {
		t.Errorf("a leaf's children is not an empty list:\n%s", raw)
	}
	sub := runJSON[[]client.TreeNode](t, runFolder, "list", "Work", "--json")
	if len(sub) != 1 || sub[0].Name != "Plans" {
		t.Errorf("JSON subtree: %+v", sub)
	}
	if err := runFolder([]string{"list", "loose"}); err == nil {
		t.Errorf("listing an artifact: no error")
	}
}

func TestMoveCommand(t *testing.T) {
	c := loggedIn(t)
	f := runJSON[client.Artifact](t, runFolder, "create", "Work", "--json")
	a := runJSON[client.Artifact](t, runArtifact, "create", "notes", "--json")

	moved := runJSON[client.Artifact](t, runMove, "notes", "--to", "Work", "--json")
	if moved.ID != a.ID || moved.ParentID != f.ID || moved.Name != "notes" || moved.Kind != "artifact" {
		t.Errorf("move --to: %+v", moved)
	}
	if got, _ := c.GetArtifact(a.ID); got.ParentID != f.ID {
		t.Errorf("stored parent: %q", got.ParentID)
	}
	top := runJSON[client.Artifact](t, runMove, a.ID, "--top", "--json")
	if top.ParentID != "" || top.Name != "notes" {
		t.Errorf("move --top: %+v", top)
	}
	if out := printed(t, runMove, "notes", "--to", f.ID); !strings.Contains(out, "moved notes") || !strings.Contains(out, "into "+f.ID) {
		t.Errorf("text output: %q", out)
	}
	if out := printed(t, runMove, "notes", "--top"); !strings.Contains(out, "to the top level") {
		t.Errorf("text output: %q", out)
	}

	for name, args := range map[string][]string{
		"neither flag":       {"notes"},
		"both flags":         {"notes", "--to", "Work", "--top"},
		"no item":            {"--to", "Work"},
		"into an artifact":   {"Work", "--to", "notes"},
		"a missing folder":   {"notes", "--to", "nowhere"},
		"a folder in itself": {"Work", "--to", "Work"},
	} {
		if err := runMove(args); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if err := runMove([]string{"notes"}); err == nil || !strings.Contains(err.Error(), "exactly one of --to and --top") {
		t.Errorf("neither flag: %v", err)
	}
}

func TestFolderDeleteCommand(t *testing.T) {
	c := loggedIn(t)
	f := runJSON[client.Artifact](t, runFolder, "create", "Work", "--json")
	runJSON[client.Artifact](t, runFolder, "create", "Plans", "--in", "Work", "--json")
	runJSON[client.Artifact](t, runArtifact, "create", "q3", "--in", "Plans", "--json")
	runJSON[client.Artifact](t, runArtifact, "create", "a", "--in", "Work", "--json")
	keep := runJSON[client.Artifact](t, runArtifact, "create", "keep", "--json")

	// With no terminal and no --yes it refuses, and deletes nothing.
	old := stdinIsTerminal
	t.Cleanup(func() { stdinIsTerminal = old })
	stdinIsTerminal = func() bool { return false }
	withStdin(t, "y\n")
	if err := runFolder([]string{"delete", "Work"}); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("no --yes, no terminal: %v", err)
	}
	if _, err := c.GetArtifact(f.ID); err != nil {
		t.Fatalf("the folder was deleted: %v", err)
	}

	// At a terminal it asks, and anything but yes is a no.
	stdinIsTerminal = func() bool { return true }
	withStdin(t, "n\n")
	if err := runFolder([]string{"delete", "Work"}); err == nil || !strings.Contains(err.Error(), "not deleted") {
		t.Errorf("answered no: %v", err)
	}
	if _, err := c.GetArtifact(f.ID); err != nil {
		t.Fatalf("the folder was deleted after a no: %v", err)
	}
	withStdin(t, "yes\n")
	out := printed(t, runFolder, "delete", "Work")
	if !strings.Contains(out, "2 folders and 2 artifacts") {
		t.Errorf("text output: %q", out)
	}
	left, _ := c.ListArtifacts()
	if len(left) != 1 || left[0].ID != keep.ID {
		t.Errorf("left: %+v", left)
	}
}

func TestFolderDeleteYesAndJSON(t *testing.T) {
	c := loggedIn(t)
	f := runJSON[client.Artifact](t, runFolder, "create", "Work", "--json")
	runJSON[client.Artifact](t, runFolder, "create", "Inner", "--in", "Work", "--json")
	runJSON[client.Artifact](t, runArtifact, "create", "a", "--in", "Work", "--json")
	got := runJSON[struct {
		Folder  string `json:"folder"`
		Deleted struct {
			Folders   int `json:"folders"`
			Artifacts int `json:"artifacts"`
		} `json:"deleted"`
	}](t, runFolder, "delete", "Work", "--yes", "--json")
	if got.Folder != f.ID || got.Deleted.Folders != 2 || got.Deleted.Artifacts != 1 {
		t.Errorf("JSON: %+v", got)
	}
	if left, _ := c.ListArtifacts(); len(left) != 0 {
		t.Errorf("left: %+v", left)
	}
	if err := runFolder([]string{"delete", "Work", "--yes"}); err == nil {
		t.Errorf("deleting a folder that is gone: no error")
	}
	if err := runFolder([]string{"delete"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Errorf("no folder: %v", err)
	}
}

func TestFolderDeleteRefusesAnArtifact(t *testing.T) {
	c := loggedIn(t)
	a := runJSON[client.Artifact](t, runArtifact, "create", "notes", "--json")
	if err := runFolder([]string{"delete", "notes", "--yes"}); err == nil || !strings.Contains(err.Error(), "with id or name") {
		t.Errorf("delete of an artifact by name: %v", err)
	}
	if err := runFolder([]string{"delete", a.ID, "--yes"}); err == nil || !strings.Contains(err.Error(), "not a folder") {
		t.Errorf("delete of an artifact by ID: %v", err)
	}
	if _, err := c.GetArtifact(a.ID); err != nil {
		t.Errorf("the artifact was deleted: %v", err)
	}
}
