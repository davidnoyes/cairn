// Folders. A folder is an artifact with no content, so creating one, naming
// it, and resolving it by name use the artifact calls; this file adds the
// options that make an item a folder or put it in one, moving, the tree, and
// deleting a folder with everything in it. See "Folders" in design/e2e-api.md.
package client

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/aloisdeniel/cairn/internal/store"
)

// createOptions is what CreateOption sets.
type createOptions struct {
	folder bool
	parent string
}

// CreateOption changes what CreateArtifact creates.
type CreateOption func(*createOptions)

// AsFolder creates a folder rather than an artifact.
func AsFolder() CreateOption { return func(o *createOptions) { o.folder = true } }

// InFolder puts the new item in the folder with this ID.
func InFolder(id string) CreateOption { return func(o *createOptions) { o.parent = id } }

// CreateFolder creates a folder named name in the folder parent, or at the
// top level when parent is empty.
func (c *Client) CreateFolder(name, parent string) (*Artifact, error) {
	return c.CreateArtifact(name, "", AsFolder(), InFolder(parent))
}

// Move puts the item in the folder parent, or at the top level when parent is
// empty, and returns its view with no name opened. The item's latest record
// still names its old folder, so it is pending, and the server refuses any
// other record for it, until FanOut with a Placing writes one that names the
// new folder.
func (c *Client) Move(id, parent string) (*Artifact, error) {
	var to any
	if parent != "" {
		to = parent
	}
	var out artifactWire
	if err := c.doJSON("PUT", "/api/artifacts/"+id+"/parent", map[string]any{"parent": to}, &out); err != nil {
		return nil, err
	}
	return out.artifact(), nil
}

// TreeNode is an item and the items that sit in it. Stub is set for an item
// the caller cannot read yet, which has no name: it sits in a folder the
// caller reads, and its owner has yet to apply the folder's sharing to it.
type TreeNode struct {
	*Artifact
	Stub     bool        `json:"stub,omitempty"`
	Children []*TreeNode `json:"children"`
}

// Tree reads the items as a tree: the caller's own items at the top level
// when root is empty, otherwise the items inside the folder root, which must
// be a folder the caller can read. Inside a folder, every item the server
// lists is shown, whoever owns it, and one the caller cannot read yet is a
// stub with no name. Folders come first and then artifacts, each sorted by
// name, with names opened.
func (c *Client) Tree(root string) ([]*TreeNode, error) {
	all, err := c.listWithStubs()
	if err != nil {
		return nil, err
	}
	if root != "" {
		if f := byID(all, root); f == nil || f.Kind != store.KindFolder || f.Access == accessNone {
			return nil, fmt.Errorf("%w: no folder of yours has the id %s", ErrNoArtifact, root)
		}
	} else {
		// Only the caller's own items start the tree.
		all = slices.DeleteFunc(all, func(a *Artifact) bool { return a.ParentID == "" && a.Access != "owner" })
	}
	c.OpenNames(all...) // a stub has no fields; an item whose chain fails shows under its ID
	return branch(all, root), nil
}

// byID returns the artifact among as with the id, or nil.
func byID(as []*Artifact, id string) *Artifact {
	for _, a := range as {
		if a.ID == id {
			return a
		}
	}
	return nil
}

// branch builds the items of all whose parent is parent, and theirs below,
// ordered as Tree says.
func branch(all []*Artifact, parent string) []*TreeNode {
	nodes := []*TreeNode{}
	for _, a := range all {
		if a.ParentID == parent {
			nodes = append(nodes, &TreeNode{Artifact: a, Stub: a.Access == accessNone, Children: branch(all, a.ID)})
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		x, y := nodes[i], nodes[j]
		if fx, fy := x.Kind == store.KindFolder, y.Kind == store.KindFolder; fx != fy {
			return fx
		}
		return strings.ToLower(x.Title()) < strings.ToLower(y.Title())
	})
	return nodes
}

// FolderPaths maps the ID of each item in all to the names of the folders it
// sits in, joined with "/", from the top down; an item at the top level, or in
// a folder not in all, maps to "".
func FolderPaths(all []*Artifact) map[string]string {
	paths := make(map[string]string, len(all))
	for _, a := range all {
		var names []string
		for p := byID(all, a.ParentID); p != nil && len(names) < store.MaxFolderDepth; p = byID(all, p.ParentID) {
			names = append([]string{p.Title()}, names...)
		}
		paths[a.ID] = strings.Join(names, "/")
	}
	return paths
}

// FolderContents is what deleting a folder does to what is inside it. The
// caller's own items go: every artifact of theirs at any depth, and every
// folder of theirs, deepest first and the folder itself last. The walk stops
// at an item someone else owns, which Moved lists: it lands at its owner's top
// level, with everything inside it, when the folder it sits in goes. A stub
// is such an item, and has no name.
type FolderContents struct {
	Folders   []*Artifact
	Artifacts []*Artifact
	Moved     []*Artifact
}

// DeleteCounts is how many folders and artifacts a delete removed, and how
// many items of other owners it left at their owners' top levels.
type DeleteCounts struct {
	Folders   int
	Artifacts int
	Moved     int
}

// ErrNotFolderOwner means the caller tried to delete a folder someone else
// owns: only its owner does.
var ErrNotFolderOwner = errors.New("only the folder's owner deletes it")

// FolderContents lists what deleting the folder id does, with no name opened.
// The folder must be the caller's own.
func (c *Client) FolderContents(id string) (*FolderContents, error) {
	all, err := c.listWithStubs()
	if err != nil {
		return nil, err
	}
	root := byID(all, id)
	if root == nil || root.Kind != store.KindFolder || root.Access == accessNone {
		return nil, fmt.Errorf("%w: no folder has the id %s", ErrNoArtifact, id)
	}
	if root.Access != "owner" {
		return nil, fmt.Errorf("%w: %s belongs to someone else", ErrNotFolderOwner, id)
	}
	out := &FolderContents{}
	depth := map[string]int{id: 0}
	queue := []*Artifact{root}
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		for _, a := range all {
			switch {
			case a.ParentID != f.ID:
			case a.Access != "owner":
				out.Moved = append(out.Moved, a)
			case a.Kind == store.KindFolder:
				depth[a.ID] = depth[f.ID] + 1
				out.Folders = append(out.Folders, a)
				queue = append(queue, a)
			default:
				out.Artifacts = append(out.Artifacts, a)
			}
		}
	}
	sort.SliceStable(out.Folders, func(i, j int) bool { return depth[out.Folders[i].ID] > depth[out.Folders[j].ID] })
	out.Folders = append(out.Folders, root)
	return out, nil
}

// DeleteFolder deletes every artifact of the caller's in the folder id, at any
// depth, then each folder of theirs in it from the deepest up, and the folder
// itself last: the server refuses to delete a folder that still holds an item
// its owner owns, and moves the items of other owners it holds to their
// owners' top levels, which they have to place again. It calls progress, when not nil, after each deletion with how many are done
// of how many the run has. An item already gone is skipped, and the folder
// goes last, so running it again finishes a run that was interrupted. The
// counts are what this run removed, and Moved is how many items of other
// owners the folder held when it began.
func (c *Client) DeleteFolder(id string, progress func(done, total int)) (DeleteCounts, error) {
	var counts DeleteCounts
	contents, err := c.FolderContents(id)
	if err != nil {
		return counts, err
	}
	counts.Moved = len(contents.Moved)
	total := len(contents.Artifacts) + len(contents.Folders)
	done := 0
	remove := func(a *Artifact, n *int) error {
		err := c.DeleteArtifact(a.ID)
		var apiErr *APIError
		switch {
		case err == nil:
			*n++
		case !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound:
			return fmt.Errorf("deleting %s: %w", a.ID, err)
		}
		done++
		if progress != nil {
			progress(done, total)
		}
		return nil
	}
	for _, a := range contents.Artifacts {
		if err := remove(a, &counts.Artifacts); err != nil {
			return counts, err
		}
	}
	for _, f := range contents.Folders {
		if err := remove(f, &counts.Folders); err != nil {
			return counts, err
		}
	}
	return counts, nil
}
