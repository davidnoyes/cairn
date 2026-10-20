package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/aloisdeniel/cairn/internal/client"
	"golang.org/x/term"
)

// Folders. See "Commands for folders" in design/e2e-api.md.

func runFolder(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: cairn folder <create|list|delete> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return folderCreate(rest)
	case "list":
		return folderList(rest)
	case "delete":
		return folderDelete(rest)
	default:
		return fmt.Errorf("unknown folder subcommand %q", sub)
	}
}

// resolveFolder is resolveArtifact among the folders: an ID or an exact name.
func resolveFolder(c *client.Client, ref string) (*client.Artifact, error) {
	f, err := c.ResolveFolder(ref)
	if err != nil {
		return nil, explainRefusal(c, err)
	}
	return f, nil
}

func folderCreate(args []string) error {
	const usage = "cairn folder create NAME [--in FOLDER] [--json]"
	fs := flag.NewFlagSet("folder create", flag.ExitOnError)
	in := fs.String("in", "", "folder to create it in (an ID or a name); the top level when empty")
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 1, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	parent, err := parentFolder(c, *in)
	if err != nil {
		return err
	}
	f, err := c.CreateFolder(pos[0], parent)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(f)
	}
	fmt.Printf("created folder %s (%s)\n", f.Title(), f.ID)
	return nil
}

// parentFolder resolves the --in flag to a folder's ID, or "" when it is
// empty.
func parentFolder(c *client.Client, in string) (string, error) {
	if in == "" {
		return "", nil
	}
	f, err := resolveFolder(c, in)
	if err != nil {
		return "", err
	}
	return f.ID, nil
}

func folderList(args []string) error {
	const usage = "cairn folder list [FOLDER] [--json]"
	fs := flag.NewFlagSet("folder list", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositionalRange(fs, args, 0, 1, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	root := ""
	if len(pos) == 1 {
		f, err := resolveFolder(c, pos[0])
		if err != nil {
			return err
		}
		root = f.ID
	}
	nodes, err := c.Tree(root)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(nodes)
	}
	printTree(nodes, "", ownerNames(c))
	return nil
}

// ownerNames returns a function that names the owner with the ID it is given
// by address, from the directory, or by the ID when the directory does not
// hold them or cannot be read.
func ownerNames(c *client.Client) func(id string) string {
	var dir []client.DirectoryUser
	loaded := false
	return func(id string) string {
		if !loaded {
			dir, _ = c.Directory()
			loaded = true
		}
		if u, err := client.FindUser(dir, id); err == nil {
			return u.Email
		}
		return id
	}
}

// printTree prints nodes and what is inside them, indented by depth. An item
// the caller cannot read yet has no name: it shows as not shared yet, with
// its owner, as owner names them.
func printTree(nodes []*client.TreeNode, indent string, owner func(id string) string) {
	for _, n := range nodes {
		title := n.Title()
		if n.Stub {
			title = "(not shared with you yet, owned by " + owner(n.OwnerID) + ")"
		} else if n.Kind == "folder" {
			title += "/"
		}
		fmt.Printf("%s%s  %s\n", indent, title, n.ID)
		printTree(n.Children, indent+"  ", owner)
	}
}

// stdinIsTerminal reports whether a person is there to answer a question. A
// test replaces it.
var stdinIsTerminal = func() bool { return term.IsTerminal(int(syscall.Stdin)) }

// confirmed asks question and reports whether the answer on stdin is yes.
func confirmed(question string) bool {
	fmt.Fprint(os.Stderr, question+" [y/N] ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func folderDelete(args []string) error {
	const usage = "cairn folder delete FOLDER [--yes] [--json]"
	fs := flag.NewFlagSet("folder delete", flag.ExitOnError)
	yes := fs.Bool("yes", false, "delete without asking")
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 1, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	f, err := resolveFolder(c, pos[0])
	if err != nil {
		return err
	}
	contents, err := c.FolderContents(f.ID)
	if err != nil {
		return err
	}
	// The folder is among the folders the delete removes.
	plan := fmt.Sprintf("Deleting %s (%s) removes %s, itself included, and %s.",
		f.Title(), f.ID, plural(len(contents.Folders), "folder", "folders"), plural(len(contents.Artifacts), "artifact", "artifacts"))
	fmt.Fprintln(os.Stderr, plan)
	if len(contents.Moved) > 0 {
		owner := ownerNames(c)
		fmt.Fprintf(os.Stderr, "%s someone else owns move to their owners' top levels, with everything inside them, and wait for their owners to place them again (cairn apply, or cairn move):\n",
			plural(len(contents.Moved), "item", "items"))
		for _, m := range contents.Moved {
			fmt.Fprintf(os.Stderr, "  %s  %s, owned by %s\n", m.ID, m.Kind, owner(m.OwnerID))
		}
	}
	if !*yes {
		if !stdinIsTerminal() {
			return errors.New("not deleting: there is no terminal to ask on; run it again with --yes")
		}
		if !confirmed("Delete them?") {
			return errors.New("not deleted")
		}
	}
	counts, err := c.DeleteFolder(f.ID, func(done, total int) {
		fmt.Fprintf(os.Stderr, "\r%d of %d deleted", done, total)
	})
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("%w\nrun the command again to finish the delete", err)
	}
	if *jsonOut {
		moved := []map[string]string{}
		for _, m := range contents.Moved {
			moved = append(moved, map[string]string{"id": m.ID, "kind": m.Kind, "owner": m.OwnerID})
		}
		return printJSON(map[string]any{
			"folder":  f.ID,
			"deleted": map[string]int{"folders": counts.Folders, "artifacts": counts.Artifacts},
			"moved":   moved,
		})
	}
	fmt.Printf("deleted folder %s (%s): %s and %s\n", f.Title(), f.ID,
		plural(counts.Folders, "folder", "folders"), plural(counts.Artifacts, "artifact", "artifacts"))
	if counts.Moved > 0 {
		fmt.Printf("%s of other owners moved to their owners' top levels\n", plural(counts.Moved, "item", "items"))
	}
	return nil
}

func runMove(args []string) error {
	const usage = "cairn move ITEM (--to FOLDER | --top) [--json]"
	fs := flag.NewFlagSet("move", flag.ExitOnError)
	to := fs.String("to", "", "folder to move it into (an ID or a name)")
	top := fs.Bool("top", false, "move it to the top level")
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 1, usage)
	if err != nil {
		return err
	}
	if (*to == "") == !*top {
		return fmt.Errorf("usage: %s: give exactly one of --to and --top", usage)
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	item, err := resolveArtifact(c, pos[0])
	if err != nil {
		return err
	}
	parent, err := parentFolder(c, *to)
	if err != nil {
		return err
	}
	moved, err := c.Move(item.ID, parent)
	if err != nil {
		return err
	}
	moved.Name, moved.Description = item.Name, item.Description
	return folderThen(c, item, &client.Placing{Parent: parent}, *jsonOut, func() error {
		if *jsonOut {
			return printMoved(moved)
		}
		if parent == "" {
			fmt.Printf("moved %s (%s) to the top level\n", item.Title(), item.ID)
			return nil
		}
		fmt.Printf("moved %s (%s) into %s\n", item.Title(), item.ID, *to)
		return nil
	})
}

// printMoved prints the moved item's view in JSON, with the fan-out that
// followed the move when there was one.
func printMoved(moved *client.Artifact) error {
	raw, err := json.Marshal(moved)
	if err != nil {
		return err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	if r, ok := fanOuts[moved.ID]; ok {
		out["fanOut"] = fanOutJSON(r)
	}
	return printJSON(out)
}
