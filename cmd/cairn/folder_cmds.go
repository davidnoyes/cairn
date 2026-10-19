package main

import (
	"bufio"
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
	printTree(nodes, "")
	return nil
}

// printTree prints nodes and what is inside them, indented by depth.
func printTree(nodes []*client.TreeNode, indent string) {
	for _, n := range nodes {
		title := n.Title()
		if n.Kind == "folder" {
			title += "/"
		}
		fmt.Printf("%s%s  %s\n", indent, title, n.ID)
		printTree(n.Children, indent+"  ")
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
		return printJSON(map[string]any{
			"folder":  f.ID,
			"deleted": map[string]int{"folders": counts.Folders, "artifacts": counts.Artifacts},
		})
	}
	fmt.Printf("deleted folder %s (%s): %s and %s\n", f.Title(), f.ID,
		plural(counts.Folders, "folder", "folders"), plural(counts.Artifacts, "artifact", "artifacts"))
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
	if *jsonOut {
		return printJSON(moved)
	}
	if parent == "" {
		fmt.Printf("moved %s (%s) to the top level\n", item.Title(), item.ID)
		return nil
	}
	fmt.Printf("moved %s (%s) into %s\n", item.Title(), item.ID, *to)
	return nil
}
