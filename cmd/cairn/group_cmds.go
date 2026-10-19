package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

const groupUsage = `usage: cairn group <subcommand>
  cairn group create NAME [--member USER]... [--json]            Create a group, with you as its manager
  cairn group list [--json]                                      List every group, with your role in it
  cairn group show GROUP [--json]                                Show a group's members, with role, fingerprint, and pin state
  cairn group add GROUP USER [--manager] [--accept-new-key] [--json]  Add a member, or change a role
  cairn group remove GROUP USER [--json]                         Remove a member
  cairn group rename GROUP NAME [--json]                         Rename a group
  cairn group delete GROUP [--json]                              Delete a group (a manager, or an administrator)
GROUP is a group ID or an exact name`

func runGroup(args []string) error {
	if len(args) == 0 {
		return errors.New(groupUsage)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return groupCreate(rest)
	case "list":
		return groupList(rest)
	case "show":
		return groupShow(rest)
	case "add":
		return groupAdd(rest)
	case "remove":
		return groupRemove(rest)
	case "rename":
		return groupRename(rest)
	case "delete":
		return groupDelete(rest)
	default:
		return fmt.Errorf("unknown group subcommand %q\n%s", sub, groupUsage)
	}
}

// resolveGroup is c.ResolveGroup with a keyring refusal explained.
func resolveGroup(c *client.Client, ref string) (*client.GroupSummary, error) {
	g, err := c.ResolveGroup(ref)
	if err != nil {
		return nil, explainRefusal(c, err)
	}
	return g, nil
}

// groupMemberJSON is one member in the --json output of create and show.
type groupMemberJSON struct {
	User        string `json:"user"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	Role        string `json:"role"`
	FP          string `json:"fp"`
	State       string `json:"state"`
	WasVerified *bool  `json:"wasVerified,omitempty"`
}

// groupJSON is a verified group in the --json output of create and show.
type groupJSON struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Seq     int               `json:"seq"`
	Role    string            `json:"role"`
	Members []groupMemberJSON `json:"members"`
}

func groupViewJSON(v *client.GroupView) groupJSON {
	out := groupJSON{ID: v.ID, Name: v.Name, Seq: v.Seq, Role: v.Role, Members: []groupMemberJSON{}}
	for _, m := range v.Members {
		row := groupMemberJSON{User: m.User, Name: m.Name, Email: m.Email, Role: m.Role, FP: m.FP, State: m.State}
		if m.State == e2e.PinRotated {
			row.WasVerified = &m.WasVerified
		}
		out.Members = append(out.Members, row)
	}
	return out
}

// printGroup prints a verified group as text.
func printGroup(v *client.GroupView) {
	fmt.Printf("%s (%s), record %d\n", v.Name, v.ID, v.Seq)
	for _, m := range v.Members {
		who := m.Email
		if who == "" {
			who = m.User
		}
		fmt.Printf("%-7s  %-32s  %-10s  %s\n", m.Role, who, priorLabel(m.State, m.WasVerified), showFP(m.FP))
	}
	for _, m := range v.Members {
		if m.State == e2e.PinRotated && m.WasVerified {
			fmt.Printf("re-verify %s: compare the new fingerprint with them, then run: cairn pin %s --verified\n", m.Email, m.Email)
		}
	}
}

func groupCreate(args []string) error {
	const usage = "cairn group create NAME [--member USER]... [--json]"
	fs := flag.NewFlagSet("group create", flag.ExitOnError)
	var members stringList
	fs.Var(&members, "member", "a user, by email or ID, to add as a member (repeatable)")
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 1, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	v, err := c.CreateGroup(pos[0], members)
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printJSON(groupViewJSON(v))
	}
	printGroup(v)
	return nil
}

func groupList(args []string) error {
	fs := flag.NewFlagSet("group list", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	if _, err := parsePositional(fs, args, 0, "cairn group list [--json]"); err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	groups, err := c.Groups()
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		out := make([]map[string]any, 0, len(groups))
		for _, g := range groups {
			out = append(out, map[string]any{"id": g.ID, "name": g.Name, "seq": g.Seq, "members": g.Members, "role": g.Role})
		}
		return printJSON(out)
	}
	if len(groups) == 0 {
		fmt.Println("no groups")
		return nil
	}
	for _, g := range groups {
		role := g.Role
		if role == "" {
			role = "-"
		}
		fmt.Printf("%-7s  %-32s  %3d members  %s\n", role, g.Name, g.Members, g.ID)
	}
	return nil
}

func groupShow(args []string) error {
	const usage = "cairn group show GROUP [--json]"
	fs := flag.NewFlagSet("group show", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 1, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	g, err := resolveGroup(c, pos[0])
	if err != nil {
		return err
	}
	v, err := c.ShowGroup(g.ID)
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printJSON(groupViewJSON(v))
	}
	printGroup(v)
	return nil
}

func groupAdd(args []string) error {
	const usage = "cairn group add GROUP USER [--manager] [--accept-new-key] [--json]"
	fs := flag.NewFlagSet("group add", flag.ExitOnError)
	manager := fs.Bool("manager", false, "add the user as a manager, not a member")
	acceptNewKey := fs.Bool("accept-new-key", false, "add the user even though their fingerprint changed since it was pinned")
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 2, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	g, err := resolveGroup(c, pos[0])
	if err != nil {
		return err
	}
	res, err := c.AddGroupMember(g.ID, pos[1], *manager, *acceptNewKey)
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printJSON(map[string]any{
			"group": g.ID, "user": res.User.ID, "email": res.User.Email, "fp": res.User.FP,
			"prior": res.Prior, "role": res.Role, "unchanged": res.Unchanged,
		})
	}
	fmt.Printf("%s (%s)\nfingerprint %s (%s)\n", res.User.Email, res.User.ID, showFP(res.User.FP), shareState(res.Prior, res.WasVerified))
	if res.Unchanged {
		fmt.Printf("already a %s of %s; nothing changed\n", res.Role, g.Name)
	} else {
		fmt.Printf("%s is now a %s of %s\n", res.User.Email, res.Role, g.Name)
	}
	if res.Prior != e2e.PinVerified {
		fmt.Printf("compare the fingerprint with them, then run: cairn pin %s --verified\n", res.User.Email)
	}
	return nil
}

func groupRemove(args []string) error {
	const usage = "cairn group remove GROUP USER [--json]"
	fs := flag.NewFlagSet("group remove", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 2, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	g, err := resolveGroup(c, pos[0])
	if err != nil {
		return err
	}
	user, err := c.RemoveGroupMember(g.ID, pos[1])
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printJSON(map[string]any{"group": g.ID, "user": user, "removed": true})
	}
	fmt.Printf("removed %s from %s\n", pos[1], g.Name)
	return nil
}

func groupRename(args []string) error {
	const usage = "cairn group rename GROUP NAME [--json]"
	fs := flag.NewFlagSet("group rename", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 2, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	g, err := resolveGroup(c, pos[0])
	if err != nil {
		return err
	}
	if err := c.RenameGroup(g.ID, pos[1]); err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printJSON(map[string]any{"group": g.ID, "name": pos[1]})
	}
	fmt.Printf("renamed %s to %s\n", g.Name, pos[1])
	return nil
}

func groupDelete(args []string) error {
	const usage = "cairn group delete GROUP [--json]"
	fs := flag.NewFlagSet("group delete", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 1, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	g, err := resolveGroup(c, pos[0])
	if err != nil {
		return err
	}
	if err := c.DeleteGroup(g.ID); err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printJSON(map[string]any{"group": g.ID, "deleted": true})
	}
	fmt.Printf("deleted %s (%s)\n", g.Name, g.ID)
	return nil
}
