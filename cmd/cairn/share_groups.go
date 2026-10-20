package main

import (
	"fmt"
	"strings"

	"github.com/aloisdeniel/cairn/internal/client"
)

// everyone is what cairn share and unshare call the team share.
const everyone = "everyone"

// groupLabel names a listed group by its name, or says the server no longer
// holds it.
func groupLabel(g client.ListedGroup) string {
	if g.Deleted {
		return "(deleted group)"
	}
	return g.Name
}

// groupsJSON is groups as share, members, and approve print them in JSON:
// each with its ID and name, the role it grants when it has one, and whether
// the server no longer holds it.
func groupsJSON(groups []client.ListedGroup) []map[string]any {
	out := []map[string]any{}
	for _, g := range groups {
		row := map[string]any{"id": g.ID, "name": g.Name, "deleted": g.Deleted}
		if g.Role != "" {
			row["role"] = g.Role
		}
		if g.Via != "" {
			row["via"], row["viaName"] = g.Via, g.ViaName
		}
		out = append(out, row)
	}
	return out
}

// groupNames maps the ID of each group a pending user is held by to its
// name, from the server's list, or is nil when none is.
func groupNames(c *client.Client, pending []client.PendingUser) (map[string]string, error) {
	held := false
	for _, p := range pending {
		held = held || len(p.Groups) > 0
	}
	if !held {
		return nil, nil
	}
	all, err := c.Groups()
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, g := range all {
		names[g.ID] = g.Name
	}
	return names, nil
}

// groupRows is the groups with these IDs, named from names.
func groupRows(ids []string, names map[string]string) []client.ListedGroup {
	var out []client.ListedGroup
	for _, id := range ids {
		out = append(out, client.ListedGroup{ID: id, Name: names[id]})
	}
	return out
}

// groupSuffix is the groups of a pending line, or "" when there are none.
func groupSuffix(groups []client.ListedGroup) string {
	if len(groups) == 0 {
		return ""
	}
	names := make([]string, len(groups))
	for i, g := range groups {
		names[i] = groupLabel(g)
	}
	return "  groups: " + strings.Join(names, ", ")
}

// printDropped says which listed groups a new record dropped, because the
// server no longer holds them.
func printDropped(ids []string) {
	for _, id := range ids {
		fmt.Printf("dropped group %s from the member list: it no longer exists\n", id)
	}
}

// printShareGroup prints what sharing with a group did.
func printShareGroup(a *client.Artifact, res *client.ShareGroupResult, jsonOut bool) error {
	if jsonOut {
		approved, _ := listingJSON(res.Approved, nil)
		_, pending := listingJSON(nil, res.Pending)
		listed, unlisted := listingJSON(res.Listed, res.Unlisted)
		return printArtifactJSON(a.ID, map[string]any{
			"artifact": a.ID, "group": map[string]string{"id": res.Group.ID, "name": res.Group.Name},
			"role": res.Role, "epoch": res.Epoch, "unchanged": res.Unchanged,
			"approved": approved, "pending": pending, "listed": listed, "unlisted": unlisted,
			"droppedGroups": append([]string{}, res.DroppedGroups...),
		})
	}
	printDropped(res.DroppedGroups)
	if res.Unchanged {
		fmt.Printf("%s (%s) is already shared with %s (%s) as %s; nothing changed\n", a.Name, a.ID, res.Group.Name, res.Group.ID, res.Role)
	} else {
		fmt.Printf("shared %s (%s) with group %s (%s) as %s\n", a.Name, a.ID, res.Group.Name, res.Group.ID, res.Role)
	}
	for _, d := range res.Approved {
		fmt.Printf("approved %s (%s), fingerprint %s\n", d.Email, d.Name, showFP(d.FP))
	}
	for _, x := range res.Pending {
		fmt.Printf("pending: %s (%s), fingerprint %s: %v\nwhen you have checked it, run: cairn approve %s %s\n",
			x.User.Name, x.User.Email, showFP(x.User.FP), x.Err, a.ID, x.User.Email)
	}
	printListing(a.ID, res.Role, res.Listed, res.Unlisted)
	return nil
}

// printUnshareGroup prints what dropping a group did.
func printUnshareGroup(c *client.Client, a *client.Artifact, res *client.UnshareGroupResult, jsonOut bool) error {
	if jsonOut {
		listed, _ := listingJSON(res.Listed, nil)
		out := map[string]any{
			"artifact": a.ID, "group": map[string]string{"id": res.Group.ID, "name": res.Group.Name},
			"epoch": res.Epoch, "listed": listed,
		}
		epochChangeJSON(out, res.EpochChange)
		return printArtifactJSON(a.ID, out)
	}
	if res.Group.Name == "" {
		fmt.Printf("removed group %s from %s\n", res.Group.ID, a.Name)
	} else {
		fmt.Printf("removed group %s (%s) from %s\n", res.Group.Name, res.Group.ID, a.Name)
	}
	printEpochChange(c, a.ID, res.Epoch, res.EpochChange)
	for _, d := range res.Listed {
		fmt.Printf("listed approved member %s (%s), fingerprint %s\n", d.Email, d.Name, showFP(d.FP))
	}
	return nil
}
