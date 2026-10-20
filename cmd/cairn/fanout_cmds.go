package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/store"
)

// Shared folders: sharing, unsharing, and moving change the folder, and are
// followed by a record for each item inside it. See "Commands for shared
// folders" in design/e2e-api.md.

// fanOuts holds the fan-out each command ran, by the ID of the folder it
// changed, for printArtifactJSON to add to the command's JSON.
var fanOuts = map[string]*client.FanOutResult{}

// fanOutProgress is the progress callback of FanOut: how many items are done,
// on one line of stderr that the next call overwrites.
func fanOutProgress(done, total int) {
	fmt.Fprintf(os.Stderr, "\r%d of %d items up to date with the folder", done, total)
	if done == total {
		fmt.Fprintln(os.Stderr)
	}
}

// folderThen runs print, the command's own report, around the fan-out a
// folder needs after the command changed it: a text report first, so the
// change shows before the items are worked through, and a JSON one after,
// so that it holds the fan-out's result. Anything but a folder is just
// printed. A fan-out that left items pending ends in an error after the
// report: running the same command again finishes it.
func folderThen(c *client.Client, a *client.Artifact, includeRoot, jsonOut bool, print func() error) error {
	if a.Kind != store.KindFolder && !includeRoot {
		return print()
	}
	if !jsonOut {
		if err := print(); err != nil {
			return err
		}
	}
	res, err := c.FanOut(a.ID, includeRoot, fanOutProgress)
	if res != nil {
		fanOuts[a.ID] = res
	}
	if jsonOut {
		if perr := print(); perr != nil {
			return perr
		}
	} else if res != nil {
		printFanOut(res)
	}
	if err != nil {
		return explainRefusal(c, fmt.Errorf("%w; run the same command again to finish", err))
	}
	return nil
}

// resumeFolder is what a command on a folder does when its own step finds
// nothing to change, because an earlier run already made it: the fan-out
// still runs, so that running the same command again finishes an interrupted
// one. It reports whether err is such an error.
func resumeFolder(a *client.Artifact, err error) bool {
	return a.Kind == store.KindFolder && (errors.Is(err, client.ErrNotMember) || errors.Is(err, client.ErrNotSharedWithGroup))
}

// printFanOut says what the fan-out did, and for each item that failed, why.
func printFanOut(res *client.FanOutResult) {
	if len(res.Items) == 0 {
		return
	}
	fmt.Printf("%s: %d updated, %d at a new epoch, %d already up to date, %d still pending\n",
		plural(len(res.Items), "item", "items"), res.Count(client.FanOutUpdated), res.Count(client.FanOutNewEpoch),
		res.Count(client.FanOutCurrent), res.Count(client.FanOutFailed))
	for _, it := range res.Items {
		for _, x := range it.Excluded {
			fmt.Printf("%s: new epoch, excluded %s\n", it.ID, excludedLabel(x.User))
		}
		if it.ResealErr != nil {
			fmt.Printf("%s: sealing the data again under the new epoch failed: %v\nrun: cairn reseal %s\n", it.ID, it.ResealErr, it.ID)
		}
		for _, d := range it.Approved {
			fmt.Printf("%s: approved %s (%s)\n", it.ID, d.Email, d.Name)
		}
		for _, x := range it.Pending {
			fmt.Printf("%s: pending: %s: %v\n", it.ID, x.User.Email, x.Err)
		}
		if it.State == client.FanOutFailed {
			fmt.Printf("%s: still pending: %v\n", it.ID, it.Err)
		}
	}
}

// fanOutJSON is a fan-out as a command prints it in JSON: how many items
// ended in each state, and each item with its state and what happened to it.
func fanOutJSON(res *client.FanOutResult) map[string]any {
	items := []map[string]any{}
	failed := []map[string]string{}
	for _, it := range res.Items {
		excluded := []string{}
		for _, x := range it.Excluded {
			excluded = append(excluded, x.User.ID)
		}
		row := map[string]any{"id": it.ID, "kind": it.Kind, "state": it.State, "excluded": excluded}
		if it.State == client.FanOutNewEpoch {
			row["resealed"] = resealJSON(it.Resealed, it.ResealErr)
		}
		approved, _ := listingJSON(it.Approved, nil)
		_, pending := listingJSON(nil, it.Pending)
		if len(approved) > 0 {
			row["approved"] = approved
		}
		if len(pending) > 0 {
			row["pending"] = pending
		}
		if it.Err != nil {
			row["error"] = it.Err.Error()
			failed = append(failed, map[string]string{"id": it.ID, "error": it.Err.Error()})
		}
		items = append(items, row)
	}
	return map[string]any{
		"total": len(res.Items), "current": res.Count(client.FanOutCurrent), "updated": res.Count(client.FanOutUpdated),
		"newEpoch": res.Count(client.FanOutNewEpoch), "failed": failed, "items": items,
	}
}

// viaLabel is the " via FOLDER" a members line carries for an inherited
// entry, naming the folder, or "" for a direct grant.
func viaLabel(via, name string) string {
	if via == "" {
		return ""
	}
	if name == "" || name == via {
		return " via " + via
	}
	return " via " + strings.TrimSpace(name) + " (" + via + ")"
}
