package main

import (
	"flag"
	"fmt"

	"github.com/aloisdeniel/cairn/internal/client"
)

// Applying what other people shared. See "Commands for other people's items"
// in design/e2e-api.md.

func runApply(args []string) error {
	const usage = "cairn apply [--json]"
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	if _, err := parsePositional(fs, args, 0, usage); err != nil {
		return err
	}
	c, err := plainClient()
	if err != nil {
		return err
	}
	res, err := c.Apply()
	if res != nil {
		if *jsonOut {
			if perr := printJSON(applyJSON(res)); perr != nil {
				return perr
			}
		} else {
			printApply(res)
		}
	}
	if err != nil {
		return explainRefusal(c, fmt.Errorf("%w; run the same command again to finish", err))
	}
	return nil
}

// ownerLabel is how a line names the owner of an item that waits on them: their
// address when the directory holds them, else their ID.
func ownerLabel(it client.FanOutItem) string {
	if it.OwnerEmail != "" {
		return it.OwnerEmail
	}
	return it.Owner
}

// printApply says what apply did, and what still waits on someone else.
func printApply(res *client.ApplyResult) {
	if len(res.FanOut.Items) == 0 && len(res.Waiting) == 0 && len(res.Approvals) == 0 {
		fmt.Println("nothing to apply")
		return
	}
	printFanOut(&res.FanOut)
	for _, a := range res.Approvals {
		for _, d := range a.Approved {
			fmt.Printf("%s: approved %s (%s)\n", a.ID, d.Email, d.Name)
		}
		for _, x := range a.Pending {
			fmt.Printf("%s: pending: %s: %v\n", a.ID, x.User.Email, x.Err)
		}
	}
	if len(res.Waiting) > 0 {
		verb := "wait"
		if len(res.Waiting) == 1 {
			verb = "waits"
		}
		fmt.Printf("%s still %s on someone else:\n", plural(len(res.Waiting), "item", "items"), verb)
		for _, it := range res.Waiting {
			fmt.Printf("%s: waits on %s\n", it.ID, ownerLabel(it))
		}
	}
}

// applyJSON is what apply printed, as JSON: applied is the fan-out of the
// items it signed, waiting the pending items only someone else can sign, and
// approvals the group members it approved.
func applyJSON(res *client.ApplyResult) map[string]any {
	waiting := []map[string]string{}
	for _, it := range res.Waiting {
		waiting = append(waiting, map[string]string{"id": it.ID, "kind": it.Kind, "owner": it.Owner, "ownerEmail": it.OwnerEmail})
	}
	approvals := []map[string]any{}
	for _, a := range res.Approvals {
		approved, pending := listingJSON(a.Approved, a.Pending)
		approvals = append(approvals, map[string]any{"id": a.ID, "kind": a.Kind, "approved": approved, "pending": pending})
	}
	return map[string]any{"applied": fanOutJSON(&res.FanOut), "waiting": waiting, "approvals": approvals}
}
