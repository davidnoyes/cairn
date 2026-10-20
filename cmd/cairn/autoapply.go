package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/aloisdeniel/cairn/internal/client"
)

// Applying on its own. Whenever a command can unlock the caller's keys, it
// first brings the items the caller owns or manages up to date with their
// folders, so sharing needs no further step. It signs the pending records and
// nothing else: approving a group's newcomers stays an explicit decision, in
// cairn approve or cairn apply.

// autoApply runs the inheritance-only apply for a client that holds the full
// API key, and says on stderr what it did, so stdout, --json included, is
// unchanged. A failure is a warning and the command goes on; only a refused
// credential is returned, as the command's own request would fail with it.
func autoApply(c *client.Client) error {
	if c.Key == nil {
		return nil
	}
	res, err := c.ApplyInherited()
	return reportAutoApply(os.Stderr, res, err)
}

func reportAutoApply(w io.Writer, res *client.ApplyResult, err error) error {
	var api *client.APIError
	if errors.As(err, &api) && api.Status == http.StatusUnauthorized {
		return err
	}
	if err != nil && !errors.Is(err, client.ErrFanOutIncomplete) {
		fmt.Fprintf(w, "warning: could not apply folder sharing: %v\n", err)
	}
	if line := autoApplySummary(res); line != "" {
		fmt.Fprintln(w, line)
	}
	return nil
}

// autoApplySummary is the one line for what the apply did, or "" when it did
// nothing: items brought up to date, items that need a move, and items that
// failed. Items that wait on someone else are left to cairn apply, because
// the caller can do nothing about them.
func autoApplySummary(res *client.ApplyResult) string {
	if res == nil {
		return ""
	}
	var parts []string
	if n := res.FanOut.Count(client.FanOutUpdated) + res.FanOut.Count(client.FanOutNewEpoch); n > 0 {
		parts = append(parts, "applied folder sharing to "+plural(n, "item", "items"))
	}
	if n := res.FanOut.Count(client.FanOutNeedsMove); n > 0 {
		verb := "needs"
		if n > 1 {
			verb = "need"
		}
		parts = append(parts, fmt.Sprintf("%s %s a move; run cairn apply for why and how", plural(n, "item", "items"), verb))
	}
	if n := res.FanOut.Count(client.FanOutFailed); n > 0 {
		parts = append(parts, plural(n, "item", "items")+" could not be brought up to date; run cairn apply for the reason")
	}
	return strings.Join(parts, "; ")
}
