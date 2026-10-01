package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"strings"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

// parsePositional parses fs and returns exactly n positional arguments,
// whether they come before or after the flags.
func parsePositional(fs *flag.FlagSet, args []string, n int, usage string) ([]string, error) {
	var pos []string
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		pos, args = append(pos, args[0]), args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	pos = append(pos, fs.Args()...)
	if len(pos) != n {
		return nil, fmt.Errorf("usage: %s", usage)
	}
	return pos, nil
}

// showFP groups a hex fingerprint for reading aloud.
func showFP(fp string) string {
	b, err := hex.DecodeString(fp)
	if err != nil {
		return fp
	}
	return e2e.FormatFingerprint(b)
}

func runPin(args []string) error {
	const usage = "cairn pin USER [--verified] [--accept-new-key] [--json]"
	fs := flag.NewFlagSet("pin", flag.ExitOnError)
	verified := fs.Bool("verified", false, "mark the fingerprint verified: you compared it with the user out of band")
	acceptNewKey := fs.Bool("accept-new-key", false, "replace a pinned fingerprint that changed")
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 1, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	res, err := c.Pin(pos[0], *verified, *acceptNewKey)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(map[string]string{"user": res.User.ID, "email": res.User.Email, "fp": res.User.FP, "prior": res.Prior, "state": res.State})
	}
	fmt.Printf("%s (%s)\nfingerprint %s\npinned %s (was %s)\n", res.User.Email, res.User.ID, showFP(res.User.FP), res.State, res.Prior)
	return nil
}

func runMembers(args []string) error {
	const usage = "cairn members ARTIFACT [--json]"
	fs := flag.NewFlagSet("members", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 1, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	a, err := c.ResolveArtifact(pos[0])
	if err != nil {
		return err
	}
	va, rows, err := c.Members(a.ID)
	if err != nil {
		return err
	}
	if *jsonOut {
		out := make([]map[string]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, map[string]string{"user": r.User, "name": r.Name, "email": r.Email, "role": r.Role, "fp": r.FP, "state": r.State})
		}
		return printJSON(map[string]any{"artifact": a.ID, "epoch": va.Chain.Latest.Epoch, "seq": va.Chain.Latest.Seq, "members": out})
	}
	fmt.Printf("%s (%s), epoch %d, record %d\n", a.Name, a.ID, va.Chain.Latest.Epoch, va.Chain.Latest.Seq)
	for _, r := range rows {
		who := r.Email
		if who == "" {
			who = r.User
		}
		fmt.Printf("%-6s  %-32s  %-10s  %s\n", r.Role, who, r.State, showFP(r.FP))
	}
	return nil
}

func runShare(args []string) error {
	const usage = "cairn share ARTIFACT USER [--role viewer|editor] [--accept-new-key] [--json]"
	fs := flag.NewFlagSet("share", flag.ExitOnError)
	role := fs.String("role", "viewer", "viewer or editor")
	acceptNewKey := fs.Bool("accept-new-key", false, "share even though the user's fingerprint changed since it was pinned")
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 2, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	a, err := c.ResolveArtifact(pos[0])
	if err != nil {
		return err
	}
	res, err := c.Share(a.ID, pos[1], *role, *acceptNewKey)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(map[string]any{
			"artifact": a.ID, "user": res.User.ID, "email": res.User.Email, "fp": res.User.FP,
			"prior": res.Prior, "role": res.Role, "promoted": res.Promoted, "unchanged": res.Unchanged, "epoch": res.Epoch,
		})
	}
	fmt.Printf("%s (%s)\nfingerprint %s (%s)\n", res.User.Email, res.User.ID, showFP(res.User.FP), shareState(res.Prior))
	switch {
	case res.Unchanged:
		fmt.Printf("already a %s of %s; nothing changed\n", res.Role, a.Name)
	case res.Promoted:
		fmt.Printf("promoted to %s of %s\n", res.Role, a.Name)
	default:
		fmt.Printf("added as %s of %s\n", res.Role, a.Name)
	}
	if res.Prior != e2e.PinVerified {
		fmt.Printf("compare the fingerprint with them, then run: cairn pin %s --verified\n", res.User.Email)
	}
	return nil
}

func shareState(prior string) string {
	switch prior {
	case e2e.PinNew:
		return "new; pinned unverified"
	case e2e.PinChanged:
		return "changed; the new key is pinned unverified"
	}
	return prior
}

// Interface check: the config file is the CLI's anchor store.
var _ client.AnchorStore = configAnchors{}
