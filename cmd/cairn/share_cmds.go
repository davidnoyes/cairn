package main

import (
	"encoding/hex"
	"errors"
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

// explainRefusal adds to a keyring refusal what it means and how to go on
// once the user has checked with their admin; any other error is unchanged.
func explainRefusal(c *client.Client, err error) error {
	var refused *client.KeyringRefusedError
	if !errors.As(err, &refused) {
		return err
	}
	path, perr := configPath()
	if perr != nil {
		path = "the cairn config file"
	}
	key := configAnchors{host: c.Host}.key(refused.UserID, refused.FP)
	return fmt.Errorf("%w\nThe server is serving an older or altered keyring, for example after a restore from backup; it can also be tampering. Do not go on until you confirm with your admin which it is. If the server was restored, remove the \"anchors\" entry %q from %s, then run the command again", err, key, path)
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
		return explainRefusal(c, err)
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
		return explainRefusal(c, err)
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
		return explainRefusal(c, err)
	}
	if *jsonOut {
		listed, unlisted := listingJSON(res.Listed, res.Unlisted)
		return printJSON(map[string]any{
			"artifact": a.ID, "user": res.User.ID, "email": res.User.Email, "fp": res.User.FP,
			"prior": res.Prior, "role": res.Role, "promoted": res.Promoted, "unchanged": res.Unchanged, "epoch": res.Epoch,
			"listed": listed, "unlisted": unlisted,
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
	printListing(a.ID, res.TeamRole, res.Listed, res.Unlisted)
	if res.Prior != e2e.PinVerified {
		fmt.Printf("compare the fingerprint with them, then run: cairn pin %s --verified\n", res.User.Email)
	}
	return nil
}

// listingJSON is the listed and unlisted approved team members, as share
// and team print them in JSON.
func listingJSON(listed []client.DirectoryUser, unlisted []client.UnlistedUser) (l, u []map[string]string) {
	l, u = []map[string]string{}, []map[string]string{}
	for _, d := range listed {
		l = append(l, map[string]string{"user": d.ID, "name": d.Name, "email": d.Email, "fp": d.FP})
	}
	for _, x := range unlisted {
		u = append(u, map[string]string{"user": x.User.ID, "name": x.User.Name, "email": x.User.Email, "fp": x.User.FP, "reason": x.Err.Error()})
	}
	return l, u
}

// printListing says which approved team members the record listed, and
// names, with their fingerprints, those it did not: the owner decides about
// each of them by name. role is the team's role, which the owner passes to
// cairn share so that an editor team's member is not shared as a viewer.
func printListing(artifact, role string, listed []client.DirectoryUser, unlisted []client.UnlistedUser) {
	for _, d := range listed {
		fmt.Printf("listed approved team member %s (%s), fingerprint %s\n", d.Email, d.Name, showFP(d.FP))
	}
	for _, x := range unlisted {
		fmt.Printf("not listed: %s (%s), fingerprint %s: %v\ncheck the fingerprint with them, then run: cairn share %s %s --role %s\n",
			x.User.Name, x.User.Email, showFP(x.User.FP), x.Err, artifact, x.User.Email, role)
	}
}

// parsePositionalRange is parsePositional for a command that takes between
// min and max positional arguments.
func parsePositionalRange(fs *flag.FlagSet, args []string, min, max int, usage string) ([]string, error) {
	var pos []string
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		pos, args = append(pos, args[0]), args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	pos = append(pos, fs.Args()...)
	if len(pos) < min || len(pos) > max {
		return nil, fmt.Errorf("usage: %s", usage)
	}
	return pos, nil
}

func runApprove(args []string) error {
	const usage = "cairn approve ARTIFACT [USER] [--accept-new-key] [--json]"
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	acceptNewKey := fs.Bool("accept-new-key", false, "approve even though the user's fingerprint changed since it was pinned")
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositionalRange(fs, args, 1, 2, usage)
	if err != nil {
		return err
	}
	if len(pos) == 1 && *acceptNewKey {
		return fmt.Errorf("usage: %s; --accept-new-key needs a USER", usage)
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	a, err := c.ResolveArtifact(pos[0])
	if err != nil {
		return err
	}
	if len(pos) == 1 {
		return listPending(c, a.ID, a.Name, *jsonOut)
	}
	res, err := c.Approve(a.ID, pos[1], *acceptNewKey)
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printJSON(map[string]any{
			"artifact": a.ID, "user": res.User.ID, "email": res.User.Email, "fp": res.User.FP,
			"prior": res.Prior, "epoch": res.Epoch, "approved": true,
		})
	}
	fmt.Printf("%s (%s)\nfingerprint %s (%s)\napproved for %s: they can read it now, and the owner's next cairn team or cairn share lists them with the team's role\n",
		res.User.Email, res.User.ID, showFP(res.User.FP), shareState(res.Prior), a.Name)
	if res.Prior != e2e.PinVerified {
		fmt.Printf("compare the fingerprint with them, then run: cairn pin %s --verified\n", res.User.Email)
	}
	return nil
}

// listPending prints the users waiting on artifact id.
func listPending(c *client.Client, id, name string, jsonOut bool) error {
	list, err := c.Pending(id)
	if err != nil {
		return explainRefusal(c, err)
	}
	if jsonOut {
		out := make([]map[string]string, 0, len(list))
		for _, p := range list {
			out = append(out, map[string]string{"user": p.User.ID, "name": p.User.Name, "email": p.User.Email, "fp": p.User.FP, "state": p.State})
		}
		return printJSON(map[string]any{"artifact": id, "pending": out})
	}
	if len(list) == 0 {
		va, _, err := c.Members(id)
		if err != nil {
			return explainRefusal(c, err)
		}
		if va.Chain.Latest.Team == "none" {
			fmt.Printf("%s is not shared with the team; run cairn team %s viewer|editor\n", name, id)
		} else {
			fmt.Printf("no team members waiting on %s\n", name)
		}
		return nil
	}
	states := map[string]bool{}
	for _, p := range list {
		states[p.State] = true
		fmt.Printf("%-10s  %-20s  %-32s  %s\n", p.State, p.User.Name, p.User.Email, showFP(p.User.FP))
	}
	fmt.Println("new: waiting for approval; approved: approved, not yet listed by the owner; keyChanged: keys changed since they were wrapped to or listed")
	if states[client.PendingNew] {
		fmt.Printf("compare a fingerprint with them, then run: cairn approve %s USER\n", id)
	}
	if states[client.PendingApproved] {
		fmt.Printf("approved: the owner's next cairn team %s viewer|editor or cairn share lists them\n", id)
	}
	if states[client.PendingKeyChanged] {
		fmt.Printf("keyChanged: the owner shares again with cairn share %s USER\n", id)
	}
	return nil
}

func runReview(args []string) error {
	const usage = "cairn review ARTIFACT [--json]"
	fs := flag.NewFlagSet("review", flag.ExitOnError)
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
	list, err := c.Review(a.ID)
	if err != nil {
		return explainRefusal(c, err)
	}
	// Emails only label the list: without the directory it shows user IDs.
	emails := map[string]string{}
	if len(list) > 0 {
		dir, _ := c.Directory()
		for _, u := range dir {
			emails[u.ID] = u.Email
		}
	}
	if *jsonOut {
		out := make([]map[string]any, 0, len(list))
		for _, v := range list {
			var pusher any
			if v.PushedBy != "" {
				pusher = v.PushedBy
			}
			out = append(out, map[string]any{"id": v.ID, "seq": v.Seq, "pushedBy": pusher, "email": emails[v.PushedBy], "createdAt": v.CreatedAt})
		}
		return printJSON(map[string]any{"artifact": a.ID, "versions": out})
	}
	if len(list) == 0 {
		fmt.Printf("no versions on %s need review\n", a.Name)
		return nil
	}
	if len(list) == 1 {
		fmt.Printf("1 version on %s needs review: its pusher is no longer an editor\n", a.Name)
	} else {
		fmt.Printf("%d versions on %s need review: their pushers are no longer editors\n", len(list), a.Name)
	}
	for _, v := range list {
		who := emails[v.PushedBy]
		if who == "" {
			who = v.PushedBy
		}
		if who == "" {
			who = "(account deleted)"
		}
		date, _, _ := strings.Cut(v.CreatedAt, "T")
		fmt.Printf("%-4d  %s  %-32s  %s\n", v.Seq, v.ID, who, date)
	}
	fmt.Printf("after you have looked at one, run: cairn vouch %s VERSION\n", a.ID)
	return nil
}

func runVouch(args []string) error {
	const usage = "cairn vouch ARTIFACT VERSION [--json]"
	fs := flag.NewFlagSet("vouch", flag.ExitOnError)
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
	if err := c.Vouch(a.ID, pos[1]); err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printJSON(map[string]any{"artifact": a.ID, "version": pos[1], "vouched": true})
	}
	fmt.Printf("vouched for version %s of %s\n", pos[1], a.Name)
	return nil
}

func runTeam(args []string) error {
	const usage = "cairn team ARTIFACT none|viewer|editor [--json]"
	fs := flag.NewFlagSet("team", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 2, usage)
	if err != nil {
		return err
	}
	if err := client.CheckTeam(pos[1]); err != nil {
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
	res, err := c.Team(a.ID, pos[1])
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		listed, unlisted := listingJSON(res.Listed, res.Unlisted)
		return printJSON(map[string]any{
			"artifact": a.ID, "team": res.Team, "epoch": res.Epoch, "unchanged": res.Unchanged,
			"listed": listed, "unlisted": unlisted,
		})
	}
	if res.Unchanged {
		fmt.Printf("team is already %s; nothing changed\n", res.Team)
	} else {
		fmt.Printf("team set to %s for %s\n", res.Team, a.Name)
	}
	printListing(a.ID, res.Team, res.Listed, res.Unlisted)
	return nil
}

// parseOnOff reads an on or off argument; what names it in the error.
func parseOnOff(what, s string) (bool, error) {
	switch s {
	case "on":
		return true, nil
	case "off":
		return false, nil
	}
	return false, fmt.Errorf("%s must be on or off, not %q", what, s)
}

func runPublic(args []string) error {
	const usage = "cairn public ARTIFACT on|off [--writes on|off] [--json]"
	fs := flag.NewFlagSet("public", flag.ExitOnError)
	writesFlag := fs.String("writes", "", "on or off: whether a signed-in link holder can write to the database and files")
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 2, usage)
	if err != nil {
		return err
	}
	on, err := parseOnOff("public", pos[1])
	if err != nil {
		return err
	}
	var writes *bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "writes" {
			writes = new(bool)
		}
	})
	if writes != nil {
		if *writesFlag == "" {
			return errors.New("--writes takes on or off")
		}
		w, err := parseOnOff("--writes", *writesFlag)
		if err != nil {
			return err
		}
		*writes = w
	}
	if !on && writes != nil {
		return client.ErrPublicWritesWithOff
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	a, err := c.ResolveArtifact(pos[0])
	if err != nil {
		return err
	}
	res, err := c.Public(a.ID, on, writes)
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printJSON(map[string]any{
			"artifact": a.ID, "public": res.Public, "publicWrites": res.PublicWrites, "epoch": res.Epoch,
			"link": res.Link, "unchanged": res.Unchanged,
		})
	}
	if !res.Public {
		fmt.Printf("%s is already private; nothing changed\n", a.Name)
		return nil
	}
	if res.Unchanged {
		fmt.Printf("%s is already public; nothing changed\n", a.Name)
	} else {
		fmt.Printf("%s is public\n", a.Name)
	}
	state := "off: a signed-in link holder cannot write"
	if res.PublicWrites {
		state = "on: a signed-in link holder can write to the database and files"
	}
	fmt.Printf("public writes are %s\n\n%s\n\nAnyone who holds this link can read the artifact. The key is in the part after the #, so share the link only with people who should read it.\n", state, res.Link)
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
