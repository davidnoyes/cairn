package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"strconv"
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

// rotationAdvice is what to do about err when it is a user's rotation records
// in doubt, which is a fork, a rollback, or records that could not be read,
// or "" for any other error.
func rotationAdvice(err error) string {
	var changed *client.KeyChangedError
	switch {
	case !errors.As(err, &changed):
		return ""
	case errors.Is(changed.Fork, e2e.ErrRollback):
		return "The server served fewer rotation records than you pinned, which can hide a rotation from you. Do not pass --accept-new-key until you have confirmed the fingerprint with them over a channel you trust"
	case changed.Fork != nil:
		return "The server serves rotation records for this user that conflict with each other or with what you pinned. It may be tampering, or whoever holds one of their old private keys may have signed these. Do not pass --accept-new-key until you have confirmed the new fingerprint with them in person or over a channel you trust"
	case changed.FetchErr != nil:
		return "This is usually a network or server fault, and their keys may be fine"
	}
	return ""
}

// explainRefusal adds to a keyring refusal what it means and how to go on
// once the user has checked with their admin; any other error is unchanged.
func explainRefusal(c *client.Client, err error) error {
	if advice := rotationAdvice(err); advice != "" {
		return fmt.Errorf("%w\n%s", err, advice)
	}
	var handover *client.HandoverNotAckedError
	if errors.As(err, &handover) {
		return fmt.Errorf("%w\nconfirm the handover with the people involved, then run the command again with --accept-new-owner", err)
	}
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
	fmt.Printf("%s (%s)\nfingerprint %s\npinned %s (was %s)\n", res.User.Email, res.User.ID, showFP(res.User.FP), res.State, priorLabel(res.Prior, res.WasVerified))
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
	offer, err := visibleOffer(c, a.ID, rows)
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		out := make([]map[string]string, 0, len(rows))
		for _, r := range rows {
			row := map[string]string{"user": r.User, "name": r.Name, "email": r.Email, "role": r.Role, "fp": r.FP, "state": r.State}
			if r.State == e2e.PinRotated {
				row["wasVerified"] = strconv.FormatBool(r.WasVerified)
			}
			out = append(out, row)
		}
		res := map[string]any{"artifact": a.ID, "epoch": va.Chain.Latest.Epoch, "seq": va.Chain.Latest.Seq, "members": out}
		if offer != nil {
			res["transfer"] = map[string]any{"to": offer.to, "email": offer.email, "by": offer.by, "at": offer.at}
		}
		return printArtifactJSON(a.ID, res)
	}
	fmt.Printf("%s (%s), epoch %d, record %d\n", a.Name, a.ID, va.Chain.Latest.Epoch, va.Chain.Latest.Seq)
	for _, r := range rows {
		who := r.Email
		if who == "" {
			who = r.User
		}
		fmt.Printf("%-6s  %-32s  %-10s  %s\n", r.Role, who, priorLabel(r.State, r.WasVerified), showFP(r.FP))
	}
	for _, r := range rows {
		if r.State == e2e.PinRotated && r.WasVerified {
			fmt.Printf("re-verify %s: compare the new fingerprint with them, then run: cairn pin %s --verified\n", r.Email, r.Email)
		}
	}
	if offer != nil {
		fmt.Println(offer.text(a.ID))
	}
	return nil
}

// openOffer is an open ownership offer as cairn members shows it.
type openOffer struct {
	to, email, by, at string
	toSelf            bool
}

// visibleOffer returns the artifact's open ownership offer when the caller is
// its owner or the user it is offered to, and nil otherwise. rows are the
// members the chain lists, which name the offered user.
func visibleOffer(c *client.Client, artifactID string, rows []client.MemberView) (*openOffer, error) {
	open, err := c.OpenTransfer(artifactID)
	if err != nil || open == nil {
		return nil, err
	}
	o := &openOffer{to: open.To, email: open.To, by: open.By, at: open.At}
	if len(o.at) > len("2006-01-02") {
		o.at = o.at[:len("2006-01-02")]
	}
	var owner bool
	for _, r := range rows {
		owner = owner || r.State == "self" && r.Role == "owner"
		if r.User == open.To {
			o.toSelf = r.State == "self"
			if r.Email != "" {
				o.email = r.Email
			}
		}
	}
	if !owner && !o.toSelf {
		return nil, nil
	}
	return o, nil
}

func (o *openOffer) text(artifactID string) string {
	by := ""
	if o.by == "admin" {
		by = " by an administrator"
	}
	if o.toSelf {
		return fmt.Sprintf("ownership offered to you on %s%s; accept with: cairn transfer accept %s", o.at, by, artifactID)
	}
	return fmt.Sprintf("ownership offered to %s on %s%s; they accept with: cairn transfer accept %s", o.email, o.at, by, artifactID)
}

func runShare(args []string) error {
	const usage = "cairn share ARTIFACT USER [--role viewer|editor] [--accept-new-key] [--accept-new-owner] [--json]"
	fs := flag.NewFlagSet("share", flag.ExitOnError)
	accept := acceptNewOwnerFlag(fs)
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
	c.AcceptNewOwner = *accept
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
		dropped := []string{}
		for _, x := range res.Dropped {
			dropped = append(dropped, x.Email)
		}
		out := map[string]any{
			"artifact": a.ID, "user": res.User.ID, "email": res.User.Email, "fp": res.User.FP,
			"prior": res.Prior, "role": res.Role, "promoted": res.Promoted, "demoted": res.Demoted,
			"unchanged": res.Unchanged, "epoch": res.Epoch, "listed": listed, "unlisted": unlisted, "dropped": dropped,
		}
		epochChangeJSON(out, res.EpochChange)
		return printArtifactJSON(a.ID, out)
	}
	fmt.Printf("%s (%s)\nfingerprint %s (%s)\n", res.User.Email, res.User.ID, showFP(res.User.FP), shareState(res.Prior, res.WasVerified))
	switch {
	case res.Unchanged:
		fmt.Printf("already a %s of %s; nothing changed\n", res.Role, a.Name)
	case res.Promoted:
		fmt.Printf("promoted to %s of %s\n", res.Role, a.Name)
	case res.Demoted:
		fmt.Printf("demoted to %s of %s\n", res.Role, a.Name)
	default:
		fmt.Printf("added as %s of %s\n", res.Role, a.Name)
	}
	for _, x := range res.Dropped {
		fmt.Printf("dropped the exclusion of %s: they are listed again\n", x.Email)
	}
	printEpochChange(c, a.ID, res.Epoch, res.EpochChange)
	printListing(a.ID, res.TeamRole, res.Listed, res.Unlisted)
	if res.Prior != e2e.PinVerified {
		fmt.Printf("compare the fingerprint with them, then run: cairn pin %s --verified\n", res.User.Email)
	}
	return nil
}

// epochChangeJSON adds to out what a command that may have started a new
// epoch reports: whether it did, who it excluded and why, and the new public
// link, empty when the artifact is private.
func epochChangeJSON(out map[string]any, ch client.EpochChange) {
	excluded := []map[string]string{}
	for _, x := range ch.Excluded {
		excluded = append(excluded, map[string]string{"user": x.User.ID, "name": x.User.Name, "email": x.User.Email, "fp": x.User.FP, "reason": x.Reason})
	}
	out["newEpoch"], out["excluded"], out["link"] = ch.NewEpoch, excluded, ch.Link
}

// excludedLabel names an excluded user by email and name, or by user ID when
// their account was deleted and the directory no longer has them.
func excludedLabel(u client.DirectoryUser) string {
	if u.Email == "" {
		return "deleted account " + u.ID
	}
	return fmt.Sprintf("%s (%s)", u.Email, u.Name)
}

// printEpochChange says that a new epoch started, who it excluded and why,
// the new public link if there is one, and how many versions now need review
// because their pusher is no longer an editor. It prints nothing when ch did
// not start a new epoch.
func printEpochChange(c *client.Client, artifact string, epoch int, ch client.EpochChange) {
	if !ch.NewEpoch {
		return
	}
	fmt.Printf("started epoch %d: the old key no longer opens the artifact\n", epoch)
	for _, x := range ch.Excluded {
		fmt.Printf("excluded %s, fingerprint %s: %s\n", excludedLabel(x.User), showFP(x.User.FP), x.Reason)
	}
	if len(ch.Excluded) > 0 {
		fmt.Printf("to let an excluded user back in, compare their fingerprint with them, then run: cairn share %s USER\n", artifact)
	}
	if ch.Link != "" {
		fmt.Printf("\nthe public link changed, and the old link no longer works. The new link is:\n\n%s\n\n", ch.Link)
	}
	// Only a hint: the record is already in, so a failed lookup is not an error.
	switch list, _ := c.Review(artifact); len(list) {
	case 0:
	case 1:
		fmt.Printf("1 version needs review: its pusher is no longer an editor. To see it, run: cairn review %s\n", artifact)
	default:
		fmt.Printf("%d versions need review: their pushers are no longer editors. To see them, run: cairn review %s\n", len(list), artifact)
	}
}

func runUnshare(args []string) error {
	const usage = "cairn unshare ARTIFACT USER [--accept-new-owner] [--json]"
	fs := flag.NewFlagSet("unshare", flag.ExitOnError)
	accept := acceptNewOwnerFlag(fs)
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 2, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	c.AcceptNewOwner = *accept
	a, err := c.ResolveArtifact(pos[0])
	if err != nil {
		return err
	}
	res, err := c.Unshare(a.ID, pos[1])
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		listed, _ := listingJSON(res.Listed, nil)
		out := map[string]any{
			"artifact": a.ID, "user": res.User.ID, "email": res.User.Email, "epoch": res.Epoch, "listed": listed,
		}
		epochChangeJSON(out, res.EpochChange)
		return printArtifactJSON(a.ID, out)
	}
	if res.User.Email == "" {
		fmt.Printf("removed deleted account %s from %s\n", res.User.ID, a.Name)
	} else {
		fmt.Printf("removed %s (%s) from %s\n", res.User.Email, res.User.ID, a.Name)
	}
	printEpochChange(c, a.ID, res.Epoch, res.EpochChange)
	for _, d := range res.Listed {
		fmt.Printf("listed approved team member %s (%s), fingerprint %s\n", d.Email, d.Name, showFP(d.FP))
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
		row := map[string]string{"user": x.User.ID, "name": x.User.Name, "email": x.User.Email, "fp": x.User.FP, "reason": x.Err.Error()}
		// Set only where it holds: a conflict in their rotation records, or
		// records that could not be read.
		var changed *client.KeyChangedError
		if errors.As(x.Err, &changed) {
			if changed.Fork != nil {
				row["rotationConflict"] = "true"
			} else if changed.FetchErr != nil {
				row["rotationsUnreadable"] = "true"
			}
		}
		u = append(u, row)
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
		// A conflict or an unreadable record is not for the owner to share
		// past, so the advice is the refusal's, and no command to run.
		if advice := rotationAdvice(x.Err); advice != "" {
			fmt.Printf("not listed: %s (%s), fingerprint %s\n%v\n%s\n", x.User.Name, x.User.Email, showFP(x.User.FP), x.Err, advice)
			continue
		}
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
	const usage = "cairn approve ARTIFACT [USER] [--accept-new-key] [--accept-new-owner] [--json]"
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	accept := acceptNewOwnerFlag(fs)
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
	c.AcceptNewOwner = *accept
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
		return printArtifactJSON(a.ID, map[string]any{
			"artifact": a.ID, "user": res.User.ID, "email": res.User.Email, "fp": res.User.FP,
			"prior": res.Prior, "epoch": res.Epoch, "approved": true,
		})
	}
	fmt.Printf("%s (%s)\nfingerprint %s (%s)\napproved for %s: they can read it now, and the owner's next cairn team or cairn share lists them with the team's role\n",
		res.User.Email, res.User.ID, showFP(res.User.FP), shareState(res.Prior, res.WasVerified), a.Name)
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
			entry := map[string]string{"user": p.User.ID, "name": p.User.Name, "email": p.User.Email, "fp": p.User.FP, "state": p.State}
			if p.RotationsErr != nil {
				entry["rotationsUnreadable"] = "true"
			}
			out = append(out, entry)
		}
		return printArtifactJSON(id, map[string]any{"artifact": id, "pending": out})
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
	var unreadable []client.PendingUser
	for _, p := range list {
		// A user whose records could not be read is not told to be shared
		// with again: nothing says their keys changed.
		if p.RotationsErr == nil {
			states[p.State] = true
		} else {
			unreadable = append(unreadable, p)
		}
		fmt.Printf("%-10s  %-20s  %-32s  %s\n", p.State, p.User.Name, p.User.Email, showFP(p.User.FP))
	}
	fmt.Println("new: waiting for approval; approved: approved, not yet listed by the owner; keyChanged: keys changed since they were wrapped to or listed; rotated: keys rotated since they were listed; the owner's next record lists the new keys")
	if states[client.PendingNew] {
		fmt.Printf("compare a fingerprint with them, then run: cairn approve %s USER\n", id)
	}
	if states[client.PendingApproved] {
		fmt.Printf("approved: the owner's next cairn team %s viewer|editor or cairn share lists them\n", id)
	}
	if states[client.PendingKeyChanged] {
		fmt.Printf("keyChanged: the owner shares again with cairn share %s USER\n", id)
	}
	for _, p := range unreadable {
		fmt.Printf("keyChanged: the rotation records of %s could not be read (%v); run cairn approve %s again, their keys may be fine\n", p.User.Email, p.RotationsErr, id)
	}
	if states[client.PendingRotated] {
		fmt.Printf("rotated: the owner's next cairn share %s USER or cairn team %s viewer|editor lists the new keys\n", id, id)
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
		return printArtifactJSON(a.ID, map[string]any{"artifact": a.ID, "versions": out})
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
	const usage = "cairn vouch ARTIFACT VERSION [--accept-new-owner] [--json]"
	fs := flag.NewFlagSet("vouch", flag.ExitOnError)
	accept := acceptNewOwnerFlag(fs)
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 2, usage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	c.AcceptNewOwner = *accept
	a, err := c.ResolveArtifact(pos[0])
	if err != nil {
		return err
	}
	if err := c.Vouch(a.ID, pos[1]); err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printArtifactJSON(a.ID, map[string]any{"artifact": a.ID, "version": pos[1], "vouched": true})
	}
	fmt.Printf("vouched for version %s of %s\n", pos[1], a.Name)
	return nil
}

func runTeam(args []string) error {
	const usage = "cairn team ARTIFACT none|viewer|editor [--accept-new-owner] [--json]"
	fs := flag.NewFlagSet("team", flag.ExitOnError)
	accept := acceptNewOwnerFlag(fs)
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
	c.AcceptNewOwner = *accept
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
		out := map[string]any{
			"artifact": a.ID, "team": res.Team, "epoch": res.Epoch, "unchanged": res.Unchanged,
			"listed": listed, "unlisted": unlisted,
		}
		epochChangeJSON(out, res.EpochChange)
		return printArtifactJSON(a.ID, out)
	}
	if res.Unchanged {
		fmt.Printf("team is already %s; nothing changed\n", res.Team)
	} else {
		fmt.Printf("team set to %s for %s\n", res.Team, a.Name)
	}
	printEpochChange(c, a.ID, res.Epoch, res.EpochChange)
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
	const usage = "cairn public ARTIFACT on|off [--writes on|off] [--accept-new-owner] [--json]"
	fs := flag.NewFlagSet("public", flag.ExitOnError)
	accept := acceptNewOwnerFlag(fs)
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
	c.AcceptNewOwner = *accept
	a, err := c.ResolveArtifact(pos[0])
	if err != nil {
		return err
	}
	res, err := c.Public(a.ID, on, writes)
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		out := map[string]any{
			"artifact": a.ID, "public": res.Public, "publicWrites": res.PublicWrites, "epoch": res.Epoch,
			"link": res.Link, "unchanged": res.Unchanged,
		}
		out["listed"], _ = listingJSON(res.Listed, nil)
		epochChangeJSON(out, client.EpochChange{NewEpoch: res.NewEpoch, Excluded: res.Excluded, Link: res.Link})
		return printArtifactJSON(a.ID, out)
	}
	if !res.Public {
		if res.NewEpoch {
			fmt.Printf("%s is private\n", a.Name)
			printEpochChange(c, a.ID, res.Epoch, client.EpochChange{NewEpoch: true, Excluded: res.Excluded})
			printListing(a.ID, "", res.Listed, nil)
		} else {
			fmt.Printf("%s is already private; nothing changed\n", a.Name)
		}
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

func shareState(prior string, wasVerified bool) string {
	switch prior {
	case e2e.PinNew:
		return "new; pinned unverified"
	case e2e.PinChanged:
		return "changed; the new key is pinned unverified"
	case e2e.PinRotated:
		return priorLabel(prior, wasVerified) + "; the new key is pinned unverified"
	}
	return prior
}

// priorLabel is a pin state as shown to a person. A rotation raises no
// warning, but it drops a verified pin to unverified, which the label says.
// Rotation records that conflict are shown as a change, with the reason.
func priorLabel(state string, wasVerified bool) string {
	switch {
	case state == e2e.PinRotated && wasVerified:
		return "rotated, not re-verified"
	case state == e2e.PinRotated:
		return "keys rotated"
	case state == client.MemberConflict:
		return "changed: rotation records conflict"
	}
	return state
}

// Interface check: the config file is the CLI's anchor store.
var _ client.AnchorStore = configAnchors{}
