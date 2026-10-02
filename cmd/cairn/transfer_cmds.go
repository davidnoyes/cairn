package main

import (
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

const transferUsage = "cairn transfer ARTIFACT USER [--accept-new-key] [--accept-new-owner] [--json]\n" +
	"       cairn transfer accept ARTIFACT [--drop-previous-owner] [--accept-new-owner] [--json]\n" +
	"       cairn transfer decline|withdraw ARTIFACT [--accept-new-owner] [--json]\n" +
	"accept, decline, and withdraw are subcommands only when exactly one argument follows; to offer an artifact with one of those names, give its ID"

// transferAnswers are the subcommands of cairn transfer.
var transferAnswers = []string{"accept", "decline", "withdraw"}

// runTransfer offers ownership, or answers an offer. The first argument is a
// subcommand only when it is exactly accept, decline, or withdraw and exactly
// one more argument follows: every flag is a switch, so the arguments that do
// not start with a dash are the positional ones.
func runTransfer(args []string) error {
	var pos []string
	first := -1
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			if first < 0 {
				first = i
			}
			pos = append(pos, a)
		}
	}
	if len(pos) == 2 && slices.Contains(transferAnswers, pos[0]) {
		rest := slices.Concat(args[:first], args[first+1:])
		return runTransferAnswer(pos[0], rest)
	}
	return runTransferOffer(args)
}

func runTransferOffer(args []string) error {
	fs := flag.NewFlagSet("transfer", flag.ExitOnError)
	accept := acceptNewOwnerFlag(fs)
	acceptNewKey := fs.Bool("accept-new-key", false, "offer even though the user's fingerprint changed since it was pinned")
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 2, transferUsage)
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
	res, err := c.OfferTransfer(a.ID, pos[1], *acceptNewKey)
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printArtifactJSON(a.ID, map[string]any{
			"artifact": a.ID, "user": res.User.ID, "email": res.User.Email, "fp": res.User.FP,
			"prior": res.Prior, "replaced": res.Replaced,
		})
	}
	fmt.Printf("%s (%s)\nfingerprint %s (%s)\n", res.User.Email, res.User.ID, showFP(res.User.FP), shareState(res.Prior, res.WasVerified))
	if res.Replaced {
		fmt.Println("closed the earlier offer, which can no longer be accepted")
	}
	fmt.Printf("offered ownership of %s to %s; it stays with you until they accept\nthey accept with: cairn transfer accept %s\n", a.Name, res.User.Email, a.ID)
	if res.Prior != e2e.PinVerified {
		fmt.Printf("compare the fingerprint with them, then run: cairn pin %s --verified\n", res.User.Email)
	}
	return nil
}

func runTransferAnswer(answer string, args []string) error {
	usage := "cairn transfer " + answer + " ARTIFACT [--accept-new-owner] [--json]"
	fs := flag.NewFlagSet("transfer "+answer, flag.ExitOnError)
	accept := acceptNewOwnerFlag(fs)
	var drop *bool
	if answer == "accept" {
		usage = "cairn transfer accept ARTIFACT [--drop-previous-owner] [--accept-new-owner] [--json]"
		drop = fs.Bool("drop-previous-owner", false, "start a new epoch that excludes the previous owner, who cannot read it afterwards; by default they stay as an editor, except after an administrator's offer, which always drops them")
	}
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 1, usage)
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
	switch answer {
	case "accept":
		return transferAccept(c, a.ID, a.Name, *drop, *jsonOut)
	case "decline":
		if err := c.DeclineTransfer(a.ID); err != nil {
			return explainRefusal(c, err)
		}
		if *jsonOut {
			return printArtifactJSON(a.ID, map[string]any{"artifact": a.ID, "declined": true})
		}
		fmt.Printf("declined the offer of ownership of %s\n", a.Name)
	default:
		if err := c.WithdrawTransfer(a.ID); err != nil {
			return explainRefusal(c, err)
		}
		if *jsonOut {
			return printArtifactJSON(a.ID, map[string]any{"artifact": a.ID, "withdrawn": true})
		}
		fmt.Printf("withdrew the offer of ownership of %s; it can no longer be accepted\n", a.Name)
	}
	return nil
}

func transferAccept(c *client.Client, id, name string, drop, jsonOut bool) error {
	res, err := c.AcceptTransfer(id, client.AcceptTransferOptions{DropPreviousOwner: drop})
	if err != nil {
		return explainRefusal(c, err)
	}
	if jsonOut {
		out := map[string]any{
			"artifact": id, "epoch": res.Epoch, "previousOwner": res.PreviousOwner.ID, "previousOwnerEmail": res.PreviousOwner.Email,
			"keptPreviousOwner": res.Kept, "byAdministrator": res.Handover,
		}
		epochChangeJSON(out, res.EpochChange)
		return printArtifactJSON(id, out)
	}
	fmt.Printf("you own %s now, at epoch %d\n", name, res.Epoch)
	if res.Handover {
		fmt.Println("an administrator handed it to you; every other member sees a notice of the handover")
	}
	if res.Kept {
		fmt.Printf("%s stays as an editor, and still reads every epoch\n", res.PreviousOwner.Email)
	}
	printEpochChange(c, id, res.Epoch, res.EpochChange)
	return nil
}
