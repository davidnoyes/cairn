// Command cairn is the Cairn artifact server and its client CLI.
package main

import (
	"fmt"
	"os"
)

const usage = `cairn — self-hosted artifact server and client

Server:
  cairn serve            Run the server
  cairn backup           Snapshot a data directory (live-safe)
  cairn verify           Check a server serves a signed release unchanged ([--manifest FILE] [--key KEY]... [--version V] [--allow-skip] [URL])

Client:
  cairn signup           Generate keys, sign up, and print the recovery code
  cairn confirm-email    Follow an emailed verification link
  cairn login            Sign in, create a device key, and save it
  cairn logout           Revoke the device key and forget it (--force: forget it even if the revoke fails)
  cairn whoami           Show the authenticated user and their fingerprint
  cairn forgot           Ask for a password reset link
  cairn reset            Set a new password from an emailed reset link
  cairn keys             Manage API keys (list|revoke)
  cairn artifact         Manage artifacts (list|create NAME|show|update|delete)
  cairn members          List an artifact's owner and members, with pin states, from its verified chain
  cairn share            Add a member, or promote a viewer (ARTIFACT USER --role viewer|editor)
  cairn unshare          Remove a member and start a new epoch (ARTIFACT USER)
  cairn team             Share with the whole team, or stop (ARTIFACT none|viewer|editor)
  cairn approve          List team members waiting, or approve one by name (ARTIFACT [USER])
  cairn review           List versions pushed by someone no longer an editor, which need a vouch (ARTIFACT)
  cairn vouch            Vouch for a version after reviewing it (ARTIFACT VERSION)
  cairn public           Turn the public link on or off (ARTIFACT on|off [--writes on|off])
  cairn pin              Pin a user's fingerprint in your keyring (--verified once compared)
  cairn transfer         Offer ownership to an editor (ARTIFACT USER), or answer an offer (accept|decline|withdraw ARTIFACT)
  cairn successor        Name a successor, or ask for access as one (code|status|nominate|remove|refuse|request|notice-email)
  cairn rotate-keys      Replace your keys, move your artifacts to a new epoch (--keep-epochs: stay), and print the new recovery code
  cairn push             Upload a directory as a new (or replaced) version (--create: new artifact)
  cairn db               Run SQL on a version's database, on your own decrypted copy (query|batch|revisions|restore|download)
  cairn files            Manage a version's stored files by path (list|put|get|delete)
  cairn reseal           Seal an artifact's data again under its current epoch (ARTIFACT); runs after unshare, public off, and the like
  cairn import           Import the artifacts of a backup from a server that predates encryption (BACKUP-DIR)
  cairn open             Print (or open) an artifact URL

Run 'cairn <command> -h' for command flags. Client commands honor
CAIRN_HOST and CAIRN_API_KEY for headless use.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = runServe(args)
	case "signup":
		err = runSignup(args)
	case "confirm-email":
		err = runConfirmEmail(args)
	case "login":
		err = runLogin(args)
	case "logout":
		err = runLogout(args)
	case "whoami":
		err = runWhoami(args)
	case "forgot":
		err = runForgot(args)
	case "reset":
		err = runReset(args)
	case "keys":
		err = runKeys(args)
	case "artifact":
		err = runArtifact(args)
	case "members":
		err = runMembers(args)
	case "share":
		err = runShare(args)
	case "unshare":
		err = runUnshare(args)
	case "team":
		err = runTeam(args)
	case "approve":
		err = runApprove(args)
	case "review":
		err = runReview(args)
	case "vouch":
		err = runVouch(args)
	case "public":
		err = runPublic(args)
	case "pin":
		err = runPin(args)
	case "transfer":
		err = runTransfer(args)
	case "successor":
		err = runSuccessor(args)
	case "rotate-keys":
		err = runRotateKeys(args)
	case "push":
		err = runPush(args)
	case "db":
		err = runDB(args)
	case "files":
		err = runFiles(args)
	case "reseal":
		err = runReseal(args)
	case "import":
		err = runImport(args)
	case "open":
		err = runOpen(args)
	case "verify":
		err = runVerify(args)
	case "backup":
		err = runBackup(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// envOr returns the environment value or a default.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
