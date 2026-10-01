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

Client:
  cairn signup           Generate keys, sign up, and print the recovery code
  cairn confirm-email    Follow an emailed verification link
  cairn login            Sign in, create a device key, and save it
  cairn logout           Revoke the device key and forget it
  cairn whoami           Show the authenticated user and their fingerprint
  cairn forgot           Ask for a password reset link
  cairn reset            Set a new password from an emailed reset link
  cairn keys             Manage API keys (list|revoke)
  cairn artifact         Manage artifacts (list|create|show|update|delete)
  cairn push             Upload a directory as a new (or replaced) version
  cairn db               Run SQL against a version's shared database
  cairn files            Manage a version's file storage (list|put|get|delete)
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
	case "push":
		err = runPush(args)
	case "db":
		err = runDB(args)
	case "files":
		err = runFiles(args)
	case "open":
		err = runOpen(args)
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
