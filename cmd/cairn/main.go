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
  cairn login            Authenticate against a server
  cairn logout           Forget stored credentials
  cairn whoami           Show the authenticated user
  cairn artifact         Manage artifacts (list|create|show|update|delete)
  cairn push             Upload a directory as a new (or replaced) version
  cairn db               Run SQL against a version's shared database
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
	case "login":
		err = runLogin(args)
	case "logout":
		err = runLogout(args)
	case "whoami":
		err = runWhoami(args)
	case "artifact":
		err = runArtifact(args)
	case "push":
		err = runPush(args)
	case "db":
		err = runDB(args)
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
