package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aloisdeniel/cairn/internal/client"
)

// The notice of an administrator's handover. Every command that verifies an
// artifact's chain prints it to stderr, once per run, whether or not the
// person acknowledged it; a --json command adds it to its output instead of
// mixing text into stdout.

// handovers holds the latest notice each artifact showed during this run, and
// announced the artifacts it was printed for.
var (
	handovers  = map[string]client.HandoverNotice{}
	announced  = map[string]bool{}
	acceptHelp = "go ahead although ownership was handed over by an administrator, after you confirmed it with the people involved; recorded once"
)

// watchHandovers makes c print the notice, and starts a run with none seen.
func watchHandovers(c *client.Client) {
	handovers, announced = map[string]client.HandoverNotice{}, map[string]bool{}
	c.OnHandover = func(artifactID string, n client.HandoverNotice) {
		handovers[artifactID] = n
		if !announced[artifactID] {
			announced[artifactID] = true
			fmt.Fprintln(os.Stderr, n.String())
		}
	}
}

// acceptNewOwnerFlag is the flag every command that writes to an artifact takes.
func acceptNewOwnerFlag(fs *flag.FlagSet) *bool {
	return fs.Bool("accept-new-owner", false, acceptHelp)
}

// printArtifactJSON prints out, a command's JSON, with the handover notice of
// artifactID when it showed one: {"date", "acked"}.
func printArtifactJSON(artifactID string, out map[string]any) error {
	if n, ok := handovers[artifactID]; ok {
		out["handover"] = map[string]any{"date": n.Date, "acked": n.Acked}
	}
	return printJSON(out)
}
