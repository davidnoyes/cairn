package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"

	"github.com/aloisdeniel/cairn/internal/client"
)

func runRotateKeys(args []string) error {
	const usage = "cairn rotate-keys [--keep-epochs] [--json] [--password-stdin]"
	fs := flag.NewFlagSet("rotate-keys", flag.ExitOnError)
	keepEpochs := fs.Bool("keep-epochs", false, "keep each artifact you own at its current epoch, instead of starting a new one")
	jsonOut := fs.Bool("json", false, "JSON output")
	pwStdin := fs.Bool("password-stdin", false, "read the password from stdin (one line)")
	if _, err := parsePositional(fs, args, 0, usage); err != nil {
		return err
	}
	// The rotation revokes every API key, so a key that came from the
	// environment would be dead with nothing to replace it.
	if os.Getenv("CAIRN_API_KEY") != "" || os.Getenv("CAIRN_HOST") != "" {
		return errors.New("rotate-keys revokes every API key, CAIRN_API_KEY included; unset CAIRN_HOST and CAIRN_API_KEY, sign in with cairn login, then run it again")
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	password, err := readPasswordOrStdin(*pwStdin, "password: ")
	if err != nil {
		return err
	}
	res, err := c.RotateKeys(password, *keepEpochs)
	if res == nil {
		return explainRefusal(c, err)
	}
	// The keys were rotated: save the new device key first, so what is shown
	// says whether it worked, then show what cannot be had again, whatever
	// failed after the server accepted the rotation.
	var serr error
	if res.APIKey != "" {
		serr = saveConfig(cliConfig{Host: c.Host, Email: res.Email, APIKey: res.APIKey})
	}
	if *jsonOut {
		warnings := res.Warnings
		if warnings == nil {
			warnings = []string{}
		}
		if perr := printJSON(map[string]any{
			"seq": res.Seq, "recoveryCode": res.RecoveryCode, "epochs": res.Epochs, "links": res.Links, "warnings": warnings, "unconfirmed": res.Unconfirmed,
		}); perr != nil {
			return perr
		}
	} else {
		printRotation(res, *keepEpochs, res.APIKey != "" && serr == nil)
	}
	if serr != nil {
		return fmt.Errorf("the keys were rotated, but saving the new device key failed: %w; save the new recovery code and run cairn login", serr)
	}
	return err
}

// printRotation shows what a rotation did. saved is whether the new device
// key reached the config file.
func printRotation(res *client.RotateResult, keepEpochs, saved bool) {
	if res.Unconfirmed {
		fmt.Println("The server may have rotated your keys; the error below says why it is not known. If it did, this is your new recovery code and the old one no longer works. Nobody, including an administrator, can recover your account without your password or this code.")
		fmt.Println()
		fmt.Println("  " + res.RecoveryCode)
		fmt.Println()
		fmt.Printf("rotation %d is unconfirmed: run cairn login, then cairn rotate-keys again\n", res.Seq)
		return
	}
	fmt.Println("Keys rotated. Save this recovery code. Nobody, including an administrator, can recover your account without your password or this code. The old recovery code no longer works.")
	fmt.Println()
	fmt.Println("  " + res.RecoveryCode)
	fmt.Println()
	if saved {
		fmt.Printf("rotation %d; every API key was revoked and this device has a new one, saved\n", res.Seq)
	} else {
		fmt.Printf("rotation %d; every API key was revoked and this device has no saved key: run cairn login\n", res.Seq)
	}
	epoch := "moved"
	if keepEpochs {
		epoch = "kept"
	}
	ids := make([]string, 0, len(res.Epochs))
	for id := range res.Epochs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		fmt.Printf("artifact %s: epoch %d (%s)\n", id, res.Epochs[id], epoch)
		if link := res.Links[id]; link != "" {
			fmt.Printf("  new public link, the old one stopped working: %s\n", link)
		}
	}
	for _, w := range res.Warnings {
		fmt.Println("warning: " + w)
	}
}
