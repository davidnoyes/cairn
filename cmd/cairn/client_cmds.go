package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/versiondb"
	"golang.org/x/term"
)

// splitLeadingArg peels a leading positional argument off args so commands
// accept both "cairn push <dir> --flags" and "cairn push --flags <dir>"
// (Go's flag package stops parsing at the first positional otherwise).
func splitLeadingArg(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

// leadOrArg resolves the positional argument from either position.
func leadOrArg(lead string, fs *flag.FlagSet) string {
	if lead != "" {
		return lead
	}
	return fs.Arg(0)
}

// readPassword prompts and reads a password without echoing it to a
// terminal, or reads a plain line when stdin isn't one.
func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	if term.IsTerminal(int(syscall.Stdin)) {
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// readPasswordOrStdin implements every command's --password-stdin flag: one
// line from stdin, unprompted, for scripts and tests.
func readPasswordOrStdin(stdin bool, prompt string) (string, error) {
	if stdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	return readPassword(prompt)
}

func runSignup(args []string) error {
	fs := flag.NewFlagSet("signup", flag.ExitOnError)
	host := fs.String("host", envOr("CAIRN_HOST", ""), "server URL, e.g. http://localhost:8787")
	email := fs.String("email", "", "account email")
	name := fs.String("name", "", "display name")
	pwStdin := fs.Bool("password-stdin", false, "read the password from stdin (one line); skips the recovery-code confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" || *email == "" {
		return fmt.Errorf("usage: cairn signup --host <url> --email <email> [--name <name>]")
	}
	password, err := readPasswordOrStdin(*pwStdin, "password: ")
	if err != nil {
		return err
	}
	c := client.New(*host, "")
	recoveryDisplay, err := c.Signup(*email, *name, password)
	if err != nil {
		return err
	}
	fmt.Println("Save this recovery code. Nobody, including an administrator, can recover your account without your password or this code.")
	fmt.Println()
	fmt.Println("  " + recoveryDisplay)
	fmt.Println()
	if !*pwStdin {
		if err := confirmRecoveryCode(recoveryDisplay); err != nil {
			return err
		}
	}
	fmt.Println("check your email to verify your account, then run: cairn confirm-email <link>")
	return nil
}

// confirmRecoveryCode asks the user to retype one randomly chosen group of
// the displayed recovery code, to prove they saved it.
func confirmRecoveryCode(display string) error {
	groups := strings.Split(display, "-")
	idx := randIndex(len(groups))
	fmt.Printf("To confirm you saved it, retype group %d of %d: ", idx+1, len(groups))
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.ToUpper(strings.TrimSpace(line)) != groups[idx] {
		return fmt.Errorf("that doesn't match the recovery code — save it and run signup again")
	}
	return nil
}

func randIndex(n int) int {
	b := make([]byte, 1)
	rand.Read(b)
	return int(b[0]) % n
}

func runConfirmEmail(args []string) error {
	fs := flag.NewFlagSet("confirm-email", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	link := fs.Arg(0)
	if link == "" {
		return fmt.Errorf("usage: cairn confirm-email <link>")
	}
	host, err := client.LinkHost(link)
	if err != nil {
		return err
	}
	if err := client.New(host, "").ConfirmEmail(link); err != nil {
		return err
	}
	fmt.Println("email confirmed")
	return nil
}

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	host := fs.String("host", envOr("CAIRN_HOST", loadConfig().Host), "server URL, e.g. http://localhost:8787")
	email := fs.String("email", "", "account email")
	pwStdin := fs.Bool("password-stdin", false, "read the password from stdin (one line)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		return fmt.Errorf("--host is required (e.g. cairn login --host http://localhost:8787)")
	}
	if *email == "" {
		fmt.Print("email: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return err
		}
		*email = strings.TrimSpace(line)
	}
	password, err := readPasswordOrStdin(*pwStdin, "password: ")
	if err != nil {
		return err
	}
	c := client.New(*host, "")
	out, err := c.Login(*email, password)
	if err != nil {
		return err
	}
	if err := saveConfig(cliConfig{Host: c.Host, Email: out.Email, APIKey: out.APIKey}); err != nil {
		return err
	}
	fmt.Printf("logged in to %s as %s\n", c.Host, out.Email)
	return nil
}

// logoutTimeout bounds logout's revoke call so a black-holed host can't hang
// it. It is a variable so tests can shorten it; only logout uses it, since
// pushes of large uploads must not get a short timeout.
var logoutTimeout = 15 * time.Second

func runLogout(args []string) error {
	fs := flag.NewFlagSet("logout", flag.ExitOnError)
	force := fs.Bool("force", false, "log out locally even if the key could not be revoked on the server")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Getenv("CAIRN_API_KEY") != "" {
		fmt.Fprintln(os.Stderr, "logout revokes only the saved login; the key in CAIRN_API_KEY stays valid (revoke it with `cairn keys revoke <id>`)")
	}
	cfg := loadConfig()
	if cfg.APIKey != "" {
		key, err := e2e.ParseAPIKey(cfg.APIKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "stored API key is unreadable; clearing it without revoking")
		} else {
			c := client.New(cfg.Host, bearerOf(key))
			c.HTTP = &http.Client{Timeout: logoutTimeout}
			if err := c.Logout(key.KeyID); err != nil {
				var apiErr *client.APIError
				// A 401 means the key was already invalid (revoked elsewhere, or
				// expired); there's nothing left to revoke, so log out anyway.
				// Any other failure leaves the key live, so keep the config
				// unless --force.
				if !(errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized) {
					if !*force {
						return fmt.Errorf("could not revoke key %s on %s: %w; you are still logged in (use --force to log out locally anyway)", key.KeyID, cfg.Host, err)
					}
					fmt.Fprintf(os.Stderr, "key %s may still be valid; revoke it after logging in again, or from another device, with `cairn keys revoke %s`\n", key.KeyID, key.KeyID)
				}
			}
		}
	}
	if err := saveConfig(cliConfig{}); err != nil {
		return err
	}
	fmt.Println("logged out")
	return nil
}

func runWhoami(args []string) error {
	fs := flag.NewFlagSet("whoami", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	me, err := c.Me()
	if err != nil {
		return err
	}
	bundle, err := c.MeBundle()
	if err != nil {
		return err
	}
	fp := e2e.FormatFingerprint(e2e.Fingerprint(bundle.X25519Pub, bundle.Ed25519Pub))
	if *jsonOut {
		return printJSON(map[string]any{"user": me, "fingerprint": fp})
	}
	role := "user"
	if me.IsAdmin {
		role = "admin"
	}
	fmt.Printf("%s (%s) — %s on %s\n", me.Email, me.Name, role, c.Host)
	fmt.Printf("fingerprint: %s\n", fp)
	return nil
}

func runForgot(args []string) error {
	fs := flag.NewFlagSet("forgot", flag.ExitOnError)
	host := fs.String("host", envOr("CAIRN_HOST", ""), "server URL")
	email := fs.String("email", "", "account email")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" || *email == "" {
		return fmt.Errorf("usage: cairn forgot --host <url> --email <email>")
	}
	if err := client.New(*host, "").Forgot(*email); err != nil {
		return err
	}
	fmt.Println("if that address has an account, a reset link was sent")
	return nil
}

func runReset(args []string) error {
	fs := flag.NewFlagSet("reset", flag.ExitOnError)
	recoveryCode := fs.String("recovery-code", "", "the saved recovery code")
	noRecoveryCode := fs.Bool("no-recovery-code", false, "generate new keys instead; your existing artifacts become unreadable")
	yes := fs.Bool("yes", false, "confirm --no-recovery-code when stdin is not a terminal")
	pwStdin := fs.Bool("password-stdin", false, "read the new password from stdin (one line)")
	lead, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	link := leadOrArg(lead, fs)
	if link == "" {
		return fmt.Errorf("usage: cairn reset <link> (--recovery-code <code> | --no-recovery-code)")
	}
	if (*recoveryCode == "") == !*noRecoveryCode {
		return fmt.Errorf("specify exactly one of --recovery-code or --no-recovery-code")
	}
	host, err := client.LinkHost(link)
	if err != nil {
		return err
	}
	c := client.New(host, "")

	if *noRecoveryCode {
		fmt.Fprintln(os.Stderr, "warning: without the recovery code, your existing artifacts become unreadable")
		if !*yes && !term.IsTerminal(int(syscall.Stdin)) {
			return fmt.Errorf("refusing to continue on a non-terminal without --yes")
		}
		if !*yes {
			fmt.Print("continue? [y/N] ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.ToLower(strings.TrimSpace(line)) != "y" {
				return fmt.Errorf("aborted")
			}
		}
		password, err := readPasswordOrStdin(*pwStdin, "new password: ")
		if err != nil {
			return err
		}
		recoveryDisplay, err := c.ResetNew(link, password)
		if err != nil {
			return err
		}
		fmt.Println("Save this recovery code. Nobody, including an administrator, can recover your account without your password or this code.")
		fmt.Println()
		fmt.Println("  " + recoveryDisplay)
		return nil
	}

	password, err := readPasswordOrStdin(*pwStdin, "new password: ")
	if err != nil {
		return err
	}
	if err := c.ResetRecovery(link, *recoveryCode, password); err != nil {
		return err
	}
	fmt.Println("password reset")
	return nil
}

func runKeys(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: cairn keys <list|revoke> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return keysList(rest)
	case "revoke":
		return keysRevoke(rest)
	default:
		return fmt.Errorf("unknown keys subcommand %q", sub)
	}
}

func keysList(args []string) error {
	fs := flag.NewFlagSet("keys list", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	keys, err := c.ListKeys()
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(keys)
	}
	for _, k := range keys {
		device := ""
		if k.Device {
			device = " (device)"
		}
		fmt.Printf("%s  %-16s%s  %s\n", k.ID, k.Name, device, k.CreatedAt)
	}
	return nil
}

func keysRevoke(args []string) error {
	fs := flag.NewFlagSet("keys revoke", flag.ExitOnError)
	lead, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	id := leadOrArg(lead, fs)
	if id == "" {
		return fmt.Errorf("usage: cairn keys revoke <id>")
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	if err := c.RevokeKey(id); err != nil {
		return err
	}
	cfg := loadConfig()
	if key, err := e2e.ParseAPIKey(cfg.APIKey); err == nil && key.KeyID == id {
		if err := saveConfig(cliConfig{}); err != nil {
			return err
		}
		fmt.Printf("revoked key %s; this was this device's login, so you are now logged out\n", id)
		return nil
	}
	fmt.Printf("revoked key %s\n", id)
	return nil
}

func runArtifact(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: cairn artifact <list|create|show|update|delete> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return artifactList(rest)
	case "create":
		return artifactCreate(rest)
	case "show":
		return artifactShow(rest)
	case "update":
		return artifactUpdate(rest)
	case "delete":
		return artifactDelete(rest)
	default:
		return fmt.Errorf("unknown artifact subcommand %q", sub)
	}
}

func artifactList(args []string) error {
	fs := flag.NewFlagSet("artifact list", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	as, err := c.ListArtifacts()
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(as)
	}
	for _, a := range as {
		vis := "private"
		if a.Public {
			vis = "public"
		}
		fmt.Printf("%s  %-24s  %-7s  %s\n", a.ID, a.Name, vis, a.Description)
	}
	return nil
}

func artifactCreate(args []string) error {
	fs := flag.NewFlagSet("artifact create", flag.ExitOnError)
	nameFlag := fs.String("name", "", "artifact name (same as the NAME argument)")
	description := fs.String("description", "", "artifact description")
	resource := fs.String("resource", "", "associated resource as type=value (e.g. claude-session=abc)")
	jsonOut := fs.Bool("json", false, "JSON output")
	lead, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	name := leadOrArg(lead, fs)
	if name != "" && *nameFlag != "" && name != *nameFlag {
		return fmt.Errorf("the NAME argument %q and --name %q disagree", name, *nameFlag)
	}
	if name == "" {
		name = *nameFlag
	}
	if name == "" {
		return fmt.Errorf("usage: cairn artifact create NAME [--description D] [--resource type=value] [--json]")
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	a, err := c.CreateArtifact(name, *description)
	if err != nil {
		return err
	}
	if *resource != "" {
		typ, value, ok := strings.Cut(*resource, "=")
		if !ok {
			return fmt.Errorf("--resource must be type=value")
		}
		if err := c.AddResource(a.ID, typ, value); err != nil {
			return err
		}
	}
	if *jsonOut {
		return printJSON(a)
	}
	fmt.Printf("created artifact %s (%s)\n", a.Name, a.ID)
	return nil
}

func artifactShow(args []string) error {
	fs := flag.NewFlagSet("artifact show", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	lead, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	target := leadOrArg(lead, fs)
	if target == "" {
		return fmt.Errorf("usage: cairn artifact show <id|name>")
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	a, err := c.ResolveArtifact(target)
	if err != nil {
		return err
	}
	versions, err := c.ListVersions(a.ID)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(map[string]any{"artifact": a, "versions": versions})
	}
	vis := "private"
	if a.Public {
		vis = "public"
	}
	fmt.Printf("%s (%s, %s)\n%s\n", a.Name, a.ID, vis, a.Description)
	for _, res := range a.Resources {
		fmt.Printf("  resource %s = %s\n", res.Type, res.Value)
	}
	fmt.Printf("versions (%d):\n", len(versions))
	for _, v := range versions {
		fmt.Printf("  #%d  %s  %-16s  %s\n", v.Seq, v.ID, v.Name, v.Changelog)
	}
	return nil
}

func artifactUpdate(args []string) error {
	fs := flag.NewFlagSet("artifact update", flag.ExitOnError)
	name := fs.String("name", "", "new name")
	description := fs.String("description", "", "new description")
	jsonOut := fs.Bool("json", false, "JSON output")
	lead, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	target := leadOrArg(lead, fs)
	if target == "" {
		return fmt.Errorf("usage: cairn artifact update <id|name> [flags]")
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	a, err := c.ResolveArtifact(target)
	if err != nil {
		return err
	}
	fields := map[string]any{}
	if *name != "" {
		fields["name"] = *name
	}
	if *description != "" {
		fields["description"] = *description
	}
	updated, err := c.UpdateArtifact(a.ID, fields)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(updated)
	}
	fmt.Printf("updated artifact %s\n", updated.ID)
	return nil
}

func artifactDelete(args []string) error {
	fs := flag.NewFlagSet("artifact delete", flag.ExitOnError)
	lead, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	target := leadOrArg(lead, fs)
	if target == "" {
		return fmt.Errorf("usage: cairn artifact delete <id|name>")
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	a, err := c.ResolveArtifact(target)
	if err != nil {
		return err
	}
	if err := c.DeleteArtifact(a.ID); err != nil {
		return err
	}
	fmt.Printf("deleted artifact %s (%s)\n", a.Name, a.ID)
	return nil
}

func runPush(args []string) error {
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	accept := acceptNewOwnerFlag(fs)
	artifact := fs.String("artifact", "", "target artifact id or name (required)")
	create := fs.Bool("create", false, "create the artifact when it does not exist")
	name := fs.String("name", "", "version name")
	changelog := fs.String("changelog", "", "version changelog")
	overwrite := fs.String("overwrite", "", "replace this version id ('latest' targets the newest) instead of creating a new version")
	jsonOut := fs.Bool("json", false, "JSON output")
	lead, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	dir := leadOrArg(lead, fs)
	if dir == "" || *artifact == "" {
		return fmt.Errorf("usage: cairn push <dir> --artifact <id|name> [--create] [--name v1] [--changelog ...] [--overwrite <vid|latest>] [--accept-new-owner]")
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if _, err := os.Stat(dir + "/index.html"); err != nil {
		return fmt.Errorf("%s does not contain an index.html", dir)
	}
	if err := client.CheckTree(dir); err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	c.AcceptNewOwner = *accept
	a, err := c.ResolveArtifact(*artifact)
	if err != nil {
		if !*create {
			return fmt.Errorf("%w (use --create to create it)", err)
		}
		a, err = c.CreateArtifact(*artifact, "")
		if err != nil {
			return err
		}
	}
	versionID := ""
	if *overwrite == "latest" {
		versions, err := c.ListVersions(a.ID)
		if err != nil {
			return err
		}
		if len(versions) == 0 {
			return fmt.Errorf("--overwrite latest: artifact has no versions yet")
		}
		versionID = versions[0].ID
	} else {
		versionID = *overwrite
	}
	v, err := c.Push(a.ID, versionID, dir, *name, *changelog)
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printArtifactJSON(a.ID, map[string]any{
			"artifact": a,
			"version":  v,
			"url":      fmt.Sprintf("%s/full/%s/%s", c.Host, a.ID, v.ID),
		})
	}
	fmt.Printf("pushed %s as version #%d (%s)\n", dir, v.Seq, v.ID)
	fmt.Printf("  full screen: %s/full/%s/%s\n", c.Host, a.ID, v.ID)
	fmt.Printf("  shared:      %s/shared/%s/%s\n", c.Host, a.ID, v.ID)
	return nil
}

func runDB(args []string) error {
	if len(args) == 0 || args[0] != "query" {
		return fmt.Errorf("usage: cairn db query --artifact <id|name> [--version <vid>] [--params '[..]'] \"<sql>\"")
	}
	fs := flag.NewFlagSet("db query", flag.ExitOnError)
	artifact := fs.String("artifact", "", "artifact id or name (required)")
	version := fs.String("version", "", "version id (default: latest)")
	paramsJSON := fs.String("params", "[]", "statement parameters as a JSON array")
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 || *artifact == "" {
		return fmt.Errorf("usage: cairn db query --artifact <id|name> [--version <vid>] [--params '[..]'] \"<sql>\"")
	}
	var params []any
	if err := json.Unmarshal([]byte(*paramsJSON), &params); err != nil {
		return fmt.Errorf("--params must be a JSON array: %w", err)
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	a, err := c.ResolveArtifact(*artifact)
	if err != nil {
		return err
	}
	vid, err := resolveVersionID(c, a.ID, *version)
	if err != nil {
		return err
	}
	res, err := c.Query(a.ID, vid, fs.Arg(0), params)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(res)
	}
	printResult(res)
	return nil
}

// resolveVersionID returns the given version id, or the artifact's latest
// version when empty.
func resolveVersionID(c *client.Client, artifactID, version string) (string, error) {
	if version != "" {
		return version, nil
	}
	versions, err := c.ListVersions(artifactID)
	if err != nil {
		return "", err
	}
	if len(versions) == 0 {
		return "", fmt.Errorf("artifact has no versions yet")
	}
	return versions[0].ID, nil
}

func printResult(res *versiondb.Result) {
	if len(res.Columns) > 0 {
		fmt.Println(strings.Join(res.Columns, "\t"))
	}
	for _, row := range res.Rows {
		cells := make([]string, len(row))
		for i, v := range row {
			if v == nil {
				cells[i] = "NULL"
			} else {
				cells[i] = fmt.Sprint(v)
			}
		}
		fmt.Println(strings.Join(cells, "\t"))
	}
	if res.Truncated {
		fmt.Fprintln(os.Stderr, "(result truncated)")
	}
	if len(res.Rows) == 0 && res.RowsAffected > 0 {
		fmt.Printf("%d row(s) affected\n", res.RowsAffected)
	}
}

func runFiles(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: cairn files <list|put|get|delete> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return filesList(rest)
	case "put":
		return filesPut(rest)
	case "get":
		return filesGet(rest)
	case "delete":
		return filesDelete(rest)
	default:
		return fmt.Errorf("unknown files subcommand %q", sub)
	}
}

// filesTarget parses the shared --artifact/--version flags and resolves them.
func filesTarget(artifact, version string) (*client.Client, string, string, error) {
	if artifact == "" {
		return nil, "", "", fmt.Errorf("--artifact is required")
	}
	c, err := apiClient()
	if err != nil {
		return nil, "", "", err
	}
	a, err := c.ResolveArtifact(artifact)
	if err != nil {
		return nil, "", "", err
	}
	vid, err := resolveVersionID(c, a.ID, version)
	if err != nil {
		return nil, "", "", err
	}
	return c, a.ID, vid, nil
}

func filesList(args []string) error {
	fs := flag.NewFlagSet("files list", flag.ExitOnError)
	artifact := fs.String("artifact", "", "artifact id or name (required)")
	version := fs.String("version", "", "version id (default: latest)")
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, aid, vid, err := filesTarget(*artifact, *version)
	if err != nil {
		return err
	}
	files, err := c.ListFiles(aid, vid)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(files)
	}
	for _, f := range files {
		fmt.Printf("%10d  %s  %s\n", f.Size, f.ModifiedAt, f.Path)
	}
	return nil
}

func filesPut(args []string) error {
	fs := flag.NewFlagSet("files put", flag.ExitOnError)
	artifact := fs.String("artifact", "", "artifact id or name (required)")
	version := fs.String("version", "", "version id (default: latest)")
	remote := fs.String("path", "", "storage path (default: the local file name)")
	jsonOut := fs.Bool("json", false, "JSON output")
	lead, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	local := leadOrArg(lead, fs)
	if local == "" {
		return fmt.Errorf("usage: cairn files put <local-file> --artifact <id|name> [--version <vid>] [--path remote/path]")
	}
	f, err := os.Open(local)
	if err != nil {
		return err
	}
	defer f.Close()
	name := *remote
	if name == "" {
		name = filepath.Base(local)
	}
	c, aid, vid, err := filesTarget(*artifact, *version)
	if err != nil {
		return err
	}
	info, err := c.UploadFile(aid, vid, name, f)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(info)
	}
	fmt.Printf("uploaded %s (%d bytes)\n", info.Path, info.Size)
	return nil
}

func filesGet(args []string) error {
	fs := flag.NewFlagSet("files get", flag.ExitOnError)
	artifact := fs.String("artifact", "", "artifact id or name (required)")
	version := fs.String("version", "", "version id (default: latest)")
	out := fs.String("out", "", "write to this local file (default: stdout)")
	lead, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	name := leadOrArg(lead, fs)
	if name == "" {
		return fmt.Errorf("usage: cairn files get <remote/path> --artifact <id|name> [--version <vid>] [--out local-file]")
	}
	c, aid, vid, err := filesTarget(*artifact, *version)
	if err != nil {
		return err
	}
	body, err := c.DownloadFile(aid, vid, name)
	if err != nil {
		return err
	}
	defer body.Close()
	dst := io.Writer(os.Stdout)
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		dst = f
	}
	_, err = io.Copy(dst, body)
	return err
}

func filesDelete(args []string) error {
	fs := flag.NewFlagSet("files delete", flag.ExitOnError)
	artifact := fs.String("artifact", "", "artifact id or name (required)")
	version := fs.String("version", "", "version id (default: latest)")
	lead, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	name := leadOrArg(lead, fs)
	if name == "" {
		return fmt.Errorf("usage: cairn files delete <remote/path> --artifact <id|name> [--version <vid>]")
	}
	c, aid, vid, err := filesTarget(*artifact, *version)
	if err != nil {
		return err
	}
	if err := c.DeleteFile(aid, vid, name); err != nil {
		return err
	}
	fmt.Printf("deleted %s\n", name)
	return nil
}

func runOpen(args []string) error {
	fs := flag.NewFlagSet("open", flag.ExitOnError)
	version := fs.String("version", "", "specific version id")
	full := fs.Bool("full", false, "print the full-screen URL instead of the shared one")
	fs.Bool("shared", false, "accepted for old scripts and does nothing: the shared URL is the default")
	lead, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	target := leadOrArg(lead, fs)
	if target == "" {
		return fmt.Errorf("usage: cairn open <id|name> [--version <vid>] [--full]")
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	a, err := c.ResolveArtifact(target)
	if err != nil {
		return err
	}
	url := c.Host
	base := "/shared/"
	if *full {
		base = "/full/"
	}
	url += base + a.ID
	if *version != "" {
		url += "/" + *version
	}
	fmt.Println(url)
	return nil
}
