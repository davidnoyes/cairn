package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aloisdeniel/cairn/internal/client"
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

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	host := fs.String("host", envOr("CAIRN_HOST", loadConfig().Host), "server URL, e.g. http://localhost:8787")
	email := fs.String("email", "", "account email")
	password := fs.String("password", "", "password (prompted when omitted)")
	confirmFlag := fs.String("confirm", "", "password confirmation (first login only, for non-interactive use)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		return fmt.Errorf("--host is required (e.g. cairn login --host http://localhost:8787)")
	}
	reader := bufio.NewReader(os.Stdin)
	if *email == "" {
		fmt.Print("email: ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		*email = strings.TrimSpace(line)
	}
	confirm := *confirmFlag
	if *password == "" {
		p, err := readPassword("password: ")
		if err != nil {
			return err
		}
		*password = p
	}
	c := client.New(*host, "")
	out, err := c.Login(*email, *password, confirm)
	if err != nil && strings.Contains(err.Error(), "first login") {
		// Unclaimed account: this login sets the password.
		fmt.Println("First login: this password will become your account password.")
		confirm, err = readPassword("confirm password: ")
		if err != nil {
			return err
		}
		out, err = c.Login(*email, *password, confirm)
	}
	if err != nil {
		return err
	}
	if err := saveConfig(cliConfig{Host: c.Host, Token: out.Token}); err != nil {
		return err
	}
	fmt.Printf("logged in to %s as %s\n", c.Host, out.User.Email)
	return nil
}

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

func runLogout(args []string) error {
	cfg := loadConfig()
	cfg.Token = ""
	if err := saveConfig(cfg); err != nil {
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
	if *jsonOut {
		return printJSON(me)
	}
	role := "user"
	if me.IsAdmin {
		role = "admin"
	}
	fmt.Printf("%s (%s) — %s on %s\n", me.Email, me.Name, role, c.Host)
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
	name := fs.String("name", "", "artifact name (required)")
	description := fs.String("description", "", "artifact description")
	public := fs.Bool("public", false, "anyone can view without login")
	resource := fs.String("resource", "", "associated resource as type=value (e.g. claude-session=abc)")
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("--name is required")
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	a, err := c.CreateArtifact(*name, *description, *public)
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
	public := fs.String("public", "", "set visibility: true or false")
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
	if *public != "" {
		fields["public"] = *public == "true"
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
	artifact := fs.String("artifact", "", "target artifact id or name (required)")
	create := fs.Bool("create", false, "create the artifact when it does not exist")
	public := fs.Bool("public", false, "with --create: make the new artifact public")
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
		return fmt.Errorf("usage: cairn push <dir> --artifact <id|name> [--create] [--name v1] [--changelog ...] [--overwrite <vid|latest>]")
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if _, err := os.Stat(dir + "/index.html"); err != nil {
		return fmt.Errorf("%s does not contain an index.html", dir)
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	a, err := c.ResolveArtifact(*artifact)
	if err != nil {
		if !*create {
			return fmt.Errorf("%w (use --create to create it)", err)
		}
		a, err = c.CreateArtifact(*artifact, "", *public)
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
		return err
	}
	if *jsonOut {
		return printJSON(map[string]any{
			"artifact": a,
			"version":  v,
			"url":      fmt.Sprintf("%s/artifacts/%s/%s/", c.Host, a.ID, v.ID),
		})
	}
	fmt.Printf("pushed %s as version #%d (%s)\n", dir, v.Seq, v.ID)
	fmt.Printf("  full screen: %s/artifacts/%s/%s/\n", c.Host, a.ID, v.ID)
	fmt.Printf("  shared:      %s/shared/%s\n", c.Host, a.ID)
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
	shared := fs.Bool("shared", false, "print the shared (framed) URL")
	lead, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	target := leadOrArg(lead, fs)
	if target == "" {
		return fmt.Errorf("usage: cairn open <id|name> [--version <vid>] [--shared]")
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
	base := "/artifacts/"
	if *shared {
		base = "/shared/"
	}
	url += base + a.ID
	if *version != "" {
		url += "/" + *version
	}
	if !*shared && *version != "" {
		url += "/"
	}
	fmt.Println(url)
	return nil
}
