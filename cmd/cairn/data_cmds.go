package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/sqlrun"
)

// The db and files commands work on a version's database and stored files,
// which the server holds as sealed blobs. Each downloads and checks what it
// reads, and seals and signs what it writes, as the browser does.

const dbUsage = "cairn db <query|batch|revisions|restore|download> --artifact <id|name> [--version <vid>] [...]"

// dataFlags are the flags every db and files command takes.
type dataFlags struct {
	artifact, version *string
	accept            *bool
}

func newDataFlags(fs *flag.FlagSet) dataFlags {
	return dataFlags{
		artifact: fs.String("artifact", "", "artifact id or name (required)"),
		version:  fs.String("version", "", "version id (default: latest)"),
		accept:   acceptNewOwnerFlag(fs),
	}
}

// open signs in, resolves the artifact, and opens the version's data. A
// command that may write opens it for write.
func (f dataFlags) open(write bool) (*client.Client, *client.Data, string, error) {
	if *f.artifact == "" {
		return nil, nil, "", errors.New("--artifact is required")
	}
	c, err := apiClient()
	if err != nil {
		return nil, nil, "", err
	}
	c.AcceptNewOwner = *f.accept
	a, err := c.ResolveArtifact(*f.artifact)
	if err != nil {
		return nil, nil, "", err
	}
	d, err := c.OpenData(a.ID, *f.version, write)
	if err != nil {
		return nil, nil, "", explainRefusal(c, err)
	}
	return c, d, a.ID, nil
}

func runDB(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: %s", dbUsage)
	}
	switch args[0] {
	case "query":
		return dbQuery(args[1:])
	case "batch":
		return dbBatch(args[1:])
	case "revisions":
		return dbRevisions(args[1:])
	case "restore":
		return dbRestore(args[1:])
	case "download":
		return dbDownload(args[1:])
	}
	return fmt.Errorf("unknown db subcommand %q\nusage: %s", args[0], dbUsage)
}

// runStatements runs stmts on the version's database, and wraps a refusal of
// the keyring as the other write commands do.
func runStatements(f dataFlags, stmts []sqlrun.Statement) ([]*sqlrun.Result, error) {
	c, d, _, err := f.open(true)
	if err != nil {
		return nil, err
	}
	res, err := d.Exec(stmts)
	if err != nil {
		return nil, explainRefusal(c, err)
	}
	return res, nil
}

func dbQuery(args []string) error {
	const usage = `cairn db query --artifact <id|name> [--version <vid>] [--params '[..]'] [--json] "<sql>"`
	fs := flag.NewFlagSet("db query", flag.ExitOnError)
	f := newDataFlags(fs)
	paramsJSON := fs.String("params", "[]", "statement parameters as a JSON array")
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *f.artifact == "" {
		return fmt.Errorf("usage: %s", usage)
	}
	var params []any
	if err := json.Unmarshal([]byte(*paramsJSON), &params); err != nil {
		return fmt.Errorf("--params must be a JSON array: %w", err)
	}
	res, err := runStatements(f, []sqlrun.Statement{{SQL: fs.Arg(0), Params: params}})
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(res[0])
	}
	printResult(res[0])
	return nil
}

func dbBatch(args []string) error {
	const usage = `cairn db batch --artifact <id|name> [--version <vid>] [--file <path>] [--json]`
	fs := flag.NewFlagSet("db batch", flag.ExitOnError)
	f := newDataFlags(fs)
	file := fs.String("file", "", `JSON array of {"sql", "params"} (default: standard input)`)
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *f.artifact == "" {
		return fmt.Errorf("usage: %s", usage)
	}
	var in io.Reader = os.Stdin
	if *file != "" {
		fh, err := os.Open(*file)
		if err != nil {
			return err
		}
		defer fh.Close()
		in = fh
	}
	var stmts []sqlrun.Statement
	if err := json.NewDecoder(in).Decode(&stmts); err != nil {
		return fmt.Errorf(`the batch must be a JSON array of {"sql", "params"}: %w`, err)
	}
	if len(stmts) == 0 {
		return errors.New("the batch holds no statements")
	}
	res, err := runStatements(f, stmts)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(res)
	}
	for i, r := range res {
		fmt.Printf("-- statement %d\n", i+1)
		printResult(r)
	}
	return nil
}

func printResult(res *sqlrun.Result) {
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
	if len(res.Rows) == 0 && res.RowsAffected > 0 {
		fmt.Printf("%d row(s) affected\n", res.RowsAffected)
	}
}

func dbRevisions(args []string) error {
	const usage = "cairn db revisions --artifact <id|name> [--version <vid>] [--json]"
	fs := flag.NewFlagSet("db revisions", flag.ExitOnError)
	f := newDataFlags(fs)
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *f.artifact == "" {
		return fmt.Errorf("usage: %s", usage)
	}
	c, d, _, err := f.open(false)
	if err != nil {
		return err
	}
	revs, err := d.Revisions()
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printJSON(revs)
	}
	for _, r := range revs {
		fmt.Printf("%6d  epoch %-3d %10d  %s  %s\n", r.Revision, r.Epoch, r.Size, r.CreatedAt, r.WrittenBy)
	}
	return nil
}

func dbRestore(args []string) error {
	const usage = "cairn db restore --artifact <id|name> [--version <vid>] --revision <n> [--json]"
	fs := flag.NewFlagSet("db restore", flag.ExitOnError)
	f := newDataFlags(fs)
	revision := fs.Int("revision", 0, "the revision to restore (required)")
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *f.artifact == "" || *revision < 1 {
		return fmt.Errorf("usage: %s", usage)
	}
	c, d, aid, err := f.open(true)
	if err != nil {
		return err
	}
	rev, err := d.Restore(*revision)
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printArtifactJSON(aid, map[string]any{"artifact": aid, "version": d.Version().ID, "restored": *revision, "revision": rev})
	}
	fmt.Printf("restored revision %d as revision %d\n", *revision, rev)
	return nil
}

func dbDownload(args []string) error {
	const usage = "cairn db download --artifact <id|name> [--version <vid>] [--out <file>]"
	fs := flag.NewFlagSet("db download", flag.ExitOnError)
	f := newDataFlags(fs)
	out := fs.String("out", "database.db", "write the database to this file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *f.artifact == "" {
		return fmt.Errorf("usage: %s", usage)
	}
	c, d, _, err := f.open(false)
	if err != nil {
		return err
	}
	plain, rev, err := d.Latest()
	if err != nil {
		return explainRefusal(c, err)
	}
	if err := os.WriteFile(*out, plain, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote revision %d to %s (%d bytes)\n", rev, *out, len(plain))
	return nil
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

func filesList(args []string) error {
	fs := flag.NewFlagSet("files list", flag.ExitOnError)
	f := newDataFlags(fs)
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, d, _, err := f.open(false)
	if err != nil {
		return err
	}
	files, err := d.ListFiles()
	if err != nil {
		return explainRefusal(c, err)
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
	f := newDataFlags(fs)
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
	data, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	name := *remote
	if name == "" {
		name = filepath.Base(local)
	}
	c, d, _, err := f.open(true)
	if err != nil {
		return err
	}
	info, err := d.PutFile(name, data)
	if err != nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		return printJSON(info)
	}
	fmt.Printf("uploaded %s (%d bytes)\n", info.Path, info.Size)
	return nil
}

func filesGet(args []string) error {
	fs := flag.NewFlagSet("files get", flag.ExitOnError)
	f := newDataFlags(fs)
	out := fs.String("out", "", "write to this local file (default: stdout)")
	lead, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	name := leadOrArg(lead, fs)
	if name == "" {
		return fmt.Errorf("usage: cairn files get <remote/path> --artifact <id|name> [--version <vid>] [--out local-file]")
	}
	c, d, _, err := f.open(false)
	if err != nil {
		return err
	}
	data, err := d.GetFile(name)
	if err != nil {
		return explainRefusal(c, err)
	}
	if *out != "" {
		return os.WriteFile(*out, data, 0o644)
	}
	_, err = os.Stdout.Write(data)
	return err
}

func filesDelete(args []string) error {
	fs := flag.NewFlagSet("files delete", flag.ExitOnError)
	f := newDataFlags(fs)
	lead, rest := splitLeadingArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	name := leadOrArg(lead, fs)
	if name == "" {
		return fmt.Errorf("usage: cairn files delete <remote/path> --artifact <id|name> [--version <vid>]")
	}
	c, d, _, err := f.open(true)
	if err != nil {
		return err
	}
	if err := d.DeleteFile(name); err != nil {
		return explainRefusal(c, err)
	}
	fmt.Printf("deleted %s\n", name)
	return nil
}

func runReseal(args []string) error {
	const usage = "cairn reseal ARTIFACT [--accept-new-owner] [--json]"
	fs := flag.NewFlagSet("reseal", flag.ExitOnError)
	accept := acceptNewOwnerFlag(fs)
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
	res, err := c.Reseal(a.ID)
	if err != nil && res == nil {
		return explainRefusal(c, err)
	}
	if *jsonOut {
		if perr := printArtifactJSON(a.ID, map[string]any{"artifact": a.ID, "resealed": resealJSON(res, err)}); perr != nil {
			return perr
		}
		return err
	}
	if res.Databases == 0 && res.Files == 0 && res.Versions == 0 && len(res.Skipped) == 0 && err == nil {
		fmt.Println("nothing to seal again: the data is under the current epoch")
		return nil
	}
	printReseal(a.ID, res, nil)
	return err
}
