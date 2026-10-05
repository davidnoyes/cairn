package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/aloisdeniel/cairn/internal/client"
	_ "modernc.org/sqlite"
)

// import moves the artifacts of a server from before encryption to this one.
// It reads a snapshot made by `cairn backup` in place, writes nothing to disk
// itself, and holds one file at a time in memory.

const importUsage = "cairn import [--json] BACKUP-DIR"

// errInterrupted marks an import stopped by Ctrl-C or SIGTERM.
var errInterrupted = errors.New("interrupted")

// importedArtifact is one artifact the import created.
type importedArtifact struct {
	OldID    string `json:"oldId"`
	NewID    string `json:"newId"`
	Name     string `json:"name"`
	Versions int    `json:"versions"`
	Public   bool   `json:"public"`
}

// oldVersion is one version of the backup, with where its parts are on disk.
// dbPath is empty when the version has no database, files lists the slash
// paths of its stored files.
type oldVersion struct {
	name, changelog string
	contentDir      string
	dbPath          string
	filesDir        string
	files           []string
}

type oldArtifact struct {
	id, name, description string
	public                bool
	resources             [][2]string
	versions              []oldVersion
}

func runImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, err := parsePositional(fs, args, 1, importUsage)
	if err != nil {
		return err
	}
	c, err := apiClient()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Once the first signal arrives, give the default behavior back, so a
	// second Ctrl-C kills the process.
	go func() {
		<-ctx.Done()
		stop()
	}()

	var out io.Writer = os.Stdout
	if *jsonOut {
		out = io.Discard
	}
	done, err := importBackup(ctx, c, pos[0], out, os.Stderr)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(map[string]any{"artifacts": done})
	}
	var public []importedArtifact
	for _, a := range done {
		if a.Public {
			public = append(public, a)
		}
	}
	if len(public) > 0 {
		fmt.Println("\nThese artifacts were public on the old server, and are private now:")
		for _, a := range public {
			fmt.Printf("  %s  %s\n", a.NewID, a.Name)
		}
		fmt.Println("Run 'cairn public <id> on' to make one public again.")
	}
	return nil
}

// importBackup checks the backup in dir, then imports each of its artifacts as
// c. It prints a line to out for each artifact it finishes, and one to
// progress for each version it starts. The artifacts it finished are returned
// even when it fails.
func importBackup(ctx context.Context, c *client.Client, dir string, out, progress io.Writer) ([]importedArtifact, error) {
	plan, err := readBackup(dir)
	if err != nil {
		return nil, err
	}
	done := []importedArtifact{}
	for _, a := range plan {
		imp, err := importArtifact(ctx, c, a, progress)
		if err != nil {
			return done, importFailed(err, done)
		}
		done = append(done, *imp)
		fmt.Fprintf(out, "imported %s as %s: %s (%d versions)\n", imp.OldID, imp.NewID, imp.Name, imp.Versions)
	}
	return done, nil
}

// importFailed is the error for a stopped import: the cause, and what the
// import already created, which a second run would create again.
func importFailed(err error, done []importedArtifact) error {
	if len(done) == 0 {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%v\nalready imported (old ID -> new ID):", err)
	for _, a := range done {
		fmt.Fprintf(&b, "\n  %s -> %s  %s", a.OldID, a.NewID, a.Name)
	}
	b.WriteString("\nrunning the import again imports every artifact again, so delete these first with 'cairn artifact delete'")
	return errors.New(b.String())
}

// interrupted is errInterrupted once the person asked to stop.
func interrupted(ctx context.Context) error {
	if ctx.Err() != nil {
		return errInterrupted
	}
	return nil
}

// importArtifact creates a private artifact for a and uploads its versions. A
// failure or interrupt deletes the partly imported artifact.
func importArtifact(ctx context.Context, c *client.Client, a oldArtifact, progress io.Writer) (*importedArtifact, error) {
	if err := interrupted(ctx); err != nil {
		return nil, err
	}
	created, err := c.CreateArtifact(a.name, a.description)
	if err != nil {
		return nil, fmt.Errorf("artifact %q: %w", a.name, err)
	}
	if err := importContents(ctx, c, created.ID, a, progress); err != nil {
		if derr := c.DeleteArtifact(created.ID); derr != nil {
			err = fmt.Errorf("%w; deleting the partly imported artifact %s failed too (%v), so delete it yourself", err, created.ID, derr)
		}
		return nil, err
	}
	return &importedArtifact{OldID: a.id, NewID: created.ID, Name: a.name, Versions: len(a.versions), Public: a.public}, nil
}

func importContents(ctx context.Context, c *client.Client, newID string, a oldArtifact, progress io.Writer) error {
	for _, r := range a.resources {
		if err := interrupted(ctx); err != nil {
			return err
		}
		if err := c.AddResource(newID, r[0], r[1]); err != nil {
			return fmt.Errorf("artifact %q: resource %s: %w", a.name, r[0], err)
		}
	}
	for i, v := range a.versions {
		fmt.Fprintf(progress, "importing %q: version %d of %d\n", a.name, i+1, len(a.versions))
		if err := importVersion(ctx, c, newID, v); err != nil {
			return fmt.Errorf("artifact %q, version %d: %w", a.name, i+1, err)
		}
	}
	return nil
}

// importVersion uploads one version's content, database, and stored files,
// then reads them back from the server and compares them with the backup.
func importVersion(ctx context.Context, c *client.Client, newID string, v oldVersion) error {
	if err := interrupted(ctx); err != nil {
		return err
	}
	pushed, err := c.Push(newID, "", v.contentDir, v.name, v.changelog)
	if err != nil {
		return err
	}
	var d *client.Data
	if v.dbPath != "" || len(v.files) > 0 {
		if err := interrupted(ctx); err != nil {
			return err
		}
		if d, err = c.OpenData(newID, pushed.ID, true); err != nil {
			return err
		}
	}
	if v.dbPath != "" {
		if err := interrupted(ctx); err != nil {
			return err
		}
		plain, err := os.ReadFile(v.dbPath)
		if err != nil {
			return err
		}
		base := 0
		if _, rev, err := d.Latest(); err == nil {
			base = rev
		} else if !errors.Is(err, client.ErrNoDatabase) {
			return err
		}
		if _, err := d.PutRevision(plain, base); err != nil {
			return err
		}
	}
	for _, rel := range v.files {
		if err := interrupted(ctx); err != nil {
			return err
		}
		plain, err := os.ReadFile(filepath.Join(v.filesDir, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		if _, err := d.PutFile(rel, plain); err != nil {
			return fmt.Errorf("stored file %s: %w", rel, err)
		}
	}
	if err := interrupted(ctx); err != nil {
		return err
	}
	return readBack(c, newID, pushed.ID, v, d)
}

// readBack compares what the server now holds for the version, decrypted, with
// the backup, and reports the first difference.
func readBack(c *client.Client, newID, versionID string, v oldVersion, d *client.Data) error {
	remote, err := c.VersionFiles(newID, versionID)
	if err != nil {
		return fmt.Errorf("reading the content back: %w", err)
	}
	err = walkFiles(v.contentDir, func(rel, abs string) error {
		local, err := os.ReadFile(abs)
		if err != nil {
			return err
		}
		if got, ok := remote[rel]; !ok || !bytes.Equal(got, local) {
			return fmt.Errorf("read-back check failed: content file %s differs from the backup", rel)
		}
		delete(remote, rel)
		return nil
	})
	if err != nil {
		return err
	}
	if len(remote) > 0 {
		return fmt.Errorf("read-back check failed: the server holds %d content file(s) the backup does not", len(remote))
	}

	if v.dbPath != "" {
		got, _, err := d.Latest()
		if err != nil {
			return fmt.Errorf("reading the database back: %w", err)
		}
		local, err := os.ReadFile(v.dbPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, local) {
			return errors.New("read-back check failed: the database differs from the backup")
		}
	}

	if len(v.files) > 0 {
		listed, err := d.ListFiles()
		if err != nil {
			return fmt.Errorf("listing the stored files back: %w", err)
		}
		paths := make([]string, len(listed))
		for i, f := range listed {
			paths[i] = f.Path
		}
		if want := slices.Sorted(slices.Values(v.files)); !slices.Equal(paths, want) {
			return fmt.Errorf("read-back check failed: the server lists stored files %q, the backup has %q", paths, want)
		}
		for _, rel := range v.files {
			local, err := os.ReadFile(filepath.Join(v.filesDir, filepath.FromSlash(rel)))
			if err != nil {
				return err
			}
			got, err := d.GetFile(rel)
			if err != nil {
				return fmt.Errorf("reading stored file %s back: %w", rel, err)
			}
			if !bytes.Equal(got, local) {
				return fmt.Errorf("read-back check failed: stored file %s differs from the backup", rel)
			}
		}
	}
	return nil
}

// walkFiles calls fn with the slash path and the disk path of every file under
// root, in lexical order. It refuses anything that is not a regular file.
func walkFiles(root string, fn func(rel, abs string) error) error {
	return filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !e.Type().IsRegular() {
			return fmt.Errorf("%q is not a regular file", p)
		}
		return fn(rel, p)
	})
}

// readBackup checks the backup in dir and returns its artifacts in the order to
// import them. It touches nothing on the server, and nothing in dir: the
// metadata database opens read-only and immutable, so SQLite creates no
// journal, WAL, or shared-memory file beside it.
func readBackup(dir string) ([]oldArtifact, error) {
	dbFile := filepath.Join(dir, "cairn.db")
	if _, err := os.Stat(dbFile); err != nil {
		return nil, fmt.Errorf("%s has no cairn.db: it is not a backup made by 'cairn backup' on the old server", dir)
	}
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(e.Name(), ".db-wal") {
			return fmt.Errorf("%s exists: this looks like a live data directory, not a backup; take a snapshot with 'cairn backup' on the old server", p)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(dbFile)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: abs}
	db, err := sql.Open("sqlite", u.String()+"?mode=ro&immutable=1")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := checkOldSchema(db); err != nil {
		return nil, err
	}
	return readOldArtifacts(db, dir)
}

// checkOldSchema refuses a database that is not the one a server from before
// encryption kept: the new server dropped the name and description columns, and
// the version name and changelog columns, into encrypted fields.
func checkOldSchema(db *sql.DB) error {
	for table, cols := range map[string][]string{
		"artifacts":          {"name", "description", "public", "created_at"},
		"artifact_resources": {"artifact_id", "type", "value"},
		"versions":           {"artifact_id", "name", "changelog", "seq", "content_dir"},
	} {
		rows, err := db.Query(`SELECT name FROM pragma_table_info('` + table + `')`)
		if err != nil {
			return fmt.Errorf("cairn.db is not a Cairn database: %w", err)
		}
		have := map[string]bool{}
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				rows.Close()
				return err
			}
			have[n] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, col := range cols {
			if !have[col] {
				return errors.New("this is not a backup of a Cairn server from before encryption: cairn.db lacks " + table + "." + col)
			}
		}
	}
	return nil
}

// readOldArtifacts lists the artifacts, oldest first, with their resources and
// versions, and checks every version's parts so a bad backup fails before the
// first upload.
func readOldArtifacts(db *sql.DB, dir string) ([]oldArtifact, error) {
	rows, err := db.Query(`SELECT id, name, description, public FROM artifacts ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	var out []oldArtifact
	for rows.Next() {
		var a oldArtifact
		var public int
		if err := rows.Scan(&a.id, &a.name, &a.description, &public); err != nil {
			rows.Close()
			return nil, err
		}
		a.public = public != 0
		out = append(out, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		a := &out[i]
		if !filepath.IsLocal(a.id) {
			return nil, fmt.Errorf("artifact ID %q is not a plain name", a.id)
		}
		res, err := db.Query(`SELECT type, value FROM artifact_resources WHERE artifact_id = ? ORDER BY rowid`, a.id)
		if err != nil {
			return nil, err
		}
		for res.Next() {
			var r [2]string
			if err := res.Scan(&r[0], &r[1]); err != nil {
				res.Close()
				return nil, err
			}
			a.resources = append(a.resources, r)
		}
		res.Close()
		if err := res.Err(); err != nil {
			return nil, err
		}
		vs, err := db.Query(`SELECT id, name, changelog, content_dir FROM versions WHERE artifact_id = ? ORDER BY seq`, a.id)
		if err != nil {
			return nil, err
		}
		type row struct{ id, contentDir string }
		var ids []row
		for vs.Next() {
			var v oldVersion
			var r row
			if err := vs.Scan(&r.id, &v.name, &v.changelog, &r.contentDir); err != nil {
				vs.Close()
				return nil, err
			}
			ids = append(ids, r)
			a.versions = append(a.versions, v)
		}
		vs.Close()
		if err := vs.Err(); err != nil {
			return nil, err
		}
		for j, r := range ids {
			if err := checkOldVersion(dir, a, &a.versions[j], r.id, r.contentDir, j+1); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// checkOldVersion fills in where version vid's parts are, and refuses a
// content tree or stored-file path the new server would refuse.
func checkOldVersion(dir string, a *oldArtifact, v *oldVersion, vid, contentDir string, n int) error {
	what := fmt.Sprintf("artifact %q, version %d", a.name, n)
	if !filepath.IsLocal(vid) || !filepath.IsLocal(contentDir) {
		return fmt.Errorf("%s: a directory name in cairn.db is not a plain name", what)
	}
	v.contentDir = filepath.Join(dir, "content", a.id, contentDir)
	if err := client.CheckTree(v.contentDir); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if dbPath := filepath.Join(dir, "dbs", a.id, vid+".db"); fileExists(dbPath) {
		v.dbPath = dbPath
	}
	v.filesDir = filepath.Join(dir, "files", a.id, vid)
	if _, err := os.Stat(v.filesDir); err != nil {
		return nil
	}
	err := walkFiles(v.filesDir, func(rel, _ string) error {
		if err := client.CheckFilePath(rel); err != nil {
			return fmt.Errorf("stored file %q: %w", rel, err)
		}
		v.files = append(v.files, rel)
		return nil
	})
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}
