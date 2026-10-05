package client

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aloisdeniel/cairn/internal/sqlrun"
)

// countPuts makes d's client count its database PUTs in the returned counter.
func countPuts(c *Client) *atomic.Int32 {
	var n atomic.Int32
	intercept(c, &tamper{before: func(req *http.Request) *http.Response {
		if req.Method == "PUT" && strings.HasSuffix(req.URL.Path, "/db") {
			n.Add(1)
		}
		return nil
	}})
	return &n
}

func TestExecRunsSQLOnAPrivateCopy(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	exec(t, d, "CREATE TABLE t (n INTEGER, data BLOB)")
	ins := exec(t, d, "INSERT INTO t VALUES (?, x'00ff')", 7)
	if ins.RowsAffected != 1 || ins.LastInsertID != 1 {
		t.Errorf("insert = %+v", ins)
	}
	res := exec(t, d, "SELECT n, data FROM t")
	if len(res.Rows) != 1 || res.Rows[0][0].(int64) != 7 || res.Rows[0][1] != "AP8=" || res.Columns[0] != "n" {
		t.Errorf("select = %+v", res)
	}
	// Each write is a revision: create, insert; the select wrote nothing.
	if revs, _ := d.Revisions(); len(revs) != 2 {
		t.Errorf("%d revisions, want 2", len(revs))
	}
	// A batch is one transaction: a failure in it leaves the database as it was.
	_, err := d.Exec([]sqlrun.Statement{
		{SQL: "INSERT INTO t (n) VALUES (1)"},
		{SQL: "INSERT INTO nowhere VALUES (1)"},
	})
	if err == nil || !strings.Contains(err.Error(), "statement 2") {
		t.Fatalf("a failing batch = %v, want an error naming statement 2", err)
	}
	if res := exec(t, d, "SELECT count(*) FROM t"); res.Rows[0][0].(int64) != 1 {
		t.Errorf("the failed batch left %v rows, want 1", res.Rows[0][0])
	}
	out, err := d.Exec([]sqlrun.Statement{{SQL: "INSERT INTO t (n) VALUES (2)"}, {SQL: "INSERT INTO t (n) VALUES (3)"}})
	if err != nil || len(out) != 2 {
		t.Fatalf("batch = %+v, %v, want one result per statement", out, err)
	}
	if res := exec(t, d, "SELECT count(*) FROM t"); res.Rows[0][0].(int64) != 3 {
		t.Errorf("rows = %v, want 3", res.Rows[0][0])
	}
}

func TestExecRefusesMoreThanOneStatement(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	exec(t, d, "CREATE TABLE t (n INTEGER)")
	puts := countPuts(e.ada)
	_, err := d.Exec([]sqlrun.Statement{{SQL: "INSERT INTO t VALUES (1); DROP TABLE t"}})
	if !errors.Is(err, sqlrun.ErrMultiStatement) {
		t.Fatalf("Exec = %v, want ErrMultiStatement", err)
	}
	if puts.Load() != 0 {
		t.Errorf("a refused statement uploaded %d revisions", puts.Load())
	}
	if res := exec(t, d, "SELECT count(*) FROM t"); res.Rows[0][0].(int64) != 0 {
		t.Errorf("the tail ran: %v rows", res.Rows[0][0])
	}
}

// TestExecDetectsAWriteBySignal runs, for each of the three signals, a
// statement that moves that one alone, and one that moves none.
func TestExecDetectsAWriteBySignal(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		puts int32
	}{
		{"total_changes only", "INSERT INTO t VALUES (1)", 1},
		{"schema_version only", "CREATE TABLE u (n INTEGER)", 1},
		{"user_version only", "PRAGMA user_version = 3", 1},
		{"a pure read", "SELECT * FROM t", 0},
		{"a write that changes nothing", "UPDATE t SET n = 1 WHERE n = 99", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newDataEnv(t)
			d := e.open(t, e.ada, true)
			exec(t, d, "CREATE TABLE t (n INTEGER)")
			puts := countPuts(e.ada)
			if _, err := d.Exec([]sqlrun.Statement{{SQL: tc.sql}}); err != nil {
				t.Fatal(err)
			}
			if puts.Load() != tc.puts {
				t.Errorf("%d PUTs, want %d", puts.Load(), tc.puts)
			}
		})
	}
}

func TestExecOnAVersionWithNoDatabaseReadsAsEmpty(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	puts := countPuts(e.ada)
	res := exec(t, d, "SELECT name FROM sqlite_master")
	if len(res.Rows) != 0 || puts.Load() != 0 {
		t.Errorf("rows = %v, PUTs = %d, want none", res.Rows, puts.Load())
	}
	if _, _, err := d.Latest(); !errors.Is(err, ErrNoDatabase) {
		t.Errorf("a read made a database: %v", err)
	}
}

// TestExecConcurrentWritersBothLand has a second writer's revision land between
// the first writer's download and upload: the first gets a 412, reloads, runs
// again, and both rows are there.
func TestExecConcurrentWritersBothLand(t *testing.T) {
	e := newDataEnv(t)
	setup := e.open(t, e.ada, true)
	exec(t, setup, "CREATE TABLE t (who TEXT)")

	rival := e.open(t, e.ada, true)
	c := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	var puts atomic.Int32
	var once sync.Once
	intercept(c, &tamper{before: func(req *http.Request) *http.Response {
		if req.Method == "PUT" && strings.HasSuffix(req.URL.Path, "/db") {
			puts.Add(1)
			once.Do(func() { exec(t, rival, "INSERT INTO t VALUES ('rival')") })
		}
		return nil
	}})
	first := e.open(t, c, true)
	exec(t, first, "INSERT INTO t VALUES ('first')")
	if puts.Load() != 2 {
		t.Errorf("%d PUTs, want 2: one refused with 412, one retried", puts.Load())
	}
	res := exec(t, setup, "SELECT who FROM t ORDER BY who")
	if len(res.Rows) != 2 || res.Rows[0][0] != "first" || res.Rows[1][0] != "rival" {
		t.Fatalf("rows = %v, want both writers' rows", res.Rows)
	}
}

func TestExecGivesUpAfterFiveTries(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	exec(t, d, "CREATE TABLE t (n INTEGER)")
	c := keyedFor(t, e.host, mustAPIKeyOf(t, e.ada))
	var puts atomic.Int32
	intercept(c, &tamper{before: func(req *http.Request) *http.Response {
		if req.Method == "PUT" && strings.HasSuffix(req.URL.Path, "/db") {
			puts.Add(1)
			return replyJSON(req, 412, http.Header{"Etag": {`"9"`}}, `{"error":"If-Match does not name the latest revision"}`)
		}
		return nil
	}})
	_, err := e.open(t, c, true).Exec([]sqlrun.Statement{{SQL: "INSERT INTO t VALUES (1)"}})
	if !errors.Is(err, ErrDatabaseBusy) || puts.Load() != 5 {
		t.Fatalf("Exec = %v after %d PUTs, want ErrDatabaseBusy after 5", err, puts.Load())
	}
}

func TestPutRevisionErrors(t *testing.T) {
	e := newDataEnv(t)
	d := e.open(t, e.ada, true)
	d.aks = map[int][]byte{}
	if _, err := d.PutRevision([]byte("x"), 0); !errors.Is(err, ErrNoWriteKey) {
		t.Errorf("PutRevision with no AK = %v", err)
	}
	if _, err := d.PutFile("a", []byte("x")); !errors.Is(err, ErrNoWriteKey) {
		t.Errorf("PutFile with no AK = %v", err)
	}
	// A reader may not write: the server's 403 comes back as it is.
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	var api *APIError
	if _, err := e.open(t, e.bob, true).PutRevision([]byte("x"), 0); !errors.As(err, &api) || api.Status != 403 {
		t.Errorf("a viewer's PutRevision = %v, want 403", err)
	}
	if _, err := e.open(t, e.bob, true).PutFile("a", []byte("x")); !errors.As(err, &api) || api.Status != 403 {
		t.Errorf("a viewer's PutFile = %v, want 403", err)
	}
}

func TestEpochMovedMidWriteIsNamed(t *testing.T) {
	e := newDataEnv(t)
	stale := e.open(t, e.ada, true)
	if _, err := e.ada.Share(e.artifact, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ada.Unshare(e.artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := stale.PutRevision([]byte("x"), 0); !errors.Is(err, ErrEpochMoved) {
		t.Errorf("PutRevision on a stale epoch = %v, want ErrEpochMoved", err)
	}
	if _, err := stale.PutFile("a", []byte("x")); !errors.Is(err, ErrEpochMoved) {
		t.Errorf("PutFile on a stale epoch = %v, want ErrEpochMoved", err)
	}
}
