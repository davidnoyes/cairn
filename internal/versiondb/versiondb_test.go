package versiondb

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/store"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	layout, err := store.NewLayout(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(layout, 5*time.Second, 100)
	t.Cleanup(m.Close)
	return m
}

func TestLazyCreationAndReadWrite(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()

	// Anonymous read of a nonexistent database: empty result, no file created.
	res, err := m.Exec(ctx, "a1", "v1", false, Statement{SQL: "SELECT * FROM sqlite_master"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 0 {
		t.Errorf("expected empty result, got %+v", res)
	}

	// Authenticated write creates the database.
	if _, err := m.Exec(ctx, "a1", "v1", true, Statement{SQL: "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)"}); err != nil {
		t.Fatal(err)
	}
	w, err := m.Exec(ctx, "a1", "v1", true, Statement{SQL: "INSERT INTO notes (body) VALUES (?)", Params: []any{"hello"}})
	if err != nil {
		t.Fatal(err)
	}
	if w.RowsAffected != 1 || w.LastInsertID != 1 {
		t.Errorf("write result: %+v", w)
	}

	// Anonymous read now sees data.
	res, err = m.Exec(ctx, "a1", "v1", false, Statement{SQL: "SELECT body FROM notes"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 || res.Rows[0][0] != "hello" {
		t.Errorf("read result: %+v", res.Rows)
	}

	// Anonymous write is rejected at the connection level.
	if _, err := m.Exec(ctx, "a1", "v1", false, Statement{SQL: "INSERT INTO notes (body) VALUES ('nope')"}); err == nil {
		t.Error("anonymous write succeeded")
	}
	// ...including sneaky writes that defeat keyword sniffing.
	if _, err := m.Exec(ctx, "a1", "v1", false, Statement{SQL: "WITH x AS (SELECT 1) INSERT INTO notes (body) SELECT 'sneaky' FROM x"}); err == nil {
		t.Error("CTE write on read-only connection succeeded")
	}
	res, _ = m.Exec(ctx, "a1", "v1", false, Statement{SQL: "SELECT COUNT(*) FROM notes"})
	if res.Rows[0][0].(int64) != 1 {
		t.Errorf("row count changed: %+v", res.Rows)
	}
}

func TestMultiStatementBehavior(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	if _, err := m.Exec(ctx, "a1", "v1", true, Statement{SQL: "CREATE TABLE t (n INTEGER)"}); err != nil {
		t.Fatal(err)
	}
	// Multi-statement input is rejected up front (the driver would otherwise
	// execute the tail with undefined semantics).
	_, err := m.Exec(ctx, "a1", "v1", true, Statement{SQL: "SELECT n FROM t; DROP TABLE t"})
	if !errors.Is(err, ErrMultiStatement) {
		t.Fatalf("expected ErrMultiStatement, got %v", err)
	}
	if _, err := m.Exec(ctx, "a1", "v1", true, Statement{SQL: "SELECT COUNT(*) FROM t"}); err != nil {
		t.Fatalf("table was dropped by trailing statement: %v", err)
	}
}

func TestSingleStatementScanner(t *testing.T) {
	single := []string{
		"SELECT 1",
		"SELECT 1;",
		"SELECT 1; ",
		"SELECT 1; -- trailing comment",
		"SELECT 1; /* done */",
		"SELECT ';' FROM t",
		`SELECT "a;b" FROM t`,
		"SELECT `a;b` FROM t",
		"SELECT [a;b] FROM t",
		"SELECT 1 -- comment; DROP TABLE t",
		"SELECT 1 /* ; DROP TABLE t */",
		"SELECT 'it''s; fine'",
		"SELECT 1;;",
	}
	for _, s := range single {
		if !isSingleStatement(s) {
			t.Errorf("false positive: %q", s)
		}
	}
	multi := []string{
		"SELECT 1; SELECT 2",
		"SELECT 1;DROP TABLE t",
		"SELECT ';'; DROP TABLE t",
		"SELECT 1; /* c */ DROP TABLE t",
		"SELECT 1; -- c\nDROP TABLE t",
	}
	for _, s := range multi {
		if isSingleStatement(s) {
			t.Errorf("missed multi-statement: %q", s)
		}
	}
}

func TestBatchAtomicity(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	if _, err := m.Batch(ctx, "a1", "v1", []Statement{
		{SQL: "CREATE TABLE t (n INTEGER NOT NULL)"},
		{SQL: "INSERT INTO t VALUES (1)"},
		{SQL: "INSERT INTO t VALUES (2)"},
	}); err != nil {
		t.Fatal(err)
	}
	// A failing statement rolls back the whole batch.
	_, err := m.Batch(ctx, "a1", "v1", []Statement{
		{SQL: "INSERT INTO t VALUES (3)"},
		{SQL: "INSERT INTO t VALUES (NULL)"}, // NOT NULL violation
	})
	if err == nil {
		t.Fatal("batch with violation succeeded")
	}
	res, err := m.Exec(ctx, "a1", "v1", true, Statement{SQL: "SELECT COUNT(*) FROM t"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows[0][0].(int64) != 2 {
		t.Errorf("rollback failed, count = %v", res.Rows[0][0])
	}
}

func TestRowLimitAndTypes(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	stmts := []Statement{{SQL: "CREATE TABLE t (n INTEGER)"}}
	for i := 0; i < 150; i++ {
		stmts = append(stmts, Statement{SQL: "INSERT INTO t VALUES (?)", Params: []any{i}})
	}
	if _, err := m.Batch(ctx, "a1", "v1", stmts); err != nil {
		t.Fatal(err)
	}
	res, err := m.Exec(ctx, "a1", "v1", false, Statement{SQL: "SELECT n FROM t ORDER BY n"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Rows) != 100 {
		t.Errorf("truncation: truncated=%v rows=%d", res.Truncated, len(res.Rows))
	}
	if res.Columns[0] != "n" {
		t.Errorf("columns: %v", res.Columns)
	}
}

func TestInvalidateAndDelete(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	if _, err := m.Exec(ctx, "a1", "v1", true, Statement{SQL: "CREATE TABLE t (n INTEGER)"}); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteDatabase("a1", "v1"); err != nil {
		t.Fatal(err)
	}
	// Reads after deletion behave like a fresh version.
	res, err := m.Exec(ctx, "a1", "v1", false, Statement{SQL: "SELECT 1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 0 {
		t.Errorf("expected empty result after delete, got %+v", res.Rows)
	}
	if _, err := m.PreparedPath(ctx, "a1", "v1"); !errors.Is(err, ErrNoDatabase) {
		t.Errorf("PreparedPath after delete: %v", err)
	}
}

func TestBlobsAreBase64(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	if _, err := m.Batch(ctx, "a1", "v1", []Statement{
		{SQL: "CREATE TABLE b (data BLOB)"},
		{SQL: "INSERT INTO b VALUES (x'00ff')"},
	}); err != nil {
		t.Fatal(err)
	}
	res, err := m.Exec(ctx, "a1", "v1", false, Statement{SQL: "SELECT data FROM b"})
	if err != nil {
		t.Fatal(err)
	}
	sv, ok := res.Rows[0][0].(string)
	if !ok || !strings.EqualFold(sv, "AP8=") {
		t.Errorf("blob encoding: %#v", res.Rows[0][0])
	}
}
