package sqlrun

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "modernc.org/sqlite"
)

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
		if !IsSingleStatement(s) {
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
		if IsSingleStatement(s) {
			t.Errorf("missed multi-statement: %q", s)
		}
	}
}

func testTx(t *testing.T) *sql.Tx {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	return tx
}

func TestRunRefusesMoreThanOneStatement(t *testing.T) {
	tx := testTx(t)
	ctx := context.Background()
	if _, err := Run(ctx, tx, Statement{SQL: "CREATE TABLE t (n INTEGER)"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx, tx, Statement{SQL: "SELECT n FROM t; DROP TABLE t"}); !errors.Is(err, ErrMultiStatement) {
		t.Fatalf("got %v, want ErrMultiStatement", err)
	}
	if _, err := Run(ctx, tx, Statement{SQL: "SELECT COUNT(*) FROM t"}); err != nil {
		t.Fatalf("the table was dropped by the trailing statement: %v", err)
	}
}

func TestRunShapesTheResult(t *testing.T) {
	tx := testTx(t)
	ctx := context.Background()
	if _, err := Run(ctx, tx, Statement{SQL: "CREATE TABLE b (n INTEGER, data BLOB)"}); err != nil {
		t.Fatal(err)
	}
	ins, err := Run(ctx, tx, Statement{SQL: "INSERT INTO b VALUES (?, x'00ff')", Params: []any{7}})
	if err != nil {
		t.Fatal(err)
	}
	if ins.RowsAffected != 1 || ins.LastInsertID != 1 || len(ins.Rows) != 0 {
		t.Errorf("insert = %+v, want 1 row affected, rowid 1, no rows", ins)
	}
	res, err := Run(ctx, tx, Statement{SQL: "SELECT n, data FROM b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Columns) != 2 || res.Columns[0] != "n" || res.Types[0] != "INTEGER" || res.Types[1] != "BLOB" {
		t.Errorf("columns = %v, types = %v", res.Columns, res.Types)
	}
	if res.Rows[0][0].(int64) != 7 || res.Rows[0][1] != "AP8=" {
		t.Errorf("row = %#v, want 7 and the blob as base64", res.Rows[0])
	}
}

func TestRunReportsAStatementError(t *testing.T) {
	if _, err := Run(context.Background(), testTx(t), Statement{SQL: "SELECT * FROM missing"}); err == nil {
		t.Fatal("a statement on a missing table succeeded")
	}
}
