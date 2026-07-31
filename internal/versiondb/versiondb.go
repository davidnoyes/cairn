// Package versiondb manages the per-version shared SQLite databases exposed
// through the raw SQL API.
//
// Write access is enforced at the connection level, never by parsing SQL:
// anonymous requests run on a query_only connection pool, authenticated
// requests on a read-write pool. Databases are created lazily on first
// authenticated use.
package versiondb

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aloisdeniel/cairn/internal/store"
	_ "modernc.org/sqlite"
)

// maxOpen bounds how many version databases keep open handles at once;
// least-recently-used idle entries are closed beyond that.
const maxOpen = 64

var (
	// ErrReadOnly is returned when an unauthenticated caller attempts a write.
	ErrReadOnly = errors.New("write attempted on read-only database access")
	// ErrNoDatabase is returned by reads when the database was never created.
	ErrNoDatabase = errors.New("database does not exist yet")
)

// Statement is one SQL statement with its bound parameters.
type Statement struct {
	SQL    string `json:"sql"`
	Params []any  `json:"params"`
}

// ErrMultiStatement is returned when a statement string contains more than one
// SQL statement. The driver's behavior for such input is undefined (it may
// execute the tail), so it is rejected up front; Batch is the multi-statement
// path.
var ErrMultiStatement = errors.New("only one SQL statement per call is allowed; use the batch endpoint for scripts")

// isSingleStatement scans the input, skipping string literals, quoted
// identifiers and comments, and reports whether at most one statement is
// present. This is mechanical tokenization — read/write authorization never
// depends on it (that is enforced at the connection level).
func isSingleStatement(sqlText string) bool {
	s := sqlText
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\'', '"', '`':
			// Quoted region; doubled quotes escape themselves.
			for i++; i < len(s); i++ {
				if s[i] == c {
					if i+1 < len(s) && s[i+1] == c {
						i++
						continue
					}
					break
				}
			}
		case '[':
			for i++; i < len(s) && s[i] != ']'; i++ {
			}
		case '-':
			if i+1 < len(s) && s[i+1] == '-' {
				for i += 2; i < len(s) && s[i] != '\n'; i++ {
				}
			}
		case '/':
			if i+1 < len(s) && s[i+1] == '*' {
				end := strings.Index(s[i+2:], "*/")
				if end < 0 {
					return true // unterminated comment: nothing after it
				}
				i += 2 + end + 1
			}
		case ';':
			// A semicolon is fine only if everything after it is whitespace
			// or comments.
			rest := s[i+1:]
			return isBlank(rest)
		}
	}
	return true
}

// isBlank reports whether s contains only whitespace and comments.
func isBlank(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i += 2; i < len(s) && s[i] != '\n'; i++ {
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return true
			}
			i += 2 + end + 1
		case c == ';':
			// stray trailing semicolons are harmless
		default:
			return false
		}
	}
	return true
}

// Result is the JSON-friendly outcome of one statement.
type Result struct {
	Columns      []string `json:"columns"`
	Types        []string `json:"types"`
	Rows         [][]any  `json:"rows"`
	RowsAffected int64    `json:"rowsAffected"`
	LastInsertID int64    `json:"lastInsertId"`
	Truncated    bool     `json:"truncated,omitempty"`
}

type entry struct {
	key      string
	ro, rw   *sql.DB
	refs     int
	lastUsed time.Time
	// stale entries are closed once their refcount drains (set by Invalidate).
	stale bool
}

// Manager caches open handles to version databases.
type Manager struct {
	layout  store.Layout
	timeout time.Duration
	maxRows int

	mu      sync.Mutex
	entries map[string]*entry
}

func NewManager(layout store.Layout, timeout time.Duration, maxRows int) *Manager {
	return &Manager{layout: layout, timeout: timeout, maxRows: maxRows, entries: make(map[string]*entry)}
}

func key(artifactID, versionID string) string { return artifactID + "/" + versionID }

func dsn(path string, readOnly bool) string {
	base := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)", path)
	if readOnly {
		// query_only rejects writes at the SQLite level while still allowing
		// WAL/shm coordination files to be used, unlike mode=ro.
		base += "&_pragma=query_only(1)"
	}
	return base
}

// acquire returns the entry for a version database, opening it if needed.
// When create is false and the database file does not exist, ErrNoDatabase is
// returned (without creating an empty file).
func (m *Manager) acquire(artifactID, versionID string, create bool) (*entry, error) {
	path := m.layout.VersionDB(artifactID, versionID)
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(artifactID, versionID)
	e := m.entries[k]
	if e != nil && !e.stale {
		e.refs++
		e.lastUsed = time.Now()
		return e, nil
	}
	if _, err := os.Stat(path); err != nil {
		if !create {
			return nil, ErrNoDatabase
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
	}
	rw, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		return nil, err
	}
	rw.SetMaxOpenConns(1) // single writer per database
	ro, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		rw.Close()
		return nil, err
	}
	ro.SetMaxOpenConns(4)
	e = &entry{key: k, ro: ro, rw: rw, refs: 1, lastUsed: time.Now()}
	m.entries[k] = e
	m.evictLocked()
	return e, nil
}

func (m *Manager) release(e *entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.refs--
	if e.refs == 0 && (e.stale || m.entries[e.key] != e) {
		e.ro.Close()
		e.rw.Close()
	}
}

// evictLocked closes idle handles beyond maxOpen, oldest first.
func (m *Manager) evictLocked() {
	for len(m.entries) > maxOpen {
		var oldest *entry
		for _, e := range m.entries {
			if e.refs > 0 {
				continue
			}
			if oldest == nil || e.lastUsed.Before(oldest.lastUsed) {
				oldest = e
			}
		}
		if oldest == nil {
			return // everything is in use; try again on a later acquire
		}
		oldest.ro.Close()
		oldest.rw.Close()
		delete(m.entries, oldest.key)
	}
}

// Invalidate drops cached handles for a version (used when the version or its
// artifact is deleted). In-flight queries finish on the old handles.
func (m *Manager) Invalidate(artifactID, versionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(artifactID, versionID)
	if e := m.entries[k]; e != nil {
		e.stale = true
		delete(m.entries, k)
		if e.refs == 0 {
			e.ro.Close()
			e.rw.Close()
		}
	}
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, e := range m.entries {
		e.ro.Close()
		e.rw.Close()
		delete(m.entries, k)
	}
}

// Exec runs one statement against a version database. write selects the
// read-write pool (authenticated callers); otherwise the query_only pool is
// used and the database is not created if absent.
func (m *Manager) Exec(ctx context.Context, artifactID, versionID string, write bool, stmt Statement) (*Result, error) {
	e, err := m.acquire(artifactID, versionID, write)
	if err != nil {
		if errors.Is(err, ErrNoDatabase) {
			// A never-written database reads as empty.
			return &Result{Columns: []string{}, Types: []string{}, Rows: [][]any{}}, nil
		}
		return nil, err
	}
	defer m.release(e)
	db := e.ro
	if write {
		db = e.rw
	}
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return m.runStatement(ctx, conn, stmt, write)
}

// Batch runs statements inside a single transaction on the read-write pool,
// giving clients atomic migrations.
func (m *Manager) Batch(ctx context.Context, artifactID, versionID string, stmts []Statement) ([]*Result, error) {
	e, err := m.acquire(artifactID, versionID, true)
	if err != nil {
		return nil, err
	}
	defer m.release(e)
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	tx, err := e.rw.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	results := make([]*Result, 0, len(stmts))
	for i, stmt := range stmts {
		res, err := m.runQuerier(ctx, tx, stmt)
		if err != nil {
			return nil, fmt.Errorf("statement %d: %w", i+1, err)
		}
		results = append(results, res)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return results, nil
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (m *Manager) runStatement(ctx context.Context, conn *sql.Conn, stmt Statement, write bool) (*Result, error) {
	res, err := m.runQuerier(ctx, conn, stmt)
	if err != nil {
		return nil, err
	}
	if write {
		// changes()/last_insert_rowid() are per-connection, and conn pins one.
		conn.QueryRowContext(ctx, `SELECT changes(), last_insert_rowid()`).Scan(&res.RowsAffected, &res.LastInsertID)
	}
	return res, nil
}

func (m *Manager) runQuerier(ctx context.Context, q querier, stmt Statement) (*Result, error) {
	if !isSingleStatement(stmt.SQL) {
		return nil, ErrMultiStatement
	}
	rows, err := q.QueryContext(ctx, stmt.SQL, stmt.Params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	types := make([]string, len(cols))
	if colTypes, err := rows.ColumnTypes(); err == nil {
		for i, ct := range colTypes {
			types[i] = ct.DatabaseTypeName()
		}
	}
	res := &Result{Columns: cols, Types: types, Rows: [][]any{}}
	for rows.Next() {
		if len(res.Rows) >= m.maxRows {
			res.Truncated = true
			break
		}
		scan := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range scan {
			ptrs[i] = &scan[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, v := range scan {
			scan[i] = jsonValue(v)
		}
		res.Rows = append(res.Rows, scan)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if tr, ok := q.(*sql.Tx); ok {
		tr.QueryRowContext(ctx, `SELECT changes(), last_insert_rowid()`).Scan(&res.RowsAffected, &res.LastInsertID)
	}
	return res, nil
}

// jsonValue converts SQLite values to JSON-friendly ones; BLOBs become
// base64 strings.
func jsonValue(v any) any {
	switch t := v.(type) {
	case []byte:
		return base64.StdEncoding.EncodeToString(t)
	default:
		return v
	}
}

// PreparedPath checkpoints the WAL (if the database is open) and returns the
// database file path for download, or ErrNoDatabase.
func (m *Manager) PreparedPath(ctx context.Context, artifactID, versionID string) (string, error) {
	path := m.layout.VersionDB(artifactID, versionID)
	if _, err := os.Stat(path); err != nil {
		return "", ErrNoDatabase
	}
	e, err := m.acquire(artifactID, versionID, false)
	if err != nil {
		return "", err
	}
	defer m.release(e)
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	if _, err := e.rw.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return "", err
	}
	return path, nil
}

// DeleteDatabase invalidates handles and removes the database file (version
// deletion).
func (m *Manager) DeleteDatabase(artifactID, versionID string) error {
	m.Invalidate(artifactID, versionID)
	path := m.layout.VersionDB(artifactID, versionID)
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
