// Package sqlrun runs one SQL statement on a transaction and shapes the
// outcome as JSON-friendly values. It holds the single-statement scanner, which
// is mechanical tokenization only: whether a statement wrote is never decided
// by parsing it.
package sqlrun

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
)

// Statement is one SQL statement with its bound parameters.
type Statement struct {
	SQL    string `json:"sql"`
	Params []any  `json:"params"`
}

// Result is the JSON-friendly outcome of one statement.
type Result struct {
	Columns      []string `json:"columns"`
	Types        []string `json:"types"`
	Rows         [][]any  `json:"rows"`
	RowsAffected int64    `json:"rowsAffected"`
	LastInsertID int64    `json:"lastInsertId"`
}

// ErrMultiStatement is returned when a statement string contains more than one
// SQL statement. The driver's behavior for such input is undefined (it may
// execute the tail), so it is rejected up front; a batch is the multi-statement
// path.
var ErrMultiStatement = errors.New("only one SQL statement per call is allowed; use db batch for scripts")

// IsSingleStatement scans the input, skipping string literals, quoted
// identifiers and comments, and reports whether at most one statement is
// present.
func IsSingleStatement(sqlText string) bool {
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
			return isBlank(s[i+1:])
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

// Run runs stmt on tx and returns its rows, and the rows it changed and the
// last row it inserted, as the connection reports them.
func Run(ctx context.Context, tx *sql.Tx, stmt Statement) (*Result, error) {
	if !IsSingleStatement(stmt.SQL) {
		return nil, ErrMultiStatement
	}
	rows, err := tx.QueryContext(ctx, stmt.SQL, stmt.Params...)
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
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT changes(), last_insert_rowid()`).Scan(&res.RowsAffected, &res.LastInsertID); err != nil {
		return nil, err
	}
	return res, nil
}

// jsonValue converts SQLite values to JSON-friendly ones; BLOBs become
// base64 strings.
func jsonValue(v any) any {
	if b, ok := v.([]byte); ok {
		return base64.StdEncoding.EncodeToString(b)
	}
	return v
}
