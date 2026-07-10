// Package store implements DIYDDNS's persistence layer over SQLite. Every
// aggregate has its own *.go file plus an integration test against a real
// on-disk database created by newTestStore in testdb_test.go.
package store

import (
	"errors"

	sqlite "modernc.org/sqlite"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when a write would violate a UNIQUE constraint
// (e.g., duplicate email, duplicate (user_id, label) on devices).
var ErrConflict = errors.New("store: conflict")

// sqliteConstraintUnique is the SQLite extended result code for a UNIQUE
// constraint violation (SQLITE_CONSTRAINT_UNIQUE). Verified empirically
// against modernc.org/sqlite: see TestIsUniqueViolationDetectsDuplicateKey.
const sqliteConstraintUnique = 2067

// isUniqueViolation reports whether err is a SQLite UNIQUE constraint
// violation, as opposed to some other constraint failure (e.g. CHECK, FK)
// or an unrelated error. Repositories use this to translate a failed
// INSERT/UPDATE into ErrConflict.
func isUniqueViolation(err error) bool {
	var sErr *sqlite.Error
	if errors.As(err, &sErr) {
		return sErr.Code() == sqliteConstraintUnique
	}
	return false
}
