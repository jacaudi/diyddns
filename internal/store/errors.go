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

// isUniqueViolation reports whether err is a SQLite uniqueness constraint
// violation. It covers two extended result codes:
//
//   - SQLITE_CONSTRAINT_UNIQUE (2067): UNIQUE index violation.
//   - SQLITE_CONSTRAINT_PRIMARYKEY (1555): PRIMARY KEY violation.
//
// Both indicate a duplicate-key conflict and are mapped to ErrConflict.
func isUniqueViolation(err error) bool {
	var sErr *sqlite.Error
	if errors.As(err, &sErr) {
		code := sErr.Code()
		return code == 2067 || code == 1555
	}
	return false
}
