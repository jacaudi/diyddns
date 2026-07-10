// Package store implements DIYDDNS's persistence layer over SQLite. Every
// aggregate has its own *.go file plus an integration test against a real
// on-disk database created by newTestStore in testdb_test.go.
package store

import "errors"

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when a write would violate a UNIQUE constraint
// (e.g., duplicate email, duplicate (user_id, label) on devices).
var ErrConflict = errors.New("store: conflict")
