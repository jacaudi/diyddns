package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Store is DIYDDNS's persistence handle. Open returns a fully migrated,
// PRAGMA-configured Store ready for repository use. Close releases the
// underlying *sql.DB.
type Store struct {
	db *sql.DB
}

// Open opens the SQLite database at path, applies the runtime pragmas to
// every connection, and runs all embedded migrations. path may be ":memory:"
// for in-process use.
func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: sql.Open: %w", err)
	}

	// Single-writer SQLite is happiest with one writer connection. With
	// SetMaxOpenConns(1) the pool never opens a second connection, so the
	// per-connection pragmas applied below (via the sole pooled *sql.Conn)
	// persist for every later query.
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: db.Conn: %w", err)
	}
	if err := applyPragmas(ctx, conn); err != nil {
		_ = conn.Close()
		_ = db.Close()
		return nil, err
	}
	if err := conn.Close(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: conn close: %w", err)
	}

	if err := Migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

// DB returns the underlying *sql.DB. Prefer typed repository accessors
// (Users, Sessions, etc.) over raw DB access; this exists for diagnostics
// and tests.
func (s *Store) DB() *sql.DB { return s.db }

// Close releases the database handle.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}
