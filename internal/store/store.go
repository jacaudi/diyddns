package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Store is DIYDDNS's persistence handle. It wraps a single *sql.DB pool
// configured with the runtime pragmas and migrations applied. Obtain one
// via Open and release it via Close.
type Store struct {
	db *sql.DB
}

// Open opens the SQLite database at path, applies the runtime pragmas
// (WAL, foreign_keys=ON, synchronous=NORMAL, busy_timeout=5000), and
// runs all embedded migrations. path may be ":memory:" for in-process use.
func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: sql.Open: %w", err)
	}
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

// Close releases the underlying database handle. Safe to call multiple times.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}
