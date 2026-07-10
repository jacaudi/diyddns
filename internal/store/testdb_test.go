package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestStore returns a Store backed by a fresh on-disk SQLite database in
// t.TempDir(). Migrations have been applied. The returned context has a
// reasonable timeout. The DB file is automatically cleaned up by t.TempDir.
func newTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.db")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s, ctx
}

// TestNewTestStoreSmokesMigrations is a sanity test: opening newTestStore
// must complete without error and produce a queryable DB whose schema
// includes the expected tables.
func TestNewTestStoreSmokesMigrations(t *testing.T) {
	s, ctx := newTestStore(t)

	tables := []string{
		"users", "sessions", "devices", "ip_history",
		"enrollment_codes", "replay_nonces", "audit_log", "bootstrap",
	}
	for _, tbl := range tables {
		var got string
		err := s.DB().QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl,
		).Scan(&got)
		if err != nil {
			t.Errorf("table %q missing after migrations: %v", tbl, err)
			continue
		}
		if got != tbl {
			t.Errorf("table lookup: got %q, want %q", got, tbl)
		}
	}
}

// TestPragmasApplied proves that the pragmas Open applies to its setup
// connection actually persist for queries issued through the connection
// pool afterward (s.DB()), not just on the connection Open used to apply
// them. Open relies on SetMaxOpenConns(1) to guarantee this: with at most
// one pooled connection, every later query reuses the same connection the
// pragmas were set on. If foreign_keys comes back 0 here, that guarantee is
// broken and every FK-cascade behavior the repositories depend on (Tasks
// 11-18) would silently not be enforced.
func TestPragmasApplied(t *testing.T) {
	s, ctx := newTestStore(t)

	var foreignKeys int
	if err := s.DB().QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Errorf("PRAGMA foreign_keys = %d, want 1 (FK enforcement not active on pooled connection)", foreignKeys)
	}

	var journalMode string
	if err := s.DB().QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		t.Errorf("PRAGMA journal_mode = %q, want %q (case-insensitive)", journalMode, "wal")
	}
}
