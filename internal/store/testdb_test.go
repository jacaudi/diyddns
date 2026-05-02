package store

import (
	"context"
	"path/filepath"
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
