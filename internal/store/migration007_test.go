package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/jacaudi/diyddns/migrations"
)

// openAtVersion6 opens a fresh database and migrates it to version 6 — the
// last schema BEFORE 00007 — with the same pragmas Open applies, so the
// round trip below runs under foreign_keys=ON exactly as production does.
// It stops short of head deliberately: Open would run 00007 immediately and
// leave nothing pre-00007 to seed.
func openAtVersion6(t *testing.T) (*sql.DB, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "migration007.db"))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("db.Conn: %v", err)
	}
	if err := applyPragmas(ctx, conn); err != nil {
		t.Fatalf("applyPragmas: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("conn.Close: %v", err)
	}

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatalf("goose.SetDialect: %v", err)
	}
	if err := goose.UpToContext(ctx, db, ".", 6); err != nil {
		t.Fatalf("goose up to 6: %v", err)
	}
	if v, err := goose.GetDBVersionContext(ctx, db); err != nil || v != 6 {
		t.Fatalf("version after UpTo(6) = %d (err %v), want 6", v, err)
	}
	return db, ctx
}

// countRows runs a single-value COUNT/SELECT and returns the integer.
func countRows(t *testing.T, ctx context.Context, db *sql.DB, query string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx, query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// dbTableExists is tableExists against a raw *sql.DB (no Store yet).
func dbTableExists(t *testing.T, ctx context.Context, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n); err != nil {
		t.Fatalf("sqlite_master lookup %q: %v", name, err)
	}
	return n > 0
}

// dbColumnExists is columnExists against a raw *sql.DB (no Store yet).
func dbColumnExists(t *testing.T, ctx context.Context, db *sql.DB, table, column string) bool {
	t.Helper()
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		t.Fatalf("table_info %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		if name == column {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("table_info %s rows: %v", table, err)
	}
	return false
}

// TestMigration007_SeededRoundTrip is design §12's remaining unmeasured case
// and D15's "existing rows are dropped": seed the per-user shape at version 6,
// apply 00007 Up, then Down, then Up again.
//
//   - Up drops every pre-00007 endpoint (a URL one user chose must not start
//     receiving every user's events) and, by cascade, its deliveries, and
//     drops the attempt ledger, the user_initiated_at column and its index.
//   - Down restores the per-user shape EMPTY — it cannot restore ownership —
//     with feed_tokens and feed_state gone.
//   - Up again is clean on that restored shape.
func TestMigration007_SeededRoundTrip(t *testing.T) {
	db, ctx := openAtVersion6(t)
	now := NowUnix()

	// --- seed the pre-00007 world -------------------------------------
	if _, err := db.ExecContext(ctx,
		`INSERT INTO users (id, email, role, disabled, created_at, updated_at)
		 VALUES ('u1', 'u1@example.com', 'user', 0, ?, ?)`, now, now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO notification_endpoints (id, user_id, label, url, secret_sealed, enabled, created_at, updated_at)
		 VALUES ('ep1', 'u1', 'mine', 'https://example.com/hook', 'sealed', 1, ?, ?)`, now, now); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO notification_deliveries (endpoint_id, event_type, event_id, payload, attempts, next_attempt_at, status, user_initiated_at, created_at, updated_at)
		 VALUES ('ep1', 'device.ip_changed', 1, X'7B7D', 0, ?, 'pending', ?, ?, ?)`, now, now, now, now); err != nil {
		t.Fatalf("seed delivery: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO notification_attempts (user_id, at) VALUES ('u1', ?)`, now); err != nil {
		t.Fatalf("seed attempt: %v", err)
	}
	if n := countRows(t, ctx, db, `SELECT count(*) FROM notification_endpoints`); n != 1 {
		t.Fatalf("seeded endpoints = %d, want 1", n)
	}

	// --- Up ------------------------------------------------------------
	if err := goose.UpContext(ctx, db, "."); err != nil {
		t.Fatalf("goose up to head: %v", err)
	}
	if n := countRows(t, ctx, db, `SELECT count(*) FROM notification_endpoints`); n != 0 {
		t.Errorf("endpoints after Up = %d, want 0 (D15: pre-00007 rows are dropped)", n)
	}
	if n := countRows(t, ctx, db, `SELECT count(*) FROM notification_deliveries`); n != 0 {
		t.Errorf("deliveries after Up = %d, want 0 (cascaded with their endpoint)", n)
	}
	if dbColumnExists(t, ctx, db, "notification_endpoints", "user_id") {
		t.Error("notification_endpoints.user_id survived Up")
	}
	if dbColumnExists(t, ctx, db, "notification_deliveries", "user_initiated_at") {
		t.Error("notification_deliveries.user_initiated_at survived Up")
	}
	if dbTableExists(t, ctx, db, "notification_attempts") {
		t.Error("notification_attempts survived Up")
	}
	if !dbTableExists(t, ctx, db, "feed_tokens") || !dbTableExists(t, ctx, db, "feed_state") {
		t.Error("feed_tokens and feed_state must exist after Up")
	}

	// --- Down ----------------------------------------------------------
	if err := goose.DownContext(ctx, db, "."); err != nil {
		t.Fatalf("goose down from 7: %v", err)
	}
	if v, err := goose.GetDBVersionContext(ctx, db); err != nil || v != 6 {
		t.Fatalf("version after Down = %d (err %v), want 6", v, err)
	}
	if !dbColumnExists(t, ctx, db, "notification_endpoints", "user_id") {
		t.Error("Down must restore notification_endpoints.user_id")
	}
	if !dbColumnExists(t, ctx, db, "notification_deliveries", "user_initiated_at") {
		t.Error("Down must restore notification_deliveries.user_initiated_at")
	}
	if !dbTableExists(t, ctx, db, "notification_attempts") {
		t.Error("Down must restore notification_attempts")
	}
	if dbTableExists(t, ctx, db, "feed_tokens") || dbTableExists(t, ctx, db, "feed_state") {
		t.Error("Down must drop feed_tokens and feed_state")
	}
	if n := countRows(t, ctx, db, `SELECT count(*) FROM notification_endpoints`); n != 0 {
		t.Errorf("endpoints after Down = %d, want 0 — Down restores the shape, never the ownership", n)
	}
	if n := countRows(t, ctx, db, `SELECT count(*) FROM notification_deliveries`); n != 0 {
		t.Errorf("deliveries after Down = %d, want 0", n)
	}

	// --- re-Up ----------------------------------------------------------
	if err := goose.UpContext(ctx, db, "."); err != nil {
		t.Fatalf("re-Up after Down: %v", err)
	}
	if v, err := goose.GetDBVersionContext(ctx, db); err != nil || v != 7 {
		t.Fatalf("version after re-Up = %d (err %v), want 7", v, err)
	}
	if dbTableExists(t, ctx, db, "notification_attempts") {
		t.Error("notification_attempts survived the re-Up")
	}
	if n := countRows(t, ctx, db, `SELECT seq FROM feed_state WHERE id = 1`); n != 0 {
		t.Errorf("feed_state.seq after re-Up = %d, want 0", n)
	}
}
