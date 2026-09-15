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

// openAtVersion7 opens a fresh database and migrates it to version 7 — the
// last schema BEFORE 00008 — with the same pragmas Open applies, so the
// round trip below runs under foreign_keys=ON exactly as production does.
// It stops short of head deliberately: Open would run 00008 immediately and
// leave nothing pre-00008 to seed.
func openAtVersion7(t *testing.T) (*sql.DB, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "migration008.db"))
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
	if err := goose.UpToContext(ctx, db, ".", 7); err != nil {
		t.Fatalf("goose up to 7: %v", err)
	}
	if v, err := goose.GetDBVersionContext(ctx, db); err != nil || v != 7 {
		t.Fatalf("version after UpTo(7) = %d (err %v), want 7", v, err)
	}
	return db, ctx
}

// seedUserRaw inserts the minimal user row devices.user_id can reference.
func seedUserRaw(t *testing.T, ctx context.Context, db *sql.DB, id string) {
	t.Helper()
	now := NowUnix()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO users (id, email, role, disabled, created_at, updated_at)
		 VALUES (?, ?, 'user', 0, ?, ?)`, id, id+"@example.com", now, now); err != nil {
		t.Fatalf("seed user %s: %v", id, err)
	}
}

// seedDeviceRaw inserts a device row at the pre-00008 schema. ipv4/ipv6 bind
// as SQL NULL when the argument is "", never as an empty SQL string literal --
// the backfill keys on `current_ipv6 IS NOT NULL`, and an empty string
// literal also satisfies IS NOT NULL.
func seedDeviceRaw(t *testing.T, ctx context.Context, db *sql.DB, id, userID, ipv4, ipv6 string, lastSeen int64) {
	t.Helper()
	now := NowUnix()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO devices (id, user_id, label, secret_hash, current_ipv4, current_ipv6, last_seen_at, created_at, updated_at)
		 VALUES (?, ?, ?, 'hash', ?, ?, ?, ?, ?)`,
		id, userID, id, nullIfEmpty(ipv4), nullIfEmpty(ipv6), lastSeen, now, now); err != nil {
		t.Fatalf("seed device %s: %v", id, err)
	}
}

// upTo migrates to schema version n, failing the test on error.
func upTo(t *testing.T, ctx context.Context, db *sql.DB, n int64) {
	t.Helper()
	if err := goose.UpToContext(ctx, db, ".", n); err != nil {
		t.Fatalf("goose up to %d: %v", n, err)
	}
}

// downTo migrates to schema version n, failing the test on error.
func downTo(t *testing.T, ctx context.Context, db *sql.DB, n int64) {
	t.Helper()
	if err := goose.DownToContext(ctx, db, ".", n); err != nil {
		t.Fatalf("goose down to %d: %v", n, err)
	}
}

// scanStr runs a single-value query and returns the string. The integer
// case is already covered by countRows (migration007_test.go); scanStr
// exists only for TestMigration008_UpDownUp's COALESCE-to-empty-string
// assertions, which countRows cannot Scan into.
func scanStr(t *testing.T, ctx context.Context, db *sql.DB, query string) string {
	t.Helper()
	var s string
	if err := db.QueryRowContext(ctx, query).Scan(&s); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return s
}

// The backfill seeds each family the device CURRENTLY carries (design §11.1).
// Backfilling NULL instead maps to Go 0 and would expire every device on the
// first sweep; backfilling a family the device does not carry would create an
// instant with no address behind it.
func TestMigration008_BackfillsConfirmedAt(t *testing.T) {
	db, ctx := openAtVersion7(t)
	seedUserRaw(t, ctx, db, "u1")
	// seedDeviceRaw MUST bind "" as SQL NULL, not as ''. The backfill keys on
	// `current_ipv6 IS NOT NULL`, and '' IS NOT NULL is TRUE -- so a device
	// seeded with '' gets a v6 instant it must not have, and d-v4's
	// wantV6 = nil then fails for a reason that looks like a migration bug and
	// is not.
	seedDeviceRaw(t, ctx, db, "d-dual", "u1", "1.2.3.4", "2001:db8::1", 1000)
	seedDeviceRaw(t, ctx, db, "d-v4", "u1", "1.2.3.4", "", 2000)
	seedDeviceRaw(t, ctx, db, "d-v6", "u1", "", "2001:db8::1", 3000)
	seedDeviceRaw(t, ctx, db, "d-none", "u1", "", "", 4000)

	upTo(t, ctx, db, 8) // the backfill runs HERE, after the rows exist

	for _, tc := range []struct {
		id             string
		wantV4, wantV6 any
	}{
		{"d-dual", int64(1000), int64(1000)},
		{"d-v4", int64(2000), nil},
		{"d-v6", nil, int64(3000)},
		{"d-none", nil, nil},
	} {
		var v4, v6 sql.NullInt64
		if err := db.QueryRow(
			`SELECT v4_confirmed_at, v6_confirmed_at FROM devices WHERE id = ?`, tc.id,
		).Scan(&v4, &v6); err != nil {
			t.Fatalf("%s: %v", tc.id, err)
		}
		gotV4, gotV6 := any(nil), any(nil)
		if v4.Valid {
			gotV4 = v4.Int64
		}
		if v6.Valid {
			gotV6 = v6.Int64
		}
		if gotV4 != tc.wantV4 || gotV6 != tc.wantV6 {
			t.Errorf("%s: (%v, %v), want (%v, %v)", tc.id, gotV4, gotV6, tc.wantV4, tc.wantV6)
		}
	}
}

func TestMigration008_WarnLevelsStartAtZero(t *testing.T) {
	db, ctx := openAtVersion7(t)
	seedUserRaw(t, ctx, db, "u1")
	seedDeviceRaw(t, ctx, db, "d1", "u1", "1.2.3.4", "", 1000)
	upTo(t, ctx, db, 8)

	var v4l, v6l int
	if err := db.QueryRow(
		`SELECT v4_warn_level, v6_warn_level FROM devices WHERE id = 'd1'`).Scan(&v4l, &v6l); err != nil {
		t.Fatal(err)
	}
	if v4l != 0 || v6l != 0 {
		t.Errorf("warn levels = (%d,%d), want (0,0)", v4l, v6l)
	}
}

// D19: rolling back must not re-open the allow-list, and the round trip must
// not disturb a device that was never expired.
//
// Asserting only "a NULL address is still NULL after Down" is VACUOUS -- it
// passes against an empty Down migration. This drives a real round trip.
func TestMigration008_UpDownUp(t *testing.T) {
	db, ctx := openAtVersion7(t)
	seedUserRaw(t, ctx, db, "u1")
	seedDeviceRaw(t, ctx, db, "live", "u1", "1.2.3.4", "2001:db8::1", 5000)
	seedDeviceRaw(t, ctx, db, "cleared", "u1", "", "", 1000) // as the sweep leaves it

	upTo(t, ctx, db, 8)
	if got := countRows(t, ctx, db,
		`SELECT v4_confirmed_at FROM devices WHERE id = 'live'`); got != 5000 {
		t.Fatalf("v4_confirmed_at = %d, want 5000 from the backfill", got)
	}

	downTo(t, ctx, db, 7)
	if got := scanStr(t, ctx, db,
		`SELECT COALESCE(current_ipv4,'') FROM devices WHERE id = 'live'`); got != "1.2.3.4" {
		t.Errorf("live device's address = %q after Down, want 1.2.3.4", got)
	}
	if got := scanStr(t, ctx, db,
		`SELECT COALESCE(current_ipv4,'') FROM devices WHERE id = 'cleared'`); got != "" {
		t.Errorf("the down migration restored a cleared address: %q", got)
	}

	upTo(t, ctx, db, 8) // must re-run cleanly on the same database
	if got := countRows(t, ctx, db,
		`SELECT v4_warn_level FROM devices WHERE id = 'live'`); got != 0 {
		t.Errorf("v4_warn_level = %d after Up, want 0", got)
	}
}
