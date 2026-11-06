package store

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/logtest"
)

const slowMsg = "store: slow statement"

// openTimed returns a single-connection pool over an in-memory database whose
// statements are timed against threshold, and the buffer its records land in.
func openTimed(t *testing.T, threshold time.Duration) (*sql.DB, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	db := sql.OpenDB(newTimedConnector(":memory:", slog.New(slog.NewJSONHandler(&buf, nil)), threshold))
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(context.Background(), "CREATE TABLE t(x)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	buf.Reset()
	return db, &buf
}

// slowRecords returns every slow-statement record in buf.
func slowRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range logtest.Records(t, buf.String()) {
		if r["msg"] == slowMsg {
			out = append(out, r)
		}
	}
	return out
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func TestTimedConn_ExecLogsOnce(t *testing.T) {
	db, buf := openTimed(t, time.Nanosecond)
	mustExec(t, db, "INSERT INTO t VALUES (1)")

	recs := slowRecords(t, buf)
	if len(recs) != 1 {
		t.Fatalf("slow records = %d, want 1; log:\n%s", len(recs), buf)
	}
	r := recs[0]
	if r["sql"] != "INSERT INTO t VALUES (1)" {
		t.Errorf("sql = %v", r["sql"])
	}
	if r["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", r["level"])
	}
	if _, ok := r["duration_ms"]; !ok {
		t.Errorf("duration_ms missing: %v", r)
	}
}

func TestTimedConn_FastStatementSilent(t *testing.T) {
	db, buf := openTimed(t, time.Hour)
	mustExec(t, db, "INSERT INTO t VALUES (1)")
	rows, err := db.QueryContext(context.Background(), "SELECT x FROM t")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
	}
	_ = rows.Close()

	if n := len(slowRecords(t, buf)); n != 0 {
		t.Fatalf("slow records = %d, want 0; log:\n%s", n, buf)
	}
}

func TestTimedConn_QueryLogsAtCloseNotBefore(t *testing.T) {
	db, buf := openTimed(t, time.Nanosecond)
	mustExec(t, db, "INSERT INTO t VALUES (1), (2), (3)")
	buf.Reset()

	rows, err := db.QueryContext(context.Background(), "SELECT x FROM t")
	if err != nil {
		t.Fatal(err)
	}
	if !rows.Next() {
		t.Fatal("expected a first row")
	}
	if n := len(slowRecords(t, buf)); n != 0 {
		t.Fatalf("logged before rows were released: %d records", n)
	}
	for rows.Next() {
	}
	if n := len(slowRecords(t, buf)); n != 1 {
		t.Fatalf("after draining to EOF: %d records, want 1", n)
	}
	_ = rows.Close()
	if n := len(slowRecords(t, buf)); n != 1 {
		t.Fatalf("after explicit Close: %d records, want still 1", n)
	}
}

func TestTimedConn_TxStatementsAreTimed(t *testing.T) {
	db, buf := openTimed(t, time.Nanosecond)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"INSERT INTO t VALUES (1)", "INSERT INTO t VALUES (2)"} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, r := range slowRecords(t, buf) {
		got = append(got, r["sql"].(string))
	}
	want := []string{"INSERT INTO t VALUES (1)", "INSERT INTO t VALUES (2)", "COMMIT"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("sql = %q, want %q", got, want)
	}
}

func TestTimedConn_NeverLogsArgs(t *testing.T) {
	db, buf := openTimed(t, time.Nanosecond)
	mustExec(t, db, "INSERT INTO t VALUES (?)", "alice@example.com")

	if len(slowRecords(t, buf)) != 1 {
		t.Fatalf("expected the statement to be logged; log:\n%s", buf)
	}
	if strings.Contains(buf.String(), "alice@example.com") {
		t.Fatalf("bound argument leaked into the log:\n%s", buf)
	}
}

func TestTimedConn_SQLCollapsedAndTruncated(t *testing.T) {
	db, buf := openTimed(t, time.Nanosecond)
	mustExec(t, db, "SELECT\n\t 1   +  1")
	long := "SELECT 1 /*" + strings.Repeat("x", 300) + "*/"
	mustExec(t, db, long)

	recs := slowRecords(t, buf)
	if len(recs) != 2 {
		t.Fatalf("slow records = %d, want 2", len(recs))
	}
	if recs[0]["sql"] != "SELECT 1 + 1" {
		t.Errorf("collapsed sql = %q", recs[0]["sql"])
	}
	if n := len(recs[1]["sql"].(string)); n != 200 {
		t.Errorf("truncated sql length = %d, want 200", n)
	}
}

// TestTimedConn_CommitAndRollbackAreTimed: modernc's tx.Commit/Rollback run
// "commit"/"rollback" directly, bypassing ExecContext, and a commit can carry
// a WAL checkpoint's fsync — a real connection hold.
func TestTimedConn_CommitAndRollbackAreTimed(t *testing.T) {
	db, buf := openTimed(t, time.Nanosecond)
	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, r := range slowRecords(t, buf) {
		got = append(got, r["sql"].(string))
	}
	if strings.Join(got, "|") != "COMMIT|ROLLBACK" {
		t.Fatalf("sql = %q, want [COMMIT ROLLBACK]", got)
	}
}
