package server

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// seedRetentionDevice creates a user and a device, then appends one ip_history
// row per entry of observedAt IN SLICE ORDER, so a caller controls the
// observed_at <-> id correlation. That control is load-bearing — see
// TestPruneRetention_CapOnly for why a shared ascending helper would be wrong.
func seedRetentionDevice(t *testing.T, st *store.Store, label string, observedAt []int64) string {
	t.Helper()
	ctx := t.Context()
	u, err := st.Users().Create(ctx, store.User{Email: label + "@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	d, err := st.Devices().Create(ctx, store.Device{UserID: u.ID, Label: label, SecretHash: "h"})
	if err != nil {
		t.Fatalf("Devices().Create: %v", err)
	}
	for i, ts := range observedAt {
		if _, err := st.IPHistory().Append(ctx, store.IPHistory{
			DeviceID: d.ID, IPv4: "1.2.3.4", ObservedAt: ts,
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	return d.ID
}

func ipHistoryCount(t *testing.T, st *store.Store, deviceID string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM ip_history WHERE device_id = ?`, deviceID).Scan(&n); err != nil {
		t.Fatalf("count ip_history: %v", err)
	}
	return n
}

func auditLogCount(t *testing.T, st *store.Store) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil {
		t.Fatalf("count audit_log: %v", err)
	}
	return n
}

func seedAuditRows(t *testing.T, st *store.Store, createdAt []int64) {
	t.Helper()
	for i, ts := range createdAt {
		if _, err := st.AuditLog().Append(t.Context(), store.AuditEntry{
			EventType: "test.event", CreatedAt: ts,
		}); err != nil {
			t.Fatalf("AuditLog().Append %d: %v", i, err)
		}
	}
}

// TestPruneRetention_Disabled proves a zero policy costs nothing and deletes
// nothing — the state every existing deployment upgrades into.
func TestPruneRetention_Disabled(t *testing.T) {
	st := openTestStore(t)
	dev := seedRetentionDevice(t, st, "disabled", []int64{100, 200, 300})
	seedAuditRows(t, st, []int64{100, 200})

	ipRows, auditRows := pruneRetention(t.Context(), st, config.RetentionSection{}, discardLog())

	if ipRows != 0 || auditRows != 0 {
		t.Errorf("ipRows, auditRows = %d, %d; want 0, 0", ipRows, auditRows)
	}
	if got := ipHistoryCount(t, st, dev); got != 3 {
		t.Errorf("ip_history rows = %d, want 3", got)
	}
	if got := auditLogCount(t, st); got != 2 {
		t.Errorf("audit_log rows = %d, want 2", got)
	}
}

// TestPruneRetention_AgeOnly: 10 rows, 6 of them older than a 1-day window.
func TestPruneRetention_AgeOnly(t *testing.T) {
	st := openTestStore(t)
	now := store.NowUnix()
	old := now - 48*3600 // outside a 1-day window
	recent := now - 60   // inside it
	dev := seedRetentionDevice(t, st, "ageonly", []int64{
		old, old, old, old, old, old, recent, recent, recent, recent,
	})

	ipRows, _ := pruneRetention(t.Context(), st, config.RetentionSection{
		IPHistoryDays: 1,
	}, discardLog())

	if ipRows != 6 {
		t.Errorf("ipRows = %d, want 6", ipRows)
	}
	if got := ipHistoryCount(t, st, dev); got != 4 {
		t.Errorf("ip_history rows = %d, want 4", got)
	}
}

// TestPruneRetention_CapOnly is the trap. With age retention OFF and only a
// per-device cap set, an implementation that passes `now` as olderThan instead
// of math.MinInt64 deletes the device's ENTIRE history but its newest row.
//
// The fixture seeds observed_at DESCENDING against id ON PURPOSE. With this
// repo's usual ascending fixture (ip_history_test.go:289 — "Insert in
// observed_at order so id ordering matches observed_at ordering") this test
// ALSO passes against a keepN subquery that has lost its ORDER BY id DESC,
// because SQLite walks the covering index ip_history_device_observed and that
// walk order already is id DESC. Measured: ascending fixture, ORDER BY
// stripped -> deleted=5, test passes, bug invisible. Descending or identical
// observed_at -> deleted=0, bug caught. Do not "normalise" this fixture and do
// not share a seeding helper with the ascending cases.
func TestPruneRetention_CapOnly(t *testing.T) {
	st := openTestStore(t)
	dev := seedRetentionDevice(t, st, "caponly",
		[]int64{1000, 900, 800, 700, 600, 500, 400, 300, 200, 100})

	ipRows, auditRows := pruneRetention(t.Context(), st, config.RetentionSection{
		IPHistoryPerDeviceMax: 5,
	}, discardLog())

	if got := ipHistoryCount(t, st, dev); got != 5 {
		t.Errorf("ip_history rows = %d, want 5 (an olderThan of now would leave 1)", got)
	}
	if ipRows != 5 {
		t.Errorf("ipRows = %d, want 5", ipRows)
	}
	if auditRows != 0 {
		t.Errorf("auditRows = %d, want 0", auditRows)
	}
}

// TestPruneRetention_BothSet: the cap binds tighter than the age window.
func TestPruneRetention_BothSet(t *testing.T) {
	st := openTestStore(t)
	now := store.NowUnix()
	old := now - 48*3600
	recent := now - 60
	dev := seedRetentionDevice(t, st, "bothset", []int64{
		old, old, old, old, old, old, recent, recent, recent, recent,
	})

	pruneRetention(t.Context(), st, config.RetentionSection{
		IPHistoryDays: 1, IPHistoryPerDeviceMax: 3,
	}, discardLog())

	if got := ipHistoryCount(t, st, dev); got != 3 {
		t.Errorf("ip_history rows = %d, want 3 (the cap binds tighter than the age window)", got)
	}
}

// TestPruneRetention_AlwaysKeepsLatest pins #67's acceptance criterion. The
// fixture BREAKS the ascending observed_at<->id correlation deliberately:
// Prune keeps MAX(id) while Latest orders by observed_at DESC, id DESC, so an
// ascending fixture leaves the two indistinguishable and the assertion
// unexercised. Here the highest id carries the LOWEST observed_at.
func TestPruneRetention_AlwaysKeepsLatest(t *testing.T) {
	st := openTestStore(t)
	dev := seedRetentionDevice(t, st, "keeplatest",
		[]int64{1000, 900, 800, 700, 600, 500, 400, 300, 200, 100})

	pruneRetention(t.Context(), st, config.RetentionSection{
		IPHistoryPerDeviceMax: 1,
	}, discardLog())

	if got := ipHistoryCount(t, st, dev); got != 1 {
		t.Fatalf("ip_history rows = %d, want exactly 1", got)
	}
	var observedAt int64
	if err := st.DB().QueryRowContext(t.Context(),
		`SELECT observed_at FROM ip_history WHERE device_id = ? ORDER BY id DESC LIMIT 1`, dev,
	).Scan(&observedAt); err != nil {
		t.Fatalf("read surviving row: %v", err)
	}
	if observedAt != 100 {
		t.Errorf("surviving row observed_at = %d, want 100 (the highest id, not the newest timestamp)", observedAt)
	}
}

// TestPruneRetention_AuditLogOnly covers half the issue title, and pins that
// the ip_history pass is not entered when both its knobs are zero.
func TestPruneRetention_AuditLogOnly(t *testing.T) {
	st := openTestStore(t)
	now := store.NowUnix()
	dev := seedRetentionDevice(t, st, "auditonly", []int64{100, 200, 300})
	seedAuditRows(t, st, []int64{
		now - 48*3600, now - 48*3600, now - 48*3600, now - 60, now - 60,
	})

	ipRows, auditRows := pruneRetention(t.Context(), st, config.RetentionSection{
		AuditLogDays: 1,
	}, discardLog())

	if auditRows != 3 {
		t.Errorf("auditRows = %d, want 3", auditRows)
	}
	if ipRows != 0 {
		t.Errorf("ipRows = %d, want 0 (the ip_history pass must not be entered)", ipRows)
	}
	if got := ipHistoryCount(t, st, dev); got != 3 {
		t.Errorf("ip_history rows = %d, want 3 (untouched)", got)
	}
	if got := auditLogCount(t, st); got != 2 {
		t.Errorf("audit_log rows = %d, want 2", got)
	}
}

// TestPruneRetention_DrainsPastOneBatch pins the drain loop: with a batch size
// well below the eligible row count, ALL eligible rows go in one sweep, not one
// batch's worth. Run cap-ENABLED, the form where the concurrent-insert
// precondition binds and where the per-batch sort lives.
func TestPruneRetention_DrainsPastOneBatch(t *testing.T) {
	st := openTestStore(t)
	dev := seedRetentionDevice(t, st, "drain",
		[]int64{1000, 900, 800, 700, 600, 500, 400, 300, 200, 100})

	// pruneBatchSize is a package-level var with exactly one writer: this test.
	// package server uses no t.Parallel(), so an unrestored write would silently
	// lower the batch size for every later test in the package.
	old := pruneBatchSize
	pruneBatchSize = 3
	t.Cleanup(func() { pruneBatchSize = old })

	ipRows, _ := pruneRetention(t.Context(), st, config.RetentionSection{
		IPHistoryPerDeviceMax: 2,
	}, discardLog())

	if ipRows != 8 {
		t.Errorf("ipRows = %d, want 8 (the drain must run past the batch size of 3)", ipRows)
	}
	if got := ipHistoryCount(t, st, dev); got != 2 {
		t.Errorf("ip_history rows = %d, want 2", got)
	}
}

// TestPruneRetention_PerDeviceContinueOnError proves one failing device does not
// starve the devices ordered after it.
func TestPruneRetention_PerDeviceContinueOnError(t *testing.T) {
	ctx := t.Context()
	st := openTestStore(t)
	healthy := seedRetentionDevice(t, st, "healthy", []int64{100, 200, 300, 400})
	failing := seedRetentionDevice(t, st, "failing", []int64{100, 200, 300, 400})

	// ListAll orders by created_at DESC, and both devices are created within the
	// same second, so the tie resolves to INSERTION order — which would put the
	// healthy device first and let an abort-on-error implementation pass. Force
	// the failing device to sort first, or this test proves nothing.
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devices SET created_at = created_at + 100 WHERE id = ?`, failing); err != nil {
		t.Fatalf("reorder devices: %v", err)
	}

	// The failing device MUST have prunable rows, or the trigger never fires and
	// this test passes vacuously.
	if _, err := st.DB().ExecContext(ctx, fmt.Sprintf(
		`CREATE TRIGGER inject_fail BEFORE DELETE ON ip_history
		 WHEN OLD.device_id = '%s'
		 BEGIN SELECT RAISE(ABORT, 'injected'); END;`, failing)); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	if devs, err := st.Devices().ListAll(ctx); err != nil {
		t.Fatalf("ListAll: %v", err)
	} else if devs[0].ID != failing {
		t.Fatalf("fixture: the failing device must sort first, got %q", devs[0].ID)
	}

	ipRows, _ := pruneRetention(ctx, st, config.RetentionSection{IPHistoryDays: 1}, discardLog())

	if got := ipHistoryCount(t, st, failing); got != 4 {
		t.Errorf("failing device rows = %d, want 4 (its drain aborted)", got)
	}
	if got := ipHistoryCount(t, st, healthy); got != 1 {
		t.Errorf("healthy device rows = %d, want 1 (it must still be pruned)", got)
	}
	if ipRows != 3 {
		t.Errorf("ipRows = %d, want 3 (the healthy device's deletions)", ipRows)
	}
}

// TestPruneRetention_CountsSurviveMidDrainFailure proves a drain that commits
// one batch and then fails reports what it COMMITTED, not 0. Those totals gate
// the retention.prune audit event, so zeroing them would suppress the operator's
// only durable record of thousands of irreversible deletions.
func TestPruneRetention_CountsSurviveMidDrainFailure(t *testing.T) {
	ctx := t.Context()
	st := openTestStore(t)
	dev := seedRetentionDevice(t, st, "middrain",
		[]int64{100, 200, 300, 400, 500, 600, 700, 800, 900, 1000})

	old := pruneBatchSize
	pruneBatchSize = 3
	t.Cleanup(func() { pruneBatchSize = old })

	// A counter table, not a device-keyed trigger: a device-keyed trigger aborts
	// the FIRST batch, so the committed count would be 0 — the opposite of what
	// this test observes. This fires during batch 2 regardless of which rows a
	// batch picks, which matters because the outer SELECT carries no ORDER BY.
	if _, err := st.DB().ExecContext(ctx, `CREATE TABLE probe_counter (n INTEGER NOT NULL)`); err != nil {
		t.Fatalf("counter table: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `INSERT INTO probe_counter (n) VALUES (0)`); err != nil {
		t.Fatalf("counter seed: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		CREATE TRIGGER inject_after_batch BEFORE DELETE ON ip_history
		BEGIN
		  UPDATE probe_counter SET n = n + 1;
		  SELECT RAISE(ABORT, 'injected') WHERE (SELECT n FROM probe_counter) > 3;
		END;`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	ipRows, _ := pruneRetention(ctx, st, config.RetentionSection{IPHistoryDays: 1}, discardLog())

	if ipRows != 3 {
		t.Errorf("ipRows = %d, want 3 (the first batch committed before batch 2 failed)", ipRows)
	}
	if got := ipHistoryCount(t, st, dev); got != 7 {
		t.Errorf("ip_history rows = %d, want 7", got)
	}
}

// TestPruneRetention_AuditLogDrainFailureKeepsIPCounts proves a failed audit_log
// drain keeps its committed count and leaves the ip_history counts standing.
func TestPruneRetention_AuditLogDrainFailureKeepsIPCounts(t *testing.T) {
	ctx := t.Context()
	st := openTestStore(t)
	now := store.NowUnix()
	dev := seedRetentionDevice(t, st, "auditfail", []int64{100, 200, 300, 400})
	seedAuditRows(t, st, []int64{now - 48*3600, now - 48*3600, now - 48*3600})

	// A BEFORE INSERT trigger cannot fail a DELETE; it must be BEFORE DELETE.
	if _, err := st.DB().ExecContext(ctx, `
		CREATE TRIGGER inject_audit_fail BEFORE DELETE ON audit_log
		BEGIN SELECT RAISE(ABORT, 'injected'); END;`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	ipRows, auditRows := pruneRetention(ctx, st, config.RetentionSection{
		IPHistoryDays: 1, AuditLogDays: 1,
	}, discardLog())

	if auditRows != 0 {
		t.Errorf("auditRows = %d, want 0 (every batch failed)", auditRows)
	}
	if ipRows != 3 {
		t.Errorf("ipRows = %d, want 3 (the ip_history counts must still stand)", ipRows)
	}
	if got := ipHistoryCount(t, st, dev); got != 1 {
		t.Errorf("ip_history rows = %d, want 1", got)
	}
}

// TestPruneRetention_ListAllFailureStillPrunesAuditLog proves a failure to
// enumerate devices skips the ip_history pass ONLY — the audit_log pass, which
// does not depend on it, must still run.
func TestPruneRetention_ListAllFailureStillPrunesAuditLog(t *testing.T) {
	ctx := t.Context()
	st := openTestStore(t)
	now := store.NowUnix()
	seedRetentionDevice(t, st, "orphan", []int64{100, 200, 300})
	seedAuditRows(t, st, []int64{
		now - 48*3600, now - 48*3600, now - 48*3600, now - 48*3600,
	})

	// No trigger can fail a SELECT, so rename the table out from under ListAll.
	// SQLite rewrites ip_history's FK to "devices_x" as part of the rename
	// (foreign_keys is ON), and the restoring rename below puts it back to
	// "devices" — measured. The restore is clean, but not because the FK was
	// left untouched.
	if _, err := st.DB().ExecContext(ctx, `ALTER TABLE devices RENAME TO devices_x`); err != nil {
		t.Fatalf("rename devices: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.DB().ExecContext(context.Background(), `ALTER TABLE devices_x RENAME TO devices`)
	})

	ipRows, auditRows := pruneRetention(ctx, st, config.RetentionSection{
		IPHistoryDays: 1, AuditLogDays: 1,
	}, discardLog())

	if ipRows != 0 {
		t.Errorf("ipRows = %d, want 0", ipRows)
	}
	if auditRows != 4 {
		t.Errorf("auditRows = %d, want 4 (the audit_log pass must still run)", auditRows)
	}
}

// TestPrune_EmitsRetentionAuditEvent: exactly one event per sweep that deleted
// something, with an empty actor and no details_json.
func TestPrune_EmitsRetentionAuditEvent(t *testing.T) {
	ctx := t.Context()
	st := openTestStore(t)
	seedRetentionDevice(t, st, "auditevent",
		[]int64{1000, 900, 800, 700, 600, 500, 400, 300, 200, 100})

	prune(ctx, st, config.RetentionSection{IPHistoryPerDeviceMax: 5}, discardLog())

	var count int
	var actor, details sql.NullString
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE event_type = ?`, "retention.prune",
	).Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 1 {
		t.Fatalf("retention.prune events = %d, want exactly 1", count)
	}
	if err := st.DB().QueryRowContext(ctx,
		`SELECT actor_user_id, details_json FROM audit_log WHERE event_type = ?`, "retention.prune",
	).Scan(&actor, &details); err != nil {
		t.Fatalf("read event: %v", err)
	}
	if actor.Valid && actor.String != "" {
		t.Errorf("actor_user_id = %q, want empty (the web UI renders that as \"system\")", actor.String)
	}
	if details.Valid && details.String != "" {
		t.Errorf("details_json = %q, want empty — the column has no readers", details.String)
	}
}

// TestPrune_NoAuditEventWhenNothingDeleted: a sweep that deletes nothing writes
// no event, so an idle server does not accrue an hourly row.
func TestPrune_NoAuditEventWhenNothingDeleted(t *testing.T) {
	ctx := t.Context()
	st := openTestStore(t)
	seedRetentionDevice(t, st, "noevent", []int64{100, 200, 300})

	// Retention fully disabled: nothing is eligible.
	prune(ctx, st, config.RetentionSection{}, discardLog())

	var count int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE event_type = ?`, "retention.prune",
	).Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 0 {
		t.Errorf("retention.prune events = %d, want 0", count)
	}
}
