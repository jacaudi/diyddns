package server

import (
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
