package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// seedNotificationRows creates one endpoint, then inserts delivery rows with
// the given (status, createdAt) pairs.
func seedNotificationRows(t *testing.T, st *store.Store, deliveries []struct {
	status    string
	createdAt int64
}) {
	t.Helper()
	ctx := t.Context()
	now := store.NowUnix()
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO notification_endpoints
		   (id, label, url, secret_sealed, enabled, created_at, updated_at)
		 VALUES ('ep1', 'l', 'https://example.com/h', 'sealed', 1, ?, ?)`,
		now, now); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	for _, d := range deliveries {
		if _, err := st.DB().ExecContext(ctx,
			`INSERT INTO notification_deliveries
			   (endpoint_id, event_type, event_id, payload, attempts,
			    next_attempt_at, status, created_at, updated_at)
			 VALUES ('ep1','device.ip_changed',1,?,0,?,?,?,?)`,
			[]byte(`{}`), now, d.status, d.createdAt, d.createdAt); err != nil {
			t.Fatalf("seed delivery: %v", err)
		}
	}
}

func countRows(t *testing.T, st *store.Store, table string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(t.Context(), `SELECT count(*) FROM `+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestPrune_DeliveriesNeedTheirKey: delivery history is a retention decision,
// so a zero key must delete nothing however old the rows.
func TestPrune_DeliveriesNeedTheirKey(t *testing.T) {
	st := openTestStore(t)
	now := store.NowUnix()
	old := now - 86400*90
	seedNotificationRows(t, st, []struct {
		status    string
		createdAt int64
	}{
		{store.DeliveryDelivered, old},
		{store.DeliveryFailed, old},
	})

	prune(t.Context(), st, config.RetentionSection{}, discardLog())

	if got := countRows(t, st, "notification_deliveries"); got != 2 {
		t.Errorf("notification_deliveries = %d rows, want 2 — retention is disabled by default", got)
	}
}

// TestPrune_DeliveriesRetentionKeepsPending is the safety property at the
// pruner level: enabling retention must never delete a delivery the sweeper
// still owes, however old it is.
func TestPrune_DeliveriesRetentionKeepsPending(t *testing.T) {
	st := openTestStore(t)
	now := store.NowUnix()
	old := now - 86400*90
	seedNotificationRows(t, st, []struct {
		status    string
		createdAt int64
	}{
		{store.DeliveryPending, old},   // ancient but owed — must survive
		{store.DeliveryDelivered, old}, // terminal — must go
		{store.DeliveryFailed, old},    // terminal — must go
		{store.DeliveryDelivered, now}, // inside the window — must survive
	})

	prune(t.Context(), st, config.RetentionSection{NotificationDeliveriesDays: 30}, discardLog())

	if got := countRows(t, st, "notification_deliveries"); got != 2 {
		t.Fatalf("notification_deliveries = %d rows, want 2", got)
	}
	var pending int
	if err := st.DB().QueryRowContext(t.Context(),
		`SELECT count(*) FROM notification_deliveries WHERE status = ?`, store.DeliveryPending).Scan(&pending); err != nil {
		t.Fatalf("count pending: %v", err)
	}
	if pending != 1 {
		t.Errorf("pending rows = %d, want 1 — retention must never delete owed work", pending)
	}
}

// TestPrune_DeliveryDeletionsAreAudited: the retention.prune audit row is the
// only durable record that deletion happened, and it must fire when the ONLY
// thing deleted was deliveries.
func TestPrune_DeliveryDeletionsAreAudited(t *testing.T) {
	st := openTestStore(t)
	now := store.NowUnix()
	seedNotificationRows(t, st, []struct {
		status    string
		createdAt int64
	}{
		{store.DeliveryDelivered, now - 86400*90},
	})

	prune(t.Context(), st, config.RetentionSection{NotificationDeliveriesDays: 30}, discardLog())

	var events int
	if err := st.DB().QueryRowContext(t.Context(),
		`SELECT count(*) FROM audit_log WHERE event_type = 'retention.prune'`).Scan(&events); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if events != 1 {
		t.Errorf("retention.prune audit rows = %d, want 1 — deleting only deliveries must still be recorded", events)
	}
}

// TestPrune_LogsTheNewCounts: operators read the Debug line to see what a sweep
// did; a sweep that deletes rows it does not name is unobservable. The
// attempt ledger is gone (#106), so its count must NOT appear.
func TestPrune_LogsTheNewCounts(t *testing.T) {
	st := openTestStore(t)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	prune(t.Context(), st, config.RetentionSection{}, log)

	if !strings.Contains(buf.String(), "notification_deliveries") {
		t.Error("prune's summary line does not report notification_deliveries")
	}
	if strings.Contains(buf.String(), "notification_attempts") {
		t.Error("prune's summary line still reports notification_attempts; the ledger was removed")
	}
}
