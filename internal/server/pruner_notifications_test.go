package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// seedNotificationRows creates a user and one endpoint, then inserts delivery
// rows with the given (status, createdAt) pairs and attempt-ledger rows at the
// given timestamps. Returns the user id.
func seedNotificationRows(t *testing.T, st *store.Store, deliveries []struct {
	status    string
	createdAt int64
}, attemptsAt []int64) string {
	t.Helper()
	ctx := t.Context()
	u, err := st.Users().Create(ctx, store.User{Email: "notify@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	now := store.NowUnix()
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO notification_endpoints
		   (id, user_id, label, url, secret_sealed, enabled, created_at, updated_at)
		 VALUES ('ep1', ?, 'l', 'https://example.com/h', 'sealed', 1, ?, ?)`,
		u.ID, now, now); err != nil {
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
	for _, at := range attemptsAt {
		if _, err := st.DB().ExecContext(ctx,
			`INSERT INTO notification_attempts (user_id, at) VALUES (?, ?)`, u.ID, at); err != nil {
			t.Fatalf("seed attempt: %v", err)
		}
	}
	return u.ID
}

func countRows(t *testing.T, st *store.Store, table string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(t.Context(), `SELECT count(*) FROM `+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestPrune_AttemptLedgerIsSweptWithoutAnyRetentionKey: the ledger is
// expiry-gated, so a default (all-zero) retention policy must still clear it.
// If this ever needs a key to work, the table grows forever on every default
// deployment.
func TestPrune_AttemptLedgerIsSweptWithoutAnyRetentionKey(t *testing.T) {
	st := openTestStore(t)
	now := store.NowUnix()
	seedNotificationRows(t, st, nil, []int64{
		now - 7200, // older than attemptLedgerTTL — must go
		now - 30,   // inside a live budget window — must stay
	})

	prune(t.Context(), st, config.RetentionSection{}, discardLog())

	if got := countRows(t, st, "notification_attempts"); got != 1 {
		t.Errorf("notification_attempts = %d rows, want 1 (only the recent one survives)", got)
	}
}

// TestPrune_DeliveriesNeedTheirKey: unlike the ledger, delivery history is a
// retention decision, so a zero key must delete nothing however old the rows.
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
	}, nil)

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
	}, nil)

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
// thing deleted was deliveries — i.e. the audit condition must include the
// delivery count, not just ip_history and audit_log.
func TestPrune_DeliveryDeletionsAreAudited(t *testing.T) {
	st := openTestStore(t)
	now := store.NowUnix()
	seedNotificationRows(t, st, []struct {
		status    string
		createdAt int64
	}{
		{store.DeliveryDelivered, now - 86400*90},
	}, nil)

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
// did; a sweep that deletes rows it does not name is unobservable.
func TestPrune_LogsTheNewCounts(t *testing.T) {
	st := openTestStore(t)
	// capturingLog() defaults to Info; prune's summary is Debug, so this test
	// needs its own handler or it asserts against an empty buffer.
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	prune(t.Context(), st, config.RetentionSection{}, log)

	for _, key := range []string{"notification_attempts", "notification_deliveries"} {
		if !strings.Contains(buf.String(), key) {
			t.Errorf("prune's summary line does not report %q", key)
		}
	}
}
