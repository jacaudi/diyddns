package notify

import (
	"io"
	"log/slog"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// seedEndpoints inserts three server-global endpoints, two enabled.
func seedEndpoints(t *testing.T, st *store.Store) {
	t.Helper()
	now := store.NowUnix()
	if _, err := st.DB().ExecContext(t.Context(),
		`INSERT INTO notification_endpoints
		   (id, label, url, secret_sealed, enabled, created_at, updated_at)
		 VALUES
		   ('ep1', 'a', 'https://example.com/1', 'sealed', 1, ?, ?),
		   ('ep2', 'b', 'https://example.com/2', 'sealed', 1, ?, ?),
		   ('ep3', 'c', 'https://example.com/3', 'sealed', 0, ?, ?)`,
		now, now, now, now, now, now); err != nil {
		t.Fatalf("seed endpoints: %v", err)
	}
}

func deliveredEndpoints(t *testing.T, st *store.Store) []string {
	t.Helper()
	rows, err := st.DB().QueryContext(t.Context(),
		`SELECT endpoint_id FROM notification_deliveries ORDER BY endpoint_id`)
	if err != nil {
		t.Fatalf("query deliveries: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return got
}

// TestEnqueuer_Enqueue_FansOutToEveryEnabledEndpoint: endpoints are
// server-global (#106), so every enabled endpoint gets the row whoever owns
// the device, and a disabled one gets nothing.
func TestEnqueuer_Enqueue_FansOutToEveryEnabledEndpoint(t *testing.T) {
	st := newTestStore(t)
	seedEndpoints(t, st)
	e := NewEnqueuer(st, slog.New(slog.NewTextHandler(io.Discard, nil)))

	e.Enqueue(t.Context(), EventRemoved, 9, []byte(`{"type":"device.removed"}`))

	if got := deliveredEndpoints(t, st); len(got) != 2 || got[0] != "ep1" || got[1] != "ep2" {
		t.Errorf("delivered endpoints = %v, want [ep1 ep2]", got)
	}
	var eventType string
	var eventID int64
	if err := st.DB().QueryRowContext(t.Context(),
		`SELECT event_type, event_id FROM notification_deliveries WHERE endpoint_id = 'ep1'`).Scan(&eventType, &eventID); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if eventType != EventRemoved || eventID != 9 {
		t.Errorf("row = (%s, %d), want (device.removed, 9)", eventType, eventID)
	}
}

// TestEnqueuer_IPChanged_StillSatisfiesNotifier: the wrapper renders and
// fans out, so the Enqueuer alone still implements service.Notifier. It must
// reach exactly the enabled endpoints (never the disabled ep3) and stamp the
// stored rows with the ip_changed type and the event's own id — that
// selection and rendering is the wrapper's one job.
func TestEnqueuer_IPChanged_StillSatisfiesNotifier(t *testing.T) {
	st := newTestStore(t)
	seedEndpoints(t, st)
	e := NewEnqueuer(st, slog.New(slog.NewTextHandler(io.Discard, nil)))

	e.IPChanged(t.Context(), store.IPChangeEvent{
		EventID: 99, OccurredAt: store.NowUnix(),
		Device:   store.Device{ID: "dev1", Label: "l"},
		PrevIPv4: "1.1.1.1", CurrIPv4: "2.2.2.2",
	})

	if got := deliveredEndpoints(t, st); len(got) != 2 || got[0] != "ep1" || got[1] != "ep2" {
		t.Errorf("delivered endpoints = %v, want [ep1 ep2]", got)
	}
	var eventType string
	var eventID int64
	if err := st.DB().QueryRowContext(t.Context(),
		`SELECT event_type, event_id FROM notification_deliveries WHERE endpoint_id = 'ep1'`).Scan(&eventType, &eventID); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if eventType != EventIPChanged || eventID != 99 {
		t.Errorf("row = (%s, %d), want (device.ip_changed, 99)", eventType, eventID)
	}
}
