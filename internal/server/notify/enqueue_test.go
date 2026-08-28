package notify

import (
	"io"
	"log/slog"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

func TestEnqueuer_IPChanged_FansOutToOwnerEnabledEndpointsOnly(t *testing.T) {
	st := newTestStore(t)
	ctx := t.Context()
	now := store.NowUnix()

	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO users (id, email, role, disabled, created_at, updated_at)
		 VALUES ('owner', 'owner@example.com', 'user', 0, ?, ?),
		        ('other', 'other@example.com', 'user', 0, ?, ?)`,
		now, now, now, now); err != nil {
		t.Fatalf("seed users: %v", err)
	}

	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO notification_endpoints
		   (id, user_id, label, url, secret_sealed, enabled, created_at, updated_at)
		 VALUES
		   ('ep1', 'owner', 'a', 'https://example.com/1', 'sealed', 1, ?, ?),
		   ('ep2', 'owner', 'b', 'https://example.com/2', 'sealed', 1, ?, ?),
		   ('ep3', 'owner', 'c', 'https://example.com/3', 'sealed', 0, ?, ?),
		   ('ep4', 'other', 'd', 'https://example.com/4', 'sealed', 1, ?, ?)`,
		now, now, now, now, now, now, now, now); err != nil {
		t.Fatalf("seed endpoints: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := NewEnqueuer(st, log)

	e.IPChanged(ctx, store.IPChangeEvent{
		EventID:    99,
		OccurredAt: now,
		Device:     store.Device{ID: "dev1", UserID: "owner"},
		PrevIPv4:   "1.1.1.1", CurrIPv4: "2.2.2.2",
	})

	rows, err := st.DB().QueryContext(ctx,
		`SELECT endpoint_id, user_initiated_at FROM notification_deliveries ORDER BY endpoint_id`)
	if err != nil {
		t.Fatalf("query deliveries: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var got []string
	for rows.Next() {
		var endpointID string
		var userInitiatedAt any
		if err := rows.Scan(&endpointID, &userInitiatedAt); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if userInitiatedAt != nil {
			t.Errorf("endpoint %s: user_initiated_at = %v, want NULL", endpointID, userInitiatedAt)
		}
		got = append(got, endpointID)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	if len(got) != 2 || got[0] != "ep1" || got[1] != "ep2" {
		t.Errorf("delivered endpoints = %v, want [ep1 ep2]", got)
	}
}
