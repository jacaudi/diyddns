package store

import "testing"

func TestMigration004_CreatesNotificationTables(t *testing.T) {
	s, ctx := newTestStore(t)

	for _, tbl := range []string{"notification_endpoints", "notification_deliveries"} {
		var got string
		err := s.DB().QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&got)
		if err != nil {
			t.Errorf("table %q missing after migrations: %v", tbl, err)
		}
	}
	for _, idx := range []string{
		"notification_endpoints_user",
		"notification_deliveries_endpoint",
		"notification_deliveries_next_attempt",
		"notification_deliveries_user_initiated",
	} {
		var got string
		err := s.DB().QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&got)
		if err != nil {
			t.Errorf("index %q missing after migrations: %v", idx, err)
		}
	}
}

func TestMigration004_AcceptsDeliveryInsert(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()

	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO users (id, email, role, disabled, created_at, updated_at)
		 VALUES ('u1', 'a@example.com', 'user', 0, ?, ?)`, now, now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO notification_endpoints
		   (id, user_id, label, url, secret_sealed, enabled, created_at, updated_at)
		 VALUES ('ep1', 'u1', 'l', 'https://example.com/h', 'sealed', 1, ?, ?)`,
		now, now); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	// Exactly the column list Task 6's enqueue uses. A column missing here is
	// how the design's budget became a silent no-op (design §21).
	res, err := s.DB().ExecContext(ctx,
		`INSERT INTO notification_deliveries
		   (endpoint_id, event_type, event_id, payload, attempts,
		    next_attempt_at, status, user_initiated_at, created_at, updated_at)
		 VALUES ('ep1', 'device.ip_changed', 42, ?, 0, ?, 'pending', NULL, ?, ?)`,
		[]byte(`{}`), now, now, now)
	if err != nil {
		t.Fatalf("insert delivery: %v", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		t.Errorf("RowsAffected = %d, want 1", n)
	}
}

// TestNotificationEndpoints_ListEnabledByUser also guards the cross-user
// blind spot: with only one user seeded, removing the `user_id = ?`
// predicate from the query would still pass (there is nothing else to leak
// into the result), so u2's enabled endpoint below is what actually exercises
// scoping.
func TestNotificationEndpoints_ListEnabledByUser(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO users (id, email, role, disabled, created_at, updated_at)
		 VALUES ('u1', 'a@example.com', 'user', 0, ?, ?), ('u2', 'b@example.com', 'user', 0, ?, ?)`,
		now, now, now, now); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO notification_endpoints
		   (id, user_id, label, url, secret_sealed, enabled, created_at, updated_at)
		 VALUES
		   ('ep1', 'u1', 'enabled', 'https://example.com/1', 'sealed', 1, ?, ?),
		   ('ep2', 'u1', 'disabled', 'https://example.com/2', 'sealed', 0, ?, ?),
		   ('ep3', 'u2', 'other user enabled', 'https://example.com/3', 'sealed', 1, ?, ?)`,
		now, now, now, now, now, now); err != nil {
		t.Fatalf("seed endpoints: %v", err)
	}

	got, err := s.NotificationEndpoints().ListEnabledByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListEnabledByUser: %v", err)
	}
	if len(got) != 1 || got[0].ID != "ep1" {
		t.Errorf("ListEnabledByUser = %+v, want exactly [ep1]", got)
	}
}

func TestNotificationDeliveries_EnqueueLeavesUserInitiatedNull(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO users (id, email, role, disabled, created_at, updated_at)
		 VALUES ('u1', 'a@example.com', 'user', 0, ?, ?)`, now, now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO notification_endpoints
		   (id, user_id, label, url, secret_sealed, enabled, created_at, updated_at)
		 VALUES ('ep1', 'u1', 'l', 'https://example.com/h', 'sealed', 1, ?, ?)`,
		now, now); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}

	err := s.NotificationDeliveries().Enqueue(ctx, NotificationDelivery{
		EndpointID: "ep1", EventType: "device.ip_changed", EventID: 42,
		Payload: []byte(`{}`), NextAttemptAt: NowUnix(), Status: "pending",
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	var ui any
	if err := s.DB().QueryRowContext(ctx,
		`SELECT user_initiated_at FROM notification_deliveries WHERE endpoint_id='ep1'`).Scan(&ui); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if ui != nil {
		t.Errorf("user_initiated_at = %v, want NULL; a server-initiated delivery must not spend a user's budget", ui)
	}
}
