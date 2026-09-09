package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

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
	// notification_endpoints_user and notification_deliveries_user_initiated
	// were dropped by migration 00007 along with user ownership and the
	// per-user attempt budget (#106).
	for _, idx := range []string{
		"notification_deliveries_endpoint_id",
		"notification_deliveries_next_attempt",
	} {
		var got string
		err := s.DB().QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&got)
		if err != nil {
			t.Errorf("index %q missing after migrations: %v", idx, err)
		}
	}
	for _, idx := range []string{"notification_endpoints_user", "notification_deliveries_user_initiated"} {
		var got string
		err := s.DB().QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&got)
		if err == nil {
			t.Errorf("index %q still exists; migration 00007 must drop it", idx)
		}
	}
}

// TestListByEndpoint_UsesIndexNoTempBTree is the regression guard for S4: the
// endpoint-detail page's delivery-history query used to sort EVERY row for
// the endpoint before applying LIMIT ("USE TEMP B-TREE FOR ORDER BY" in
// EXPLAIN QUERY PLAN), because ORDER BY created_at DESC, id DESC could not be
// satisfied by any index. ListByEndpoint now orders by id DESC alone (id is
// INTEGER PRIMARY KEY AUTOINCREMENT and created_at is set once at insert, so
// the two orderings are equivalent), which migration 00005's composite
// (endpoint_id, id) index satisfies directly.
func TestListByEndpoint_UsesIndexNoTempBTree(t *testing.T) {
	s, ctx := newTestStore(t)

	rows, err := s.DB().QueryContext(ctx, "EXPLAIN QUERY PLAN "+listByEndpointQuery, "ep1", 50)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var plan []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scan: %v", err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	for _, step := range plan {
		if strings.Contains(step, "TEMP B-TREE") {
			t.Errorf("query plan uses a temp b-tree for ORDER BY: %v", plan)
		}
	}
	if len(plan) == 0 {
		t.Fatal("EXPLAIN QUERY PLAN returned no rows")
	}
	if !strings.Contains(plan[0], "notification_deliveries_endpoint_id") {
		t.Errorf("plan does not use the composite index: %v", plan)
	}
}

// seedEndpointRow inserts one server-global endpoint directly.
func seedEndpointRow(t *testing.T, s *Store, ctx context.Context, id, label, url string, enabled bool) {
	t.Helper()
	now := NowUnix()
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO notification_endpoints
		   (id, label, url, secret_sealed, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, 'sealed', ?, ?, ?)`,
		id, label, url, boolToInt(enabled), now, now); err != nil {
		t.Fatalf("seed endpoint %s: %v", id, err)
	}
}

func TestMigration004_AcceptsDeliveryInsert(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	seedEndpointRow(t, s, ctx, "ep1", "l", "https://example.com/h", true)

	// Exactly the column list Enqueue uses.
	res, err := s.DB().ExecContext(ctx,
		`INSERT INTO notification_deliveries
		   (endpoint_id, event_type, event_id, payload, attempts,
		    next_attempt_at, status, created_at, updated_at)
		 VALUES ('ep1', 'device.ip_changed', 42, ?, 0, ?, 'pending', ?, ?)`,
		[]byte(`{}`), now, now, now)
	if err != nil {
		t.Fatalf("insert delivery: %v", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		t.Errorf("RowsAffected = %d, want 1", n)
	}
}

func TestNotificationEndpoints_CreateGetListDelete(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()

	ep := NotificationEndpoint{ID: "ep1", Label: "a", URL: "https://example.com/1", SecretSealed: "sealed", CreatedAt: now, UpdatedAt: now}
	if err := s.NotificationEndpoints().Create(ctx, ep); err != nil {
		t.Fatalf("Create: %v", err)
	}
	dup := NotificationEndpoint{ID: "ep2", Label: "b", URL: "https://example.com/1", SecretSealed: "sealed", CreatedAt: now, UpdatedAt: now}
	if err := s.NotificationEndpoints().Create(ctx, dup); !errors.Is(err, ErrConflict) {
		t.Errorf("Create(duplicate url) err = %v, want ErrConflict", err)
	}

	got, err := s.NotificationEndpoints().Get(ctx, "ep1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Label != "a" || !got.Enabled {
		t.Errorf("Get = %+v, want label a, enabled", got)
	}
	if _, err := s.NotificationEndpoints().Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get(missing) err = %v, want ErrNotFound", err)
	}

	list, err := s.NotificationEndpoints().List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].ID != "ep1" {
		t.Errorf("List = %+v, want [ep1]", list)
	}

	if err := s.NotificationEndpoints().Delete(ctx, "ep1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.NotificationEndpoints().Delete(ctx, "ep1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete(again) err = %v, want ErrNotFound", err)
	}
}

// TestNotificationEndpoints_ListEnabled: the fan-out reads every enabled
// endpoint server-wide (design D2); disabled ones are excluded.
func TestNotificationEndpoints_ListEnabled(t *testing.T) {
	s, ctx := newTestStore(t)
	seedEndpointRow(t, s, ctx, "ep1", "enabled", "https://example.com/1", true)
	seedEndpointRow(t, s, ctx, "ep2", "disabled", "https://example.com/2", false)
	seedEndpointRow(t, s, ctx, "ep3", "also enabled", "https://example.com/3", true)

	got, err := s.NotificationEndpoints().ListEnabled(ctx)
	if err != nil {
		t.Fatalf("ListEnabled: %v", err)
	}
	if len(got) != 2 || got[0].ID != "ep1" || got[1].ID != "ep3" {
		t.Errorf("ListEnabled = %+v, want exactly [ep1 ep3]", got)
	}
}

func TestNotificationEndpoints_SetEnabled(t *testing.T) {
	s, ctx := newTestStore(t)
	seedEndpointRow(t, s, ctx, "ep1", "l", "https://example.com/1", true)

	if err := s.NotificationEndpoints().SetEnabled(ctx, "ep1", false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	got, err := s.NotificationEndpoints().Get(ctx, "ep1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Enabled {
		t.Error("endpoint still enabled after SetEnabled(false)")
	}
	if err := s.NotificationEndpoints().SetEnabled(ctx, "missing", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetEnabled(missing) err = %v, want ErrNotFound", err)
	}
}

func TestNotificationDeliveries_EnqueueAndDue(t *testing.T) {
	s, ctx := newTestStore(t)
	seedEndpointRow(t, s, ctx, "ep1", "l", "https://example.com/h", true)

	err := s.NotificationDeliveries().Enqueue(ctx, NotificationDelivery{
		EndpointID: "ep1", EventType: "device.ip_changed", EventID: 42,
		Payload: []byte(`{}`), NextAttemptAt: NowUnix(), Status: DeliveryPending,
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	due, err := s.NotificationDeliveries().DueForAttempt(ctx, NowUnix()+1, 10)
	if err != nil {
		t.Fatalf("DueForAttempt: %v", err)
	}
	if len(due) != 1 || due[0].EndpointURL != "https://example.com/h" || due[0].EventID != 42 {
		t.Errorf("DueForAttempt = %+v, want the one enqueued row joined with its endpoint", due)
	}
}

// TestInsertUserTest_EnabledOnly: the admin's test route inserts one
// endpoint.test row for an enabled endpoint and refuses for a disabled or
// missing one — the enabled predicate is carried by the single INSERT.
func TestInsertUserTest_EnabledOnly(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	seedEndpointRow(t, s, ctx, "on", "l", "https://example.com/on", true)
	seedEndpointRow(t, s, ctx, "off", "l2", "https://example.com/off", false)

	ok, err := s.NotificationDeliveries().InsertUserTest(ctx, "on", []byte(`{}`), now)
	if err != nil || !ok {
		t.Fatalf("InsertUserTest(on) = %v, %v; want true, nil", ok, err)
	}
	ok, err = s.NotificationDeliveries().InsertUserTest(ctx, "off", []byte(`{}`), now)
	if err != nil || ok {
		t.Fatalf("InsertUserTest(off) = %v, %v; want false, nil", ok, err)
	}
	ok, err = s.NotificationDeliveries().InsertUserTest(ctx, "missing", []byte(`{}`), now)
	if err != nil || ok {
		t.Fatalf("InsertUserTest(missing) = %v, %v; want false, nil", ok, err)
	}
	rows, err := s.NotificationDeliveries().ListByEndpoint(ctx, "on", 10)
	if err != nil {
		t.Fatalf("ListByEndpoint: %v", err)
	}
	if len(rows) != 1 || rows[0].EventType != "endpoint.test" || rows[0].EventID != 0 {
		t.Errorf("rows = %+v, want one endpoint.test row with event_id 0", rows)
	}
}

// TestInsertRedelivery_TerminalAndEnabledOnly: a redelivery is a COPY of a
// terminal row (history preserved), refused for a pending source or a
// disabled endpoint.
func TestInsertRedelivery_TerminalAndEnabledOnly(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	seedEndpointRow(t, s, ctx, "ep1", "l", "https://example.com/h", true)

	insert := func(status string) int64 {
		t.Helper()
		res, err := s.DB().ExecContext(ctx,
			`INSERT INTO notification_deliveries
			   (endpoint_id, event_type, event_id, payload, attempts, next_attempt_at, status, created_at, updated_at)
			 VALUES ('ep1', 'device.ip_changed', 7, ?, 3, NULL, ?, ?, ?)`,
			[]byte(`{"k":1}`), status, now, now)
		if err != nil {
			t.Fatalf("seed %s: %v", status, err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	failed := insert(DeliveryFailed)
	pending := insert(DeliveryPending)

	ok, err := s.NotificationDeliveries().InsertRedelivery(ctx, failed, now)
	if err != nil || !ok {
		t.Fatalf("InsertRedelivery(failed) = %v, %v; want true, nil", ok, err)
	}
	ok, err = s.NotificationDeliveries().InsertRedelivery(ctx, pending, now)
	if err != nil || ok {
		t.Fatalf("InsertRedelivery(pending) = %v, %v; want false, nil", ok, err)
	}
	if err := s.NotificationEndpoints().SetEnabled(ctx, "ep1", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	ok, err = s.NotificationDeliveries().InsertRedelivery(ctx, failed, now)
	if err != nil || ok {
		t.Fatalf("InsertRedelivery(disabled endpoint) = %v, %v; want false, nil", ok, err)
	}

	rows, err := s.NotificationDeliveries().ListByEndpoint(ctx, "ep1", 10)
	if err != nil {
		t.Fatalf("ListByEndpoint: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3 (failed, pending, and the one copy)", len(rows))
	}
	copyRow := rows[0] // newest first
	if copyRow.Status != DeliveryPending || copyRow.Attempts != 0 || copyRow.EventID != 7 || string(copyRow.Payload) != `{"k":1}` {
		t.Errorf("redelivery copy = %+v, want pending, 0 attempts, same event_id and payload", copyRow)
	}
}

// TestNotificationDeliveries_PruneNeverTouchesPending is the safety property
// that matters. A pending row is work the sweeper still owes; deleting one
// silently drops a delivery the user is waiting on, and no retry would ever
// notice. Only terminal rows are eligible, however old a pending row is.
func TestNotificationDeliveries_PruneNeverTouchesPending(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	old := now - 86400*30
	seedEndpointRow(t, s, ctx, "ep1", "l", "https://example.com/h", true)

	insert := func(status string, createdAt int64) {
		t.Helper()
		if _, err := s.DB().ExecContext(ctx,
			`INSERT INTO notification_deliveries
			   (endpoint_id, event_type, event_id, payload, attempts,
			    next_attempt_at, status, created_at, updated_at)
			 VALUES ('ep1','device.ip_changed',1,?,0,?,?,?,?)`,
			[]byte(`{}`), now, status, createdAt, createdAt); err != nil {
			t.Fatalf("seed %s: %v", status, err)
		}
	}
	insert(DeliveryPending, old)   // ancient but still owed — must survive
	insert(DeliveryDelivered, old) // terminal and old — must go
	insert(DeliveryFailed, old)    // terminal and old — must go
	insert(DeliveryDelivered, now) // terminal but recent — must survive

	n, err := s.NotificationDeliveries().Prune(ctx, now-86400, 5000)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 2 {
		t.Errorf("pruned %d, want 2", n)
	}
	var pending int
	if err := s.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM notification_deliveries WHERE status = ?`, DeliveryPending).Scan(&pending); err != nil {
		t.Fatalf("count pending: %v", err)
	}
	if pending != 1 {
		t.Errorf("pending rows = %d, want 1 — pruning must never delete owed work", pending)
	}
}

// TestNotificationDeliveries_PruneRespectsBatch: the sweep must be batched, so
// a large backlog cannot monopolise the process's single SQLite connection.
func TestNotificationDeliveries_PruneRespectsBatch(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	old := now - 86400*30
	seedEndpointRow(t, s, ctx, "ep1", "l", "https://example.com/h", true)

	for range 7 {
		if _, err := s.DB().ExecContext(ctx,
			`INSERT INTO notification_deliveries
			   (endpoint_id, event_type, event_id, payload, attempts,
			    next_attempt_at, status, created_at, updated_at)
			 VALUES ('ep1','device.ip_changed',1,?,1,NULL,?,?,?)`,
			[]byte(`{}`), DeliveryFailed, old, old); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	n, err := s.NotificationDeliveries().Prune(ctx, now-86400, 3)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 3 {
		t.Errorf("first batch pruned %d, want 3 (the batch cap)", n)
	}
}
