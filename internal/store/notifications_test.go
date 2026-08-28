package store

import (
	"context"
	"strings"
	"sync"
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
	for _, idx := range []string{
		"notification_endpoints_user",
		// notification_deliveries_endpoint (endpoint_id) was replaced by
		// migration 00005 with notification_deliveries_endpoint_id
		// (endpoint_id, id) — see that migration's comment for why the
		// single-column index became fully redundant once ListByEndpoint's
		// ORDER BY changed to id DESC.
		"notification_deliveries_endpoint_id",
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

// seedBudgetUser creates a user and one enabled endpoint for the ledger tests.
func seedBudgetUser(t *testing.T, s *Store, ctx context.Context, userID, epID string) {
	t.Helper()
	now := NowUnix()
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO users (id, email, role, disabled, created_at, updated_at)
		 VALUES (?, ?, 'user', 0, ?, ?)`, userID, userID+"@example.com", now, now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO notification_endpoints
		   (id, user_id, label, url, secret_sealed, enabled, created_at, updated_at)
		 VALUES (?, ?, 'l', ?, 'sealed', 1, ?, ?)`,
		epID, userID, "https://example.com/"+epID, now, now); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
}

// TestBudget_SurvivesEndpointDeleteAndRecreate pins the reason the attempt
// ledger exists at all.
//
// The budget originally counted stamped rows in notification_deliveries, whose
// endpoint_id is ON DELETE CASCADE. A user could delete the endpoint, recreate
// it, and get a fresh window — measured at 20 attempts in one 5-minute window
// against a cap of 5, unbounded. Re-keying the count on the owner was necessary
// but NOT sufficient: the cascade destroys the rows regardless of how they are
// counted (5 stamped rows before the delete, 0 after). Hence a ledger with no
// reference to endpoints.
func TestBudget_SurvivesEndpointDeleteAndRecreate(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	windowStart := now - 300
	const budget = 5

	seedBudgetUser(t, s, ctx, "u1", "ep1")

	spend := func() int {
		t.Helper()
		allowed := 0
		for range budget + 3 {
			ok, err := s.NotificationAttempts().Claim(ctx, "u1", now, windowStart, budget)
			if err != nil {
				t.Fatalf("Claim: %v", err)
			}
			if ok {
				allowed++
			}
		}
		return allowed
	}

	if got := spend(); got != budget {
		t.Fatalf("first window: %d allowed, want %d", got, budget)
	}

	if _, err := s.DB().ExecContext(ctx, `DELETE FROM notification_endpoints WHERE id = 'ep1'`); err != nil {
		t.Fatalf("delete endpoint: %v", err)
	}
	seedBudgetUser2(t, s, ctx, "u1", "ep2")

	if got := spend(); got != 0 {
		t.Errorf("after delete-and-recreate: %d further attempts allowed, want 0 — "+
			"the budget window reset, so it does not bound the user's outbound rate", got)
	}
}

// seedBudgetUser2 adds a second endpoint for an existing user.
func seedBudgetUser2(t *testing.T, s *Store, ctx context.Context, userID, epID string) {
	t.Helper()
	now := NowUnix()
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO notification_endpoints
		   (id, user_id, label, url, secret_sealed, enabled, created_at, updated_at)
		 VALUES (?, ?, 'l', ?, 'sealed', 1, ?, ?)`,
		epID, userID, "https://example.com/"+epID, now, now); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
}

// TestBudget_IsPerUserNotPerEndpoint: a second endpoint must not multiply the
// budget.
func TestBudget_IsPerUserNotPerEndpoint(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	windowStart := now - 300
	const budget = 5

	seedBudgetUser(t, s, ctx, "u1", "ep1")
	seedBudgetUser2(t, s, ctx, "u1", "ep2")

	allowed := 0
	for range budget * 2 {
		ok, err := s.NotificationAttempts().Claim(ctx, "u1", now, windowStart, budget)
		if err != nil {
			t.Fatalf("Claim: %v", err)
		}
		if ok {
			allowed++
		}
	}
	if allowed != budget {
		t.Errorf("two endpoints allowed %d attempts, want %d — the budget multiplied per endpoint", allowed, budget)
	}
}

// TestBudget_ClaimIsAtomicUnderConcurrency closes the property design §17
// parked as unverified: that INSERT ... WHERE (SELECT count) < N is atomic
// under modernc.org/sqlite with SetMaxOpenConns(1).
func TestBudget_ClaimIsAtomicUnderConcurrency(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	windowStart := now - 300
	const budget = 5
	const racers = 12

	seedBudgetUser(t, s, ctx, "u1", "ep1")

	var wg sync.WaitGroup
	results := make([]bool, racers)
	for i := range results {
		wg.Go(func() {
			ok, err := s.NotificationAttempts().Claim(ctx, "u1", now, windowStart, budget)
			if err != nil {
				t.Errorf("Claim: %v", err)
				return
			}
			results[i] = ok
		})
	}
	wg.Wait()

	allowed := 0
	for _, ok := range results {
		if ok {
			allowed++
		}
	}
	if allowed != budget {
		t.Errorf("%d of %d concurrent claims allowed, want exactly %d — the claim is not atomic",
			allowed, racers, budget)
	}
	var rows int
	if err := s.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM notification_attempts WHERE user_id='u1'`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != budget {
		t.Errorf("ledger holds %d rows, want %d", rows, budget)
	}
}

// TestBudget_WindowExpires: attempts outside the window do not count.
func TestBudget_WindowExpires(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	const budget = 5

	seedBudgetUser(t, s, ctx, "u1", "ep1")

	old := now - 1000
	for range budget {
		if ok, err := s.NotificationAttempts().Claim(ctx, "u1", old, old-300, budget); err != nil || !ok {
			t.Fatalf("seed old claim: ok=%v err=%v", ok, err)
		}
	}
	ok, err := s.NotificationAttempts().Claim(ctx, "u1", now, now-300, budget)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if !ok {
		t.Error("claim refused although every prior attempt is outside the window")
	}
}

// TestNotificationAttempts_PruneExpired: ledger rows outside any live budget
// window are dead weight. They are expiry-gated, not retention-gated — an
// operator has no policy to express about them, exactly like replay_nonces.
func TestNotificationAttempts_PruneExpired(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	seedBudgetUser(t, s, ctx, "u1", "ep1")

	for _, at := range []int64{now - 7200, now - 5400, now - 60, now} {
		if _, err := s.DB().ExecContext(ctx,
			`INSERT INTO notification_attempts (user_id, at) VALUES ('u1', ?)`, at); err != nil {
			t.Fatalf("seed attempt: %v", err)
		}
	}

	n, err := s.NotificationAttempts().PruneExpired(ctx, now-3600)
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if n != 2 {
		t.Errorf("pruned %d, want 2 (the two older than the cutoff)", n)
	}
	var left int
	if err := s.DB().QueryRowContext(ctx, `SELECT count(*) FROM notification_attempts`).Scan(&left); err != nil {
		t.Fatalf("count: %v", err)
	}
	if left != 2 {
		t.Errorf("%d rows left, want 2", left)
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
	seedBudgetUser(t, s, ctx, "u1", "ep1")

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
	seedBudgetUser(t, s, ctx, "u1", "ep1")

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
