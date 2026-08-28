package service

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/server/notify"
	"github.com/jacaudi/diyddns/internal/store"
)

// newNotificationServiceTest opens a fresh in-memory store, seeds one user,
// and builds a NotificationService with no operator-configured allow-list
// and a generous per-user endpoint cap. Reused by every NotificationService
// test in this file.
func newNotificationServiceTest(t *testing.T) (*store.Store, string, *NotificationService) {
	t.Helper()
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	allowed, err := notify.ParseAllowed(nil)
	if err != nil {
		t.Fatalf("ParseAllowed: %v", err)
	}
	svc := NewNotificationService(st, testKey32(), 5, allowed, discardAudit{})
	return st, usr.ID, svc
}

// seedEndpoint inserts a notification endpoint directly via the store,
// bypassing service-level validation so tests can construct scenarios the
// service itself would reject at creation time (e.g. a disabled endpoint).
func seedEndpoint(t *testing.T, st *store.Store, userID, url string, enabled bool) store.NotificationEndpoint {
	t.Helper()
	now := store.NowUnix()
	ep := store.NotificationEndpoint{
		ID:           store.NewID(),
		UserID:       userID,
		Label:        "ep",
		URL:          url,
		SecretSealed: "sealed",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := st.NotificationEndpoints().Create(t.Context(), ep, 1000); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	ep.Enabled = true
	if !enabled {
		if err := st.NotificationEndpoints().SetEnabled(t.Context(), userID, ep.ID, false); err != nil {
			t.Fatalf("seed endpoint disable: %v", err)
		}
		ep.Enabled = false
	}
	return ep
}

// seedTerminalDelivery inserts one notification_deliveries row directly,
// with no user_initiated_at (a server-initiated delivery that reached
// status), so budget tests start from a clean window.
func seedTerminalDelivery(t *testing.T, st *store.Store, endpointID, status string) int64 {
	t.Helper()
	now := store.NowUnix()
	res, err := st.DB().ExecContext(t.Context(),
		`INSERT INTO notification_deliveries
		   (endpoint_id, event_type, event_id, payload, attempts,
		    next_attempt_at, status, user_initiated_at, created_at, updated_at)
		 VALUES (?, 'device.ip_changed', 1, ?, 1, NULL, ?, NULL, ?, ?)`,
		endpointID, []byte(`{}`), status, now, now,
	)
	if err != nil {
		t.Fatalf("seed terminal delivery: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("seed terminal delivery: LastInsertId: %v", err)
	}
	return id
}

// seedUserInitiatedDelivery inserts one notification_deliveries row with
// user_initiated_at stamped explicitly at userInitiatedAt, so budget-window
// tests can construct attempts that are old enough to have aged out.
func seedUserInitiatedDelivery(t *testing.T, st *store.Store, endpointID string, userInitiatedAt int64) int64 {
	t.Helper()
	now := store.NowUnix()
	res, err := st.DB().ExecContext(t.Context(),
		`INSERT INTO notification_deliveries
		   (endpoint_id, event_type, event_id, payload, attempts,
		    next_attempt_at, status, user_initiated_at, created_at, updated_at)
		 VALUES (?, 'endpoint.test', 0, ?, 0, NULL, 'delivered', ?, ?, ?)`,
		endpointID, []byte(`{}`), userInitiatedAt, now, now,
	)
	if err != nil {
		t.Fatalf("seed user-initiated delivery: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("seed user-initiated delivery: LastInsertId: %v", err)
	}
	return id
}

// TestBudget_OldAttemptsAgeOutOfWindow is the regression guard for the
// windowStart computation in Test/Redeliver:
//
//	windowStart := now - int64(notify.UserBudgetWindow/time.Second)
//
// notify.UserBudgetWindow is a time.Duration (nanoseconds); it must be
// divided by time.Second before being subtracted from now, a Unix-seconds
// timestamp. Passing the raw, unconverted Duration makes windowStart deeply
// negative — a window reaching back roughly 9,500 years — which inside a
// short-lived test is indistinguishable from a correct 300-second window: it
// only manifests when an attempt genuinely older than 5 minutes should age
// OUT of the budget and, under the bug, doesn't. This control has silently
// failed three times in this project's history; this test is the guard.
//
// It exhausts the budget with attempts a full day old, then asserts a fresh
// attempt is ALLOWED because those old attempts have aged out of the
// 5-minute window. Under the raw-Duration mutation the old rows never age
// out, the budget stays "exhausted" forever, and this assertion fails.
func TestBudget_OldAttemptsAgeOutOfWindow(t *testing.T) {
	st, userID, svc := newNotificationServiceTest(t)
	ep := seedEndpoint(t, st, userID, "https://example.com/hook", true)

	dayOld := store.NowUnix() - int64(24*time.Hour/time.Second)
	for range notify.UserBudgetCount {
		seedUserInitiatedDelivery(t, st, ep.ID, dayOld)
	}

	ok, err := svc.Test(t.Context(), userID, ep.ID)
	if err != nil {
		t.Fatalf("Test: unexpected error %v", err)
	}
	if !ok {
		t.Fatal("expected a fresh attempt to be allowed: the day-old attempts should have aged out of the 5-minute budget window")
	}
}

func TestCreate_RejectsNonHTTPScheme(t *testing.T) {
	st, userID, svc := newNotificationServiceTest(t)

	if _, _, err := svc.Create(t.Context(), userID, "bad", "ftp://example.com/hook"); err == nil {
		t.Fatal("expected an error for a non-http(s) scheme")
	}

	eps, err := st.NotificationEndpoints().ListByUser(t.Context(), userID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(eps) != 0 {
		t.Fatalf("expected no endpoint written, got %d", len(eps))
	}
}

func TestCreate_RejectsDeniedIPLiteral(t *testing.T) {
	st, userID, svc := newNotificationServiceTest(t)

	_, _, err := svc.Create(t.Context(), userID, "metadata", "https://169.254.169.254/")
	if !errors.Is(err, notify.ErrDenied) {
		t.Fatalf("err = %v, want notify.ErrDenied", err)
	}

	eps, err := st.NotificationEndpoints().ListByUser(t.Context(), userID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(eps) != 0 {
		t.Fatalf("expected no endpoint written, got %d", len(eps))
	}
}

func TestCreate_AcceptsHostnameWithoutResolving(t *testing.T) {
	_, userID, svc := newNotificationServiceTest(t)

	ep, secret, err := svc.Create(t.Context(), userID, "consumer", "https://consumer.lan/hook")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ep.URL != "https://consumer.lan/hook" {
		t.Fatalf("URL = %q, want https://consumer.lan/hook", ep.URL)
	}
	if secret == "" {
		t.Fatal("expected a non-empty returned secret")
	}
}

func TestCreate_ReturnsSecretOnceAndSealsIt(t *testing.T) {
	st, userID, svc := newNotificationServiceTest(t)

	ep, secretB64, err := svc.Create(t.Context(), userID, "ep", "https://example.com/hook")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if secretB64 == "" {
		t.Fatal("expected a returned secret")
	}
	raw, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		t.Fatalf("returned secret is not valid base64: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("decoded secret length = %d, want 32", len(raw))
	}

	stored, err := st.NotificationEndpoints().GetOwned(t.Context(), userID, ep.ID)
	if err != nil {
		t.Fatalf("GetOwned: %v", err)
	}
	if stored.SecretSealed == secretB64 {
		t.Fatal("the stored column must not equal the plaintext secret returned to the caller")
	}
	opened, err := auth.OpenSecret(testKey32(), stored.SecretSealed)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	if !bytes.Equal(opened, raw) {
		t.Fatal("the sealed secret must decrypt to the returned plaintext secret")
	}
}

func TestCreate_EnforcesMaxPerUser(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	allowed, err := notify.ParseAllowed(nil)
	if err != nil {
		t.Fatalf("ParseAllowed: %v", err)
	}
	svc := NewNotificationService(st, testKey32(), 2, allowed, discardAudit{})

	if _, _, err := svc.Create(t.Context(), usr.ID, "one", "https://one.example.com/"); err != nil {
		t.Fatalf("create 1: %v", err)
	}
	if _, _, err := svc.Create(t.Context(), usr.ID, "two", "https://two.example.com/"); err != nil {
		t.Fatalf("create 2: %v", err)
	}
	if _, _, err := svc.Create(t.Context(), usr.ID, "three", "https://three.example.com/"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("create 3: err = %v, want ErrConflict", err)
	}
}

func TestOwnership_ForeignEndpointIsNotFound(t *testing.T) {
	st, userID, svc := newNotificationServiceTest(t)
	other := seedUser(t, st, "other@b.co", "user")
	ep := seedEndpoint(t, st, userID, "https://example.com/hook", true)

	if _, err := svc.Get(t.Context(), other.ID, ep.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get: err = %v, want store.ErrNotFound", err)
	}
	if err := svc.SetEnabled(t.Context(), other.ID, ep.ID, false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SetEnabled: err = %v, want store.ErrNotFound", err)
	}
	if _, err := svc.Deliveries(t.Context(), other.ID, ep.ID, 50); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Deliveries: err = %v, want store.ErrNotFound", err)
	}
	if err := svc.Delete(t.Context(), other.ID, ep.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete: err = %v, want store.ErrNotFound", err)
	}

	// The endpoint must still exist for its real owner — Delete above must
	// not have succeeded against the foreign call.
	if _, err := svc.Get(t.Context(), userID, ep.ID); err != nil {
		t.Fatalf("owner's Get after foreign calls: %v", err)
	}
}

func TestRedeliver_ForeignDeliveryIsNotFound(t *testing.T) {
	st, userID, svc := newNotificationServiceTest(t)
	other := seedUser(t, st, "other@b.co", "user")
	ep := seedEndpoint(t, st, userID, "https://example.com/hook", true)
	deliveryID := seedTerminalDelivery(t, st, ep.ID, "failed")

	ok, err := svc.Redeliver(t.Context(), other.ID, deliveryID)
	if err != nil {
		t.Fatalf("Redeliver: unexpected error %v", err)
	}
	if ok {
		t.Fatal("expected refusal for a delivery owned by a different user")
	}
}

func TestRedeliver_RefusedOnDisabledEndpoint(t *testing.T) {
	st, userID, svc := newNotificationServiceTest(t)
	ep := seedEndpoint(t, st, userID, "https://example.com/hook", false)
	deliveryID := seedTerminalDelivery(t, st, ep.ID, "failed")

	ok, err := svc.Redeliver(t.Context(), userID, deliveryID)
	if err != nil {
		t.Fatalf("Redeliver: unexpected error %v", err)
	}
	if ok {
		t.Fatal("expected refusal: disabled means no outbound traffic on this endpoint")
	}
}

func TestRedeliver_RefusedOnNonTerminalRow(t *testing.T) {
	st, userID, svc := newNotificationServiceTest(t)
	ep := seedEndpoint(t, st, userID, "https://example.com/hook", true)
	deliveryID := seedTerminalDelivery(t, st, ep.ID, "pending")

	ok, err := svc.Redeliver(t.Context(), userID, deliveryID)
	if err != nil {
		t.Fatalf("Redeliver: unexpected error %v", err)
	}
	if ok {
		t.Fatal("expected refusal: a pending row is not terminal")
	}
}

func TestTest_RefusedOnDisabledEndpoint(t *testing.T) {
	st, userID, svc := newNotificationServiceTest(t)
	ep := seedEndpoint(t, st, userID, "https://example.com/hook", false)

	ok, err := svc.Test(t.Context(), userID, ep.ID)
	if err != nil {
		t.Fatalf("Test: unexpected error %v", err)
	}
	if ok {
		t.Fatal("expected refusal: disabled means no outbound traffic on this endpoint")
	}
}

// TestBudget_TestAndRedeliverShareIt is the load-bearing test for design
// §10.3. Eight user-initiated attempts against ONE endpoint, alternating
// between Test and Redeliver, must yield exactly 5 allowed / 3 refused —
// proving the budget is a single shared counter across both routes and that
// BOTH routes' INSERT statements stamp user_initiated_at (a column missing
// from either statement's column list made this control a silent no-op
// twice; see design §21).
func TestBudget_TestAndRedeliverShareIt(t *testing.T) {
	st, userID, svc := newNotificationServiceTest(t)
	ep := seedEndpoint(t, st, userID, "https://example.com/hook", true)
	deliveryID := seedTerminalDelivery(t, st, ep.ID, "failed")

	calls := []string{"redeliver", "test", "redeliver", "test", "redeliver", "redeliver", "test", "redeliver"}
	var allowed, refused int
	for i, route := range calls {
		var ok bool
		var err error
		switch route {
		case "test":
			ok, err = svc.Test(t.Context(), userID, ep.ID)
		case "redeliver":
			ok, err = svc.Redeliver(t.Context(), userID, deliveryID)
		}
		if err != nil {
			t.Fatalf("call %d (%s): unexpected error %v", i, route, err)
		}
		if ok {
			allowed++
		} else {
			refused++
		}
	}
	if allowed != 5 || refused != 3 {
		t.Fatalf("allowed=%d refused=%d, want 5 allowed / 3 refused", allowed, refused)
	}

	// Every row stamped inside the window must be non-NULL, on both routes:
	// query directly rather than trusting the values this test passed in.
	windowStart := store.NowUnix() - int64(notify.UserBudgetWindow/time.Second)
	rows, err := st.DB().QueryContext(t.Context(),
		`SELECT user_initiated_at FROM notification_deliveries
		  WHERE endpoint_id = ? AND user_initiated_at > ?`,
		ep.ID, windowStart)
	if err != nil {
		t.Fatalf("query stamped rows: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var stamped int
	for rows.Next() {
		var ui sql.NullInt64
		if err := rows.Scan(&ui); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !ui.Valid {
			t.Fatal("a row inside the budget window has a NULL user_initiated_at")
		}
		stamped++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if stamped != 5 {
		t.Fatalf("stamped row count = %d, want exactly 5", stamped)
	}

	// A 6th user-initiated attempt in the same window, via the OTHER route,
	// must also be refused — proving the budget is shared, not per-route.
	ok, err := svc.Test(t.Context(), userID, ep.ID)
	if err != nil {
		t.Fatalf("Test: unexpected error %v", err)
	}
	if ok {
		t.Fatal("expected a 6th user-initiated attempt to be refused; the budget must be shared across routes")
	}
}

// TestBudget_IsAtomicUnderConcurrency proves the single-statement
// INSERT ... SELECT ... WHERE (SELECT count...) is atomic under
// modernc.org/sqlite with SetMaxOpenConns(1): six concurrent Test() calls on
// one endpoint must yield exactly five successes and exactly five rows. This
// closes the one thing design §17 explicitly parks as unverified. Run with
// -race -count=5.
// TestTest_RefusedForForeignEndpoint is the regression guard for M17:
// NotificationService.Test deliberately has no ownership pre-check (its own
// doc comment explains why — a preceding check would reopen the
// check-then-write race), so the "AND user_id = ?" predicate inside
// InsertUserTest's EXISTS clause is the ONLY thing standing between any
// authenticated user and any other user's endpoint on this route.
func TestTest_RefusedForForeignEndpoint(t *testing.T) {
	st, userID, svc := newNotificationServiceTest(t)
	other := seedUser(t, st, "other@b.co", "user")
	ep := seedEndpoint(t, st, userID, "https://example.com/hook", true)

	ok, err := svc.Test(t.Context(), other.ID, ep.ID)
	if err != nil {
		t.Fatalf("Test: unexpected error %v", err)
	}
	if ok {
		t.Fatal("expected refusal: Test's INSERT is the only ownership check on this route")
	}

	rows, err := st.NotificationDeliveries().ListByEndpoint(t.Context(), ep.ID, 10)
	if err != nil {
		t.Fatalf("ListByEndpoint: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("got %d delivery rows for a foreign Test() call, want 0", len(rows))
	}
}

// TestTest_AuditsTestSent is the regression guard for M37: a successful
// Test() must record notification.test_sent, using a real audit writer
// (not the discard fake newNotificationServiceTest wires) so the entry is
// actually queryable.
func TestTest_AuditsTestSent(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	allowed, err := notify.ParseAllowed(nil)
	if err != nil {
		t.Fatalf("ParseAllowed: %v", err)
	}
	svc := NewNotificationService(st, testKey32(), 5, allowed, NewAuditWriter(st))
	ep := seedEndpoint(t, st, usr.ID, "https://example.com/hook", true)

	ok, err := svc.Test(t.Context(), usr.ID, ep.ID)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if !ok {
		t.Fatal("Test refused, want allowed")
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "notification.test_sent"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("notification.test_sent entries = %d, want 1", len(page.Rows))
	}
}

// TestCreate_AuditsSecretRevealed is the regression guard for M38: a
// successful Create() must record notification.secret_revealed alongside
// notification.endpoint_created, using a real audit writer so the entry is
// actually queryable.
func TestCreate_AuditsSecretRevealed(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	allowed, err := notify.ParseAllowed(nil)
	if err != nil {
		t.Fatalf("ParseAllowed: %v", err)
	}
	svc := NewNotificationService(st, testKey32(), 5, allowed, NewAuditWriter(st))

	if _, _, err := svc.Create(t.Context(), usr.ID, "ep", "https://example.com/hook"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "notification.secret_revealed"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("notification.secret_revealed entries = %d, want 1", len(page.Rows))
	}
}

func TestBudget_IsAtomicUnderConcurrency(t *testing.T) {
	st, userID, svc := newNotificationServiceTest(t)
	ep := seedEndpoint(t, st, userID, "https://example.com/hook", true)
	ctx := t.Context()

	const n = 6
	results := make([]bool, n)
	var wg sync.WaitGroup
	for i := range results {
		wg.Go(func() {
			ok, err := svc.Test(ctx, userID, ep.ID)
			if err != nil {
				t.Errorf("Test call %d: unexpected error %v", i, err)
				return
			}
			results[i] = ok
		})
	}
	wg.Wait()

	var allowed int
	for _, ok := range results {
		if ok {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("allowed = %d, want exactly 5", allowed)
	}

	windowStart := store.NowUnix() - int64(notify.UserBudgetWindow/time.Second)
	var count int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM notification_deliveries
		  WHERE endpoint_id = ? AND user_initiated_at > ?`,
		ep.ID, windowStart,
	).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 5 {
		t.Fatalf("row count = %d, want exactly 5", count)
	}
}
