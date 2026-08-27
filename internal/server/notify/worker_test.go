package notify

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// testKey returns a fixed 32-byte AEAD key, matching internal/auth's own
// secret_test.go:10 convention.
func testKey() []byte { return bytes.Repeat([]byte{0x2a}, 32) }

// halfJitter is a deterministic randFloat that lands backoffFor's jitter
// factor at 1.0 (see TestBackoff_ScheduleAndClamp), so tests that only care
// about "was a retry scheduled" get a predictable, non-flaky value.
func halfJitter() float64 { return 0.5 }

// nopAudit discards every entry. None of the tests in this file assert on
// audit content; TestDeliver_BlockedTargetRecordsNoAddress asserts on the
// delivery row, not the audit log.
type nopAudit struct{}

func (nopAudit) Log(context.Context, store.AuditEntry) {}

// seedUserAndEndpoint inserts one user and one notification endpoint whose
// secret is sealed under key, returning the endpoint's id.
func seedUserAndEndpoint(t *testing.T, st *store.Store, key []byte, url string) string {
	t.Helper()
	ctx := t.Context()
	now := store.NowUnix()
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO users (id, email, role, disabled, created_at, updated_at)
		 VALUES ('u1', 'u1@example.com', 'user', 0, ?, ?)`, now, now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	secret, err := auth.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	sealed, err := auth.SealSecret(key, secret)
	if err != nil {
		t.Fatalf("SealSecret: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO notification_endpoints
		   (id, user_id, label, url, secret_sealed, enabled, created_at, updated_at)
		 VALUES ('ep1', 'u1', 'l', ?, ?, 1, ?, ?)`,
		url, sealed, now, now); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	return "ep1"
}

// setEndpointEnabled flips ep1's enabled flag.
func setEndpointEnabled(t *testing.T, st *store.Store, endpointID string, enabled bool) {
	t.Helper()
	n := 0
	if enabled {
		n = 1
	}
	if _, err := st.DB().ExecContext(t.Context(),
		`UPDATE notification_endpoints SET enabled = ? WHERE id = ?`, n, endpointID); err != nil {
		t.Fatalf("setEndpointEnabled: %v", err)
	}
}

// setEndpointURL rewrites ep1's url, simulating an operator edit between
// delivery attempts on the same outbox row.
func setEndpointURL(t *testing.T, st *store.Store, endpointID, url string) {
	t.Helper()
	if _, err := st.DB().ExecContext(t.Context(),
		`UPDATE notification_endpoints SET url = ? WHERE id = ?`, url, endpointID); err != nil {
		t.Fatalf("setEndpointURL: %v", err)
	}
}

// seedDelivery inserts one due (next_attempt_at = now, pending) outbox row
// for endpointID and returns its id.
func seedDelivery(t *testing.T, st *store.Store, endpointID, eventType string) int64 {
	t.Helper()
	now := store.NowUnix()
	res, err := st.DB().ExecContext(t.Context(),
		`INSERT INTO notification_deliveries
		   (endpoint_id, event_type, event_id, payload, attempts, next_attempt_at,
		    status, created_at, updated_at)
		 VALUES (?, ?, 1, ?, 0, ?, 'pending', ?, ?)`,
		endpointID, eventType, []byte(`{"ok":true}`), now, now, now)
	if err != nil {
		t.Fatalf("seed delivery: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}
	return id
}

// forceDueNow rewrites id's next_attempt_at to now, simulating that its
// backoff has elapsed without an actual sleep.
func forceDueNow(t *testing.T, st *store.Store, id int64) {
	t.Helper()
	if _, err := st.DB().ExecContext(t.Context(),
		`UPDATE notification_deliveries SET next_attempt_at = ? WHERE id = ?`,
		store.NowUnix(), id); err != nil {
		t.Fatalf("forceDueNow: %v", err)
	}
}

type deliveryRow struct {
	status        string
	attempts      int
	lastFailure   string
	nextAttemptAt sql.NullInt64
}

func readDelivery(t *testing.T, st *store.Store, id int64) deliveryRow {
	t.Helper()
	var r deliveryRow
	var lastFailure sql.NullString
	if err := st.DB().QueryRowContext(t.Context(),
		`SELECT status, attempts, last_failure, next_attempt_at
		   FROM notification_deliveries WHERE id = ?`, id,
	).Scan(&r.status, &r.attempts, &lastFailure, &r.nextAttemptAt); err != nil {
		t.Fatalf("readDelivery: %v", err)
	}
	r.lastFailure = lastFailure.String
	return r
}

func newTestWorker(st *store.Store, allowedCIDRs []string, maxAttempts int) *Worker {
	allowed, err := ParseAllowed(allowedCIDRs)
	if err != nil {
		panic(err)
	}
	clients := NewClients(allowed, 2*time.Second)
	return NewWorker(st, clients, testKey(), maxAttempts, nopAudit{}, halfJitter, discardLog())
}

// Backoff: the published schedule, the clamp, and the jitter order.
func TestBackoff_ScheduleAndClamp(t *testing.T) {
	// delay(n) = min(backoffBase * 2^(n-2) * jitter, maxBackoff), n >= 2.
	// Jitter is applied to the base and the RESULT is clamped. Clamping first
	// and jittering after would permit maxBackoff*1.1 = 17m36s and make the
	// `delay <= maxBackoff` assertion below false. Design §9.2.
	// The argument is the attempt being SCHEDULED, so the first retry is
	// backoffFor(2). There is deliberately no backoffFor(1).
	for _, tc := range []struct {
		attempt int
		want    time.Duration
	}{{2, 15 * time.Second}, {3, 30 * time.Second}, {4, time.Minute},
		{5, 2 * time.Minute}, {6, 4 * time.Minute}, {7, 8 * time.Minute},
		{8, 16 * time.Minute}, {12, 16 * time.Minute}} {
		got := backoffFor(tc.attempt, func() float64 { return 0.5 }) // jitter factor 1.0
		if got != tc.want {
			t.Errorf("backoffFor(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
	// The clamp must hold at the jitter extreme. randFloat()==1.0 gives the
	// maximum factor 1.1; if this fails, the implementation clamped before
	// jittering.
	if got := backoffFor(12, func() float64 { return 1.0 }); got > maxBackoff {
		t.Errorf("backoffFor with max jitter = %v, exceeds maxBackoff %v", got, maxBackoff)
	}
	// And the floor, so the order is pinned from both sides.
	if got := backoffFor(3, func() float64 { return 0.0 }); got != 27*time.Second {
		t.Errorf("backoffFor(3) at min jitter = %v, want 27s (30s * 0.9)", got)
	}
}

func TestBackoff_PanicsBelowAttemptTwo(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("backoffFor(1, ...) did not panic; a negative shift is a hot retry loop")
		}
	}()
	backoffFor(1, halfJitter)
}

func TestDeliver_2xxIsDelivered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), srv.URL)
	id := seedDelivery(t, st, ep, EventIPChanged)

	w := newTestWorker(st, []string{"127.0.0.0/8"}, 5)
	w.sweep(t.Context())

	row := readDelivery(t, st, id)
	if row.status != "delivered" {
		t.Errorf("status = %q, want delivered", row.status)
	}
	if row.nextAttemptAt.Valid {
		t.Errorf("next_attempt_at = %v, want NULL", row.nextAttemptAt)
	}
	if row.lastFailure != "" {
		t.Errorf("last_failure = %q, want empty", row.lastFailure)
	}
}

func TestDeliver_410IsTerminalOnFirstAttempt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), srv.URL)
	id := seedDelivery(t, st, ep, EventIPChanged)

	w := newTestWorker(st, []string{"127.0.0.0/8"}, 5)
	w.sweep(t.Context())

	row := readDelivery(t, st, id)
	if row.status != "failed" || row.lastFailure != "gone" {
		t.Errorf("status/last_failure = %q/%q, want failed/gone", row.status, row.lastFailure)
	}
	if row.attempts != 1 {
		t.Errorf("attempts = %d, want 1", row.attempts)
	}
	if row.nextAttemptAt.Valid {
		t.Errorf("next_attempt_at = %v, want NULL", row.nextAttemptAt)
	}
}

func TestDeliver_500IsRetried(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), srv.URL)
	id := seedDelivery(t, st, ep, EventIPChanged)

	w := newTestWorker(st, []string{"127.0.0.0/8"}, 5) // well above 1 attempt
	w.sweep(t.Context())

	row := readDelivery(t, st, id)
	if row.status != "pending" {
		t.Errorf("status = %q, want pending", row.status)
	}
	if row.attempts != 1 {
		t.Errorf("attempts = %d, want 1", row.attempts)
	}
	if row.lastFailure != "rejected" {
		t.Errorf("last_failure = %q, want rejected", row.lastFailure)
	}
	if !row.nextAttemptAt.Valid || row.nextAttemptAt.Int64 <= store.NowUnix() {
		t.Errorf("next_attempt_at = %v, want a future timestamp", row.nextAttemptAt)
	}
}

func TestDeliver_ExhaustionSetsFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), srv.URL)
	id := seedDelivery(t, st, ep, EventIPChanged)

	w := newTestWorker(st, []string{"127.0.0.0/8"}, 1) // exhausted after one attempt
	w.sweep(t.Context())

	row := readDelivery(t, st, id)
	if row.status != "failed" {
		t.Errorf("status = %q, want failed", row.status)
	}
	if row.attempts != 1 {
		t.Errorf("attempts = %d, want 1", row.attempts)
	}
	if row.nextAttemptAt.Valid {
		t.Errorf("next_attempt_at = %v, want NULL", row.nextAttemptAt)
	}
}

func TestDeliver_EndpointTestIsOneShot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), srv.URL)
	id := seedDelivery(t, st, ep, EventTest)

	// Configured maxAttempts is generous; endpoint.test must still exhaust
	// after exactly one attempt.
	w := newTestWorker(st, []string{"127.0.0.0/8"}, 5)
	w.sweep(t.Context())

	row := readDelivery(t, st, id)
	if row.status != "failed" {
		t.Errorf("status = %q, want failed after one attempt", row.status)
	}
	if row.attempts != 1 {
		t.Errorf("attempts = %d, want 1", row.attempts)
	}
}

func TestDeliver_BlockedTargetRecordsNoAddress(t *testing.T) {
	const target = "https://10.1.2.3/hook" // RFC1918, denied, never dialed for real

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), target)
	id := seedDelivery(t, st, ep, EventIPChanged)

	w := newTestWorker(st, []string{"127.0.0.0/8"}, 1)
	w.sweep(t.Context())

	row := readDelivery(t, st, id)
	if row.status != "failed" || row.lastFailure != "blocked" {
		t.Errorf("status/last_failure = %q/%q, want failed/blocked", row.status, row.lastFailure)
	}
	if strings.Contains(row.lastFailure, "10.1.2.3") {
		t.Errorf("last_failure leaked the resolved address: %q", row.lastFailure)
	}
}

func TestDeliver_SignatureVariesButBodyDoesNot(t *testing.T) {
	type captured struct {
		body string
		sig  string
	}
	var hits []captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hits = append(hits, captured{body: string(b), sig: r.Header.Get("X-Diyddns-Signature")})
		w.WriteHeader(http.StatusInternalServerError) // force a retry
	}))
	defer srv.Close()

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), srv.URL)
	id := seedDelivery(t, st, ep, EventIPChanged)

	w := newTestWorker(st, []string{"127.0.0.0/8"}, 5)
	w.sweep(t.Context())
	forceDueNow(t, st, id) // skip the real backoff wait
	w.sweep(t.Context())

	if len(hits) != 2 {
		t.Fatalf("server hit %d times, want 2", len(hits))
	}
	if hits[0].body != hits[1].body {
		t.Errorf("body bytes differ across attempts: %q vs %q", hits[0].body, hits[1].body)
	}
	if hits[0].sig == hits[1].sig {
		t.Error("signature identical across attempts; nonce/timestamp must vary per attempt")
	}
}

func TestSweep_SkipsDisabledEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), srv.URL)
	id := seedDelivery(t, st, ep, EventIPChanged)
	setEndpointEnabled(t, st, ep, false)

	w := newTestWorker(st, []string{"127.0.0.0/8"}, 5)
	w.sweep(t.Context())

	row := readDelivery(t, st, id)
	if row.status != "pending" || row.attempts != 0 {
		t.Errorf("row = %+v, want untouched (pending, 0 attempts) — disabling must stop in-flight delivery", row)
	}
}

// Proves client selection is re-derived from the stored url every attempt,
// never cached: the first attempt's scheme has no client at all (unsupported
// "ftp"), and only after the endpoint's url is edited to a supported scheme
// does the request ever reach a server. A cached "no client for this row"
// decision would make the second attempt fail exactly like the first.
func TestDeliver_ClientSelectionIsReDerived(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), "ftp://127.0.0.1/hook")
	id := seedDelivery(t, st, ep, EventIPChanged)

	w := newTestWorker(st, []string{"127.0.0.0/8"}, 5)
	w.sweep(t.Context())

	row := readDelivery(t, st, id)
	if row.status != "pending" || row.lastFailure != "internal" {
		t.Fatalf("first attempt row = %+v, want pending/internal", row)
	}
	if hits.Load() != 0 {
		t.Fatalf("unsupported scheme reached a client: %d hits", hits.Load())
	}

	setEndpointURL(t, st, ep, srv.URL)
	forceDueNow(t, st, id)
	w.sweep(t.Context())

	row = readDelivery(t, st, id)
	if row.status != "delivered" {
		t.Errorf("second attempt status = %q, want delivered", row.status)
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}
}

func TestDeliver_UnsupportedStoredSchemeIsInternal(t *testing.T) {
	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), "ftp://127.0.0.1/hook")
	id := seedDelivery(t, st, ep, EventIPChanged)

	w := newTestWorker(st, []string{"127.0.0.0/8"}, 1)
	w.sweep(t.Context())

	row := readDelivery(t, st, id)
	if row.status != "failed" || row.lastFailure != "internal" {
		t.Errorf("status/last_failure = %q/%q, want failed/internal", row.status, row.lastFailure)
	}
}
