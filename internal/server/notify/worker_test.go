package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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

// capturingAudit records every entry it is given, for tests that need to
// assert an audit event actually fired (and what it said).
type capturingAudit struct{ entries []store.AuditEntry }

func (c *capturingAudit) Log(_ context.Context, e store.AuditEntry) {
	c.entries = append(c.entries, e)
}

// roundTripFunc adapts a plain function to http.RoundTripper, so a test can
// give each of two *http.Client values a distinguishable transport without
// any real dial or listener.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// recordingClient returns an *http.Client whose Transport sets *called to
// true and answers every request with a 204, never touching the network.
func recordingClient(called *bool) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		*called = true
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
}

// fakeErrCtx wraps a live context but reports a caller-controlled non-nil
// Err() while leaving Done() exactly as the embedded context reports it
// (never closed for a context built from t.Context()). This is deliberately
// NOT the same as an actually-cancelled context: database/sql's own
// connection-acquisition check rejects any call made with a Done() context
// before the driver ever runs (verified empirically — ExecContext/
// QueryContext with an already-cancelled context fail immediately with
// "context canceled"), which would mask whether worker.go's OWN ctx.Err()
// guards are present at all. Keeping Done() open while faking Err() isolates
// exactly the application-level guards under test from that unrelated
// protection.
type fakeErrCtx struct {
	context.Context
	err atomic.Bool
}

func (c *fakeErrCtx) Err() error {
	if c.err.Load() {
		return context.Canceled
	}
	return nil
}

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

// newLoggingTestWorker mirrors newTestWorker above, but takes a logger, since
// that helper hardcodes discardLog().
func newLoggingTestWorker(st *store.Store, allowedCIDRs []string, maxAttempts int, log *slog.Logger) *Worker {
	allowed, err := ParseAllowed(allowedCIDRs)
	if err != nil {
		panic(err)
	}
	return NewWorker(st, NewClients(allowed, 2*time.Second), testKey(), maxAttempts, nopAudit{}, halfJitter, log)
}

// findRecord returns the first JSON record in buf whose msg matches, or fails.
func findRecord(t *testing.T, buf *bytes.Buffer, msg string) map[string]any {
	t.Helper()
	// SplitSeq, not Split: golangci-lint runs `modernize`, and its test-file
	// exclusion list is [gocyclo dupl gosec errcheck unparam prealloc] -- so
	// `stringsseq` fires on a range over strings.Split in a _test.go file.
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line not JSON: %v (%s)", err, line)
		}
		if rec["msg"] == msg {
			return rec
		}
	}
	t.Fatalf("no record with msg %q in:\n%s", msg, buf.String())
	return nil
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

	// last_failure is the only column that could carry a leaked address (the
	// others are the original event payload/type, untouched by a failed
	// send), so asserting it against the exact fixed literal IS the leak
	// check: any leaked detail — the address, a wrapped Go error, anything
	// beyond the six fixed classes — would make this equality fail. A
	// separate strings.Contains(row.lastFailure, "10.1.2.3") check here would
	// be vacuous: it could only ever fire on a value this line has already
	// rejected.
	row := readDelivery(t, st, id)
	if row.status != "failed" || row.lastFailure != "blocked" {
		t.Fatalf("status/last_failure = %q/%q, want failed/blocked (or a leaked detail)", row.status, row.lastFailure)
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

// TestDeliver_HTTPSchemeUsesHTTPClient binds the worker's OWN scheme->client
// derivation (worker.go's `client, err := w.clients.For(target.Scheme)`) to
// the correct *http.Client. It exists because M50 — routing http to
// c.HTTPS — survived every other test in this file: TestClients_For only
// tests the scheme->client map in isolation, and
// TestDeliver_ClientSelectionIsReDerived substitutes ftp (unsupported) for
// http, which slips past exactly this defect (see that test's comment for
// the substitution and why it matters).
//
// Each client here gets its own distinguishable transport, so the assertion
// is which client the request actually reached — not merely that SOME
// response came back, which a shared/misrouted client would also produce.
func TestDeliver_HTTPSchemeUsesHTTPClient(t *testing.T) {
	var httpCalled, httpsCalled bool
	clients := &Clients{HTTP: recordingClient(&httpCalled), HTTPS: recordingClient(&httpsCalled)}

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), "http://127.0.0.1/hook")
	id := seedDelivery(t, st, ep, EventIPChanged)

	w := NewWorker(st, clients, testKey(), 5, nopAudit{}, halfJitter, discardLog())
	w.sweep(t.Context())

	if !httpCalled {
		t.Error("an http:// delivery never reached the HTTP client")
	}
	if httpsCalled {
		t.Error("an http:// delivery reached the HTTPS client — scheme routing is broken (M50)")
	}
	row := readDelivery(t, st, id)
	if row.status != "delivered" {
		t.Errorf("status = %q, want delivered", row.status)
	}
}

// TestSweep_CtxErrSkipsRemainingRows binds the sweep loop's per-iteration
// `if ctx.Err() != nil { return }` (worker.go's guard against starting a new
// attempt once shutdown has begun) to an observable effect: with two due
// rows and a ctx that already reports non-nil Err(), sweep must not attempt
// EITHER row. Uses fakeErrCtx (see its doc comment) rather than an actually-
// cancelled context, because a genuinely cancelled context would fail the
// SELECT that fetches the due rows before the loop guard is ever reached,
// which would make the mutation survive for an unrelated reason.
func TestSweep_CtxErrSkipsRemainingRows(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), srv.URL)
	id1 := seedDelivery(t, st, ep, EventIPChanged)
	id2 := seedDelivery(t, st, ep, EventIPChanged)

	w := newTestWorker(st, []string{"127.0.0.0/8"}, 5)
	fc := &fakeErrCtx{Context: t.Context()}
	fc.err.Store(true)
	w.sweep(fc)

	if hits.Load() != 0 {
		t.Errorf("server hit %d times, want 0 — sweep must not start any new attempt once ctx.Err() is non-nil", hits.Load())
	}
	for _, id := range []int64{id1, id2} {
		row := readDelivery(t, st, id)
		if row.status != "pending" || row.attempts != 0 {
			t.Errorf("row %d = %+v, want untouched (pending, 0 attempts)", id, row)
		}
	}
}

// TestAttempt_CtxErrReturnsEmptyClass binds attempt's own
// `if ctx.Err() != nil { return "" }` guard (checked after client.Do
// returns an error) to its return value directly. The send itself fails for
// a real, unrelated reason (connection refused) so the guard's branch is
// actually reached; fakeErrCtx (see its doc comment) reports ctx.Err() as
// non-nil without ever closing Done(), so the send is not itself a
// consequence of the fake cancellation.
func TestAttempt_CtxErrReturnsEmptyClass(t *testing.T) {
	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), "http://127.0.0.1:1/hook") // connection refused
	seedDelivery(t, st, ep, EventIPChanged)

	due, err := st.NotificationDeliveries().DueForAttempt(t.Context(), store.NowUnix(), 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("DueForAttempt: err=%v rows=%d", err, len(due))
	}

	w := newTestWorker(st, []string{"127.0.0.0/8"}, 5)
	fc := &fakeErrCtx{Context: t.Context()}
	fc.err.Store(true)
	if class := w.attempt(fc, due[0]); class != "" {
		t.Errorf("attempt with ctx.Err() != nil = %q, want \"\" (a shutdown must never be classified as a delivery failure)", class)
	}
}

// TestDeliverOne_CtxErrSkipsWriteBack binds deliverOne's
// `if class == "" { return }` guard to the database, using the SAME
// fakeErrCtx technique as the two tests above so attempt() genuinely
// returns "" (via its own guard, proven by TestAttempt_CtxErrReturnsEmptyClass)
// while the write-back call itself is still free to run if the guard here is
// missing.
func TestDeliverOne_CtxErrSkipsWriteBack(t *testing.T) {
	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), "http://127.0.0.1:1/hook") // connection refused
	id := seedDelivery(t, st, ep, EventIPChanged)

	due, err := st.NotificationDeliveries().DueForAttempt(t.Context(), store.NowUnix(), 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("DueForAttempt: err=%v rows=%d", err, len(due))
	}

	w := newTestWorker(st, []string{"127.0.0.0/8"}, 5)
	fc := &fakeErrCtx{Context: t.Context()}
	fc.err.Store(true)
	w.deliverOne(fc, due[0])

	row := readDelivery(t, st, id)
	if row.status != "pending" || row.attempts != 0 {
		t.Errorf("row = %+v after a cancelled-mid-attempt deliverOne, want untouched (pending, 0 attempts) — no write-back on a cancelled ctx (design §8.3)", row)
	}
}

// TestClassifySendError pins every classification classifySendError makes,
// table-driven so a future case is added the same way. M30b — a *net.DNSError
// misclassified as unreachable instead of blocked — rebuilds exactly the
// internal-DNS oracle §5.8 merges DNS failures and guard rejections to close.
func TestClassifySendError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"denied sentinel", fmt.Errorf("wrap: %w", ErrDenied), FailureBlocked},
		{"dns failure", &net.DNSError{Err: "no such host", Name: "nope.invalid", IsNotFound: true}, FailureBlocked},
		{"tls certificate verification", &tls.CertificateVerificationError{Err: errors.New("x")}, FailureTLS},
		{"plain connection error", errors.New("connection refused"), FailureUnreachable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifySendError(tc.err); got != tc.want {
				t.Errorf("classifySendError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestClassifySendError_RealTLSFailure drives a genuine untrusted-certificate
// failure rather than a hand-built error value, because the shape matters and
// hand-built ones get it wrong.
//
// An earlier version of this test asserted on BARE x509 errors
// (x509.HostnameError{}, UnknownAuthorityError{}, CertificateInvalidError{}),
// and classifySendError carried an errors.As branch for each. Those branches
// were unreachable: crypto/tls has wrapped every verification failure in
// *tls.CertificateVerificationError since Go 1.20, so the single check above
// catches all three and the extra branches never fired. The synthetic cases
// were also invalid values — x509.HostnameError{} has a nil Certificate, so
// calling its Error() panics, which only went unnoticed because errors.As
// matched before anything formatted it.
func TestClassifySendError_RealTLSFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	// A client that does NOT trust httptest's self-signed CA, dialing a
	// permitted loopback address so the destination guard is not what fails.
	allowed, err := ParseAllowed([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseAllowed: %v", err)
	}
	resp, err := NewClients(allowed, 5*time.Second).HTTPS.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("connected to a server with an untrusted certificate")
	}
	if got := classifySendError(err); got != FailureTLS {
		t.Errorf("classifySendError(%v) = %q, want %q", err, got, FailureTLS)
	}
}

// TestDeliver_302IsRejectedNotDelivered is the regression guard for M25: a
// 3xx counted as "delivered" would silently lose the event — the row reads
// delivered but the consumer's redirect target, not the consumer, received
// it (CheckRedirect refuses to follow, per TestClients_RedirectsNotFollowed).
func TestDeliver_302IsRejectedNotDelivered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), srv.URL)
	id := seedDelivery(t, st, ep, EventIPChanged)

	w := newTestWorker(st, []string{"127.0.0.0/8"}, 5)
	w.sweep(t.Context())

	row := readDelivery(t, st, id)
	if row.status == "delivered" {
		t.Fatal("a 3xx response was counted as delivered — the event was silently lost")
	}
	if row.lastFailure != "rejected" {
		t.Errorf("last_failure = %q, want rejected", row.lastFailure)
	}
}

// TestDeliver_BlockedTargetAuditsRejection is the regression guard for both
// M4 (auditBlocked never firing on a guard rejection — the audit log is the
// ONLY place a resolved address is ever recorded) and S5 (the event type
// naming design §12/the plan's "notification.target_blocked", not
// "notification.delivery_blocked").
func TestDeliver_BlockedTargetAuditsRejection(t *testing.T) {
	const target = "https://10.1.2.3/hook" // RFC1918, denied, never dialed for real

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), target)
	seedDelivery(t, st, ep, EventIPChanged)

	allowed, err := ParseAllowed([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseAllowed: %v", err)
	}
	audit := &capturingAudit{}
	w := NewWorker(st, NewClients(allowed, 2*time.Second), testKey(), 1, audit, halfJitter, discardLog())
	w.sweep(t.Context())

	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want exactly 1", len(audit.entries))
	}
	got := audit.entries[0]
	if got.EventType != "notification.target_blocked" {
		t.Errorf("EventType = %q, want notification.target_blocked", got.EventType)
	}
	if got.TargetID != ep {
		t.Errorf("TargetID = %q, want %q", got.TargetID, ep)
	}
}

func TestDeliver_LogsInfoOnDelivered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), srv.URL)
	seedDelivery(t, st, ep, EventIPChanged)

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	newLoggingTestWorker(st, []string{"127.0.0.0/8"}, 5, log).sweep(t.Context())

	line := findRecord(t, &buf, "notify: delivered")
	if line["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", line["level"])
	}
	for _, k := range []string{"delivery_id", "endpoint_id", "attempts"} {
		if _, ok := line[k]; !ok {
			t.Errorf("missing attr %q in %v", k, line)
		}
	}
}

// 410 Gone is terminal on the FIRST attempt and logs nothing at all today.
func TestDeliver_LogsWarnOn410Gone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), srv.URL)
	seedDelivery(t, st, ep, EventIPChanged)

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	newLoggingTestWorker(st, []string{"127.0.0.0/8"}, 5, log).sweep(t.Context())

	line := findRecord(t, &buf, "notify: delivery failed permanently")
	if line["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", line["level"])
	}
	if line["class"] != FailureGone {
		t.Errorf("class = %v, want %v", line["class"], FailureGone)
	}
}

// D10's load-bearing property: a delivery that will be RETRIED emits nothing
// at Info or above. maxAttempts=5 with a 500 means attempt 1 is not terminal.
func TestDeliver_SilentWhileRetrying(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), srv.URL)
	seedDelivery(t, st, ep, EventIPChanged)

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	newLoggingTestWorker(st, []string{"127.0.0.0/8"}, 5, log).sweep(t.Context())

	if strings.Contains(buf.String(), "delivery failed permanently") {
		t.Errorf("emitted a terminal record while still retrying: %s", buf.String())
	}
}

// The terminal record fires once the attempts are exhausted. maxAttempts=1
// makes the first 500 terminal.
func TestDeliver_LogsWarnWhenAttemptsExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	st := newTestStore(t)
	ep := seedUserAndEndpoint(t, st, testKey(), srv.URL)
	seedDelivery(t, st, ep, EventIPChanged)

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	newLoggingTestWorker(st, []string{"127.0.0.0/8"}, 1, log).sweep(t.Context())

	line := findRecord(t, &buf, "notify: delivery failed permanently")
	if line["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", line["level"])
	}
	if line["attempts"].(float64) != 1 {
		t.Errorf("attempts = %v, want 1", line["attempts"])
	}
}
