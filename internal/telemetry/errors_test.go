package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel"
)

// A fake clock, never a sleep.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestHandler(t *testing.T) (*rateLimited, *bytes.Buffer, *fakeClock) {
	t.Helper()
	var buf bytes.Buffer
	clk := &fakeClock{t: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)}
	h := &rateLimited{
		log: slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})),
		now: clk.now,
	}
	return h, &buf, clk
}

func records(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	// SplitSeq, not Split: modernize/stringsseq is enabled for _test.go too
	// (the exclusion list is [gocyclo dupl gosec errcheck unparam prealloc]).
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// The FIRST failure is never delayed, and a burst produces exactly one record.
func TestRateLimited_FirstIsImmediateThenSuppressed(t *testing.T) {
	h, buf, clk := newTestHandler(t)
	h.Handle(errors.New("boom 1"))
	// 200 x 1s stays INSIDE errorHandlerInterval (5 minutes = 300s). Advancing
	// 500s would leave the interval and emit a second record, which is what an
	// earlier revision of this test did.
	for range 200 {
		clk.add(time.Second)
		h.Handle(errors.New("boom n"))
	}
	if got := records(t, buf); len(got) != 1 {
		t.Fatalf("got %d records in one interval, want 1", len(got))
	}
}

// After the interval elapses, one more record emits, carrying the count of
// everything folded into it. Nothing is lost silently.
func TestRateLimited_SuppressedCountIsReported(t *testing.T) {
	h, buf, clk := newTestHandler(t)
	h.Handle(errors.New("first"))
	for range 4 {
		h.Handle(errors.New("suppressed"))
	}
	clk.add(errorHandlerInterval + time.Second)
	h.Handle(errors.New("after"))

	rs := records(t, buf)
	if len(rs) != 2 {
		t.Fatalf("got %d records, want 2", len(rs))
	}
	if got := rs[0]["suppressed_since_last"]; got != float64(0) {
		t.Errorf("first record suppressed_since_last = %v, want 0", got)
	}
	if got := rs[1]["suppressed_since_last"]; got != float64(4) {
		t.Errorf("second record suppressed_since_last = %v, want 4", got)
	}
}

// The IsZero() guard matters even though every real wall clock buries it: if
// the injected clock's very first reading happens to equal the zero
// time.Time, t.Sub(lastEmit) is 0 (< errorHandlerInterval), so without the
// explicit guard the first-ever failure would be silently suppressed instead
// of emitted immediately.
func TestRateLimited_ZeroClockFirstCallStillEmits(t *testing.T) {
	var buf bytes.Buffer
	h := &rateLimited{
		log: slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})),
		now: func() time.Time { return time.Time{} },
	}
	h.Handle(errors.New("boom"))
	if got := records(t, &buf); len(got) != 1 {
		t.Fatalf("got %d records, want 1 (the very first call must always emit)", len(got))
	}
}

// The record must carry what failed, not just that something did. Deleting
// slog.Any("error", err) in Handle passes every other test in this file: the
// record still emits, still carries suppressed_since_last, just with nothing
// telling an operator what broke. This also pins the message string itself,
// which TestRateLimited_NoRecoveredRecord otherwise only checks does NOT
// contain "recover" -- it never checks what the message actually IS.
func TestRateLimited_RecordsMessageAndError(t *testing.T) {
	h, buf, _ := newTestHandler(t)
	h.Handle(errors.New("boom"))
	rs := records(t, buf)
	if len(rs) != 1 {
		t.Fatalf("got %d records, want 1", len(rs))
	}
	// slog's JSONHandler formats an error-typed Attr value as a string via its
	// Error() method (log/slog/json_handler.go:80-82), so this is a plain
	// string comparison, not a nested object.
	if got, _ := rs[0]["error"].(string); got != "boom" {
		t.Errorf("error = %q, want %q", got, "boom")
	}
	if got, _ := rs[0]["msg"].(string); got != "otlp export failed" {
		t.Errorf("msg = %q, want %q", got, "otlp export failed")
	}
}

// The interval check is `<`, not `<=`: a failure landing EXACTLY
// errorHandlerInterval after the last emit must still emit, not be folded
// into the suppressed count for another interval. `<=` here would let a
// collector that fails on a clean multiple of the interval go one cycle
// longer between reports than the constant promises.
func TestRateLimited_ExactlyAtIntervalBoundaryEmits(t *testing.T) {
	h, buf, clk := newTestHandler(t)
	h.Handle(errors.New("first"))
	clk.add(errorHandlerInterval) // EXACTLY the interval, not +1s
	h.Handle(errors.New("second"))
	if got := records(t, buf); len(got) != 2 {
		t.Fatalf("got %d records at exactly the interval boundary, want 2 (the check is <, not <=)", len(got))
	}
}

// Pins the constant's exact value. Widening it (5m -> 10m) is silently
// invisible to every other test in this file, since none of them assert
// against a duration outside the 5-10 minute range.
func TestErrorHandlerInterval_IsFiveMinutes(t *testing.T) {
	if errorHandlerInterval != 5*time.Minute {
		t.Errorf("errorHandlerInterval = %v, want 5m", errorHandlerInterval)
	}
}

// The rate limit must re-arm on EVERY emit, not just the first. Setting
// lastEmit only once (on the very first emit) passes
// TestRateLimited_SuppressedCountIsReported, because that test only crosses
// the interval boundary once. This crosses it twice: after the second Handle
// emits and resets the window, a THIRD Handle one second later must be
// suppressed again -- if lastEmit were frozen at the first emit, the third
// call would see itself far outside a window that never moved and emit
// unconditionally forever, which is the exact stderr flood this handler
// exists to prevent.
func TestRateLimited_SuppressionWindowSlidesWithEachEmit(t *testing.T) {
	h, buf, clk := newTestHandler(t)
	h.Handle(errors.New("first"))
	clk.add(errorHandlerInterval + time.Second)
	h.Handle(errors.New("second")) // re-arms the window
	clk.add(time.Second)
	h.Handle(errors.New("third")) // must be suppressed by the re-armed window

	if got := records(t, buf); len(got) != 2 {
		t.Fatalf("got %d records, want 2 (third Handle must be suppressed by the re-armed window)", len(got))
	}
}

// Handle is installed process-wide and is called concurrently from three
// exporters' independent goroutines the moment a collector goes down; -race
// must exercise that, not just single-goroutine call sequences.
func TestRateLimited_HandleIsSafeForConcurrentUse(t *testing.T) {
	h, _, _ := newTestHandler(t)
	h.now = time.Now // a real clock: this test asserts absence of a race, not timing

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				h.Handle(errors.New("concurrent"))
			}
		})
	}
	wg.Wait()
}

// The level is exactly Warn, not merely "at or above Warn" -- the test
// handler's own threshold (Level: slog.LevelWarn) cannot distinguish Warn
// from Error, so this reads the level field back explicitly.
func TestRateLimited_LevelIsExactlyWarn(t *testing.T) {
	h, buf, _ := newTestHandler(t)
	h.Handle(errors.New("boom"))
	rs := records(t, buf)
	if len(rs) != 1 {
		t.Fatalf("got %d records, want 1", len(rs))
	}
	if got, _ := rs[0]["level"].(string); got != "WARN" {
		t.Errorf("level = %q, want %q", got, "WARN")
	}
}

// setDiagnostics is SetErrorHandler's real body; this captures what it
// installs without touching OTel's actual global state (see setDiagnostics's
// doc comment for why reading that state back is either order-dependent or,
// for the logger, impossible). It closes the same 5 mutations the coordinator
// named: dropping p.logger = logger, dropping either otel setter call, and
// -- because it inspects the actual VALUES passed to each setter -- omitting
// either the `log:` or `now:` field on the constructed *rateLimited (both of
// which would panic in production the first time an exporter's goroutine
// calls Handle against a nil field).
func TestSetDiagnostics_InstallsBothChannels(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	p := &Providers{shutdown: []func(context.Context) error{func(context.Context) error { return nil }}}

	var gotHandler otel.ErrorHandler
	var gotLogr logr.Logger
	p.setDiagnostics(logger,
		func(h otel.ErrorHandler) { gotHandler = h },
		func(l logr.Logger) { gotLogr = l },
	)

	if p.logger != logger {
		t.Fatal("setDiagnostics must store p.logger")
	}
	if gotHandler == nil {
		t.Fatal("setDiagnostics must pass a non-nil otel.ErrorHandler to setErrorHandler")
	}

	// The captured ErrorHandler must be a genuinely working *rateLimited, not
	// one missing a field: a `log: nil` or `now: nil` rateLimited panics the
	// first time Handle runs, which happens in production inside an OTel
	// exporter's own goroutine.
	gotHandler.Handle(errors.New("boom"))
	if got := records(t, &buf); len(got) != 1 {
		t.Fatalf("captured ErrorHandler.Handle produced %d records, want 1", len(got))
	}

	buf.Reset()
	gotLogr.Error(errors.New("boom2"), "exporter failed")
	if got := records(t, &buf); len(got) != 1 {
		t.Fatalf("captured logr.Logger.Error produced %d records, want 1", len(got))
	}
}

// SetErrorHandler is a documented no-op on an inert Providers (p.shutdown
// empty): installing a process global nothing will ever call is exactly the
// "structure without a present requirement" design D10 forbids.
func TestSetErrorHandler_InertIsNoOp(t *testing.T) {
	p := inert()
	p.SetErrorHandler(slog.Default())
	if p.logger != nil {
		t.Error("SetErrorHandler on an inert Providers must not set p.logger")
	}
}

// A nil logger must not reach otel.SetLogger: logr.FromSlogHandler(nil.Handler())
// would panic on a nil *slog.Logger receiver.
func TestSetErrorHandler_NilLoggerIsNoOp(t *testing.T) {
	p := &Providers{shutdown: []func(context.Context) error{func(context.Context) error { return nil }}}
	p.SetErrorHandler(nil) // must not panic
	if p.logger != nil {
		t.Error("SetErrorHandler(nil) must not set p.logger")
	}
}

// otelLogr's doc comment makes two checkable claims: Error records arrive
// structured, and V(1) Warns (OTel's global.Warn -- internal_logging.go:60-61)
// land at slog level -1 and stay below Info (go-logr/logr@v1.4.4/slogsink.go
// :68-73). This test pins both halves so a future reader cannot "fix" the
// second half wrongly, believing Warns are being dropped by accident.
func TestOtelLogr_ErrorIsStructuredWarnStaysBelowInfo(t *testing.T) {
	var buf bytes.Buffer
	base := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	lg := otelLogr(base)

	lg.Error(errors.New("boom"), "exporter failed")
	rs := records(t, &buf)
	if len(rs) != 1 {
		t.Fatalf("got %d records after Error, want 1", len(rs))
	}
	if msg, _ := rs[0]["msg"].(string); msg != "exporter failed" {
		t.Errorf("msg = %q, want %q", msg, "exporter failed")
	}
	// go-logr/logr@v1.4.4/slogsink.go:45 -- errKey is "err", not "error".
	if _, ok := rs[0]["err"]; !ok {
		t.Errorf("record missing an err field: %v", rs[0])
	}

	buf.Reset()
	lg.V(1).Info("chatty")
	if got := records(t, &buf); len(got) != 0 {
		t.Fatalf("V(1).Info produced %d records, want 0 (V(1) maps to slog level -1, below Info)", len(got))
	}
}

// There is NO "exports recovered" record. otel.ErrorHandler is Handle(error)
// and nothing else (otel@v1.46.0/error_handler.go:6-16) -- there is no success
// callback to hang one on. This test exists so a future implementer does not
// add one against a timer.
func TestRateLimited_NoRecoveredRecord(t *testing.T) {
	h, buf, clk := newTestHandler(t)
	h.Handle(errors.New("boom"))
	clk.add(24 * time.Hour)
	for _, r := range records(t, buf) {
		if msg, _ := r["msg"].(string); strings.Contains(strings.ToLower(msg), "recover") {
			t.Errorf("found a recovery record %q; the ErrorHandler interface cannot signal recovery", msg)
		}
	}
}
