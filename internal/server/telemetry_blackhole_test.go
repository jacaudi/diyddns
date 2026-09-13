package server_test

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server"
	"github.com/jacaudi/diyddns/internal/telemetry"
	"github.com/jacaudi/diyddns/internal/version"
)

// requireBlackHole asserts the test's own premise and SKIPS with a named reason
// when the environment cannot provide it.
//
// 192.0.2.1 is TEST-NET-1 (RFC 5737): never routable, never assigned. On a
// normal network a dial to it HANGS until the client timeout, which is what
// this test needs. A network-restricted CI runner may instead answer
// ENETUNREACH immediately -- which fails FAST, so the test would prove nothing
// while still passing. Skipping loudly beats passing vacuously.
func requireBlackHole(t *testing.T) {
	t.Helper()
	d := net.Dialer{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "192.0.2.1:4318")
	if conn != nil {
		_ = conn.Close()
	}
	// NOT errors.Is(err, context.DeadlineExceeded): it is UNRELIABLE here, not
	// deterministically false (Fix round 1, C3 -- the original comment's
	// specific claim was wrong). net.Dialer's ctx-deadline path RACES two
	// distinct error values for the identical underlying condition:
	//   - mapErr(ctx.Err()) can return net's own errTimeout (declared at
	//     src/net/net.go:626; its doc comment asserts the Is() behavior at
	//     :618), whose Is() method returns true for context.DeadlineExceeded
	//     (the method itself is at :634).
	//   - internal/poll's WaitWrite can return poll.DeadlineExceededError
	//     first, which has NO Is() method, so errors.Is falls back to
	//     identity and returns false (internal/poll/fd.go:53-62).
	// Both format identically as "i/o timeout", so which one wins is a
	// scheduling race, not a fixed outcome. Measured on this machine (this
	// toolchain, this address, standalone `go run`, not `go test`, 8 process
	// runs of 8 dials each): 63 of 64 samples had errors.Is(err,
	// context.DeadlineExceeded) == true and 1 was false -- genuinely
	// nondeterministic even on one machine, and the OPPOSITE of "always
	// false", which is what an earlier draft of this comment claimed. A
	// separate reviewer's run, same toolchain and address, measured true in
	// 5 of 8 samples -- a different ratio again, which is itself the point:
	// there is no fixed outcome to assert on.
	// net.Error.Timeout() is the reliable discriminator instead: true on
	// every one of those samples against the black hole, and false against a
	// connection actively refused (dialing 127.0.0.1 on a closed port) -- it
	// is what distinguishes "hung" (what this test needs) from "answered
	// immediately" (what a network-restricted runner would do).
	if err == nil {
		t.Skip("192.0.2.1:4318 accepted a connection here; this test needs a hanging dial")
	}
	ne, ok := errors.AsType[net.Error](err)
	if !ok || !ne.Timeout() {
		t.Skipf("192.0.2.1 is not black-holed here (%v); this test needs a hanging dial", err)
	}
}

// Design §10 test 3: assertions (a), (b), and (c).
//
//   - (a), the skip guard, is requireBlackHole above.
//   - (b) -- /agent/v1/checkin answers within its normal budget, even while
//     an export is live and retrying against the black hole -- is asserted
//     by the checkin loop below, against a real server.Handler holding tel.
//   - (c) -- Shutdown returns on its own, inside the worst-case budget --
//     is asserted below.
//   - (d) -- goleak, Shutdown leaves nothing running -- is NOT asserted
//     here. See TestShutdown_LeavesNoGoroutines for why, and for where it is
//     asserted instead (Fix round 1, C2).
func TestBlackHoledCollector_DoesNotDegradeCheckin(t *testing.T) {
	requireBlackHole(t)

	tel, st := telemetry.New(t.Context(),
		config.OTLPSection{Enabled: true, Endpoint: "http://192.0.2.1:4318"},
		slog.LevelInfo, version.Current(), discard())
	if st.Fatal {
		t.Fatalf("New: %s", st.Reason)
	}
	// Fix round 1, S5: without this, every t.Fatalf below (and any future
	// one added to this function) exits the test with tel's batch processor
	// and OTLP clients still retrying against the black hole for the rest of
	// the package run -- Shutdown is sync.Once-idempotent, so registering it
	// here is free and changes nothing about assertion (c) below, which
	// still calls tel.Shutdown itself and gets its own elapsed/ctx checks.
	t.Cleanup(func() { _ = tel.Shutdown(context.Background()) })

	// (b) /agent/v1/checkin answers within its normal budget even while the
	// exporters are live and retrying against the black hole. This is THE
	// standing constraint of the whole design: /agent/v1/checkin is the
	// device liveness path and telemetry must never degrade it.
	h, hub, err := server.Handler(testConfig(t, validSecretKey()), memStore(t), discard(), tel)
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	t.Cleanup(func() { _ = hub.Shutdown(context.Background()) })
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// Fix round 1, S2: a fixed 20-iteration TIGHT loop finishes in ~25ms,
	// entirely BEFORE sdktrace.WithBatcher's 5s default schedule delay ever
	// fires a first export attempt -- so the original claim that these
	// checkins run "while the exporters are ... retrying" was false; nothing
	// is retrying yet when the loop ends. Running for 7s crosses that first
	// export attempt (which then fails against the black hole and enters
	// retry-with-backoff), so later iterations genuinely exercise the
	// checkin path while an export is in flight and retrying -- but a TIGHT
	// 7s loop against an in-process httptest.Server fires thousands of
	// checkins, each minting its own span: that floods the batch processor's
	// 2048-span queue well past its 512-span export batch size, which then
	// needs multiple SEQUENTIAL 12.5s-worst-case exports to drain at
	// Shutdown (see TelemetryShutdownTimeout's doc comment) and blew
	// Shutdown's 20s ctx budget in testing. Pacing at 200ms -- an order of
	// magnitude looser than any real device's check-in cadence -- keeps the
	// span count in the same ballpark as the original 20-iteration loop
	// while still spanning the 5s tick.
	deadline := time.Now().Add(7 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		start := time.Now()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost,
			srv.URL+"/agent/v1/checkin", strings.NewReader("{}"))
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("checkin %d: %v", i, err)
		}
		_ = resp.Body.Close()
		// An unauthenticated checkin answers 401 immediately. The status does
		// not matter here; the LATENCY does.
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("checkin %d took %s with a black-holed collector; "+
				"telemetry must never be on the request path", i, elapsed)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// (c) Shutdown returns ON ITS OWN, inside the worst-case bound, rather
	// than being truncated by ctx.
	//
	// Fix round 1, S2: the original assertion here ("elapsed > budget+2s",
	// budget = the SAME 20s value used for ctx's own deadline) was a
	// tautology -- Shutdown already honors whatever deadline it is given
	// (measured: a 2s ctx yields ~2.00s elapsed, a 500ms ctx yields ~500ms
	// elapsed), so that check could only ever fail if a provider ignored its
	// own context, which nothing here does; it cannot distinguish a healthy
	// Shutdown from one being cut off by ctx. The two properties that
	// actually matter are checked directly instead: ctx must NOT have
	// expired (Shutdown finished on its own), and elapsed must stay under
	// the worst case for the number of sequential exports THIS test's own
	// checkin loop forces (see below), not an arbitrary number.
	//
	// Fix round 2: widened the ceiling from 12.5s+500ms to 12.5s+5s. The
	// tighter margin was flagged as tight enough to flake on a loaded CI
	// runner -- 500ms of headroom over a 12.5s bound leaves no room for
	// scheduling noise under contention, and this test measures wall-clock
	// against a real (if black-holed) network stack, not a mocked clock.
	//
	// Task 9 fix round 1, S2 (second effect): extending the checkin loop
	// above to 7s -- needed so later checkins genuinely overlap a live
	// export retry, per that loop's own comment -- means this Shutdown call
	// now ALWAYS has to drain AT LEAST two sequential exports, not one: the
	// automatic export sdktrace.WithBatcher's 5s schedule-delay tick starts
	// mid-loop (already in flight when Shutdown is called), plus at least
	// one more for the spans that queued after that tick fired. That is a
	// different, harder case than server.TelemetryShutdownTimeout's doc
	// comment describes ("a shutdown with an EMPTY queue ... the common
	// case") -- that comment is corrected alongside this change, since this
	// test no longer matches it. The budget below is LOCAL to this
	// assertion, not server.TelemetryShutdownTimeout itself (which stays
	// sized for main.go's real single-export, empty-queue shutdown path --
	// Task 9 does not touch that production constant).
	//
	// Fix round 3: the mechanism behind "more than one sequential export" is
	// NOT queue overflow, and this test cannot reach the
	// MaxQueueSize(2048)/MaxExportBatchSize(512) structural ceiling
	// server.TelemetryShutdownTimeout's doc comment describes for a
	// long-lived production backlog -- span count at Shutdown here is ~35,
	// nowhere near either number, and a re-reviewer's standalone probe
	// (reproducing this test's exact WithBatcher/RetryConfig/black-hole
	// mechanics, 12 runs, with otel.SetLogger capturing the SDK's internal
	// "exporting spans" debug line before every attempt) measured batch
	// sizes of 1-25 across every run. Confirmed by reading
	// sdk@v1.46.0/trace/batch_span_processor.go directly: a failed export
	// DROPS its batch unconditionally before checking the error
	// (batch_span_processor.go:305-310, "A new batch is always created
	// after exporting, even if the batch failed") -- the drain structurally
	// cannot loop on the same spans, so queue depth cannot chain exports.
	//
	// The REAL mechanism is a race in the SDK's own processQueue select:
	// exportSpans resets its 5s ticker BEFORE blocking on the network call,
	// so by the time a stuck export finally returns (up to 12.5s later),
	// the ticker has already re-fired. At that moment the timer channel and
	// the just-closed stop channel are BOTH ready, and Go's select between
	// them is pseudo-random -- losing that pick chains one more full export
	// attempt before the goroutine notices Shutdown was requested. This has
	// NO code-enforced ceiling: it is a decaying-probability tail, not a
	// structural bound. The re-reviewer's 12-run probe measured 7x2, 4x3,
	// 1x4 chained exports; Task 9's own re-verification independently
	// produced 2-, 3-, and 4-export runs across its fix rounds.
	//
	// The budget below is therefore a GENEROUS EMPIRICAL MARGIN over an
	// unbounded tail, not a proof of a maximum -- a 5th (or Nth) chained
	// export is less likely on every additional link, but not impossible,
	// and could still exceed it. It is sized at 4 chained exports because
	// that is the worst this test and its reviewers have observed across
	// ~20+ real runs, not because anything in the SDK enforces 4 as a
	// limit. If this test ever flakes on the elapsed ceiling, the fix is
	// widening this margin (or bounding the SDK's own retry/backoff
	// further), not hunting for a bug that made a 5th chain happen --
	// nothing here guarantees it can't. The two properties that matter are
	// checked directly: ctx.Err() == nil stays the PRIMARY assertion -- it
	// is what actually proves Shutdown returned on its own rather than
	// being truncated; the elapsed ceiling is the secondary, looser check
	// that still catches a genuine hang while tolerating the chain lengths
	// actually observed.
	const (
		perExportWorstCase = 12500 * time.Millisecond                // MaxElapsedTime 5s + backoff 4.5s + one 3s attempt
		observedChainDepth = 4                                       // worst chain length observed across ~20+ real runs; NOT an SDK-enforced ceiling (see above)
		worstCase          = perExportWorstCase * observedChainDepth // 50s
	)
	ctx, cancel := context.WithTimeout(context.Background(), worstCase+7500*time.Millisecond) // 57.5s
	defer cancel()
	start := time.Now()
	_ = tel.Shutdown(ctx) // an error against a black hole is expected and fine
	elapsed := time.Since(start)
	if ctxErr := ctx.Err(); ctxErr != nil {
		t.Errorf("Shutdown's ctx expired (%v) before Shutdown returned on its own; elapsed=%s", ctxErr, elapsed)
	}
	if elapsed > worstCase+5*time.Second { // 55s
		t.Errorf("Shutdown took %s, want under ~%s (%d chained worst-case exports, with headroom)", elapsed, worstCase, observedChainDepth)
	}
}

// TestShutdown_LeavesNoGoroutines proves design §10 test 3's assertion (d)
// honestly: Shutdown leaves no goroutines running once it returns.
//
// Fix round 1, C2 (the coordinator's ruling: "the split"). This does NOT run
// against the black hole. Two things were tried and rejected first, both
// documented in task-7-report.md's Fix round 1 section:
//
//   - The ORIGINAL form, goleak.VerifyNone(t, goleak.IgnoreCurrent()) called
//     LAZILY inside a single t.Cleanup closure: IgnoreCurrent() snapshots
//     goroutine IDs at the moment it runs (goleak@v1.3.0/options.go:98-108),
//     which is AFTER Shutdown already ran, so any goroutine Shutdown itself
//     leaked is already "current" and gets ignored -- vacuous by
//     construction, verified by mutation (dropping wg.Wait() from Shutdown
//     still PASSED).
//   - An EAGER-capture fix -- base := goleak.IgnoreCurrent() called BEFORE
//     Shutdown runs -- correctly flips that mutation to FAIL, but ALSO fails
//     against the otherwise-CORRECT implementation when run against the
//     black hole: otlp*http's net/http.Transport leaves at least one raw TCP
//     dial goroutine blocked in net.(*netFD).connect against 192.0.2.1 for
//     15+ seconds after Shutdown returns (observed with runtime.Stack
//     polling), bounded only by the OS's own TCP connect timeout, not by
//     anything this package controls. That is a real leak, but it is an
//     SDK/platform characteristic orthogonal to Shutdown's own correctness,
//     and fixing it (e.g. a custom net.Dialer with a bounded connect
//     timeout wired through the exporters' HTTP client options) is outside
//     this task's scope.
//
// Against a REACHABLE collector, that dial-goroutine leak does not exist
// (the connection succeeds immediately), so the eager-capture form works
// exactly as designed: it is a genuine, load-bearing proof that Shutdown
// itself -- not the black hole's own SDK-level side effects -- leaves
// nothing running. No skip guard is needed (a reachable httptest.Server
// cannot fail to be reachable), no ignore-filter is needed (nothing else is
// racing to create goroutines here), and it runs in ~0.01s.
func TestShutdown_LeavesNoGoroutines(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Captured EAGERLY, before New and Shutdown run: this is what makes the
	// assertion load-bearing rather than vacuous (see the comment above).
	base := goleak.IgnoreCurrent()

	tel, st := telemetry.New(t.Context(),
		config.OTLPSection{Enabled: true, Endpoint: srv.URL},
		slog.LevelInfo, version.Current(), discard())
	if st.Fatal {
		t.Fatalf("New: %s", st.Reason)
	}

	ctx, cancel := context.WithTimeout(context.Background(), server.TelemetryShutdownTimeout)
	defer cancel()
	if err := tel.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// srv.Close(), BEFORE the goleak check, not deferred: Close force-closes
	// any IDLE keep-alive connection (net/http/httptest/server.go's Close,
	// "Force-close any idle connections"). Shutdown flushed its exports and
	// stopped the exporter's own bookkeeping, but the underlying
	// *http.Client's keep-alive connection to srv is a plain net/http
	// connection-pool detail that Shutdown has no reason to close itself --
	// left open, its client-side readLoop goroutine would still be running
	// when VerifyNone checks, which is a real but uninteresting leak (a
	// reused, idle keep-alive connection, not anything Shutdown got wrong).
	// Closing the server's end forces that connection closed from the other
	// side, same as a real collector process exiting would.
	srv.Close()

	goleak.VerifyNone(t, base)
}
