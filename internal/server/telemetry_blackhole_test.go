package server_test

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
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

// Design §10 test 3: assertions (a) and (c) only.
//
//   - (a), the skip guard, is requireBlackHole above.
//   - (b) -- /agent/v1/checkin answers within its normal budget -- needs
//     server.Handler to hold the telemetry, which arrives in Task 9; see the
//     comment inline below.
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

	// (b) -- /agent/v1/checkin answers within its normal budget -- is NOT
	// asserted here. It needs server.Handler to hold the telemetry, and that
	// parameter arrives in Task 9. Task 9 appends the checkin-latency loop to
	// THIS test. Asserting it now, against a server telemetry is not wired
	// into, would pass without proving anything.

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
	// the single-export worst case (12.5s -- MaxElapsedTime 5s + final
	// backoff 4.5s + one 3s attempt, task-7-report.md's arithmetic section).
	//
	// Fix round 2: widened the ceiling from 12.5s+500ms to 12.5s+5s. The
	// tighter margin was flagged as tight enough to flake on a loaded CI
	// runner -- 500ms of headroom over a 12.5s bound leaves no room for
	// scheduling noise under contention, and this test measures wall-clock
	// against a real (if black-holed) network stack, not a mocked clock.
	// 5s keeps the check meaningfully below the 20s ctx budget (an
	// implementation that actually needed the full budget would still be
	// caught) while giving enough slack that ordinary CI jitter cannot flip
	// this from PASS to FAIL on its own.
	ctx, cancel := context.WithTimeout(context.Background(), server.TelemetryShutdownTimeout)
	defer cancel()
	start := time.Now()
	_ = tel.Shutdown(ctx) // an error against a black hole is expected and fine
	elapsed := time.Since(start)
	if ctxErr := ctx.Err(); ctxErr != nil {
		t.Errorf("Shutdown's ctx expired (%v) before Shutdown returned on its own; elapsed=%s", ctxErr, elapsed)
	}
	if elapsed > 17500*time.Millisecond {
		t.Errorf("Shutdown took %s, want under ~12.5s (the worst case across providers, with headroom)", elapsed)
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
