package telemetry

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel"
)

// errorHandlerInterval bounds how often export failures reach the log. OTel's
// DEFAULT handler writes every failure to stderr, which against an unreachable
// collector is one message per export interval forever.
const errorHandlerInterval = 5 * time.Minute

// rateLimited is the otel.ErrorHandler this package installs.
type rateLimited struct {
	mu         sync.Mutex
	log        *slog.Logger
	now        func() time.Time // injected so tests need not sleep
	lastEmit   time.Time        // zero until the first Handle
	suppressed int
}

// Handle emits the first failure immediately, then at most one per
// errorHandlerInterval, each carrying the count folded into it.
//
// h.log.LogAttrs runs OUTSIDE h.mu: sdk/log/logger.go:69-71 calls otel.Handle
// (this method) on the CALLER's goroutine for a processor error, so logging
// while still holding h.mu would self-deadlock if that path ever becomes
// reachable, since sync.Mutex is not reentrant -- see
// TestRateLimited_HandleDoesNotDeadlockOnReentrantLog. Not reachable today
// (minsev.LogProcessor.OnEmit delegates straight through and
// BatchProcessor.OnEmit returns nil on every path), but relying on that
// staying true is not a guarantee this package should depend on.
func (h *rateLimited) Handle(err error) {
	suppressed, shouldLog := h.recordFailure()
	if !shouldLog {
		return
	}
	h.log.LogAttrs(context.Background(), slog.LevelWarn, "otlp export failed",
		slog.Any("error", err),
		slog.Int("suppressed_since_last", suppressed),
	)
}

// recordFailure updates the rate-limit state under h.mu and reports whether
// this failure should be logged, snapshotting the suppressed count so Handle
// can log outside the lock.
func (h *rateLimited) recordFailure() (suppressed int, shouldLog bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	t := h.now()
	if !h.lastEmit.IsZero() && t.Sub(h.lastEmit) < errorHandlerInterval {
		h.suppressed++
		return 0, false
	}
	suppressed = h.suppressed
	h.lastEmit, h.suppressed = t, 0
	return suppressed, true
}

// OtelLogr adapts logger into the logr.Logger OTel's global diagnostic
// channel expects. Exported (Fix round 1, C1) because Revision 6 moved the
// caller's responsibility to install otel.SetLogger BEFORE calling New --
// cmd/diyddns-server needs this exact adapter to do that, and an unexported
// version would force main.go to duplicate its ~20-line V-level contract
// (documented below) with a bare logr.FromSlogHandler(log.Handler()) call,
// which is Tier A DRY on an external-library adapter.
//
// Extracted to its own function so
// TestOtelLogr_ErrorIsStructuredWarnStaysBelowInfo can exercise it directly:
// there is no public otel.GetLogger, and go.opentelemetry.io/otel/internal/global
// is a Go "internal" package -- this module is physically unable to import it
// -- so observing what otel.SetLogger installed is not merely order-dependent,
// it is IMPOSSIBLE from outside go.opentelemetry.io/otel. (This is a
// materially different, and stronger, reason than otel.SetErrorHandler's:
// that one IS read back through otel.GetErrorHandler, by
// TestSetErrorHandler_InstallsTheGlobalErrorHandler.)
//
// Note what this does NOT do: logr's slog sink maps V(n) to slog.Level(-n)
// (go-logr/logr@v1.4.4/slogsink.go:68-73), and OTel's global.Warn is V(1)
// (internal_logging.go:60-61), so those arrive at slog level -1 and stay
// BELOW Info. Redirecting the channel makes its Error records structured; it
// does not make its Warn records visible at logging.level: info. That is the
// correct outcome -- those Warns are high-volume -- but it must not be
// mistaken for "everything OTel says now reaches the log".
func OtelLogr(logger *slog.Logger) logr.Logger {
	return logr.FromSlogHandler(logger.Handler())
}

// SetErrorHandler routes OTel's two internal diagnostic channels to logger.
// This is the ONLY place this package installs an OTel global (Revision 6
// removed the other one, New's early bootstrap install -- see the package doc
// comment): otel.SetErrorHandler, so export failures reach the log through
// the rate-limited handler, and otel.SetLogger, so the SDK's own internal
// diagnostics do too. otel.SetLogger here is optional rather than
// load-bearing now that New installs nothing early -- it costs nothing to
// keep (it is already implemented and needs no bootstrap seam), and it is
// still the only channel that catches POST-construction SDK diagnostics
// (e.g. a runtime export error surfaced via global.Warn), so it stays.
//
// It is a NO-OP when p is inert: installing a process global nothing will ever
// call is the same "structure without a present requirement" design D10 removed
// for the provider globals.
func (p *Providers) SetErrorHandler(logger *slog.Logger) {
	if p == nil || len(p.shutdown) == 0 || logger == nil {
		return
	}
	p.logger = logger
	otel.SetErrorHandler(&rateLimited{log: logger, now: time.Now})
	otel.SetLogger(OtelLogr(logger))
}
