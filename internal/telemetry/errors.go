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
func (h *rateLimited) Handle(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	t := h.now()
	if !h.lastEmit.IsZero() && t.Sub(h.lastEmit) < errorHandlerInterval {
		h.suppressed++
		return
	}
	h.log.LogAttrs(context.Background(), slog.LevelWarn, "otlp export failed",
		slog.Any("error", err),
		slog.Int("suppressed_since_last", h.suppressed),
	)
	h.lastEmit, h.suppressed = t, 0
}

// otelLogr adapts logger into the logr.Logger OTel's global diagnostic
// channel expects. Extracted to its own function so
// TestOtelLogr_ErrorIsStructuredWarnStaysBelowInfo can exercise it directly:
// there is no public otel.GetLogger, and go.opentelemetry.io/otel/internal/global
// is a Go "internal" package -- this module is physically unable to import it
// -- so observing what otel.SetLogger installed is not merely order-dependent,
// it is IMPOSSIBLE from outside go.opentelemetry.io/otel. (This is a
// materially different, and stronger, reason than otel.SetErrorHandler's:
// that one COULD be read back through the once-only otel.GetErrorHandler, and
// tests avoid it only to stay order-independent -- see setDiagnostics below.)
//
// Note what this does NOT do: logr's slog sink maps V(n) to slog.Level(-n)
// (go-logr/logr@v1.4.4/slogsink.go:68-73), and OTel's global.Warn is V(1)
// (internal_logging.go:60-61), so those arrive at slog level -1 and stay
// BELOW Info. Redirecting the channel makes its Error records structured; it
// does not make its Warn records visible at logging.level: info. That is the
// correct outcome -- those Warns are high-volume -- but it must not be
// mistaken for "everything OTel says now reaches the log".
func otelLogr(logger *slog.Logger) logr.Logger {
	return logr.FromSlogHandler(logger.Handler())
}

// SetErrorHandler routes OTel's two internal diagnostic channels to logger.
// This is PHASE TWO of the two-phase install described on New's doc comment:
// New's phase one already installed otel.SetLogger early, against a
// caller-supplied bootstrap logger, so construction-time SDK diagnostics (a
// malformed OTEL_* variable) are captured before this method could ever run.
// This phase re-installs otel.SetLogger against the FINAL application logger
// -- legal because otel.SetLogger is an unconditional atomic store, not a
// once (otel@v1.46.0/internal/global/internal_logging.go:33-35) -- and it is
// the only phase that installs otel.SetErrorHandler, since a rate-limited
// handler needs a stable, final logger to warn through.
//
// It is a NO-OP when p is inert: installing a process global nothing will ever
// call is the same "structure without a present requirement" design D10 removed
// for the provider globals.
//
// These two are the ONLY globals this design installs, and both are installed
// here because neither has an injection alternative.
func (p *Providers) SetErrorHandler(logger *slog.Logger) {
	p.setDiagnostics(logger, otel.SetErrorHandler, otel.SetLogger)
}

// setDiagnostics is SetErrorHandler's body, with the two otel setters taken as
// parameters. This is the seam TestSetDiagnostics_InstallsBothChannels uses to
// capture what gets installed without touching OTel's real global state: both
// otel.SetErrorHandler's delegation (handler.go:24-29) and, per otelLogr's
// doc comment, otel.SetLogger's target are otherwise unobservable from a test
// in this package without becoming order-dependent or, for the logger,
// impossible outright.
//
// `go tool cover -func` reports 100% for both this function and
// SetErrorHandler, and that number is misleading if read as "everything is
// verified": coverage tracks whether a STATEMENT ran, not whether the
// function VALUE passed to it was ever actually invoked. No test that
// exercises setDiagnostics calls the REAL otel.SetErrorHandler or
// otel.SetLogger -- TestSetErrorHandler_InertIsNoOp and
// TestSetErrorHandler_NilLoggerIsNoOp only reach the early-return guards
// above (the real functions are referenced, never called), and
// TestSetDiagnostics_InstallsBothChannels deliberately substitutes capturing
// fakes for setErrorHandler/setLogger specifically to avoid touching OTel's
// global state. (The one place in this package production's REAL
// otel.SetLogger IS exercised is New's phase-1 install, a different call
// site entirely -- see TestNew_BootstrapCapturesConstructionTimeDiagnostics.)
// The honest, unverifiable-from-inside-this-module floor is exactly the one
// line `p.setDiagnostics(logger, otel.SetErrorHandler, otel.SetLogger)` in
// SetErrorHandler -- reading back whether IT did what it says is either
// order-dependent (the error handler, via the once-only
// otel.GetErrorHandler) or impossible outright (the logger, per otelLogr's
// doc comment). Everything else in setDiagnostics -- the nil guards, and the
// actual *rateLimited and logr.Logger values constructed -- IS genuinely
// exercised through this seam, values and behavior both, not just
// statement-executed.
func (p *Providers) setDiagnostics(logger *slog.Logger, setErrorHandler func(otel.ErrorHandler), setLogger func(logr.Logger)) {
	if p == nil || len(p.shutdown) == 0 || logger == nil {
		return
	}
	p.logger = logger
	setErrorHandler(&rateLimited{log: logger, now: time.Now})
	setLogger(otelLogr(logger))
}
