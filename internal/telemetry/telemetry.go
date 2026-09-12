// Package telemetry constructs the OpenTelemetry providers DIYDDNS exports
// through, and owns their shutdown. It is inert unless explicitly enabled.
//
// It installs NO OTel provider globals (design D10): every instrument is
// handed to its consumer, so "disabled" means the consumer holds a no-op and
// nothing else in the process changes. The only globals it will install are
// the two diagnostic ones, otel.SetErrorHandler and otel.SetLogger (Task 6),
// which have no injection alternative (see SetErrorHandler).
package telemetry

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/version"

	otellog "go.opentelemetry.io/otel/log" // aliased: a bare `log` identifier
	// would be ambiguous against "log/slog" (imported above), sdklog (below),
	// and this repo's own convention of naming *slog.Logger parameters `log`
	// (e.g. internal/server/server.go:70). The alias keeps every log-shaped
	// identifier in this file distinct.
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// instrumentationName is the scope every signal this package emits is
// attributed to. Declared HERE rather than in Task 5 so the literal has exactly
// one home: Task 5 does not modify inert() or Tracer(), so declaring it there
// would leave two stale copies of the same string with nothing keeping them in
// step.
const instrumentationName = "github.com/jacaudi/diyddns"

// Status reports why telemetry is not exporting. A zero Status means nothing
// has gone wrong -- not that telemetry is exporting; New returns a zero
// Status on the disabled path too, where nothing is exported at all.
//
// THE FATAL RULE, stated once and applied nowhere else. Fatal is true in
// exactly two cases:
//
//	(a) the operator gave a value that cannot mean anything -- a malformed
//	    endpoint (Task 4);
//	(b) this package and the SDK have drifted apart -- a semconv schema-URL
//	    conflict (Task 3), which is a programming error.
//
// Fatal is FALSE when the operator gave no value, or when the world is broken:
// no endpoint configured, an unreachable collector, a partial resource.
// Reason is always set when Fatal is. Do not extend this list without adding
// a clause here.
type Status struct {
	Reason string
	Fatal  bool
}

// Providers will own the three OTel providers and their exporters once Tasks
// 3-6 construct them; today it holds only the inert no-op fallbacks. A nil
// *Providers is valid and inert: every method tolerates it.
type Providers struct {
	tracer     trace.Tracer
	requestDur metric.Float64Histogram
	deliveries metric.Int64Counter

	// loggerProvider is nil until Task 5 constructs it. CONCRETE type, never
	// the otellog.LoggerProvider interface: see LoggerProvider()'s comment.
	loggerProvider *sdklog.LoggerProvider

	// shutdown holds one func per constructed provider. Empty when inert.
	shutdown []func(context.Context) error

	// logger is stored by SetErrorHandler and used by ObserveDB. Nil until
	// SetErrorHandler runs; ObserveDB drops rather than panicking if so.
	logger *slog.Logger
}

// New constructs the providers. It NEVER returns an error and never returns
// nil -- every failure path returns an inert *Providers plus a Status
// describing why (design D5).
//
// logLevel is the already-parsed logging.level; it feeds the minsev processor
// in Task 5. It is parsed by the caller, before New, because parsing can fail
// and New cannot return an error.
func New(ctx context.Context, cfg config.OTLPSection, logLevel slog.Level, info version.Info) (*Providers, Status) {
	if !cfg.Enabled {
		return inert(), Status{}
	}
	// Tasks 3-6 replace this branch. Until then an enabled server is inert
	// with an honest reason rather than half-constructed.
	return inert(), Status{Reason: "telemetry: not yet implemented"}
}

// inert returns a Providers whose every accessor is a working no-op.
func inert() *Providers {
	return &Providers{
		tracer:     tracenoop.NewTracerProvider().Tracer(instrumentationName),
		requestDur: metricnoop.Float64Histogram{},
		deliveries: metricnoop.Int64Counter{},
	}
}

// Tracer returns the tracer middleware.Trace uses -- real when enabled, a
// no-op otherwise. Never nil.
func (p *Providers) Tracer() trace.Tracer {
	if p == nil || p.tracer == nil {
		return tracenoop.NewTracerProvider().Tracer(instrumentationName)
	}
	return p.tracer
}

// RequestDuration returns the HTTP server duration histogram. Never nil.
func (p *Providers) RequestDuration() metric.Float64Histogram {
	if p == nil || p.requestDur == nil {
		return metricnoop.Float64Histogram{}
	}
	return p.requestDur
}

// DeliveryCount returns the notification delivery counter. Never nil.
func (p *Providers) DeliveryCount() metric.Int64Counter {
	if p == nil || p.deliveries == nil {
		return metricnoop.Int64Counter{}
	}
	return p.deliveries
}

// LoggerProvider returns the provider the slog bridge writes to, or nil when
// telemetry is inert.
//
// The `return nil` below is an EXPLICIT untyped nil and must stay that way.
// Returning a nil-valued concrete field through this interface yields a
// NON-NIL interface holding a typed nil, server.NewLogger's `lp == nil` branch
// is then skipped, and otelslog.NewHandler dereferences the nil provider and
// panics at boot -- on the telemetry-DISABLED path, which is the default.
func (p *Providers) LoggerProvider() otellog.LoggerProvider {
	if p == nil || p.loggerProvider == nil {
		return nil
	}
	return p.loggerProvider
}

// ObserveDB registers the sql.DBStats callback against db (Task 12). It
// returns NOTHING: returning an error would put an errcheck-forced
// `return nil, err` inside server.New, making a telemetry failure a reason the
// server refuses to start -- exactly what design D5 forbids.
func (p *Providers) ObserveDB(db *sql.DB) {
	if p == nil || db == nil {
		return
	}
}

// SetErrorHandler routes OTel's two internal diagnostic channels to logger
// (Task 6). It is a NO-OP when p is inert: installing a process global nothing
// will ever call is the same "structure without a present requirement" design
// D10 removed elsewhere.
func (p *Providers) SetErrorHandler(logger *slog.Logger) {
	if p == nil || len(p.shutdown) == 0 {
		return
	}
	p.logger = logger
}

// Shutdown flushes and stops every constructed provider. Bounded by ctx.
func (p *Providers) Shutdown(ctx context.Context) error {
	if p == nil || len(p.shutdown) == 0 {
		return nil
	}
	return nil // Task 7 implements the concurrent fan-out.
}
