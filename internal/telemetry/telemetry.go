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
	"os"
	"slices"
	"strings"

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
	"go.opentelemetry.io/otel/sdk/resource"
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

	// meter is retained for ObserveDB (Task 12), which registers its callback
	// after the store is open.
	meter metric.Meter

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

	// An endpoint must come from somewhere. Four variables can supply it, so
	// this check lives here rather than in internal/config, which reaches the
	// environment only through viper's DIYDDNS_ binding.
	//
	// A MISSING endpoint is not Fatal (THE FATAL RULE): it is an operator who
	// has not finished wiring telemetry up, and the server must still start.
	// TRIMMED, not raw. signalEndpoint trims because a k8s secret or --env-file
	// endpoint routinely carries a trailing newline; if this gate tests the raw
	// value, "\n" skips the degrade branch, reaches signalEndpoint, comes back
	// Fatal, and serveCmd exits -- turning a MISSING endpoint into a refusal to
	// boot, which is exactly what D5 and THE FATAL RULE forbid. An empty-rendered
	// Helm value produces precisely this.
	if strings.TrimSpace(cfg.Endpoint) == "" && !anyOTLPEndpointEnv() {
		return inert(), Status{
			Reason: "observability.otlp.enabled is true but no endpoint is configured " +
				"(set observability.otlp.endpoint or OTEL_EXPORTER_OTLP_ENDPOINT)",
		}
	}

	res, st := buildResource(ctx, cfg, info)
	if st.Fatal {
		return inert(), st
	}

	p := &Providers{}
	// Each build* appends its provider's Shutdown to p.shutdown before it can
	// fail, so a later failure still drains what was already constructed: the
	// inline _ = p.Shutdown(ctx) below runs against p, not against the
	// inert() this function then returns to the caller. That drain is a no-op
	// until Task 7 implements Shutdown's fan-out (today Shutdown always
	// returns nil without calling anything in p.shutdown).
	for _, build := range []func(context.Context, config.OTLPSection, *resource.Resource) Status{
		p.buildTraces,
		p.buildMetrics,
		p.buildLogsFor(logLevel),
	} {
		if st := build(ctx, cfg, res); st.Fatal {
			_ = p.Shutdown(ctx)
			return inert(), st
		}
	}
	return p, Status{}
}

// anyOTLPEndpointEnv reports whether the operator supplied an endpoint through
// any of the four variables the SDK reads.
//
// TRIMMED, same as every other endpoint gate in this package: a k8s
// secretKeyRef or `echo "http://…" | base64` is at least as likely to carry a
// trailing newline in an env var as in the YAML value, and an untrimmed
// comparison here reads a whitespace-only value as "set" -- skipping the
// degrade branch and letting New build three real providers against the SDK's
// default localhost:4318 with a zero Status, the silent-open failure this
// package exists to prevent.
func anyOTLPEndpointEnv() bool {
	return slices.ContainsFunc([]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
	}, func(k string) bool { return strings.TrimSpace(os.Getenv(k)) != "" })
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
