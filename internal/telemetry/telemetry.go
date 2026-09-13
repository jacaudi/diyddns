// Package telemetry constructs the OpenTelemetry providers DIYDDNS exports
// through, and owns their shutdown. It is inert unless explicitly enabled.
//
// It installs NO OTel provider globals, and NO diagnostic globals either
// (design D10): every instrument is handed to its consumer, so "disabled"
// means the consumer holds a no-op and nothing else in the process changes.
//
// REVISION 6 (2026-09-12 maintainer ruling, rolling back part of Task 6): New
// used to take a bootstrap *slog.Logger and install otel.SetLogger early,
// against it, so a malformed OTEL_* variable reported from inside exporter
// construction would be captured before SetErrorHandler could otherwise
// install a channel. That ordering problem is now solved by the CALLER
// instead: cmd/diyddns-server installs otel.SetLogger against its own logger
// BEFORE calling New, using server.LazyLoggerProvider to give NewLogger a
// slot it can fill once New returns the real provider. New goes back to
// installing nothing at all -- SetErrorHandler remains the only place this
// package ever touches an OTel global, and it is opt-in, called once
// construction has succeeded.
package telemetry

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/version"

	otellog "go.opentelemetry.io/otel/log" // aliased: a bare `log` identifier

	// would be ambiguous against "log/slog" (imported above), sdklog (below),
	// and this repo's own convention of naming *slog.Logger parameters `log`
	// (e.g. internal/server/server.go:143). The alias keeps every log-shaped
	// identifier in this file distinct.
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// InstrumentationName is the scope every signal this package emits is
// attributed to. Declared HERE rather than in Task 5 so the literal has exactly
// one home: Task 5 does not modify inert() or Tracer(), so declaring it there
// would leave two stale copies of the same string with nothing keeping them in
// step.
//
// Exported (Fix round 1, I5): server.NewLogger's MultiHandler branch names the
// otelslog scope for the logs signal, and until this constant was exported
// that name was a second, hand-copied literal with nothing keeping it in step
// with this one -- logs were the one signal Task 10 let drift from traces and
// metrics. internal/server already imports internal/telemetry for
// NewLoggerProvider; using the same constant there closes the gap.
const InstrumentationName = "github.com/jacaudi/diyddns"

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

	// shutdownOnce and shutdownErr make Shutdown safe to call concurrently
	// WITH ITSELF (Fix round 1, S1). A second concurrent caller blocks in
	// Do() until the first completes, then returns the same cached result,
	// rather than racing the first caller's read-then-clear of shutdown.
	shutdownOnce sync.Once
	shutdownErr  error

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
//
// New installs NO globals of its own (design D10, restored by Revision 6): a
// malformed OTEL_* variable reported from inside exporter construction is the
// CALLER's responsibility to capture, by installing otel.SetLogger against
// its own logger before calling New -- see the package doc comment and
// server.LazyLoggerProvider.
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
		tracer:     tracenoop.NewTracerProvider().Tracer(InstrumentationName),
		requestDur: metricnoop.Float64Histogram{},
		deliveries: metricnoop.Int64Counter{},
	}
}

// Tracer returns the tracer middleware.Trace uses -- real when enabled, a
// no-op otherwise. Never nil.
func (p *Providers) Tracer() trace.Tracer {
	if p == nil || p.tracer == nil {
		return tracenoop.NewTracerProvider().Tracer(InstrumentationName)
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

// Shutdown flushes and stops every constructed provider, CONCURRENTLY across
// providers, and collects every error rather than returning on the first --
// the pattern Server.Run already uses for the feed hub's collect-both-errors
// property (server.go:456-463).
//
// Concurrency is load-bearing, not stylistic: each provider's worst-case
// export is 12.5s, so sequential shutdowns would need a 37.5s budget and no
// single number would fit.
//
// Idempotent, INCLUDING against itself (Fix round 1, S1): sync.Once means a
// second call -- whether after the first has returned, or concurrent with it
// -- returns (or blocks until it can return) the SAME cached result, rather
// than re-running the funcs or racing the first call's read-then-clear of
// p.shutdown. No caller does this today, but this method's entire subject is
// concurrency, so it must tolerate being called that way itself.
func (p *Providers) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.shutdownOnce.Do(func() {
		if len(p.shutdown) == 0 {
			return
		}
		funcs := p.shutdown
		// Clearing here is no longer what makes a second call idempotent --
		// shutdownOnce already guarantees this closure body runs exactly once,
		// so a second call never reaches this line regardless. It is kept for
		// GC hygiene: it lets the closures (and whatever they hold onto --
		// exporters, HTTP clients) be collected once Shutdown has run, rather
		// than being retained on p.shutdown for the rest of *Providers's
		// lifetime.
		p.shutdown = nil

		errs := make([]error, len(funcs))
		var wg sync.WaitGroup
		for i, fn := range funcs {
			// wg.Go, NOT `wg.Add(1); go func(){ defer wg.Done(); ... }()`.
			// golangci-lint's modernize/waitgroupgo flags the older form, a
			// suppressing comment directive is forbidden (Constraint 4), and
			// Constraint 3 wants modern Go anyway.
			wg.Go(func() {
				errs[i] = fn(ctx)
			})
		}
		wg.Wait()
		p.shutdownErr = errors.Join(errs...)
	})
	return p.shutdownErr
}
