package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/config"

	"go.opentelemetry.io/contrib/processors/minsev"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/semconv/v1.43.0/httpconv"

	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// otlpExportTimeout bounds ONE export attempt (WithTimeout sets
// http.Client.Timeout -- otlptracehttp/client.go:96). Applied only when the
// operator has not set a timeout variable for that signal.
const otlpExportTimeout = 3 * time.Second

// otlpRetry is THE single source for the retry profile all three exporters
// use. Passed WHOLE at every call site: a partial RetryConfig literal zeroes
// InitialInterval and MaxInterval, which retry.go:73-79 feeds straight into
// backoff.ExponentialBackOff -- a zero initial interval is a hot retry loop
// against a dead collector.
//
// otlptracehttp.RetryConfig, otlpmetrichttp.RetryConfig and
// otlploghttp.RetryConfig are three distinct named types, but each is
// declared as `type RetryConfig retry.Config` over its own package-internal
// retry.Config -- three structs with identical field names, types, and order
// (otlptracehttp/options.go:59, otlpmetrichttp/config.go:50,
// otlploghttp/config.go:336). Identical underlying types make them directly
// convertible (verified by compiling and running the conversion; see
// task-5-report.md, Fix round 2, S5), so this value is declared once as
// otlptracehttp.RetryConfig and converted at the other two call sites instead
// of being retyped into three copies that could drift out of step.
var otlpRetry = otlptracehttp.RetryConfig{
	Enabled:         true,
	InitialInterval: 1 * time.Second, // SDK default 5s
	MaxInterval:     3 * time.Second, // SDK default 30s
	MaxElapsedTime:  5 * time.Second, // SDK default 1m
}

// minsevFor maps a slog.Level onto the minsev.Severity minsev gates against.
//
// This is an EXACT conversion, not an approximation: minsev.Severity IS the
// slog scale by construction (minsev@v0.16.3/severity.go:47-81 defines
// SeverityDebug/Info/Warn/Error as -4/0/4/8, numerically identical to
// slog.LevelDebug/Info/Warn/Error), and minsev.Severity.Severity() (severity.go
// :87-103) does the offset translation to OTel's 5/9/13/17 internally. A
// four-branch table over just the named levels is a LOSSY approximation of
// this identity conversion: logging.level accepts slog's offset syntax with no
// validator (config.go's logging.level is free-form, parsed by
// slog.Level.UnmarshalText), so "info+2" parses to slog.Level(2) and a table
// keyed only on the four named levels would round it to SeverityWarn, dropping
// INFO3 records over OTLP that stdout still emits -- a stdout/OTLP divergence
// design D4 promises cannot happen. Verified with a throwaway probe before
// making this change (see task-5-report.md, Fix round 2, S2).
func minsevFor(l slog.Level) minsev.Severity {
	return minsev.Severity(l)
}

// newLoggerProvider is THE construction site for the minsev gating. Both the
// production path (buildLogsFor, below) and the exported NewLoggerProvider seam
// Task 10 adds go through it, so a test that exercises the seam genuinely
// exercises what New builds -- and deleting the minsev wrap here breaks both.
//
// It is declared in THIS task, not Task 10, because buildLogsFor is its first
// user and Task 10 does not modify buildLogsFor: declaring it there would leave
// Task 5 uncompilable. Same reasoning as instrumentationName in Task 2.
func newLoggerProvider(proc sdklog.Processor, sev minsev.Severity, extra ...sdklog.LoggerProviderOption) *sdklog.LoggerProvider {
	opts := append([]sdklog.LoggerProviderOption{
		sdklog.WithProcessor(minsev.NewLogProcessor(proc, sev)),
	}, extra...)
	return sdklog.NewLoggerProvider(opts...)
}

// buildTraces constructs the tracer provider and stores p.tracer.
func (p *Providers) buildTraces(ctx context.Context, cfg config.OTLPSection, res *resource.Resource) Status {
	opts := []otlptracehttp.Option{
		otlptracehttp.WithRetry(otlpRetry), // see otlpRetry's doc comment
	}
	if strings.TrimSpace(cfg.Endpoint) != "" { // TRIMMED -- see New's gate
		ep, st := signalEndpoint(cfg.Endpoint, signalTraces)
		if st.Fatal {
			return st
		}
		opts = append(opts, otlptracehttp.WithEndpointURL(ep))
	}
	if applyOurTimeout(signalTraces) {
		opts = append(opts, otlptracehttp.WithTimeout(otlpExportTimeout))
	}

	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return Status{Reason: fmt.Sprintf("telemetry: trace exporter: %v", err), Fatal: true}
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	p.shutdown = append(p.shutdown, tp.Shutdown)
	p.tracer = tp.Tracer(instrumentationName)
	return Status{}
}

// buildMetrics constructs the meter provider and both instruments.
func (p *Providers) buildMetrics(ctx context.Context, cfg config.OTLPSection, res *resource.Resource) Status {
	opts := []otlpmetrichttp.Option{
		// see otlpRetry's doc comment for why this conversion is safe
		otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig(otlpRetry)),
	}
	if strings.TrimSpace(cfg.Endpoint) != "" { // TRIMMED -- see New's gate
		ep, st := signalEndpoint(cfg.Endpoint, signalMetrics)
		if st.Fatal {
			return st
		}
		opts = append(opts, otlpmetrichttp.WithEndpointURL(ep))
	}
	if applyOurTimeout(signalMetrics) {
		opts = append(opts, otlpmetrichttp.WithTimeout(otlpExportTimeout))
	}

	exp, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return Status{Reason: fmt.Sprintf("telemetry: metric exporter: %v", err), Fatal: true}
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)),
		sdkmetric.WithResource(res),
	)
	p.shutdown = append(p.shutdown, mp.Shutdown)
	p.meter = mp.Meter(instrumentationName)

	dur, err := newRequestDuration(p.meter)
	if err != nil {
		return Status{Reason: fmt.Sprintf("telemetry: request duration histogram: %v", err), Fatal: true}
	}
	p.requestDur = dur

	deliveries, err := newDeliveryCounter(p.meter)
	if err != nil {
		return Status{Reason: fmt.Sprintf("telemetry: delivery counter: %v", err), Fatal: true}
	}
	p.deliveries = deliveries
	return Status{}
}

// newDeliveryCounter builds the notification delivery counter. Unit
// {delivery} per design §7.2. Bounded cardinality by construction: the class
// attribute comes from a compile-time constant set (notify/worker.go:46-51)
// plus "delivered".
//
// Extracted to its own function, mirroring newRequestDuration, so the unit
// and name are pinned by a unit test through a ManualReader rather than only
// by the enabled-path type assertion in TestNew_EnabledIsReal.
func newDeliveryCounter(meter metric.Meter) (metric.Int64Counter, error) {
	return meter.Int64Counter(
		"diyddns.notification.delivery",
		metric.WithUnit("{delivery}"),
		metric.WithDescription("Notification delivery attempts by terminal class."),
	)
}

// buildLogsFor returns a builder closed over the parsed logging level, so the
// three builders share one signature and New can loop over them.
func (p *Providers) buildLogsFor(level slog.Level) func(context.Context, config.OTLPSection, *resource.Resource) Status {
	return func(ctx context.Context, cfg config.OTLPSection, res *resource.Resource) Status {
		opts := []otlploghttp.Option{
			// see otlpRetry's doc comment for why this conversion is safe
			otlploghttp.WithRetry(otlploghttp.RetryConfig(otlpRetry)),
		}
		if strings.TrimSpace(cfg.Endpoint) != "" { // TRIMMED -- see New's gate
			ep, st := signalEndpoint(cfg.Endpoint, signalLogs)
			if st.Fatal {
				return st
			}
			opts = append(opts, otlploghttp.WithEndpointURL(ep))
		}
		if applyOurTimeout(signalLogs) {
			opts = append(opts, otlploghttp.WithTimeout(otlpExportTimeout))
		}

		exp, err := otlploghttp.New(ctx, opts...)
		if err != nil {
			return Status{Reason: fmt.Sprintf("telemetry: log exporter: %v", err), Fatal: true}
		}
		// ONE construction site for the minsev knowledge. buildLogsFor must NOT
		// wrap the processor itself: a seam that production bypasses means the
		// Task 10.3 test proves its own wiring, not New's -- exactly what design
		// §15.4 warned about. Delete minsev from here and every test would still
		// pass, which is the defect.
		//
		// TRAP, proven by a Fix-round-2 critic: calling
		// sdklog.NewBatchProcessor(exp) into sdklog.NewLoggerProvider directly
		// here, bypassing newLoggerProvider, removes minsev from production
		// while leaving every test in Tasks 5 and 10 green -- the only thing
		// holding this together is the convention of always routing through
		// newLoggerProvider. Do not inline this call.
		lp := newLoggerProvider(sdklog.NewBatchProcessor(exp), minsevFor(level), sdklog.WithResource(res))
		p.shutdown = append(p.shutdown, lp.Shutdown)
		p.loggerProvider = lp
		return Status{}
	}
}

// newRequestDuration builds the HTTP server duration histogram.
//
// It returns the error rather than swallowing it: New maps it to a Fatal
// Status, because a histogram this design cannot construct means the metric
// pipeline is misconfigured, not that the world is broken.
//
// Which construction route to use is settled by Step 5.2's probe: .Inst()
// satisfies metric.Float64Histogram, so this goes through httpconv rather
// than the hand-built literal-boundaries fallback.
func newRequestDuration(meter metric.Meter) (metric.Float64Histogram, error) {
	h, err := httpconv.NewServerRequestDuration(meter)
	if err != nil {
		return nil, err
	}
	// .Inst() unwraps the semconv helper to the plain instrument. The helper's
	// own typed Record REQUIRES url.scheme, which design §4.5's four-attribute
	// list omits; going through Inst() lets middleware.Trace control the
	// attribute set while keeping the semconv name, unit, description and --
	// the non-negotiable part -- the seconds-shaped bucket boundaries.
	return h.Inst(), nil
}
