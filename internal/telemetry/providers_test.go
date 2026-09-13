package telemetry

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/version"
	"go.opentelemetry.io/contrib/processors/minsev"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	_ "modernc.org/sqlite"
)

const testEndpoint = "http://192.0.2.1:4318" // TEST-NET-1, RFC 5737: never routable

// shutdownBudget is a LOCAL constant, deliberately duplicating
// server.TelemetryShutdownTimeout's value (20s). internal/telemetry cannot
// import internal/server to read it directly (Fix round 1, S6): Task 9 makes
// internal/server import internal/telemetry, so the reverse import here would
// be a cycle. There is no single-source option available across this package
// boundary -- the two constants must be changed together BY HAND if the
// budget ever changes; nothing enforces that mechanically.
const shutdownBudget = 20 * time.Second

// Enabled with a valid endpoint constructs real instruments and a real logger
// provider. Nothing dials here -- otlptracehttp.New only builds an
// *http.Client (otlptracehttp/exporter.go:13-15).
func TestNew_EnabledIsReal(t *testing.T) {
	cfg := config.OTLPSection{Enabled: true, Endpoint: testEndpoint}
	tel, st := telemetryNew(t, cfg)
	t.Cleanup(func() {
		// NOT t.Context(): it is already cancelled by the time Cleanup runs, so
		// Shutdown would return immediately without flushing and could leave
		// batch-worker goroutines alive.
		//
		// testEndpoint is a black hole, so this drain spends the retry profile
		// before giving up -- which is what shutdownBudget is sized for.
		ctx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
		defer cancel()
		_ = tel.Shutdown(ctx)
	})

	if st.Fatal || st.Reason != "" {
		t.Fatalf("enabled+valid endpoint must be a zero Status, got %+v", st)
	}
	if _, ok := tel.Tracer().(tracenoop.Tracer); ok {
		t.Error("Tracer() is still a no-op on an enabled server")
	}
	if _, ok := tel.RequestDuration().(metricnoop.Float64Histogram); ok {
		t.Error("RequestDuration() is still a no-op on an enabled server")
	}
	if tel.LoggerProvider() == nil {
		t.Error("LoggerProvider() must be non-nil on an enabled server")
	}
	if _, ok := tel.DeliveryCount().(metricnoop.Int64Counter); ok {
		t.Error("DeliveryCount() is still a no-op on an enabled server")
	}
}

// Enabled with no endpoint anywhere DEGRADES; it is not Fatal. An absent value
// is an operator who has not finished wiring telemetry up (THE FATAL RULE).
//
// Table-driven over the whitespace forms an operator's secret store or
// --env-file actually produces: a bare empty string, but also a trailing
// newline, a lone space, and a mixed whitespace blob. New's gate must TRIM
// before comparing against "" -- untrimmed, any of these reads as "set",
// skips the degrade branch, reaches signalEndpoint, and comes back Fatal,
// turning a MISSING endpoint into a refusal to boot (D5 / THE FATAL RULE).
func TestNew_EnabledNoEndpointDegrades(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
	}{
		{"empty", ""},
		{"trailing newline", "\n"},
		{"single space", " "},
		{"mixed whitespace", " \n\t "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
			t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
			t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
			t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")

			tel, st := telemetryNew(t, config.OTLPSection{Enabled: true, Endpoint: tt.endpoint})
			if st.Fatal {
				t.Errorf("a missing endpoint must NOT be Fatal, got %+v", st)
			}
			if st.Reason == "" {
				t.Error("a missing endpoint must carry a Reason so serveCmd can warn")
			}
			if tel.LoggerProvider() != nil {
				t.Error("a degraded Providers must still return a genuine nil LoggerProvider")
			}
		})
	}
}

// The four OTEL_EXPORTER_OTLP_*_ENDPOINT variables are at least as likely to
// carry a k8s secretKeyRef trailing newline as the YAML value is --
// anyOTLPEndpointEnv must trim them too, or a whitespace-only env value reads
// as "set", the degrade branch is skipped, and three real providers get built
// against the SDK's default localhost:4318 with a zero Status ("nothing has
// gone wrong") -- the silent-open failure this package exists to prevent.
func TestNew_WhitespaceOnlyEnvEndpointDegrades(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "\n")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")

	tel, st := telemetryNew(t, config.OTLPSection{Enabled: true})
	if st.Fatal {
		t.Errorf("a whitespace-only env endpoint must NOT be Fatal, got %+v", st)
	}
	if st.Reason == "" {
		t.Error("a whitespace-only env endpoint must carry a Reason so serveCmd can warn")
	}
	if tel.LoggerProvider() != nil {
		t.Error("a degraded Providers must still return a genuine nil LoggerProvider")
	}
}

// A MALFORMED endpoint IS Fatal: a value that cannot mean anything, whose
// failure would otherwise be invisible (the exporter posts to http:/// forever
// while Shutdown reports success).
func TestNew_MalformedEndpointIsFatal(t *testing.T) {
	tel, st := telemetryNew(t, config.OTLPSection{Enabled: true, Endpoint: "otel-collector:4318"})
	if !st.Fatal {
		t.Errorf("a scheme-less endpoint must be Fatal, got %+v", st)
	}
	if tel == nil {
		t.Error("New must return an inert Providers even when Fatal, never nil")
	}
}

// Fix round 1, I2. Half of the deleted TestNew_BootstrapCapturesConstructionTimeDiagnostics
// survives the bootstrap parameter's removal and needed no seam at all: a
// malformed OTEL_EXPORTER_OTLP_TIMEOUT must NOT be Fatal on the ENABLED path
// -- the SDK logs the parse failure (via otel/internal/global) and falls back
// to its own default rather than erroring, so otlptracehttp.New (and its
// metric/log twins) succeed regardless. THE FATAL RULE draws the line at "a
// value that cannot mean anything"; a malformed timeout the SDK itself
// tolerates does not cross it. Nothing else in the tree covers this:
// TestNew_DisabledIgnoresMalformedEnv only exercises the DISABLED path, and
// endpoint_test.go's applyOurTimeout tests never call New at all.
func TestNew_MalformedTimeoutIsNotFatal(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_TIMEOUT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_TIMEOUT", "")
	// Non-empty and malformed: applyOurTimeout(signalTraces) sees this as
	// "operator set a timeout" and does NOT pass our own WithTimeout override,
	// so the SDK's own envconfig parse of this exact value runs and fails.
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "not-a-number")

	tel, st := telemetryNew(t, config.OTLPSection{Enabled: true, Endpoint: testEndpoint})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
		defer cancel()
		_ = tel.Shutdown(ctx)
	})
	if st.Fatal {
		t.Fatalf("a malformed OTEL_EXPORTER_OTLP_TIMEOUT must not be Fatal (the SDK logs and falls back to its default), got %+v", st)
	}
}

// minsevFor is an EXACT conversion (minsev.Severity IS the slog scale by
// construction), not a lossy approximation. The offset case -- slog.Level(2),
// what "info+2" parses to via slog.Level.UnmarshalText with no validator on
// logging.level -- is the one a four-branch table over named levels alone
// gets wrong (a table would round it to SeverityWarn); it is the whole point
// of this test.
func TestMinsevFor(t *testing.T) {
	tests := []struct {
		name string
		in   slog.Level
		want minsev.Severity
	}{
		{"debug", slog.LevelDebug, minsev.SeverityDebug},
		{"info", slog.LevelInfo, minsev.SeverityInfo},
		{"warn", slog.LevelWarn, minsev.SeverityWarn},
		{"error", slog.LevelError, minsev.SeverityError},
		{"offset (info+2)", slog.Level(2), minsev.Severity(2)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := minsevFor(tt.in); got != tt.want {
				t.Errorf("minsevFor(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// A partial RetryConfig literal at any of the three call sites zeroes
// InitialInterval and MaxInterval, which retry.go:73-79 feeds straight into
// backoff.ExponentialBackOff -- a hot retry loop against a dead collector.
// This pins the one otlpRetry source's values, plus that the conversion to
// the sibling exporters' RetryConfig types carries every field across (it
// does not prove the SDK honours them -- that half needs a real or fake
// collector and stays parked, per the controller's ruling).
func TestOtlpRetry_FieldsSurviveConversion(t *testing.T) {
	if !otlpRetry.Enabled {
		t.Error("otlpRetry.Enabled = false, want true")
	}
	if otlpRetry.InitialInterval != time.Second {
		t.Errorf("otlpRetry.InitialInterval = %v, want %v", otlpRetry.InitialInterval, time.Second)
	}
	if otlpRetry.MaxInterval != 3*time.Second {
		t.Errorf("otlpRetry.MaxInterval = %v, want %v", otlpRetry.MaxInterval, 3*time.Second)
	}
	if otlpRetry.MaxElapsedTime != 5*time.Second {
		t.Errorf("otlpRetry.MaxElapsedTime = %v, want %v", otlpRetry.MaxElapsedTime, 5*time.Second)
	}

	m := otlpmetrichttp.RetryConfig(otlpRetry)
	if m != (otlpmetrichttp.RetryConfig{
		Enabled:         otlpRetry.Enabled,
		InitialInterval: otlpRetry.InitialInterval,
		MaxInterval:     otlpRetry.MaxInterval,
		MaxElapsedTime:  otlpRetry.MaxElapsedTime,
	}) {
		t.Errorf("otlpmetrichttp.RetryConfig(otlpRetry) lost a field: got %+v", m)
	}

	l := otlploghttp.RetryConfig(otlpRetry)
	if l != (otlploghttp.RetryConfig{
		Enabled:         otlpRetry.Enabled,
		InitialInterval: otlpRetry.InitialInterval,
		MaxInterval:     otlpRetry.MaxInterval,
		MaxElapsedTime:  otlpRetry.MaxElapsedTime,
	}) {
		t.Errorf("otlploghttp.RetryConfig(otlpRetry) lost a field: got %+v", l)
	}
}

// Nothing else proves the CONFIGURED endpoint is where traces and metrics
// actually land. Dropping otlptracehttp.WithEndpointURL (traces go to the
// SDK's default localhost:4318 instead), passing signalTraces into
// buildMetrics (metrics POST to /v1/traces instead of /v1/metrics), or
// dropping either build*'s p.shutdown append (that pipeline is never
// flushed) all leave every other test in this suite green -- Task 7's
// black-hole test only asserts Shutdown returns inside its budget, which
// stays true against a fast-refusing localhost. This test uses a real
// httptest.Server (no network, no real collector) recording which paths it
// is hit on.
func TestNew_EnabledExportsToConfiguredEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		useEnv bool
	}{
		{"config endpoint", false},
		{"env-only endpoint (whitespace config)", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			seen := map[string]int{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seen[r.URL.Path]++
				mu.Unlock()
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
			t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
			t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
			t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")

			cfg := config.OTLPSection{Enabled: true, Endpoint: srv.URL}
			if tt.useEnv {
				// A whitespace-only cfg.Endpoint must not reach signalEndpoint
				// in any of the three builders (their own TrimSpace gate
				// skips it), so this exercises the env-only path: the SDK's
				// own OTEL_EXPORTER_OTLP_ENDPOINT parsing must be what
				// carries the request to srv, with New's top gate
				// (anyOTLPEndpointEnv, after the B1 fix) recognizing the
				// trimmed env value as "set".
				cfg.Endpoint = "\n"
				t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
			}

			tel, st := telemetryNew(t, cfg)
			if st.Fatal || st.Reason != "" {
				t.Fatalf("enabled+valid endpoint must be a zero Status, got %+v", st)
			}

			_, span := tel.Tracer().Start(t.Context(), "probe")
			span.End()
			tel.RequestDuration().Record(t.Context(), 0.01)

			// Shutdown, not a hand-rolled loop over tel.shutdown: its fan-out
			// is what flushes the two pipelines, and driving the funcs directly
			// would exercise this test's own wiring instead of production's.
			// NOT t.Context(): it is still live here, but Background makes the
			// budget the only thing bounding the flush.
			ctx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
			defer cancel()
			_ = tel.Shutdown(ctx)

			mu.Lock()
			defer mu.Unlock()
			if seen["/v1/traces"] == 0 {
				t.Error("no request hit /v1/traces -- the tracer is not exporting to the configured endpoint")
			}
			if seen["/v1/metrics"] == 0 {
				t.Error("no request hit /v1/metrics -- the meter is not exporting to the configured endpoint")
			}
		})
	}
}

// TestNew_BootstrapCapturesConstructionTimeDiagnostics is GONE (Revision 6,
// 2026-09-12 maintainer ruling -- see task-10-brief.md). New no longer takes
// a bootstrap *slog.Logger and installs no diagnostic channel of its own: see
// New's doc comment, which goes back to "installs NO globals" (design D10).
//
// The ordering problem this test pinned -- a malformed OTEL_* variable is
// reported from INSIDE exporter construction (otlptracehttp@v1.46.0/internal
// /envconfig/envconfig.go:75), before SetErrorHandler exists to call, since
// SetErrorHandler is a method on the *Providers New returns -- is now solved
// entirely by the CALLER's startup sequence instead of by this package: per
// Revision 6, cmd/diyddns-server installs otel.SetLogger against its own
// logger BEFORE calling New (Task 13's wiring). A test proving that ordering
// must live in cmd/diyddns-server, not here: this package has no bootstrap
// seam left for a test to exercise (the parameter is gone), and relocating it
// would mean writing Task 13's production wiring itself, which is out of this
// task's scope -- Task 10's Files: Modify/Create list does not include
// cmd/diyddns-server, and that package's ordering does not exist yet for a
// test to pin.

// A malformed OTEL_* variable must not make the DISABLED path misbehave: the
// `!cfg.Enabled` early return means New never parses an environment variable
// at all when cfg.Enabled is false, regardless of what it contains. This is
// the half of the deleted TestNew_BootstrapCapturesConstructionTimeDiagnostics
// pair that survives the bootstrap parameter's removal; the other half
// (a bootstrap logger observing a construction-time diagnostic) has no
// expression left in this package -- see the comment above.
//
// Endpoint is set to a valid value DESPITE Enabled: false, same as the
// deleted test: correct code never looks at it (the disabled short-circuit
// returns first). It matters for what this test catches -- a mutant that
// deletes the `!cfg.Enabled` guard runs all the way through buildTraces
// against this endpoint (which doesn't fail: a malformed timeout is not
// Fatal, and testEndpoint is a syntactically valid URL nothing dials), so
// tel would hold REAL, non-noop instruments rather than the inert ones
// checked below -- that is what the accessor assertions here actually catch,
// replacing the deleted test's "no diagnostic records landed" proof of the
// same guard.
func TestNew_DisabledIgnoresMalformedEnv(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_TIMEOUT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_TIMEOUT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "not-a-number")

	tel, st := New(t.Context(), config.OTLPSection{Enabled: false, Endpoint: testEndpoint}, slog.LevelInfo, version.Current())
	if tel == nil {
		t.Fatal("New returned nil; it must never return nil")
	}
	if st.Reason != "" || st.Fatal {
		t.Errorf("disabled must be a zero Status even with malformed OTEL_* env set, got %+v", st)
	}
	if _, ok := tel.Tracer().(tracenoop.Tracer); !ok {
		t.Errorf("Tracer() = %T, want trace/noop.Tracer -- the disabled guard let construction run", tel.Tracer())
	}
	if tel.LoggerProvider() != nil {
		t.Error("LoggerProvider() must be a genuine nil interface on the disabled path")
	}
}

// Nothing else proves buildTraces' sdktrace.WithResource(res) is wired: delete
// it and the tracer provider silently substitutes the memoized
// resource.Default(), whose service.name is "unknown_service:<binary>" --
// every resource_test case still passes, because they all exercise
// buildResource directly rather than what the providers were built with.
//
// The assertion is available because a recording span's concrete type
// implements sdktrace.ReadOnlySpan, which exposes Resource(). Only the trace
// signal has such a seam through New's public surface; the metrics and logs
// providers would need the httptest collector to decode OTLP protobuf bodies,
// and that is deliberately not built -- those two remain uncovered.
//
// The collector is REACHABLE so t.Cleanup's Shutdown returns immediately
// instead of spending the retry profile against a black hole.
func TestNew_TracerCarriesTheBuiltResource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// t.Cleanup, not defer: cleanups run LIFO AFTER the test function's defers,
	// so registering the collector's Close first is what keeps it listening
	// until the Shutdown registered below has flushed through it.
	t.Cleanup(srv.Close)

	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")

	const want = "resource-probe"
	tel, st := telemetryNew(t, config.OTLPSection{Enabled: true, Endpoint: srv.URL, ServiceName: want})
	if st.Fatal || st.Reason != "" {
		t.Fatalf("enabled+valid endpoint must be a zero Status, got %+v", st)
	}
	t.Cleanup(func() {
		// NOT t.Context(): it is already cancelled by the time Cleanup runs.
		ctx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
		defer cancel()
		_ = tel.Shutdown(ctx)
	})

	_, span := tel.Tracer().Start(t.Context(), "probe")
	span.End()
	ros, ok := span.(sdktrace.ReadOnlySpan)
	if !ok {
		t.Fatalf("span is %T, which does not expose ReadOnlySpan.Resource()", span)
	}
	got, ok := ros.Resource().Set().Value(semconv.ServiceNameKey)
	if !ok {
		t.Fatalf("the tracer provider's resource carries no service.name: %v", ros.Resource())
	}
	if got.AsString() != want {
		t.Errorf("service.name on the tracer provider's resource = %q, want %q -- "+
			"buildTraces is not passing the resource buildResource built", got.AsString(), want)
	}
}

func telemetryNew(t *testing.T, cfg config.OTLPSection) (*Providers, Status) {
	t.Helper()
	return New(t.Context(), cfg, slog.LevelInfo, version.Current())
}

// The SDK's DEFAULT histogram boundaries are millisecond-shaped
// {0,5,10,...,10000} (sdk/metric@v1.46.0/reader.go:206). This design records
// SECONDS, so the defaults would put every request under five seconds in the
// first bucket and the metric would carry no information. This test is the
// only thing standing between that and production.
func TestRequestDuration_HasSecondsShapedBuckets(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	h, err := newRequestDuration(mp.Meter(InstrumentationName))
	if err != nil {
		t.Fatalf("newRequestDuration: %v", err)
	}
	h.Record(t.Context(), 0.003)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	want := []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "http.server.request.duration" {
				continue
			}
			hist, ok := m.Data.(metricdata.Histogram[float64])
			if !ok {
				t.Fatalf("%s is %T, want Histogram[float64]", m.Name, m.Data)
			}
			if m.Unit != "s" {
				t.Errorf("unit = %q, want s", m.Unit)
			}
			if got := hist.DataPoints[0].Bounds; !slices.Equal(got, want) {
				t.Errorf("bounds = %v,\n want %v", got, want)
			}
			return
		}
	}
	t.Fatal("http.server.request.duration was never recorded")
}

// Deleting p.deliveries = deliveries in buildMetrics, or changing its unit
// from "{delivery}" to something else, both leave TestNew_EnabledIsReal's
// no-op type assertion green (a nil metric.Int64Counter field also fails that
// assertion the same way a wrong-unit-but-non-nil one would pass it). Only a
// unit test through a ManualReader, mirroring
// TestRequestDuration_HasSecondsShapedBuckets, pins the unit.
func TestDeliveryCount_HasCorrectUnit(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	c, err := newDeliveryCounter(mp.Meter(InstrumentationName))
	if err != nil {
		t.Fatalf("newDeliveryCounter: %v", err)
	}
	c.Add(t.Context(), 1)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "diyddns.notification.delivery" {
				continue
			}
			if m.Unit != "{delivery}" {
				t.Errorf("unit = %q, want {delivery}", m.Unit)
			}
			return
		}
	}
	t.Fatal("diyddns.notification.delivery was never recorded")
}

// The DBStats callback must emit two CUMULATIVE counters and issue no query.
//
// Driven through (&Providers{...}).ObserveDB, NOT registerDBStats directly:
// calling registerDBStats bypasses the exported method entirely, so a mutant
// that guts ObserveDB's body (leaving only its nil guards) would leave every
// test in this file green, while TestNew_CallsObserveDB (server_test.go)
// only pins that server.New calls Instruments.ObserveDB, never that the
// telemetry package's own implementation does anything once called. Fix
// round 2, C1.
func TestObserveDB_EmitsCumulativeCounters(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)

	(&Providers{meter: mp.Meter(InstrumentationName)}).ObserveDB(db)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	want := map[string]bool{
		"diyddns.db.connection.wait_time": false,
		"diyddns.db.connection.waits":     false,
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if _, ok := want[m.Name]; !ok {
				continue
			}
			want[m.Name] = true
			switch d := m.Data.(type) {
			case metricdata.Sum[float64]:
				if !d.IsMonotonic {
					t.Errorf("%s must be monotonic (WaitDuration is Add-only)", m.Name)
				}
			case metricdata.Sum[int64]:
				if !d.IsMonotonic {
					t.Errorf("%s must be monotonic (WaitCount is Add-only)", m.Name)
				}
			default:
				t.Errorf("%s is %T, want a monotonic Sum — NOT a gauge", m.Name, m.Data)
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("%s was never emitted", name)
		}
	}
}

// TestObserveDB_EmitsCumulativeCounters only proves the two instruments are
// monotonic Sums; it never drives a real wait, so a callback that observes a
// hardcoded 0 instead of reading db.Stats() would pass it too. This test
// forces a REAL wait on the single connection (SetMaxOpenConns(1)) and
// asserts the callback reports it, closing that gap.
func TestObserveDB_ReflectsRealDBStats(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)

	registerDBStats(mp.Meter(InstrumentationName), db)

	// Hold the single connection in a transaction, then start a second
	// acquisition on another goroutine. With MaxOpenConns(1) and the one
	// connection already in use, database/sql queues that second request and
	// increments its wait counters (sql.go:1363-1368) before it can proceed.
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	waiterDone := make(chan struct{})
	go func() {
		defer close(waiterDone)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		_, _ = db.ExecContext(ctx, "SELECT 1")
	}()
	time.Sleep(50 * time.Millisecond) // let the waiter queue behind tx
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	<-waiterDone

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var gotWaits int64
	var gotWaitTime float64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch d := m.Data.(type) {
			case metricdata.Sum[int64]:
				if m.Name == "diyddns.db.connection.waits" {
					gotWaits = d.DataPoints[0].Value
				}
			case metricdata.Sum[float64]:
				if m.Name == "diyddns.db.connection.wait_time" {
					gotWaitTime = d.DataPoints[0].Value
				}
			}
		}
	}
	if gotWaits == 0 {
		t.Error("diyddns.db.connection.waits = 0, want > 0 -- did the callback actually call db.Stats()?")
	}
	if gotWaitTime <= 0 {
		t.Error("diyddns.db.connection.wait_time = 0, want > 0 -- did the callback actually call db.Stats()?")
	}
}
