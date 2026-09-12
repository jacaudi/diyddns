package telemetry

import (
	"bytes"
	"context"
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
	tracenoop "go.opentelemetry.io/otel/trace/noop"
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
		// Shutdown itself is still a Task-7 stub (telemetry.go's Shutdown
		// always returns nil without calling anything in p.shutdown), so this
		// call flushes nothing and the three providers' batch-worker
		// goroutines leak for the rest of the test binary's life until Task 7
		// implements the real fan-out.
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

			// Drive tel.shutdown directly rather than tel.Shutdown: Shutdown
			// itself is still a Task-7 stub (telemetry.go's Shutdown always
			// returns nil without calling any of these funcs), so calling it
			// here would flush nothing and this test would pass vacuously.
			// Task 7 must revisit this test once Shutdown does its own
			// fan-out, and can likely delete this direct-drive workaround.
			ctx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
			defer cancel()
			for _, fn := range tel.shutdown {
				_ = fn(ctx)
			}

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

// The second diagnostic channel exists to catch exactly this: a malformed
// OTEL_* variable, reported nowhere else. The "parse duration" diagnostic
// fires INSIDE otlptracehttp.New (otlptracehttp@v1.46.0/internal/envconfig
// /envconfig.go:75), during buildTraces -- before SetErrorHandler exists to
// call, since SetErrorHandler is a method on the *Providers New returns. Only
// an EARLY install, using a bootstrap logger passed into New itself, can
// capture it.
func TestNew_BootstrapCapturesConstructionTimeDiagnostics(t *testing.T) {
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

	var buf bytes.Buffer
	bootstrap := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	tel, st := New(t.Context(), config.OTLPSection{Enabled: true, Endpoint: testEndpoint}, slog.LevelInfo, version.Current(), bootstrap)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
		defer cancel()
		_ = tel.Shutdown(ctx)
	})
	if st.Fatal {
		t.Fatalf("a malformed OTEL_EXPORTER_OTLP_TIMEOUT must not be Fatal (the SDK logs and falls back to its default), got %+v", st)
	}

	found := false
	for _, r := range records(t, &buf) {
		if msg, _ := r["msg"].(string); msg == "parse duration" {
			found = true
		}
	}
	if !found {
		t.Fatal(`bootstrap logger never saw the "parse duration" diagnostic -- the early otel.SetLogger install in New is missing or runs too late`)
	}
}

// A non-nil bootstrap must be inert on the DISABLED path, which is this
// feature's default. A disabled server constructs no exporters, so no
// construction-time diagnostic can exist to capture -- this is currently true
// only by code-flow inspection (the early install sits after the `!cfg.Enabled`
// return), so it gets a test rather than an argument.
//
// Endpoint is set to a valid value DESPITE Enabled: false: correct code never
// looks at it (the disabled short-circuit returns first), so this is inert
// for correct code. It matters for what this test actually exercises: with a
// valid endpoint, a mutant that deletes the `!cfg.Enabled` guard runs all the
// way through buildTraces (proven -- 2 real "parse duration" records land in
// the buffer), so the records assertion below is checked against genuine
// construction, not against the unrelated missing-endpoint degrade path. An
// empty endpoint does NOT make that mutant slip past undetected -- the
// missing-endpoint branch sets a non-zero Status even on the disabled path
// once the guard is gone, and the Status assertion below already catches
// that -- but it would catch a different failure than the one this test
// documents itself as proving, which is why Endpoint is set regardless.
func TestNew_DisabledInstallsNothingEvenWithBootstrapAndMalformedEnv(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_TIMEOUT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_TIMEOUT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "not-a-number")

	var buf bytes.Buffer
	bootstrap := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	tel, st := New(t.Context(), config.OTLPSection{Enabled: false, Endpoint: testEndpoint}, slog.LevelInfo, version.Current(), bootstrap)
	if tel == nil {
		t.Fatal("New returned nil; it must never return nil")
	}
	if st.Reason != "" || st.Fatal {
		t.Errorf("disabled must be a zero Status, got %+v", st)
	}
	if got := records(t, &buf); len(got) != 0 {
		t.Fatalf("got %d records on the disabled path with a non-nil bootstrap, want 0 "+
			"(a disabled server must construct no exporters and parse no OTEL_*)", len(got))
	}
}

func telemetryNew(t *testing.T, cfg config.OTLPSection) (*Providers, Status) {
	t.Helper()
	return New(t.Context(), cfg, slog.LevelInfo, version.Current(), nil)
}

// The SDK's DEFAULT histogram boundaries are millisecond-shaped
// {0,5,10,...,10000} (sdk/metric@v1.46.0/reader.go:206). This design records
// SECONDS, so the defaults would put every request under five seconds in the
// first bucket and the metric would carry no information. This test is the
// only thing standing between that and production.
func TestRequestDuration_HasSecondsShapedBuckets(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	h, err := newRequestDuration(mp.Meter(instrumentationName))
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
	c, err := newDeliveryCounter(mp.Meter(instrumentationName))
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
