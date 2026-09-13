package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "diyddns-server") {
		t.Errorf("version output = %q", out.String())
	}
}

// randomKeyB64 mints a random AES-256 key, base64-encoded the way
// auth.hmac.secret_key expects (config.DecodeSecretKey). server.New fails
// closed without a valid key (server.go:144), so every test that reaches
// server.New needs one.
func randomKeyB64(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("read random: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// pinOTLPEnv clears every OTEL_* variable exporter construction reads, so a
// value exported in a developer's shell cannot change which branch runs. This
// is not hypothetical: a Task 3 test failed on any machine with OTEL_SERVICE_NAME
// exported, and an ambient OTEL_EXPORTER_OTLP_TIMEOUT=60s stops the first export
// failing inside the windows the tests below bound themselves to.
//
// Setting to "" rather than unsetting matches what the SDK treats as absent:
// every reader here either trims (endpoint.go's applyOurTimeout,
// anyOTLPEndpointEnv) or fails to parse the empty value and falls back to its
// default (otlpconfig/envconfig.go).
func pinOTLPEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TIMEOUT",
		"OTEL_EXPORTER_OTLP_TRACES_TIMEOUT",
		"OTEL_EXPORTER_OTLP_METRICS_TIMEOUT",
		"OTEL_EXPORTER_OTLP_LOGS_TIMEOUT",
		"OTEL_EXPORTER_OTLP_PROTOCOL",
	} {
		t.Setenv(k, "")
	}
}

// TestServe_OtelSetLoggerInstalledBeforeTelemetryNew defends the ordering
// Task 6 first pinned and Revision 6 moved into serveCmd:
// otel.SetLogger(telemetry.OtelLogr(log)) MUST run before telemetry.New, or a
// malformed OTEL_* variable -- reported from inside exporter construction,
// the only place it is ever surfaced -- is silently dropped instead of
// reaching the operator's log.
//
// OTEL_EXPORTER_OTLP_TIMEOUT set to a non-numeric value makes
// otlptracehttp.New (called from telemetry.New's buildTraces) fail to parse
// the duration and report it through go.opentelemetry.io/otel/internal/global
// .Error, which is a logr.Logger.Error call -- NOT V-leveled, so it lands at
// slog.LevelError regardless of the configured level
// (go-logr/logr@v1.4.4/slogsink.go:71-73). That only reaches this test's log
// file if otel.SetLogger was installed against it before telemetry.New ran.
//
// To verify this test actually catches the regression it exists for: move
// the otel.SetLogger(telemetry.OtelLogr(log)) call in serveCmd to AFTER the
// telemetry.New call and re-run -- the "parse duration" line disappears from
// the log file and this test fails.
func TestServe_OtelSetLoggerInstalledBeforeTelemetryNew(t *testing.T) {
	// The malformed timeout is the point of this test; everything else is
	// pinned so nothing inherited from the ambient shell changes which branch
	// exporter construction takes. pinOTLPEnv runs FIRST: it clears the same
	// key this test then sets deliberately.
	pinOTLPEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "not-a-duration")

	dir := t.TempDir()
	logPath := filepath.Join(dir, "server.log")
	t.Setenv("DIYDDNS_DATABASE_PATH", filepath.Join(dir, "diyddns.db"))
	t.Setenv("DIYDDNS_SERVER_BASE_URL", "http://localhost:8080")
	t.Setenv("DIYDDNS_AUTH_HMAC_SECRET_KEY", randomKeyB64(t))
	t.Setenv("DIYDDNS_LOGGING_OUTPUT", logPath)
	t.Setenv("DIYDDNS_LOGGING_FORMAT", "json")
	t.Setenv("DIYDDNS_OBSERVABILITY_OTLP_ENABLED", "true")
	t.Setenv("DIYDDNS_OBSERVABILITY_OTLP_ENDPOINT", "http://127.0.0.1:4318")

	// Bounds the run: no code path in serveCmd's startup does network I/O
	// (exporter construction builds an http.Client, it does not dial), so
	// this only needs to outlive bootstrap + srv.Run's own goroutine spin-up
	// before ctx.Done() drives the graceful-shutdown branch.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := rootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"serve", "--listen", "127.0.0.1:0"})
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("execute: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "parse duration") {
		t.Fatalf("log file does not contain the SDK's construction-time diagnostic "+
			"(\"parse duration\") -- otel.SetLogger was not installed before telemetry.New ran; "+
			"log:\n%s", data)
	}
}

// TestServe_TelemetrySetErrorHandlerCapturesExportFailures defends the other
// half of serveCmd's telemetry wiring: tel.SetErrorHandler(log) must actually
// run, or export failures against an unreachable collector go to OTel's
// default stderr handler instead of the operator's configured log sink.
//
// The endpoint here is a real, reachable-looking address with nothing
// listening on it, so the trace/metric/log exporters all fail their first
// export attempt and telemetry.rateLimited.Handle (errors.go) logs "otlp
// export failed" through the *slog.Logger SetErrorHandler was given.
//
// To verify this test actually catches the regression it exists for: comment
// out tel.SetErrorHandler(log) in serveCmd and re-run -- the "otlp export
// failed" line disappears from the log file and this test fails.
func TestServe_TelemetrySetErrorHandlerCapturesExportFailures(t *testing.T) {
	pinOTLPEnv(t) // an ambient OTEL_EXPORTER_OTLP_TIMEOUT would outlast the 3s window
	dir := t.TempDir()
	logPath := filepath.Join(dir, "server.log")
	t.Setenv("DIYDDNS_DATABASE_PATH", filepath.Join(dir, "diyddns.db"))
	t.Setenv("DIYDDNS_SERVER_BASE_URL", "http://localhost:8080")
	t.Setenv("DIYDDNS_AUTH_HMAC_SECRET_KEY", randomKeyB64(t))
	t.Setenv("DIYDDNS_LOGGING_OUTPUT", logPath)
	t.Setenv("DIYDDNS_LOGGING_FORMAT", "json")
	t.Setenv("DIYDDNS_OBSERVABILITY_OTLP_ENABLED", "true")
	t.Setenv("DIYDDNS_OBSERVABILITY_OTLP_ENDPOINT", "http://127.0.0.1:4318")

	// Long enough for the logs signal's batch processor to attempt (and fail)
	// at least one export against the unreachable collector before shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := rootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"serve", "--listen", "127.0.0.1:0"})
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("execute: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "otlp export failed") {
		t.Fatalf("log file does not contain \"otlp export failed\" -- "+
			"tel.SetErrorHandler(log) was not installed; log:\n%s", data)
	}
}

// freeAddr reserves an unused loopback port and returns it, mirroring
// internal/smoke/helpers_test.go's freeAddr: the listener is closed before
// serveCmd binds it, so there is a small unavoidable race with anything else
// grabbing the port in between, same as every "find a free port" helper.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	return addr
}

// waitHealthy polls until /healthz answers, rather than sleeping a fixed
// amount (internal/smoke/helpers_test.go's waitHealthy, same pattern).
func waitHealthy(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("server did not become healthy within 5s")
}

// TestServe_ServerNewReceivesLiveTelemetry defends the wiring's other
// load-bearing line: srv, err := server.New(cfg, st, log, tel) must pass the
// real *telemetry.Providers, not server.NopInstruments{} -- both satisfy
// server.Instruments, so swapping one for the other still compiles and every
// OTHER test in this file (which never makes an HTTP request) still passes.
//
// The collector here is a real httptest.Server that answers every POST with
// a bare 200 (no Content-Type, so otlptracehttp's client takes the "not
// protobuf or JSON, nothing to parse" success path -- client.go's `default:
// return nil` branch -- without needing a protobuf-encoded response body).
// A REACHABLE collector is deliberate: against an unreachable one, the trace
// signal's own export failure is reported ONLY through the shared,
// rate-limited otel.ErrorHandler (errors.go's rateLimited), which races
// against the metrics and logs providers' own concurrent Shutdown-time
// export failures for the single "first failure" log line -- confirmed
// flaky (roughly half of ten back-to-back runs) before this test was
// rewritten to avoid the race entirely by making every export succeed.
//
// middleware.Trace(inst.Tracer(), inst.RequestDuration()) wraps every route
// (server.go's handler), so a single GET /healthz starts a real span when
// inst is the enabled *telemetry.Providers, and that span reaches the
// collector as a POST to /v1/traces once telemetry.Shutdown flushes it --
// something server.NopInstruments{}'s no-op tracer can never produce,
// because it starts no span at all.
//
// To verify this test actually catches the regression it exists for: change
// server.New's last argument in serveCmd to server.NopInstruments{} and
// re-run -- the collector never sees /v1/traces and this test fails.
func TestServe_ServerNewReceivesLiveTelemetry(t *testing.T) {
	var mu sync.Mutex
	sawTracesPOST := false
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/traces" {
			mu.Lock()
			sawTracesPOST = true
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	pinOTLPEnv(t) // see its comment: an ambient OTEL_* value changes what exports

	dir := t.TempDir()
	addr := freeAddr(t)
	t.Setenv("DIYDDNS_DATABASE_PATH", filepath.Join(dir, "diyddns.db"))
	t.Setenv("DIYDDNS_SERVER_BASE_URL", "http://localhost:8080")
	t.Setenv("DIYDDNS_AUTH_HMAC_SECRET_KEY", randomKeyB64(t))
	t.Setenv("DIYDDNS_LOGGING_OUTPUT", filepath.Join(dir, "server.log"))
	t.Setenv("DIYDDNS_LOGGING_FORMAT", "json")
	t.Setenv("DIYDDNS_OBSERVABILITY_OTLP_ENABLED", "true")
	t.Setenv("DIYDDNS_OBSERVABILITY_OTLP_ENDPOINT", collector.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := rootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"serve", "--listen", addr})

	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()

	waitHealthy(t, "http://"+addr)
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	_ = resp.Body.Close()

	// cancel() drives serveCmd's graceful shutdown, whose deferred
	// tel.Shutdown flushes the queued span; <-done only unblocks once every
	// defer in serveCmd's RunE (including that flush) has completed.
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("execute: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !sawTracesPOST {
		t.Fatal("collector never received a POST to /v1/traces -- " +
			"server.New did not receive the real *telemetry.Providers")
	}
}

func TestServe_RequiresDatabasePath(t *testing.T) {
	// No --config, no DIYDDNS_DATABASE_PATH → config.Load must error before
	// the server blocks.
	t.Setenv("DIYDDNS_DATABASE_PATH", "")
	cmd := rootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"serve"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "database.path") {
		t.Fatalf("want database.path error, got %v", err)
	}
}

// TestServe_FatalTelemetryStatusRefusesToBoot pins the fail-fast half of
// design §6.1's FATAL RULE, which nothing else in the tree pins: a Status with
// Fatal set must stop the boot, not merely log a Warn and carry on.
//
// "otel-collector:4318" is the exact shape design §9.3 calls out: it parses as
// an OPAQUE url with an empty Host (endpoint.go:34-37), so the exporter would
// POST to "http:///" forever while Shutdown reports success. An operator who
// wrote that believes telemetry is wired up and is wrong, which is why it is
// Fatal while a MISSING endpoint only degrades.
//
// The database file is asserted absent rather than the log merely lacking
// "server listening": plan Step 13.2's acceptance is that the error surfaces
// BEFORE any store or migration output, and store.Open creates that file.
func TestServe_FatalTelemetryStatusRefusesToBoot(t *testing.T) {
	pinOTLPEnv(t)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "diyddns.db")
	logPath := filepath.Join(dir, "server.log")
	t.Setenv("DIYDDNS_DATABASE_PATH", dbPath)
	t.Setenv("DIYDDNS_SERVER_BASE_URL", "http://localhost:8080")
	t.Setenv("DIYDDNS_AUTH_HMAC_SECRET_KEY", randomKeyB64(t))
	t.Setenv("DIYDDNS_LOGGING_OUTPUT", logPath)
	t.Setenv("DIYDDNS_LOGGING_FORMAT", "json")
	t.Setenv("DIYDDNS_OBSERVABILITY_OTLP_ENABLED", "true")
	t.Setenv("DIYDDNS_OBSERVABILITY_OTLP_ENDPOINT", "otel-collector:4318")

	// Bounds the run only so a regression that boots anyway fails this test
	// instead of hanging the suite forever; the fixed path returns long before
	// the deadline. Derived from t.Context() so the run is also tied to the
	// test's own lifetime.
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	cmd := rootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"serve", "--listen", "127.0.0.1:0"})
	err := cmd.ExecuteContext(ctx)
	if err == nil {
		t.Fatal("serve returned nil on a Fatal telemetry Status; it must refuse to boot")
	}
	for _, want := range []string{"observability.otlp.endpoint", "otel-collector:4318"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	// "telemetry: " comes from Status.Reason itself (errors.go / endpoint.go
	// build it); serveCmd must not add a second prefix.
	if n := strings.Count(err.Error(), "telemetry: "); n != 1 {
		t.Errorf("error %q carries %d \"telemetry: \" prefixes, want exactly 1", err, n)
	}

	if _, statErr := os.Stat(dbPath); statErr == nil {
		t.Error("store.Open ran: the Fatal status must surface before any store or migration output")
	}
	data, readErr := os.ReadFile(logPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatalf("read log file: %v", readErr)
	}
	for _, forbidden := range []string{"starting diyddns-server", "server listening"} {
		if strings.Contains(string(data), forbidden) {
			t.Errorf("log contains %q; the server booted on a Fatal telemetry Status:\n%s", forbidden, data)
		}
	}
}
