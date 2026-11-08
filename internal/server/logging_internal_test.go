package server

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"testing"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/telemetry"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// NewLogger alone builds no MultiHandler and no bridge: the bridge is added
// only by WithOTLP, once a provider exists.
func TestNewLogger_BuildsNoMultiHandler(t *testing.T) {
	log, err := NewLogger(config.LoggingSection{Level: "info", Format: "json", Output: "stderr"})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	rh, ok := log.Handler().(requestIDHandler)
	if !ok {
		t.Fatalf("outermost handler is %T, want requestIDHandler", log.Handler())
	}
	if _, isMulti := rh.inner.(*slog.MultiHandler); isMulti {
		t.Error("NewLogger must NOT produce a MultiHandler branch")
	}
}

// capturingProcessor records every log.Record it is handed, so a test can
// assert on what actually reached the exporter side of the pipeline.
type capturingProcessor struct {
	mu   sync.Mutex
	recs []sdklog.Record
}

func (c *capturingProcessor) OnEmit(_ context.Context, r *sdklog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, r.Clone()) // Clone: the SDK reuses the Record
	return nil
}

func (c *capturingProcessor) Enabled(context.Context, sdklog.EnabledParameters) bool { return true }
func (c *capturingProcessor) Shutdown(context.Context) error                         { return nil }
func (c *capturingProcessor) ForceFlush(context.Context) error                       { return nil }

func (c *capturingProcessor) records() []sdklog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.recs)
}

// THE minsev ASSERTION. Without minsev this test FAILS, which is what makes
// design D4 ("the OTLP bridge shares logging.level") real rather than asserted.
//
// The chain, all verified in source: MultiHandler.Enabled is the union of its
// children (multi_handler.go:26-33) and Handle re-checks per child (:38);
// otelslog.Handler.Enabled delegates to the LoggerProvider (handler.go:266-270);
// sdk/log's logger.Enabled returns true if ANY processor is enabled
// (logger.go:107-125); and BatchProcessor.Enabled returns true
// UNCONDITIONALLY (batch.go:266-268). So without a minsev wrapper the bridge
// exports EVERY Debug record at logging.level: info -- including notify's raw
// delivery errors, which worker.go:245-247 documents as deliberately never
// persisted -- to a third-party backend.
func TestNewLogger_BridgeHonoursLoggingLevel(t *testing.T) {
	rec := &capturingProcessor{} // records every log.Record it is given
	lp := telemetry.NewLoggerProvider(rec, slog.LevelInfo)
	t.Cleanup(func() { _ = lp.Shutdown(context.Background()) })

	base, err := NewLogger(config.LoggingSection{Level: "info", Format: "json", Output: "stderr"})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	log := WithOTLP(base, lp)
	log.Debug("this must not be exported")
	log.Info("this must be exported")

	if err := lp.ForceFlush(t.Context()); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}
	for _, r := range rec.records() {
		if r.Body().AsString() == "this must not be exported" {
			t.Fatal("a Debug record reached the exporter at logging.level: info — minsev is missing")
		}
	}
	if len(rec.records()) != 1 {
		t.Errorf("exported %d records, want 1", len(rec.records()))
	}
}

// The payoff of #100's request_id groundwork, extended to a real trace id.
// sdk/log/logger.go:131 lifts the SpanContext off ctx onto every record, and
// otelslog passes the caller's ctx straight through (handler.go:193-196), so
// this needs no code -- but nothing proves it until this test exists.
func TestNewLogger_RecordInsideSpanCarriesTraceID(t *testing.T) {
	rec := &capturingProcessor{}
	lp := telemetry.NewLoggerProvider(rec, slog.LevelInfo)
	t.Cleanup(func() { _ = lp.Shutdown(context.Background()) })

	base, err := NewLogger(config.LoggingSection{Level: "info", Format: "json", Output: "stderr"})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	log := WithOTLP(base, lp)

	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(t.Context(), "op")
	log.InfoContext(ctx, "inside the span")
	span.End()

	if err := lp.ForceFlush(t.Context()); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}
	got := rec.records()
	if len(got) != 1 {
		t.Fatalf("exported %d records, want 1", len(got))
	}
	if want := span.SpanContext().TraceID(); got[0].TraceID() != want {
		t.Errorf("record trace id = %s, want %s", got[0].TraceID(), want)
	}
}

// cmd/diyddns-server builds its logger BEFORE telemetry.New (so otel.SetLogger
// can catch a malformed OTEL_* variable reported from inside exporter
// construction) and adds the bridge with WithOTLP once the provider exists.
// Records logged before that point reach only the local output; records
// logged through the returned logger reach the exporter too, with
// request_id still added once, outermost.
func TestWithOTLP_AddsBridgeToExistingLogger(t *testing.T) {
	base, err := NewLogger(config.LoggingSection{Level: "info", Format: "json", Output: "stderr"})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	base.Info("before bridge")

	rec := &capturingProcessor{}
	lp := telemetry.NewLoggerProvider(rec, slog.LevelInfo)
	t.Cleanup(func() { _ = lp.Shutdown(context.Background()) })
	log := WithOTLP(base, lp)

	rh, ok := log.Handler().(requestIDHandler)
	if !ok {
		t.Fatalf("outermost handler is %T, want requestIDHandler", log.Handler())
	}
	if _, isMulti := rh.inner.(*slog.MultiHandler); !isMulti {
		t.Errorf("inner handler is %T, want *slog.MultiHandler", rh.inner)
	}

	log.Info("after bridge")
	if err := lp.ForceFlush(t.Context()); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}
	got := rec.records()
	if len(got) != 1 {
		t.Fatalf("exported %d records, want 1", len(got))
	}
	if got[0].Body().AsString() != "after bridge" {
		t.Errorf("exported record body = %q, want %q", got[0].Body().AsString(), "after bridge")
	}
}

// A nil provider (telemetry off or inert) returns the logger unchanged.
func TestWithOTLP_NilProviderIsIdentity(t *testing.T) {
	base, err := NewLogger(config.LoggingSection{Level: "info", Format: "json", Output: "stderr"})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if got := WithOTLP(base, nil); got != base {
		t.Error("WithOTLP(log, nil) must return log itself")
	}
}
