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

// A nil provider must build EXACTLY today's handler: no MultiHandler, no
// bridge. This is NOT the production telemetry-disabled path (Revision 6:
// cmd/diyddns-server always passes a *LazyLoggerProvider, never a literal
// nil) -- it is the regression guard for the secondary nil path NewLogger's
// doc comment describes, exercised directly by any caller with no lazy slot
// to offer, such as this test.
func TestNewLogger_NilProviderBuildsNoMultiHandler(t *testing.T) {
	log, err := NewLogger(config.LoggingSection{Level: "info", Format: "json", Output: "stderr"}, nil)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	rh, ok := log.Handler().(requestIDHandler)
	if !ok {
		t.Fatalf("outermost handler is %T, want requestIDHandler", log.Handler())
	}
	if _, isMulti := rh.inner.(*slog.MultiHandler); isMulti {
		t.Error("a nil LoggerProvider must NOT produce a MultiHandler branch")
	}
}

// With a provider, the bridge is the second branch -- and requestIDHandler
// stays OUTERMOST so request_id is added once and cloned into both branches,
// rather than being computed per branch.
func TestNewLogger_ProviderAddsMultiHandlerInsideRequestID(t *testing.T) {
	// The SAME seam Step 10.3's minsev test uses -- do NOT write a second
	// helper. capturingProcessor is defined in this file (see Step 10.3).
	lp := telemetry.NewLoggerProvider(&capturingProcessor{}, slog.LevelInfo)
	t.Cleanup(func() { _ = lp.Shutdown(context.Background()) })
	log, err := NewLogger(config.LoggingSection{Level: "info", Format: "json", Output: "stderr"}, lp)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	rh, ok := log.Handler().(requestIDHandler)
	if !ok {
		t.Fatalf("outermost handler is %T, want requestIDHandler", log.Handler())
	}
	if _, isMulti := rh.inner.(*slog.MultiHandler); !isMulti {
		t.Errorf("inner handler is %T, want *slog.MultiHandler", rh.inner)
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

	log, err := NewLogger(config.LoggingSection{Level: "info", Format: "json", Output: "stderr"}, lp)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
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

	log, err := NewLogger(config.LoggingSection{Level: "info", Format: "json", Output: "stderr"}, lp)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

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

// Fix round 1, C2. This is the SAME logger otelslog.NewHandler builds once
// and holds for its lifetime -- and Task 13's own documented startup order
// (otel.SetLogger(telemetry.OtelLogr(log)) BEFORE telemetry.New, per the package doc
// comment on server.LazyLoggerProvider) guarantees a real caller will ask this
// logger to log at least once while the slot is still empty: logr's slog sink
// calls Handler.Enabled first (go-logr/logr@v1.4.4/slogsink.go:68-70), and
// that lands here through otelslog before Store has ever run.
//
// A lazyLogger implementation that caches an EMPTY-SLOT miss (as opposed to
// only caching a genuine resolution) would silently and permanently stop
// exporting from that point on -- for the life of the process, since
// otelslog.Handler.WithAttrs/WithGroup copy the struct and reuse the SAME
// h.logger (otelslog@v0.20.1/handler.go:274,292). This test drives exactly
// that sequence: log while empty, THEN fill the slot, THEN log again, and
// requires the second record to actually reach the exporter.
func TestNewLogger_LazyProviderFillsAfterEmptySlotMiss(t *testing.T) {
	var lazy LazyLoggerProvider
	log, err := NewLogger(config.LoggingSection{Level: "info", Format: "json", Output: "stderr"}, &lazy)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	// A miss while the slot is empty: must not panic, and must not poison the
	// logger against ever exporting once the slot is filled.
	log.Info("before store")

	rec := &capturingProcessor{}
	lp := telemetry.NewLoggerProvider(rec, slog.LevelInfo)
	t.Cleanup(func() { _ = lp.Shutdown(context.Background()) })
	lazy.Store(lp)

	log.Info("after store")

	if err := lp.ForceFlush(t.Context()); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}
	got := rec.records()
	if len(got) != 1 {
		t.Fatalf("exported %d records after Store, want 1 (an empty-slot miss must not be cached)", len(got))
	}
	if got[0].Body().AsString() != "after store" {
		t.Errorf("exported record body = %q, want %q", got[0].Body().AsString(), "after store")
	}
}
