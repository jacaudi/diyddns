package telemetry_test

import (
	"log/slog"
	"testing"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/telemetry"
	"github.com/jacaudi/diyddns/internal/version"
	"go.opentelemetry.io/otel/metric/noop"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// Disabled is the DEFAULT configuration. Every accessor must return a usable
// no-op so no call site nil-checks (design D5, acceptance criterion 1).
func TestNew_DisabledIsInert(t *testing.T) {
	tel, st := telemetry.New(t.Context(), config.OTLPSection{Enabled: false}, slog.LevelInfo, version.Current(), nil)
	if tel == nil {
		t.Fatal("New returned nil; it must never return nil")
	}
	if st.Reason != "" || st.Fatal {
		t.Errorf("disabled must be a zero Status, got %+v", st)
	}
	if _, ok := tel.Tracer().(tracenoop.Tracer); !ok {
		t.Errorf("Tracer() = %T, want trace/noop.Tracer", tel.Tracer())
	}
	if _, ok := tel.RequestDuration().(noop.Float64Histogram); !ok {
		t.Errorf("RequestDuration() = %T, want metric/noop.Float64Histogram", tel.RequestDuration())
	}
	if _, ok := tel.DeliveryCount().(noop.Int64Counter); !ok {
		t.Errorf("DeliveryCount() = %T, want metric/noop.Int64Counter", tel.DeliveryCount())
	}
}

// THE SEGFAULT GUARD (design §15.2). LoggerProvider must return a genuine nil
// interface, never a non-nil interface holding a typed nil. Written the naive
// way -- a struct field of type *sdklog.LoggerProvider returned through the
// otellog.LoggerProvider interface -- `lp == nil` is FALSE, NewLogger builds
// the bridge branch, and otelslog.NewHandler dereferences a nil provider and
// panics AT BOOT on the telemetry-DISABLED path.
func TestNew_DisabledLoggerProviderIsGenuineNil(t *testing.T) {
	tel, _ := telemetry.New(t.Context(), config.OTLPSection{Enabled: false}, slog.LevelInfo, version.Current(), nil)
	if lp := tel.LoggerProvider(); lp != nil {
		t.Fatalf("LoggerProvider() must be a genuine nil interface, got non-nil holding %T", lp)
	}
}

// A nil *Providers is valid and inert: every method tolerates it.
func TestNilProviders_IsSafe(t *testing.T) {
	var tel *telemetry.Providers
	if tel.Tracer() == nil {
		t.Error("nil Providers must still return a usable Tracer")
	}
	if tel.RequestDuration() == nil {
		t.Error("nil Providers must still return a usable RequestDuration")
	}
	if tel.DeliveryCount() == nil {
		t.Error("nil Providers must still return a usable DeliveryCount")
	}
	if tel.LoggerProvider() != nil {
		t.Error("nil Providers must return a genuine nil LoggerProvider")
	}
	tel.ObserveDB(nil)                  // must not panic
	tel.SetErrorHandler(slog.Default()) // must not panic
	if err := tel.Shutdown(t.Context()); err != nil {
		t.Errorf("nil Providers Shutdown: %v", err)
	}
}

// Shutdown is idempotent: serveCmd's defer may run after an earlier explicit
// call on a failure path. This runs against a *disabled* Providers, so it
// exercises the len(p.shutdown) == 0 early return, not the concurrent
// fan-out itself. The fan-out's own properties (genuine concurrency, joining
// every error, not re-invoking funcs on a second call) are pinned in-package
// by shutdown_test.go's TestShutdown_* stub tests (Fix round 1, C1); the
// black-hole and reachable-collector scenarios against REAL providers are
// covered by internal/server/telemetry_blackhole_test.go, which needs
// internal/server's test helpers.
func TestShutdown_IsIdempotent(t *testing.T) {
	tel, _ := telemetry.New(t.Context(), config.OTLPSection{Enabled: false}, slog.LevelInfo, version.Current(), nil)
	if err := tel.Shutdown(t.Context()); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	if err := tel.Shutdown(t.Context()); err != nil {
		t.Errorf("second Shutdown: %v", err)
	}
}
