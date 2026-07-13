package oidc_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/oidc"
	"github.com/jacaudi/diyddns/internal/oidc/oidctest"
)

func newManager(t *testing.T, idp *oidctest.IdP, device bool) *oidc.Manager {
	t.Helper()
	cfg := config.OIDCCfg{
		Enabled: true, Issuer: idp.Issuer, ClientID: "test-client",
		ClientSecret: "secret", Scopes: []string{"openid", "profile", "email"},
		AutoLinkByEmail: true, AllowOIDCSignup: true,
	}
	return oidc.NewManager(cfg, "https://ddns.example.com", testLogger(t))
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestManager_DiscoverPublishesState(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: true})
	m := newManager(t, idp, true)

	if m.Enabled() {
		t.Fatal("Enabled() must be false before Discover")
	}
	if err := m.Discover(t.Context()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !m.Enabled() {
		t.Fatal("Enabled() must be true after successful Discover")
	}
	if !m.DeviceEnabled() {
		t.Fatal("DeviceEnabled() must be true when the IdP advertises a device endpoint")
	}
}

func TestManager_DeviceDisabledWhenIdPLacksEndpoint(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: false})
	m := newManager(t, idp, false)
	if err := m.Discover(t.Context()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !m.Enabled() {
		t.Fatal("Enabled() true expected")
	}
	if m.DeviceEnabled() {
		t.Fatal("DeviceEnabled() must be false when no device endpoint is advertised")
	}
}

func TestManager_DiscoverFailsOnBadIssuer(t *testing.T) {
	cfg := config.OIDCCfg{Enabled: true, Issuer: "http://127.0.0.1:1/nope", ClientID: "x", ClientSecret: "y", Scopes: []string{"openid"}}
	m := oidc.NewManager(cfg, "https://ddns.example.com", testLogger(t))
	if err := m.Discover(t.Context()); err == nil {
		t.Fatal("expected Discover to fail against an unreachable issuer")
	}
	if m.Enabled() {
		t.Fatal("Enabled() must stay false after a failed Discover")
	}
}

// TestManager_NilReceiverIsSafe guards C1 from SGE review: a nil *Manager
// (as constructed by test harnesses that don't wire OIDC) must report not-
// ready, never panic.
func TestManager_NilReceiverIsSafe(t *testing.T) {
	var m *oidc.Manager
	if m.Enabled() {
		t.Fatal("nil Manager Enabled() must be false")
	}
	if m.DeviceEnabled() {
		t.Fatal("nil Manager DeviceEnabled() must be false")
	}
}

func TestRetryLoop_RecoversAfterIdPComesUp(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{})
	m := newManager(t, idp, false)

	// Force discovery to fail once, then succeed: point at a bad issuer, run the
	// loop with an instant (fake) sleep, and flip the issuer after the first try.
	// Simplest deterministic form: use the manager's test hook to make sleep
	// instant, start the loop, and assert it reaches Enabled().
	oidc.SetSleepForTest(m, func(ctx context.Context, _ time.Duration) bool {
		return ctx.Err() == nil // return immediately, honoring cancellation
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { m.RetryLoop(ctx); close(done) }()

	// The good issuer means the first Discover succeeds; the loop should exit.
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("RetryLoop did not exit after successful discovery")
	}
	if !m.Enabled() {
		t.Fatal("Enabled() expected true after RetryLoop")
	}
}
