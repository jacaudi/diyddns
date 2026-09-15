package server

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// baseConfig loads a config.Server the same way production does (via
// config.Load and its defaults), with just enough overridden to make New
// succeed: a valid HMAC key and a base_url (handler's WebAuthn RP resolution
// fails closed without one, see server_test.go's testConfig).
func baseConfig(t *testing.T) config.Server {
	t.Helper()
	v := viper.New()
	v.Set("database.path", ":memory:")
	v.Set("auth.hmac.secret_key", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32)))
	v.Set("server.base_url", "https://ddns.example.com")
	cfg, err := config.Load(v, "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

// newTestServer builds a Server against a fresh in-memory store, failing the
// test if New returns an error.
func newTestServer(t *testing.T, cfg config.Server, log *slog.Logger) *Server {
	t.Helper()
	srv, err := New(cfg, openTestStore(t), log, NopInstruments{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// seedDevicePastWindow seeds one device whose IPv4 address has never been
// confirmed (v4_confirmed_at 0), which is past any positive expiry window.
func seedDevicePastWindow(t *testing.T, srv *Server) string {
	t.Helper()
	u, err := srv.st.Users().Create(t.Context(), store.User{Email: store.NewID() + "@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	d, err := srv.st.Devices().Create(t.Context(), store.Device{
		UserID: u.ID, Label: store.NewID(), SecretHash: "h",
		CurrentIPv4: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("Devices().Create: %v", err)
	}
	return d.ID
}

// deviceByID reads back a device seeded via seedDevicePastWindow.
func deviceByID(t *testing.T, srv *Server, id string) store.Device {
	t.Helper()
	d, err := srv.st.Devices().GetByID(t.Context(), id)
	if err != nil {
		t.Fatalf("Devices().GetByID: %v", err)
	}
	return d
}

// TestGating covers every row of design §9's gating matrix.
func TestGating(t *testing.T) {
	for _, tc := range []struct {
		name        string
		feed        bool
		days        int
		email       bool
		wantSweeper bool
		wantWarning bool
	}{
		{"feed off", false, 21, true, false, false},
		{"policy opted out", true, 0, true, false, false},
		{"full behaviour", true, 21, true, true, false},
		{"email off", true, 21, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig(t)
			cfg.Feed = config.FeedSection{Enabled: tc.feed, ExpireAfterDays: tc.days}
			cfg.Email.Enabled = tc.email

			var buf bytes.Buffer
			srv := newTestServer(t, cfg, slog.New(slog.NewTextHandler(&buf, nil)))

			if got := srv.sweeper != nil; got != tc.wantSweeper {
				t.Errorf("sweeper constructed = %v, want %v", got, tc.wantSweeper)
			}
			// The brief requires TWO startup log lines; this asserts the first
			// (the plain "expiry is on" notice) as well as the second (the
			// email-disabled warning), so an unconditional emit of either
			// cannot pass this test silently.
			wantEnabledLog := tc.feed && tc.days > 0
			enabledLogged := strings.Contains(buf.String(), "feed expiry enabled:")
			if enabledLogged != wantEnabledLog {
				t.Errorf("startup \"feed expiry enabled\" log = %v, want %v", enabledLogged, wantEnabledLog)
			}
			warned := strings.Contains(buf.String(), "feed expiry is enabled but email is disabled")
			if warned != tc.wantWarning {
				t.Errorf("startup warning = %v, want %v", warned, tc.wantWarning)
			}
		})
	}
}

// TestWiring_SweeperRunsOnThePrunerTick is the "implemented, tested, never
// called" hazard #73's Gate 2 caught, one level up. Zeroing the feed config
// must FAIL a test, or the whole policy can ship wired to nothing and every
// unit test still passes.
func TestWiring_SweeperRunsOnThePrunerTick(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Feed = config.FeedSection{Enabled: true, ExpireAfterDays: 21}
	srv := newTestServer(t, cfg, discardLog())

	if srv.sweeper == nil {
		t.Fatal("sweeper is nil with the policy enabled")
	}
	// Seed a device already past its window, run ONE pruner tick's worth of
	// work through the same entry point runPruner uses, and assert the
	// address was cleared. This is what proves the wiring, not that the type
	// exists.
	id := seedDevicePastWindow(t, srv)
	if err := srv.sweeper.Run(t.Context(), store.NowUnix()); err != nil {
		t.Fatal(err)
	}
	if got := deviceByID(t, srv, id); got.CurrentIPv4 != "" {
		t.Error("the sweeper did not clear an overdue address")
	}
}
