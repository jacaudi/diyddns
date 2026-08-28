package server

import (
	"testing"

	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// TestBuildMux_NotificationsDisabledWiresNopNotifier is the regression guard
// for the #65 fix-wave finding M40: with notifications.enabled left at its
// default false, buildMux must wire service.NopNotifier into the check-in
// path, not notify.Enqueuer — otherwise a device's IP-changed event would
// enqueue an outbound delivery for a subsystem the operator never turned on.
// It drives the real wiring through buildMux and a real
// CheckinService.Checkin call rather than asserting on an unexported field,
// so it also catches a wiring regression at any future call site, not just
// the one line this fix-wave found.
func TestBuildMux_NotificationsDisabledWiresNopNotifier(t *testing.T) {
	ctx := t.Context()
	cfg := routesTestConfig(t) // notifications.enabled left at its default: false
	st := openTestStore(t)

	usr, err := st.Users().Create(ctx, store.User{Email: "notify-wiring@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	dev, err := st.Devices().Create(ctx, store.Device{
		UserID: usr.ID, Label: "dev", SecretHash: "hash",
	})
	if err != nil {
		t.Fatalf("Devices().Create: %v", err)
	}
	ep := store.NotificationEndpoint{
		ID: store.NewID(), UserID: usr.ID, Label: "ep", URL: "https://example.com/hook",
		SecretSealed: "sealed", CreatedAt: store.NowUnix(), UpdatedAt: store.NowUnix(),
	}
	if err := st.NotificationEndpoints().Create(ctx, ep, 5); err != nil {
		t.Fatalf("NotificationEndpoints().Create: %v", err)
	}

	_, _, apiDeps, _, _, err := buildMux(cfg, st, discardLog())
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}

	if _, err := apiDeps.Checkin.Checkin(ctx, dev.ID, service.CheckinReport{IPv4: "203.0.113.9"}); err != nil {
		t.Fatalf("Checkin: %v", err)
	}

	rows, err := st.NotificationDeliveries().DueForAttempt(ctx, store.NowUnix()+1, 10)
	if err != nil {
		t.Fatalf("DueForAttempt: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("got %d enqueued deliveries with notifications.enabled=false, want 0 — the Enqueuer must not be wired", len(rows))
	}
}
