package server

import (
	"testing"

	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// TestBuildMux_NotificationsDisabledEnqueuesNothing is the regression guard
// for the #65 fix-wave finding M40: with notifications.enabled AND
// feed.enabled both explicitly off, a device's IP-changed event must not
// enqueue an outbound delivery for a subsystem the operator never turned on.
// The fan-out is always wired (buildFanout), with a nil enqueuer when
// notifications are off, so the only side effect left is the feed_state bump.
// It drives the real wiring through buildMux and a real CheckinService.Checkin
// call rather than asserting on an unexported field.
func TestBuildMux_NotificationsDisabledEnqueuesNothing(t *testing.T) {
	ctx := t.Context()
	cfg := routesTestConfig(t) // notifications.enabled defaults to false
	cfg.Feed.Enabled = false   // feed.enabled now defaults to true; disable explicitly for this "both off" case
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
		ID: store.NewID(), Label: "ep", URL: "https://example.com/hook",
		SecretSealed: "sealed", CreatedAt: store.NowUnix(), UpdatedAt: store.NowUnix(),
	}
	if err := st.NotificationEndpoints().Create(ctx, ep); err != nil {
		t.Fatalf("NotificationEndpoints().Create: %v", err)
	}

	_, _, apiDeps, _, _, _, _, err := buildMux(cfg, st, discardLog(), nil, nil)
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}

	if _, err := apiDeps.Checkin.Checkin(ctx, dev.ID, service.CheckinReport{IPv4: "8.8.4.4"}); err != nil {
		t.Fatalf("Checkin: %v", err)
	}

	rows, err := st.NotificationDeliveries().DueForAttempt(ctx, store.NowUnix()+1, 10)
	if err != nil {
		t.Fatalf("DueForAttempt: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("got %d enqueued deliveries with notifications.enabled=false, want 0 — the Enqueuer must not be wired", len(rows))
	}
	fs, err := st.FeedState().Get(ctx)
	if err != nil {
		t.Fatalf("FeedState: %v", err)
	}
	if fs.Seq != 1 {
		t.Errorf("feed_state.seq = %d after one check-in with both switches off, want 1 (the always-wired fan-out bumps it)", fs.Seq)
	}
}

// TestBuildMux_WebhookOffFeedOnStillFansOut: with only the feed on, a check-in bumps feed_state and writes
// no outbox row.
func TestBuildMux_WebhookOffFeedOnStillFansOut(t *testing.T) {
	ctx := t.Context()
	cfg := routesTestConfig(t)
	cfg.Feed.Enabled = true
	st := openTestStore(t)

	usr, err := st.Users().Create(ctx, store.User{Email: "feed-wiring@example.com", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := st.Devices().Create(ctx, store.Device{UserID: usr.ID, Label: "dev", SecretHash: "hash"})
	if err != nil {
		t.Fatal(err)
	}
	ep := store.NotificationEndpoint{ID: store.NewID(), Label: "ep", URL: "https://example.com/hook",
		SecretSealed: "sealed", CreatedAt: store.NowUnix(), UpdatedAt: store.NowUnix()}
	if err := st.NotificationEndpoints().Create(ctx, ep); err != nil {
		t.Fatal(err)
	}

	_, _, apiDeps, _, _, _, _, err := buildMux(cfg, st, discardLog(), nil, nil)
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	if _, err := apiDeps.Checkin.Checkin(ctx, dev.ID, service.CheckinReport{IPv4: "8.8.4.4"}); err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	rows, err := st.NotificationDeliveries().DueForAttempt(ctx, store.NowUnix()+1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("outbox rows = %d with notifications.enabled=false, want 0", len(rows))
	}
	fs, err := st.FeedState().Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if fs.Seq != 1 {
		t.Errorf("feed_state.seq = %d after one check-in with feed.enabled=true, want 1", fs.Seq)
	}
}
