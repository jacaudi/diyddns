package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/jacaudi/diyddns/internal/server/feed"
	"github.com/jacaudi/diyddns/internal/server/notify"
	"github.com/jacaudi/diyddns/internal/store"
)

// tokenAuth answers every Authenticate with one fixed token: these tests are
// about the fan-out, not the door.
type tokenAuth struct{}

func (tokenAuth) Authenticate(context.Context, string) (store.FeedToken, error) {
	return store.FeedToken{ID: "tok"}, nil
}

func seedEnabledEndpoint(t *testing.T, st *store.Store, id string) {
	t.Helper()
	now := store.NowUnix()
	if _, err := st.DB().ExecContext(t.Context(),
		`INSERT INTO notification_endpoints (id, label, url, secret_sealed, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, 'sealed', 1, ?, ?)`, id, id, "https://example.com/"+id, now, now); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
}

// streamClient opens a stream against a mux serving only the feed routes
// and returns a reader that yields decoded frames.
func streamClient(t *testing.T, st *store.Store, hub *feed.Hub) func() map[string]any {
	t.Helper()
	mux := http.NewServeMux()
	feed.Register(mux, feed.Deps{Store: st, Auth: tokenAuth{}, Hub: hub, Log: discardLog()})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	conn, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/feed/v1/stream", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + store.FeedTokenPrefix + "x"}},
	})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close() // nil on a successful upgrade: the library takes the conn over
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return func() map[string]any {
		t.Helper()
		rctx, rcancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer rcancel()
		_, b, err := conn.Read(rctx)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("frame is not JSON: %v (%s)", err, b)
		}
		return m
	}
}

// TestFanout_BumpsRendersEnqueuesBroadcasts: one IPChanged bumps feed_state,
// writes one outbox row per enabled endpoint, and reaches the stream — with
// byte-identical payloads on both transports.
func TestFanout_BumpsRendersEnqueuesBroadcasts(t *testing.T) {
	st := openTestStore(t)
	seedEnabledEndpoint(t, st, "ep1")
	seedEnabledEndpoint(t, st, "ep2")
	hub := feed.New()
	next := streamClient(t, st, hub)
	if got := next()["type"]; got != "feed.snapshot" {
		t.Fatalf("first frame type = %v, want feed.snapshot", got)
	}

	f := newFanout(st, notify.NewEnqueuer(st, discardLog()), hub, discardLog())
	f.IPChanged(t.Context(), store.IPChangeEvent{
		EventID: 77, OccurredAt: store.NowUnix(),
		Device:   store.Device{ID: "dev1", Label: "l"},
		PrevIPv4: "1.1.1.1", CurrIPv4: "2.2.2.2",
	})

	frame := next()
	if frame["type"] != "device.ip_changed" || frame["id"] != float64(77) {
		t.Errorf("stream frame = %v", frame)
	}
	due, err := st.NotificationDeliveries().DueForAttempt(t.Context(), store.NowUnix()+1, 10)
	if err != nil {
		t.Fatalf("DueForAttempt: %v", err)
	}
	if len(due) != 2 {
		t.Fatalf("outbox rows = %d, want 2", len(due))
	}
	fromStream := frame // not `var fromStream map[string]any = frame`: ST1023
	var fromOutbox map[string]any
	if err := json.Unmarshal(due[0].Payload, &fromOutbox); err != nil {
		t.Fatal(err)
	}
	if fromOutbox["id"] != fromStream["id"] || fromOutbox["type"] != fromStream["type"] {
		t.Errorf("outbox payload %v differs from the stream frame %v", fromOutbox, fromStream)
	}
	fs, err := st.FeedState().Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if fs.Seq != 1 {
		t.Errorf("feed_state.seq = %d after one event, want 1", fs.Seq)
	}
}

// TestFanout_AddedRemovedCarrySeqAsID and are ordered by bump.
func TestFanout_AddedRemovedCarrySeqAsID(t *testing.T) {
	st := openTestStore(t)
	hub := feed.New()
	next := streamClient(t, st, hub)
	next() // snapshot

	f := newFanout(st, nil, hub, discardLog()) // webhook disabled: enqueuer nil
	dev := store.Device{ID: "dev1", Label: "l", CurrentIPv4: "203.0.113.9"}
	f.DeviceAdded(t.Context(), dev)
	f.DeviceRemoved(t.Context(), dev)

	a, r := next(), next()
	if a["type"] != "device.added" || a["id"] != float64(1) {
		t.Errorf("added = %v, want id 1", a)
	}
	if r["type"] != "device.removed" || r["id"] != float64(2) {
		t.Errorf("removed = %v, want id 2", r)
	}
}

// TestFanout_DropsAddedRemovedWhenBumpFails: with the store closed, Bump
// fails; added/removed are DROPPED (never sent with a sentinel id, which the
// (type, id) dedupe rule would collapse), and nothing panics. ip_changed does
// not depend on the seq and is still broadcast.
func TestFanout_DropsAddedRemovedWhenBumpFails(t *testing.T) {
	st := openTestStore(t)
	hub := feed.New()
	next := streamClient(t, st, hub)
	next() // snapshot
	var logBuf strings.Builder
	log := slog.New(slog.NewJSONHandler(&logBuf, nil))
	f := newFanout(st, nil, hub, log)
	_ = st.Close()

	f.DeviceRemoved(t.Context(), store.Device{ID: "dev1", Label: "l", CurrentIPv4: "203.0.113.9"})
	f.IPChanged(t.Context(), store.IPChangeEvent{EventID: 5, Device: store.Device{ID: "dev1"}, PrevIPv4: "1.1.1.1", CurrIPv4: "2.2.2.2"})

	frame := next()
	if frame["type"] != "device.ip_changed" || frame["id"] != float64(5) {
		t.Fatalf("first frame after the failed bump = %v, want the ip_changed (the removed must have been dropped)", frame)
	}
	if !strings.Contains(logBuf.String(), `"msg":"feed event dropped"`) || !strings.Contains(logBuf.String(), `"event_type":"device.removed"`) {
		t.Errorf("log = %s, want feed event dropped for device.removed", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), `"msg":"feed state bump failed"`) {
		t.Errorf("log = %s, want feed state bump failed for the ip_changed", logBuf.String())
	}
}

// TestFanout_IsSerialised: concurrent callers observe bump order on the
// stream — seq 1..N arrive ascending — because the whole bump→render→enqueue→
// broadcast sequence runs under one mutex (design §7.3).
func TestFanout_IsSerialised(t *testing.T) {
	st := openTestStore(t)
	hub := feed.New()
	next := streamClient(t, st, hub)
	next() // snapshot
	f := newFanout(st, nil, hub, discardLog())

	const n = 20
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			f.DeviceAdded(t.Context(), store.Device{ID: "d", Label: "l", CurrentIPv4: "203.0.113.9"})
		})
	}
	wg.Wait()
	for i := 1; i <= n; i++ {
		if got := next()["id"]; got != float64(i) {
			t.Fatalf("frame %d has id %v; events are not in bump order", i, got)
		}
	}
}

// TestFanout_NilEnqueuerIsSkipped: with the webhook off the enqueuer is nil
// and must simply be skipped, not dereferenced; the bump still happens.
func TestFanout_NilEnqueuerIsSkipped(t *testing.T) {
	st := openTestStore(t)
	f := newFanout(st, nil, feed.New(), discardLog())
	f.IPChanged(t.Context(), store.IPChangeEvent{EventID: 1, Device: store.Device{ID: "d"}})
	fs, err := st.FeedState().Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if fs.Seq != 1 {
		t.Errorf("feed_state.seq = %d, want 1", fs.Seq)
	}
}
