package server

import (
	"context"
	"log/slog"
	"sync"

	"github.com/jacaudi/diyddns/internal/server/feed"
	"github.com/jacaudi/diyddns/internal/server/notify"
	"github.com/jacaudi/diyddns/internal/store"
)

// fanout joins the three event sources (check-in, device seams, user seams)
// to the two transports: the webhook outbox and the stream hub (design #106
// §7.3). It satisfies service.Notifier and service.DeviceNotifier
// structurally; neither service package imports notify or feed.
//
// Every method runs bump → render → enqueue → broadcast under one mutex, so
// the stream and the outbox see events in bump order: SetMaxOpenConns(1)
// serialises statements, not sequences, and without the mutex a check-in for
// device X concurrent with an admin disabling X could broadcast seq 6 before
// seq 5 and leave X allow-listed after it was disabled.
//
// Best-effort throughout: every failure is logged and swallowed; nothing here
// can fail the calling request (the #65 rule for the check-in path, applied
// to the admin paths as well).
type fanout struct {
	mu      sync.Mutex
	st      *store.Store
	enqueue *notify.Enqueuer // nil when notifications.enabled is false
	hub     *feed.Hub        // always non-nil; no subscribers when feed.enabled is false
	log     *slog.Logger
}

func newFanout(st *store.Store, enqueue *notify.Enqueuer, hub *feed.Hub, log *slog.Logger) *fanout {
	return &fanout{st: st, enqueue: enqueue, hub: hub, log: log}
}

// IPChanged fans a device.ip_changed event out. Its id is the ip_history row
// id, so a failed feed_state bump only leaves Last-Modified stale: the event
// is still sent.
func (f *fanout) IPChanged(ctx context.Context, ev store.IPChangeEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.st.FeedState().Bump(ctx, store.NowUnix()); err != nil {
		f.log.LogAttrs(ctx, slog.LevelWarn, "feed state bump failed",
			slog.String("event_type", notify.EventIPChanged), slog.Any("error", err))
	}
	payload, err := notify.RenderIPChanged(ev)
	if err != nil {
		f.log.LogAttrs(ctx, slog.LevelWarn, "notify: render failed",
			slog.String("event_type", notify.EventIPChanged), slog.String("device_id", ev.Device.ID), slog.Any("error", err))
		return
	}
	f.dispatch(ctx, notify.EventIPChanged, ev.EventID, payload)
}

// DeviceAdded fans a device.added event out. Its id IS the feed_state seq, so
// a failed bump DROPS the event (design D12): a sentinel id would be
// collapsed by the mandatory (type, id) dedupe on every conforming consumer,
// fail-open.
func (f *fanout) DeviceAdded(ctx context.Context, d store.Device) {
	f.membership(ctx, notify.EventAdded, d, notify.RenderAdded)
}

// DeviceRemoved fans a device.removed event out; same seq rule as DeviceAdded.
func (f *fanout) DeviceRemoved(ctx context.Context, d store.Device) {
	f.membership(ctx, notify.EventRemoved, d, notify.RenderRemoved)
}

func (f *fanout) membership(ctx context.Context, eventType string, d store.Device, render func(seq, now int64, d store.Device) ([]byte, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := store.NowUnix()
	seq, err := f.st.FeedState().Bump(ctx, now)
	if err != nil {
		f.log.LogAttrs(ctx, slog.LevelError, "feed event dropped",
			slog.String("event_type", eventType), slog.String("device_id", d.ID), slog.Any("error", err))
		return
	}
	payload, err := render(seq, now, d)
	if err != nil {
		f.log.LogAttrs(ctx, slog.LevelWarn, "notify: render failed",
			slog.String("event_type", eventType), slog.String("device_id", d.ID), slog.Any("error", err))
		return
	}
	f.dispatch(ctx, eventType, seq, payload)
}

// dispatch writes the outbox rows (when the webhook is on) and broadcasts to
// the hub. Called with mu held.
func (f *fanout) dispatch(ctx context.Context, eventType string, eventID int64, payload []byte) {
	if f.enqueue != nil {
		f.enqueue.Enqueue(ctx, eventType, eventID, payload)
	}
	f.hub.Broadcast(payload)
}
