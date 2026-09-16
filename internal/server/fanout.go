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
// Best-effort throughout: every fan-out method except ExpireAddresses logs
// and swallows its failures, so nothing here can fail the calling request
// (the #65 rule for the check-in path, applied to the admin paths as well).
// ExpireAddresses is the one exception: it returns an error because its
// caller, the sweep, needs to know whether the write actually landed before
// it decides whether to send notices for it.
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

// Confirmed is the pair of confirmation instants the sweep READ, replayed into
// the conditional write's WHERE so the write fails if the device confirmed
// anything in between (D8).
//
// Unexported field types are unnecessary here: the sweeper lives in this
// package and calls ExpireAddresses directly, so no interface is needed and a
// one-implementation interface would be the speculative abstraction to refuse.
type Confirmed struct{ V4, V6 int64 }

// ExpireAddresses clears the due families and emits the resulting
// device.ip_changed, only when the write changed a row.
//
// All of it runs inside the mutex that orders every other membership event,
// because the write and its event must not be separable: a concurrent
// re-entry can otherwise emit its event at seq N and leave this one at N+1,
// so the database says absent while the stream's last word says present.
//
// The event is the EXISTING ip_changed, keyed on the appended ip_history row
// (D10). README.md:276 tells consumers to ignore any type they do not
// recognise, so a new device.address_expired would be dropped by every
// conforming consumer -- which would then keep the expired address, with no
// next poll to correct it for a webhook-only consumer.
func (f *fanout) ExpireAddresses(ctx context.Context, d store.Device, v4Due, v6Due bool, pin Confirmed) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := store.NowUnix()
	historyID, changed, err := f.st.Devices().ExpireFamilies(ctx, d.ID, v4Due, v6Due, pin.V4, pin.V6, now)
	if err != nil || !changed {
		return false, err
	}

	// The post-write shape, derived rather than re-read: exactly the families
	// we asked to clear are now empty.
	after := d
	if v4Due {
		after.CurrentIPv4 = ""
	}
	if v6Due {
		after.CurrentIPv6 = ""
	}

	if _, err := f.st.FeedState().Bump(ctx, now); err != nil {
		// ip_changed's id is the history row, not the seq, so a failed bump
		// only leaves Last-Modified stale: the event is still sent.
		f.log.LogAttrs(ctx, slog.LevelWarn, "feed state bump failed",
			slog.String("event_type", notify.EventIPChanged), slog.Any("error", err))
	}
	payload, err := notify.RenderIPChanged(store.IPChangeEvent{
		EventID:    historyID,
		OccurredAt: now,
		Device:     after,
		PrevIPv4:   d.CurrentIPv4, PrevIPv6: d.CurrentIPv6,
		CurrIPv4: after.CurrentIPv4, CurrIPv6: after.CurrentIPv6,
	})
	if err != nil {
		f.log.LogAttrs(ctx, slog.LevelWarn, "notify: render failed",
			slog.String("event_type", notify.EventIPChanged),
			slog.String("device_id", d.ID), slog.Any("error", err))
		return true, nil
	}
	f.dispatch(ctx, notify.EventIPChanged, historyID, payload)
	return true, nil
}

// dispatch writes the outbox rows (when the webhook is on) and broadcasts to
// the hub. Called with mu held.
func (f *fanout) dispatch(ctx context.Context, eventType string, eventID int64, payload []byte) {
	if f.enqueue != nil {
		f.enqueue.Enqueue(ctx, eventType, eventID, payload)
	}
	f.hub.Broadcast(payload)
}
