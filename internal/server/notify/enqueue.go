package notify

import (
	"context"
	"log/slog"

	"github.com/jacaudi/diyddns/internal/store"
)

// Enqueuer writes one outbox row per enabled endpoint, server-wide (#106:
// endpoints are admin-managed and global). It performs no network I/O.
type Enqueuer struct {
	st  *store.Store
	log *slog.Logger
}

// NewEnqueuer returns an Enqueuer writing to st, logging enqueue failures to
// log. It satisfies service.Notifier structurally, without importing service.
func NewEnqueuer(st *store.Store, log *slog.Logger) *Enqueuer {
	return &Enqueuer{st: st, log: log}
}

// Enqueue fans an already-rendered payload out at enqueue time: an endpoint
// disabled when the event occurred does not retroactively receive it if
// re-enabled later.
//
// Every failure here is logged and swallowed. Enqueue returns nothing because
// its callers (the check-in path, the admin device/user paths) must succeed
// even when this cannot write — the cost, stated plainly, is that a failed
// enqueue loses that event for the webhook transport and the only trace is
// this log line (design #106 §7.3, D20).
func (e *Enqueuer) Enqueue(ctx context.Context, eventType string, eventID int64, payload []byte) {
	eps, err := e.st.NotificationEndpoints().ListEnabled(ctx)
	if err != nil {
		e.log.LogAttrs(ctx, slog.LevelWarn, "notify: list endpoints failed",
			slog.String("event_type", eventType), slog.Int64("event_id", eventID), slog.Any("error", err))
		return
	}
	now := store.NowUnix()
	for _, ep := range eps {
		if err := e.st.NotificationDeliveries().Enqueue(ctx, store.NotificationDelivery{
			EndpointID:    ep.ID,
			EventType:     eventType,
			EventID:       eventID,
			Payload:       payload,
			NextAttemptAt: now,
			Status:        store.DeliveryPending,
		}); err != nil {
			e.log.LogAttrs(ctx, slog.LevelWarn, "notify: enqueue failed",
				slog.String("endpoint_id", ep.ID), slog.String("event_type", eventType),
				slog.Int64("event_id", eventID), slog.Any("error", err))
		}
	}
}

// IPChanged renders a device.ip_changed event and fans it out. It keeps the
// Enqueuer usable on its own as a service.Notifier; the server's fan-out
// (internal/server/fanout.go) renders once itself and calls Enqueue directly.
func (e *Enqueuer) IPChanged(ctx context.Context, ev store.IPChangeEvent) {
	payload, err := RenderIPChanged(ev)
	if err != nil {
		e.log.LogAttrs(ctx, slog.LevelWarn, "notify: render failed",
			slog.String("device_id", ev.Device.ID), slog.Any("error", err))
		return
	}
	e.Enqueue(ctx, EventIPChanged, ev.EventID, payload)
}
