package notify

import (
	"context"
	"log/slog"

	"github.com/jacaudi/diyddns/internal/store"
)

// Enqueuer implements service.Notifier by writing one outbox row per enabled
// endpoint owned by the device's user. It performs no network I/O.
type Enqueuer struct {
	st  *store.Store
	log *slog.Logger
}

// NewEnqueuer returns an Enqueuer writing to st, logging enqueue failures to
// log. It satisfies service.Notifier structurally, without importing service.
func NewEnqueuer(st *store.Store, log *slog.Logger) *Enqueuer {
	return &Enqueuer{st: st, log: log}
}

// IPChanged fans out at enqueue time: an endpoint disabled when the event
// occurred does not retroactively receive it if re-enabled later.
//
// Every failure here is logged and swallowed. IPChanged returns nothing
// because /agent/v1/checkin must succeed even when this cannot write — the
// cost, stated plainly, is that a failed enqueue loses that event permanently
// and the only trace is this log line.
func (e *Enqueuer) IPChanged(ctx context.Context, ev store.IPChangeEvent) {
	eps, err := e.st.NotificationEndpoints().ListEnabledByUser(ctx, ev.Device.UserID)
	if err != nil {
		e.log.LogAttrs(ctx, slog.LevelWarn, "notify: list endpoints failed",
			slog.String("device_id", ev.Device.ID), slog.Any("error", err))
		return
	}
	if len(eps) == 0 {
		return
	}
	payload, err := RenderIPChanged(ev)
	if err != nil {
		e.log.LogAttrs(ctx, slog.LevelWarn, "notify: render failed",
			slog.String("device_id", ev.Device.ID), slog.Any("error", err))
		return
	}
	now := store.NowUnix()
	for _, ep := range eps {
		if err := e.st.NotificationDeliveries().Enqueue(ctx, store.NotificationDelivery{
			EndpointID:    ep.ID,
			EventType:     EventIPChanged,
			EventID:       ev.EventID,
			Payload:       payload,
			NextAttemptAt: now,
			Status:        "pending",
			// UserInitiatedAt deliberately zero -> NULL: server-initiated
			// deliveries must not debit the user's attempt budget.
		}); err != nil {
			e.log.LogAttrs(ctx, slog.LevelWarn, "notify: enqueue failed",
				slog.String("endpoint_id", ep.ID), slog.Int64("event_id", ev.EventID),
				slog.Any("error", err))
		}
	}
}
