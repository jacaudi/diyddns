package stale

import (
	"context"
	"log/slog"

	"github.com/jacaudi/diyddns/internal/store"
)

// AdminLister yields the users who should receive the digest. Declared here
// rather than taking a *store.Store so this package stays testable without a
// database.
type AdminLister func(ctx context.Context) ([]store.User, error)

// Dispatcher turns notices into deliveries. It owns the owner/admin split so
// the sweeper does not.
type Dispatcher struct {
	ch     Channel
	admins AdminLister
	log    *slog.Logger
}

// NewDispatcher builds a Dispatcher that delivers over ch, resolving the
// admin digest recipients via admins.
func NewDispatcher(ch Channel, admins AdminLister, log *slog.Logger) *Dispatcher {
	return &Dispatcher{ch: ch, admins: admins, log: log}
}

// SendOwner delivers one notice to one owner, inline during the sweep.
//
// Errors are logged, never returned: the sweep has already written the state,
// and the durable record of an impending removal is the device list, not the
// email (§7.3).
func (d *Dispatcher) SendOwner(ctx context.Context, n Notice) {
	if n.Owner.Email == "" {
		return
	}
	if err := d.ch.Send(ctx, Delivery{
		Audience: AudienceOwner, Recipient: n.Owner.Email, Notices: []Notice{n},
	}); err != nil {
		d.log.LogAttrs(ctx, slog.LevelWarn, "staleness notice: owner delivery failed",
			slog.String("device_id", n.Device.ID), slog.Any("error", err))
	}
}

// SendAdminDigest delivers ONE digest per admin at the end of a sweep tick
// (D16). An empty digest sends nothing: an hourly "nothing happened" mail is
// how a feature gets filtered into a folder nobody reads.
//
// A cancelled context mid-tick therefore loses the whole digest while the
// owners processed so far were already told. Consistent with at-most-once and
// with the device list being the durable record, but the admin view can miss a
// tick the owners saw (§8.3).
func (d *Dispatcher) SendAdminDigest(ctx context.Context, ns []Notice) {
	if len(ns) == 0 {
		return
	}
	admins, err := d.admins(ctx)
	if err != nil {
		d.log.LogAttrs(ctx, slog.LevelWarn, "staleness digest: admin lookup failed", slog.Any("error", err))
		return
	}
	for _, a := range admins {
		if err := d.ch.Send(ctx, Delivery{
			Audience: AudienceAdmin, Recipient: a.Email, Notices: ns,
		}); err != nil {
			d.log.LogAttrs(ctx, slog.LevelWarn, "staleness digest: delivery failed",
				slog.String("user_id", a.ID), slog.Any("error", err))
		}
	}
}
