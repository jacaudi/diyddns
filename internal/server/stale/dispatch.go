package stale

import (
	"context"
	"log/slog"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

// deliveryTimeout bounds the whole SMTP conversation for ONE delivery made
// during a sweep tick -- one owner notice, or one admin's copy of the digest.
//
// Without it, the context reaching email.smtpMailer.Send is the bare ctx
// runPruner passes all the way down from Server.Run, which carries no
// deadline until the process starts shutting down -- so smtpMailer.dial's
// conn.SetDeadline call (internal/email/smtp.go) never fires, and a peer that
// accepts the connection and then stalls hangs indefinitely. runPruner runs
// prune() and sw.Run() in ONE goroutine, ONE loop (internal/server/pruner.go),
// so a wedged Send there never returns control to the loop that would
// otherwise start the next hourly tick -- every later prune() (sessions,
// replay nonces, enrollment codes, OIDC flows, retention) starves with it, for
// the life of the process.
//
// Value matches service.adminDeliveryTimeout (internal/server/service/
// grants.go): both bound the same SMTP conversation shape (dial + STARTTLS +
// AUTH + envelope) against the same email.defaultDialTimeout (10s connect
// floor). Unlike adminDeliveryTimeout, it is NOT bounded above by
// server.shutdownTimeout -- that coupling exists because an admin's send runs
// on an HTTP handler's own request budget; this sweep is a detached
// background goroutine with no request budget and no join at shutdown, so
// there is no comparable upper bound to respect.
//
// A package constant, not a Dispatcher field: GrantService.deliveryTimeout
// (grants.go) is a field so a test can shrink it and prove the audit-write
// path on an already-expired context. Nothing here needs that -- the only
// present requirement is that Mailer.Send always receive a deadline, which
// TestDispatcher_SendOwner_BoundsTheDeliveryContext and
// TestDispatcher_SendAdminDigest_BoundsTheDeliveryContext assert directly --
// so a field would be an unearned seam for a consumer that does not exist yet.
const deliveryTimeout = 12 * time.Second

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
//
// The context deliberately drops cancellation (context.WithoutCancel) while
// keeping values, mirroring GrantService.deliver (service/grants.go): ctx is
// runPruner's own long-lived context, canceled only at server shutdown, and a
// shutdown landing mid-send should let the in-flight SMTP conversation finish
// rather than abort it mid-envelope. deliveryTimeout is re-applied on top so
// the detached send stays bounded regardless (see its doc comment for why an
// unbounded one is the actual defect being fixed here).
func (d *Dispatcher) SendOwner(ctx context.Context, n Notice) {
	if n.Owner.Email == "" {
		return
	}
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deliveryTimeout)
	defer cancel()
	if err := d.ch.Send(sendCtx, Delivery{
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
//
// Each admin's send gets its OWN bounded, cancellation-stripped context (see
// SendOwner's doc comment for why WithoutCancel), applied and released inside
// the loop rather than once for the whole digest: one wedged admin mailbox
// must cost at most deliveryTimeout, not stall (or, with a shared deadline,
// silently starve) every admin after it in the list.
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
		sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deliveryTimeout)
		err := d.ch.Send(sendCtx, Delivery{
			Audience: AudienceAdmin, Recipient: a.Email, Notices: ns,
		})
		cancel()
		if err != nil {
			d.log.LogAttrs(ctx, slog.LevelWarn, "staleness digest: delivery failed",
				slog.String("user_id", a.ID), slog.Any("error", err))
		}
	}
}
