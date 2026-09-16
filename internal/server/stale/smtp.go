package stale

import "context"

// smtpChannel is the only Channel implementation (D15). It adds nothing to a
// Notice: subject and body come from notice.go, so an apprise channel later
// renders the same content for a different medium.
type smtpChannel struct{ m Mailer }

// NewSMTPChannel is the one construction site for this Channel. Adding
// apprise is apprise.go plus one line in NewSMTPChannel's caller -- not here:
// NewSMTPChannel's signature returns exactly one Channel, so a second
// channel type is chosen by the caller, not inside this constructor.
func NewSMTPChannel(m Mailer) Channel { return smtpChannel{m: m} }

func (smtpChannel) Name() string { return "smtp" }

func (c smtpChannel) Send(ctx context.Context, d Delivery) error {
	if d.Audience == AudienceAdmin {
		return c.m.Send(ctx, d.Recipient, AdminDigestSubject(d.Notices), RenderAdminDigestBody(d.Notices))
	}
	// Exactly one Notice for an owner; the Dispatcher guarantees it.
	n := d.Notices[0]
	return c.m.Send(ctx, d.Recipient, OwnerSubject(n), RenderOwnerBody(n))
}
