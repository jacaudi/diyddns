package stale

import "context"

// mailChannel renders a Delivery into a subject and body and hands it to a
// Mailer. It adds nothing to a Notice: subject and body come from notice.go.
// The transport is the Mailer's business; this type never knew it and does
// not name it.
type mailChannel struct{ m Mailer }

// NewMailChannel is the one construction site for this Channel. A second
// channel type, if one ever exists, is chosen by the caller (buildSweeper in
// internal/server/server.go), not inside this constructor: its signature
// returns exactly one Channel.
func NewMailChannel(m Mailer) Channel { return mailChannel{m: m} }

func (c mailChannel) Send(ctx context.Context, d Delivery) error {
	if d.Audience == AudienceAdmin {
		return c.m.Send(ctx, d.Recipient, AdminDigestSubject(d.Notices), RenderAdminDigestBody(d.Notices))
	}
	// Exactly one Notice for an owner; the Dispatcher guarantees it.
	n := d.Notices[0]
	return c.m.Send(ctx, d.Recipient, OwnerSubject(n), RenderOwnerBody(n))
}
