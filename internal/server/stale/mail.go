package stale

import (
	"context"

	"github.com/jacaudi/diyddns/internal/email"
)

// mailChannel renders a Delivery into a subject and body and hands it to a
// Mailer. Subject and body come from notice.go, which is medium-neutral; the
// one thing this channel adds is the fold below, a concession to the mail
// transport. The transport itself is the Mailer's business; this type never
// knew it and does not name it.
type mailChannel struct{ m Mailer }

// NewMailChannel is the one construction site for this Channel. A second
// channel type, if one ever exists, is chosen by the caller (buildSweeper in
// internal/server/server.go), not inside this constructor: its signature
// returns exactly one Channel.
func NewMailChannel(m Mailer) Channel { return mailChannel{m: m} }

// Send renders d for mail. Labels and addresses are user-controlled and
// free-form, and the admin digest is ONE body for every admin, so one value the
// transport refuses would suppress the digest to all of them (#184). They are
// folded here, at the mail channel, because ASCIIFold is a concession to this
// transport; notice.go stays medium-neutral.
func (c mailChannel) Send(ctx context.Context, d Delivery) error {
	ns := foldForMail(d.Notices)
	if d.Audience == AudienceAdmin {
		return c.m.Send(ctx, d.Recipient, AdminDigestSubject(ns), RenderAdminDigestBody(ns))
	}
	// Exactly one Notice for an owner; the Dispatcher guarantees it.
	n := ns[0]
	return c.m.Send(ctx, d.Recipient, OwnerSubject(n), RenderOwnerBody(n))
}

// foldForMail returns a copy of ns with every user-controlled string folded to
// what the mail transport carries (email.ASCIIFold). The caller's slice is not
// modified: the Dispatcher sends one []Notice to every admin.
func foldForMail(ns []Notice) []Notice {
	out := make([]Notice, len(ns))
	for i, n := range ns {
		n.Device.Label = email.ASCIIFold(n.Device.Label)
		n.Owner.Email = email.ASCIIFold(n.Owner.Email)
		out[i] = n
	}
	return out
}
