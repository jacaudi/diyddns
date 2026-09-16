package stale

import "context"

// Delivery is one message to one recipient: a single notice for an owner, or
// the sweep's batched digest for an admin (D16).
type Delivery struct {
	Audience  Audience
	Recipient string
	Notices   []Notice
}

// Channel delivers a Delivery.
//
// smtpChannel is the ONLY implementation today, so this interface is not
// earned by two implementors. It ships because the maintainer required
// explicitly that apprise-go be a later drop-in rather than a rewrite (D15).
// That is a stated requirement, not a SOLID inference, and this code does not
// dress it up as one. Adding apprise is apprise.go plus one line in
// NewSMTPChannel's caller.
type Channel interface {
	Name() string
	Send(ctx context.Context, d Delivery) error
}

// Mailer is the mail seam this package needs, declared here at its consumer.
// Satisfied structurally by an email.Mailer value, so stale never imports
// internal/email; noopMailer's always-nil Send gives design §9's last row
// for free.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}
