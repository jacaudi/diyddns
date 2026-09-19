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
// mailChannel is the only production implementation. The interface is earned
// by the two test doubles that stand in for delivery (fakeChannel in
// dispatch_test.go, recordingChannel in internal/server/sweep_test.go), not
// by a second transport: #127's D15 shipped this seam so that an apprise
// library could be a drop-in, and #129 then adopted that library BELOW the
// Mailer instead (internal/email), which left this seam exactly as it was.
// A Name method once lived here for log lines that were never written; with
// one implementation there is nothing to distinguish, so it is gone.
type Channel interface {
	Send(ctx context.Context, d Delivery) error
}

// Mailer is the mail seam this package needs, declared here at its consumer.
// Satisfied structurally by an email.Mailer value, so stale never imports
// internal/email; noopMailer's always-nil Send gives design §9's last row
// for free.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}
