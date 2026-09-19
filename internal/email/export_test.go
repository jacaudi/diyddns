package email

import (
	"log/slog"

	"github.com/jacaudi/diyddns/internal/config"
)

// NewMailerForTest constructs the apprise-backed Mailer with the two seams
// the transport tests need and production never sets: a smaller in-flight
// cap, so saturation is reachable with one stalled send instead of thirty-two,
// and a send function, so a test can stall, panic or fail a send without any
// network I/O. It lives in export_test.go (compiled only under test), keeping
// the seams out of the shipped API. A nil send keeps the production send.
func NewMailerForTest(cfg config.EmailSection, log *slog.Logger, inFlight int, send func(rawURL, subject, body string) error) Mailer {
	if inFlight < 1 {
		// An unbuffered slots channel refuses every send, silently -- the
		// trap appriseMailer's type comment warns about.
		panic("NewMailerForTest: inFlight must be at least 1")
	}
	m := newAppriseMailer(cfg, log)
	m.slots = make(chan struct{}, inFlight)
	if send != nil {
		m.send = send
	}
	return m
}

// TargetURLForTest exposes the rendered mailto URL so a test can assert its
// shape without a network round-trip.
func TargetURLForTest(cfg config.EmailSection, to string) string {
	return newAppriseMailer(cfg, slog.New(slog.DiscardHandler)).targetURL(to)
}
