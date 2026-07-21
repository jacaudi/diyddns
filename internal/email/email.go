// Package email sends outbound account email (passkey recovery links, admin
// notifications) over SMTP. It is disabled by default: New returns a no-op
// Mailer unless config.EmailSection.Enabled is set, so callers can invoke
// Send unconditionally and use Enabled() to gate email-dependent flows (e.g.
// self-service passkey recovery) that require a working transport.
package email

import (
	"context"
	"log/slog"

	"github.com/jacaudi/diyddns/internal/config"
)

// Mailer sends a single email. Enabled reports whether the underlying
// transport is configured; a disabled Mailer's Send always succeeds without
// contacting a server, so Enabled() is how callers detect that email-gated
// features (e.g. self-service recovery) are unavailable.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
	Enabled() bool
}

// New returns a Mailer for cfg. When cfg.Enabled is false, New returns a
// no-op Mailer; otherwise it returns a Mailer that sends over SMTP per
// cfg.Host/Port/TLS.
func New(cfg config.EmailSection, log *slog.Logger) Mailer {
	if !cfg.Enabled {
		return &noopMailer{log: log}
	}
	return &smtpMailer{cfg: cfg, log: log}
}

// noopMailer is returned when the email subsystem is disabled. Send never
// contacts a server and always succeeds, so callers do not need to branch on
// Enabled() before calling Send.
type noopMailer struct {
	log *slog.Logger
}

func (m *noopMailer) Send(ctx context.Context, to, subject, _ string) error {
	m.log.DebugContext(ctx, "email.send skipped (disabled)", "to", to, "subject", subject)
	return nil
}

func (m *noopMailer) Enabled() bool { return false }
