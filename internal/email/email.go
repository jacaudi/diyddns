// Package email sends outbound account email (passkey recovery links, admin
// notifications, staleness notices) over SMTP, through the mailto service of
// github.com/unraid/apprise-go. It is disabled by default: New returns a no-op
// Mailer unless Config.Enabled is set, so callers can invoke
// Send unconditionally and use Enabled() to gate email-dependent flows (e.g.
// self-service passkey recovery) that require a working transport.
package email

import (
	"context"
	"log/slog"
)

// Config holds SMTP settings for outbound account email (e.g. passkey
// recovery notices); it is the server config's email section
// (config.EmailSection is an alias). Enabled gates whether the email
// subsystem is active. The settings are rendered into an Apprise mailto URL
// per send; config.validateEmail's rules that go beyond "is it set" mirror
// that transport's own behaviour (paired credentials, no edge whitespace,
// the From rule SplitFrom applies). It lives here, not in internal/config,
// so config can import this package's From rule instead of copying it.
type Config struct {
	Enabled  bool
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLS      string // "starttls", "implicit", or "none" — see config.validateEmail
}

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
// cfg.Host/Port/TLS through the apprise mailto service (see appriseMailer).
func New(cfg Config, log *slog.Logger) Mailer {
	if !cfg.Enabled {
		return &noopMailer{log: log}
	}
	return newAppriseMailer(cfg, log)
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
