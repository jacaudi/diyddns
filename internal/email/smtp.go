package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/smtp"

	"github.com/jacaudi/diyddns/internal/config"
)

// smtpMailer sends email over SMTP using net/smtp, honoring cfg.TLS:
//   - "implicit" dials directly over TLS (SMTPS, typically port 465).
//   - "starttls" dials plaintext, then upgrades via the SMTP STARTTLS
//     extension (typically port 587).
//   - "none" sends entirely in plaintext.
//
// config.validateEmail rejects any other cfg.TLS value at startup, so Send
// treats an unrecognized value the same as "none" rather than failing at
// send time — a defensive fallback, not a documented API.
type smtpMailer struct {
	cfg config.EmailSection
	log *slog.Logger
	// tlsConfig, when non-nil, overrides the client TLS config used for the
	// implicit-TLS dial and the STARTTLS upgrade. Production never sets it
	// (clientTLSConfig falls back to a default derived from cfg.Host); it is
	// an injection seam so tests can trust a self-signed cert. See
	// export_test.go's NewSMTPForTest.
	tlsConfig *tls.Config
}

func (m *smtpMailer) Enabled() bool { return true }

// clientTLSConfig returns the TLS config for outbound connections: the
// injected tlsConfig if present, else a default that verifies the server
// against cfg.Host with a TLS 1.2 floor.
func (m *smtpMailer) clientTLSConfig() *tls.Config {
	if m.tlsConfig != nil {
		return m.tlsConfig
	}
	return &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}
}

// Send connects to the configured SMTP server and delivers one message. The
// SMTP password (cfg.Password) is never included in a log attribute — only
// host/to/error are logged, so credential leakage via logs cannot happen
// through this code path.
func (m *smtpMailer) Send(ctx context.Context, to, subject, body string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("email: context canceled before send: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	c, err := m.dial(addr)
	if err != nil {
		m.log.ErrorContext(ctx, "email.send failed", "host", m.cfg.Host, "to", to, "error", err)
		return err
	}
	defer func() { _ = c.Close() }()

	if err := m.sendEnvelope(c, to, subject, body); err != nil {
		m.log.ErrorContext(ctx, "email.send failed", "host", m.cfg.Host, "to", to, "error", err)
		return err
	}

	m.log.DebugContext(ctx, "email.send ok", "host", m.cfg.Host, "to", to)
	return nil
}

// dial establishes the transport-level connection and wraps it in an
// *smtp.Client, per cfg.TLS. Implicit TLS dials directly over TLS; starttls
// and none both dial plaintext (starttls upgrades the connection later, in
// sendEnvelope, once the client has confirmed the server offers it).
func (m *smtpMailer) dial(addr string) (*smtp.Client, error) {
	if m.cfg.TLS == "implicit" {
		conn, err := tls.Dial("tcp", addr, m.clientTLSConfig())
		if err != nil {
			return nil, fmt.Errorf("email: dial %s over tls: %w", addr, err)
		}
		c, err := smtp.NewClient(conn, m.cfg.Host)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("email: create smtp client for %s: %w", addr, err)
		}
		return c, nil
	}

	c, err := smtp.Dial(addr)
	if err != nil {
		return nil, fmt.Errorf("email: dial %s: %w", addr, err)
	}
	return c, nil
}

// sendEnvelope drives the SMTP conversation once dial has returned a client:
// optional STARTTLS upgrade, optional AUTH, MAIL FROM/RCPT TO/DATA, QUIT.
func (m *smtpMailer) sendEnvelope(c *smtp.Client, to, subject, body string) error {
	if m.cfg.TLS == "starttls" {
		if err := c.StartTLS(m.clientTLSConfig()); err != nil {
			return fmt.Errorf("email: starttls: %w", err)
		}
	}

	if m.cfg.Username != "" {
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("email: authenticate: %w", err)
		}
	}

	if err := c.Mail(m.cfg.From); err != nil {
		return fmt.Errorf("email: mail from: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("email: rcpt to: %w", err)
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("email: open data writer: %w", err)
	}
	if _, err := w.Write(buildMessage(m.cfg.From, to, subject, body)); err != nil {
		_ = w.Close()
		return fmt.Errorf("email: write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("email: close data writer: %w", err)
	}

	if err := c.Quit(); err != nil {
		return fmt.Errorf("email: quit: %w", err)
	}
	return nil
}

// buildMessage renders a minimal RFC 5322 plaintext message.
func buildMessage(from, to, subject, body string) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", to)
	fmt.Fprintf(&buf, "Subject: %s\r\n", subject)
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(body)
	buf.WriteString("\r\n")
	return buf.Bytes()
}
