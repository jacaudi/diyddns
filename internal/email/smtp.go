package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
)

// defaultDialTimeout bounds how long dial waits for the underlying TCP
// connect (and, for implicit TLS, the handshake) to complete before giving
// up. Without this, a hung/unreachable SMTP host could block the caller
// (RequestSelfServiceRecovery's background goroutine, see grants.go)
// indefinitely — the goroutine's own 30s context.WithTimeout is the outer
// bound, but a per-connection floor keeps one slow host from eating the
// whole budget before Send even gets a chance to retry or fail cleanly.
const defaultDialTimeout = 10 * time.Second

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
	// dialTimeout bounds the connect step in dial (see defaultDialTimeout).
	// Production always sets it via New(); tests can inject a shorter value
	// via export_test.go's NewSMTPForTestWithDial to prove the bound is
	// enforced without waiting out a real timeout.
	dialTimeout time.Duration
	// dialFunc, when non-nil, replaces the connect step dial otherwise
	// performs with (&net.Dialer{}).DialContext — an injection seam (like
	// tlsConfig above) so tests can simulate a hung host deterministically,
	// without real network I/O. Production never sets it.
	dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)
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
	c, err := m.dial(ctx, addr)
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

// dial establishes the transport-level connection, bounded by dialTimeout,
// and wraps it in an *smtp.Client, per cfg.TLS. Implicit TLS completes the
// TLS handshake as part of the same bounded window; starttls and none both
// connect plaintext (starttls upgrades the connection later, in
// sendEnvelope, once the client has confirmed the server offers it).
func (m *smtpMailer) dial(ctx context.Context, addr string) (*smtp.Client, error) {
	dialCtx, cancel := context.WithTimeout(ctx, m.dialTimeout)
	defer cancel()

	connect := m.dialFunc
	if connect == nil {
		connect = (&net.Dialer{}).DialContext
	}
	conn, err := connect(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("email: dial %s: %w", addr, err)
	}

	if m.cfg.TLS == "implicit" {
		tlsConn := tls.Client(conn, m.clientTLSConfig())
		if err := tlsConn.HandshakeContext(dialCtx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("email: dial %s over tls: %w", addr, err)
		}
		conn = tlsConn
	}

	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("email: create smtp client for %s: %w", addr, err)
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
