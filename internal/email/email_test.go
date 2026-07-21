package email_test

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"net/textproto"
	"strings"
	"sync"
	"testing"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/email"
)

// TestNew_Disabled asserts that New returns a no-op Mailer when
// cfg.Enabled is false: Send never contacts a server and always succeeds,
// and Enabled() reports false so callers can gate email-dependent flows.
func TestNew_Disabled(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	m := email.New(config.EmailSection{Enabled: false}, log)

	if m.Enabled() {
		t.Error("Enabled() = true, want false for a disabled config")
	}
	if err := m.Send(t.Context(), "user@example.com", "subject", "body"); err != nil {
		t.Fatalf("Send on disabled mailer returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "email.send skipped (disabled)") {
		t.Errorf("expected debug log for skipped send, got: %s", buf.String())
	}
}

// fakeEnvelope captures what the fake SMTP server observed for one message.
type fakeEnvelope struct {
	from, to, data string
}

// startFakeSMTP starts a minimal plaintext SMTP listener that accepts one
// connection, replies affirmatively to EHLO/MAIL FROM/RCPT TO/DATA/QUIT, and
// reports the captured envelope on the returned channel. It does not
// implement AUTH, so a Send() that attempts AUTH against it fails — used to
// exercise the error-logging path.
func startFakeSMTP(t *testing.T) (host string, port int, envelopes <-chan fakeEnvelope) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ch := make(chan fakeEnvelope, 1)
	var wg sync.WaitGroup
	wg.Go(func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		serveFakeSMTPConn(conn, ch)
	})
	t.Cleanup(wg.Wait)

	addrPort, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parse listener addr: %v", err)
	}
	return addrPort.Addr().String(), int(addrPort.Port()), ch
}

// serveFakeSMTPConn implements just enough of RFC 5321 for net/smtp's client
// to complete a send: greeting, EHLO, MAIL FROM, RCPT TO, DATA, QUIT. It
// deliberately advertises no AUTH extension, so an authenticated Send fails.
// Uses net/textproto for line I/O and RFC 5321 dot-unstuffing (DATA), rather
// than hand-rolling the ".\r\n" terminator scan.
func serveFakeSMTPConn(conn net.Conn, envelopes chan<- fakeEnvelope) {
	tp := textproto.NewConn(conn)
	defer func() { _ = tp.Close() }()
	_ = tp.PrintfLine("220 fake.smtp.test ready")

	var env fakeEnvelope
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			_ = tp.PrintfLine("250 fake.smtp.test")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			env.from = line[len("MAIL FROM:"):]
			_ = tp.PrintfLine("250 ok")
		case strings.HasPrefix(upper, "RCPT TO:"):
			env.to = line[len("RCPT TO:"):]
			_ = tp.PrintfLine("250 ok")
		case upper == "DATA":
			_ = tp.PrintfLine("354 go ahead")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			env.data = string(data)
			_ = tp.PrintfLine("250 queued")
		case upper == "QUIT":
			_ = tp.PrintfLine("221 bye")
			envelopes <- env
			return
		default:
			_ = tp.PrintfLine("250 ok")
		}
	}
}

// TestSmtpMailer_Send_Success drives smtpMailer.Send against the fake
// listener with TLS "none" and asserts the fake server observed the
// expected envelope (from/to/subject/body).
func TestSmtpMailer_Send_Success(t *testing.T) {
	host, port, envelopes := startFakeSMTP(t)

	cfg := config.EmailSection{
		Enabled: true,
		Host:    host,
		Port:    port,
		From:    "noreply@example.com",
		TLS:     "none",
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m := email.New(cfg, log)

	if !m.Enabled() {
		t.Fatal("Enabled() = false, want true for an enabled config")
	}
	if err := m.Send(t.Context(), "user@example.com", "your recovery link", "click here: https://example.com/r/abc"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	env := <-envelopes
	if !strings.Contains(env.from, "noreply@example.com") {
		t.Errorf("envelope from = %q, want to contain noreply@example.com", env.from)
	}
	if !strings.Contains(env.to, "user@example.com") {
		t.Errorf("envelope to = %q, want to contain user@example.com", env.to)
	}
	if !strings.Contains(env.data, "Subject: your recovery link") {
		t.Errorf("envelope data missing subject, got: %q", env.data)
	}
	if !strings.Contains(env.data, "click here: https://example.com/r/abc") {
		t.Errorf("envelope data missing body, got: %q", env.data)
	}
}

// TestSmtpMailer_Send_NeverLogsPassword drives an authenticated Send against
// the fake listener (which doesn't support AUTH, so the send fails and an
// error is logged) and asserts the configured SMTP password never appears
// anywhere in the captured log output.
func TestSmtpMailer_Send_NeverLogsPassword(t *testing.T) {
	host, port, _ := startFakeSMTP(t)

	const password = "s3cret-password-do-not-log"
	cfg := config.EmailSection{
		Enabled:  true,
		Host:     host,
		Port:     port,
		Username: "svc-account",
		Password: password,
		From:     "noreply@example.com",
		TLS:      "none",
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m := email.New(cfg, log)

	err := m.Send(t.Context(), "user@example.com", "subject", "body")
	if err == nil {
		t.Fatal("expected Send to fail against a fake server with no AUTH support")
	}
	if strings.Contains(buf.String(), password) {
		t.Errorf("captured log output contains the SMTP password: %s", buf.String())
	}
}

// TestSmtpMailer_Send_RespectsCanceledContext asserts Send fails fast
// without dialing when the context is already canceled.
func TestSmtpMailer_Send_RespectsCanceledContext(t *testing.T) {
	cfg := config.EmailSection{Enabled: true, Host: "127.0.0.1", Port: 1, From: "noreply@example.com", TLS: "none"}
	log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	m := email.New(cfg, log)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := m.Send(ctx, "user@example.com", "subject", "body"); err == nil {
		t.Fatal("expected Send to fail with a canceled context")
	}
}

func TestRecoveryLinkBody_ContainsLink(t *testing.T) {
	const link = "https://ddns.example.com/recover/abc123"
	subject, body := email.RecoveryLinkBody(link)
	if subject == "" {
		t.Error("subject is empty")
	}
	if !strings.Contains(body, link) {
		t.Errorf("body = %q, want to contain link %q", body, link)
	}
}

func TestAdminNotifyBody_ContainsEmail(t *testing.T) {
	const userEmail = "someone@example.com"
	subject, body := email.AdminNotifyBody(userEmail)
	if subject == "" {
		t.Error("subject is empty")
	}
	if !strings.Contains(body, userEmail) {
		t.Errorf("body = %q, want to contain email %q", body, userEmail)
	}
}
