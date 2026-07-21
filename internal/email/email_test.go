package email_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

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

// startFakeServer accepts one connection on ln, hands it to serve, and
// reports the captured envelope on the returned channel. The single cleanup
// closes ln first (unblocking a pending Accept when no client ever connects,
// e.g. the canceled-context test) and only then waits for the serve
// goroutine — the reverse order would deadlock.
func startFakeServer(t *testing.T, ln net.Listener, serve func(net.Conn, chan<- fakeEnvelope)) (host string, port int, envelopes <-chan fakeEnvelope) {
	t.Helper()
	ch := make(chan fakeEnvelope, 1)
	var wg sync.WaitGroup
	wg.Go(func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		serve(conn, ch)
	})
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})

	addrPort, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parse listener addr: %v", err)
	}
	return addrPort.Addr().String(), int(addrPort.Port()), ch
}

// startFakeSMTP starts a minimal plaintext SMTP listener (no AUTH, no TLS).
func startFakeSMTP(t *testing.T) (host string, port int, envelopes <-chan fakeEnvelope) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return startFakeServer(t, ln, serveFakeSMTPConn)
}

// startFakeImplicitTLSSMTP starts an SMTP listener whose transport is TLS
// from the first byte (implicit TLS / SMTPS), using serverConf's cert.
func startFakeImplicitTLSSMTP(t *testing.T, serverConf *tls.Config) (host string, port int, envelopes <-chan fakeEnvelope) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return startFakeServer(t, tls.NewListener(ln, serverConf), serveFakeSMTPConn)
}

// startFakeStartTLSSMTP starts a plaintext SMTP listener that advertises
// STARTTLS and upgrades the connection in-band using serverConf's cert.
func startFakeStartTLSSMTP(t *testing.T, serverConf *tls.Config) (host string, port int, envelopes <-chan fakeEnvelope) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return startFakeServer(t, ln, func(conn net.Conn, ch chan<- fakeEnvelope) {
		serveStartTLSConn(conn, serverConf, ch)
	})
}

// serveFakeSMTPConn greets the client and serves one message. It advertises
// no AUTH extension, so an authenticated Send fails (exercising the
// error-logging path). Works over a plaintext or an already-TLS conn.
func serveFakeSMTPConn(conn net.Conn, envelopes chan<- fakeEnvelope) {
	tp := textproto.NewConn(conn)
	defer func() { _ = tp.Close() }()
	_ = tp.PrintfLine("220 fake.smtp.test ready")
	serveEnvelope(tp, envelopes)
}

// serveStartTLSConn drives the STARTTLS handshake, then serves the message
// over the upgraded TLS connection. net/smtp re-issues EHLO after the
// upgrade, which serveEnvelope handles.
func serveStartTLSConn(conn net.Conn, serverConf *tls.Config, envelopes chan<- fakeEnvelope) {
	tp := textproto.NewConn(conn)
	_ = tp.PrintfLine("220 fake.smtp.test ready")

	if _, err := tp.ReadLine(); err != nil { // first EHLO
		return
	}
	_ = tp.PrintfLine("250-fake.smtp.test")
	_ = tp.PrintfLine("250 STARTTLS")

	line, err := tp.ReadLine()
	if err != nil || strings.ToUpper(strings.TrimSpace(line)) != "STARTTLS" {
		return
	}
	_ = tp.PrintfLine("220 ready to start tls")

	tlsConn := tls.Server(conn, serverConf)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer func() { _ = tlsConn.Close() }()
	serveEnvelope(textproto.NewConn(tlsConn), envelopes)
}

// serveEnvelope reads the SMTP command exchange (EHLO, MAIL FROM, RCPT TO,
// DATA, QUIT) and reports the captured envelope on QUIT. It uses
// net/textproto for RFC 5321 dot-unstuffing of the DATA body. The greeting
// is the caller's responsibility (STARTTLS re-enters this loop after the
// upgrade, with no fresh greeting).
func serveEnvelope(tp *textproto.Conn, envelopes chan<- fakeEnvelope) {
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

// testTLSConfigs generates a self-signed cert (valid for 127.0.0.1) and
// returns a server config that presents it and a client config that trusts
// it via RootCAs — so the TLS handshake is genuinely verified in-test, not
// skipped.
func testTLSConfigs(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake.smtp.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	server = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		MinVersion:   tls.VersionTLS12,
	}
	client = &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	}
	return server, client
}

// assertEnvelope waits for the captured envelope and asserts the from/to/
// subject/body the mailer produced.
func assertEnvelope(t *testing.T, envelopes <-chan fakeEnvelope, from, to, subject, body string) {
	t.Helper()
	env := <-envelopes
	if !strings.Contains(env.from, from) {
		t.Errorf("envelope from = %q, want to contain %q", env.from, from)
	}
	if !strings.Contains(env.to, to) {
		t.Errorf("envelope to = %q, want to contain %q", env.to, to)
	}
	if !strings.Contains(env.data, "Subject: "+subject) {
		t.Errorf("envelope data missing subject %q, got: %q", subject, env.data)
	}
	if !strings.Contains(env.data, body) {
		t.Errorf("envelope data missing body %q, got: %q", body, env.data)
	}
}

func debugLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestSmtpMailer_Send_Success drives Send against the fake plaintext
// listener with TLS "none" and asserts the observed envelope.
func TestSmtpMailer_Send_Success(t *testing.T) {
	host, port, envelopes := startFakeSMTP(t)

	cfg := config.EmailSection{Enabled: true, Host: host, Port: port, From: "noreply@example.com", TLS: "none"}
	m := email.New(cfg, debugLogger())

	if !m.Enabled() {
		t.Fatal("Enabled() = false, want true for an enabled config")
	}
	if err := m.Send(t.Context(), "user@example.com", "your recovery link", "click here: https://example.com/r/abc"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	assertEnvelope(t, envelopes, "noreply@example.com", "user@example.com", "your recovery link", "click here: https://example.com/r/abc")
}

// TestSmtpMailer_Send_ImplicitTLS drives Send through the implicit-TLS
// (tls.Dial) branch against a fake SMTPS listener, verifying the server's
// self-signed cert via injected RootCAs, and asserts the envelope arrived
// over the TLS connection.
func TestSmtpMailer_Send_ImplicitTLS(t *testing.T) {
	serverConf, clientConf := testTLSConfigs(t)
	host, port, envelopes := startFakeImplicitTLSSMTP(t, serverConf)

	cfg := config.EmailSection{Enabled: true, Host: host, Port: port, From: "noreply@example.com", TLS: "implicit"}
	m := email.NewSMTPForTest(cfg, debugLogger(), clientConf)

	if err := m.Send(t.Context(), "user@example.com", "recovery", "link: https://example.com/r/tls"); err != nil {
		t.Fatalf("Send over implicit TLS: %v", err)
	}
	assertEnvelope(t, envelopes, "noreply@example.com", "user@example.com", "recovery", "link: https://example.com/r/tls")
}

// TestSmtpMailer_Send_StartTLS drives Send through the STARTTLS
// (smtp.Client.StartTLS) branch against a fake listener that advertises and
// performs the in-band upgrade, verifying the cert via injected RootCAs.
func TestSmtpMailer_Send_StartTLS(t *testing.T) {
	serverConf, clientConf := testTLSConfigs(t)
	host, port, envelopes := startFakeStartTLSSMTP(t, serverConf)

	cfg := config.EmailSection{Enabled: true, Host: host, Port: port, From: "noreply@example.com", TLS: "starttls"}
	m := email.NewSMTPForTest(cfg, debugLogger(), clientConf)

	if err := m.Send(t.Context(), "user@example.com", "recovery", "link: https://example.com/r/starttls"); err != nil {
		t.Fatalf("Send over STARTTLS: %v", err)
	}
	assertEnvelope(t, envelopes, "noreply@example.com", "user@example.com", "recovery", "link: https://example.com/r/starttls")
}

// TestSmtpMailer_Send_NeverLogsPassword drives an authenticated Send against
// the fake listener (which offers no AUTH, so the send fails and an error is
// logged) and asserts the configured SMTP password never appears in the
// captured log output.
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

	if err := m.Send(t.Context(), "user@example.com", "subject", "body"); err == nil {
		t.Fatal("expected Send to fail against a fake server with no AUTH support")
	}
	if strings.Contains(buf.String(), password) {
		t.Errorf("captured log output contains the SMTP password: %s", buf.String())
	}
}

// TestSmtpMailer_Send_RespectsCanceledContext points Send at a real fake
// listener but with an already-canceled context, and asserts the error is
// context.Canceled and that the server observed NO connection — proving the
// entry-guard fired rather than a dial error. Removing the ctx.Err() guard
// from Send fails this test (the send would complete and an envelope would
// arrive).
func TestSmtpMailer_Send_RespectsCanceledContext(t *testing.T) {
	host, port, envelopes := startFakeSMTP(t)

	cfg := config.EmailSection{Enabled: true, Host: host, Port: port, From: "noreply@example.com", TLS: "none"}
	m := email.New(cfg, debugLogger())

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := m.Send(ctx, "user@example.com", "subject", "body")
	if err == nil {
		t.Fatal("expected Send to fail with a canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want it to wrap context.Canceled", err)
	}
	select {
	case env := <-envelopes:
		t.Fatalf("guard did not fire: server observed an envelope %+v", env)
	default:
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
