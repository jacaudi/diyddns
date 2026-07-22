package email

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
)

// NewSMTPForTest constructs an SMTP Mailer with an injected client TLS config,
// so tests can drive the implicit-TLS and STARTTLS branches against an
// in-process fake server using a self-signed cert. It lives in export_test.go
// (compiled only under test), keeping the injection seam out of the shipped
// production API. dialTimeout is set to the production default so these
// tests exercise the real bound (met trivially against a local fake server).
func NewSMTPForTest(cfg config.EmailSection, log *slog.Logger, tlsConf *tls.Config) Mailer {
	return &smtpMailer{cfg: cfg, log: log, tlsConfig: tlsConf, dialTimeout: defaultDialTimeout}
}

// NewSMTPForTestWithDial constructs an SMTP Mailer with an injected dial
// timeout and connect function, so tests can prove dial's per-connection
// deadline is actually enforced (e.g. against a fake dialFunc that blocks
// until its context is done) without real network I/O or waiting out the
// production 10s default.
func NewSMTPForTestWithDial(cfg config.EmailSection, log *slog.Logger, dialTimeout time.Duration, dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)) Mailer {
	return &smtpMailer{cfg: cfg, log: log, dialTimeout: dialTimeout, dialFunc: dialFunc}
}
