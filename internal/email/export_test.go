package email

import (
	"crypto/tls"
	"log/slog"

	"github.com/jacaudi/diyddns/internal/config"
)

// NewSMTPForTest constructs an SMTP Mailer with an injected client TLS config,
// so tests can drive the implicit-TLS and STARTTLS branches against an
// in-process fake server using a self-signed cert. It lives in export_test.go
// (compiled only under test), keeping the injection seam out of the shipped
// production API.
func NewSMTPForTest(cfg config.EmailSection, log *slog.Logger, tlsConf *tls.Config) Mailer {
	return &smtpMailer{cfg: cfg, log: log, tlsConfig: tlsConf}
}
