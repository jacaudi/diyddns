// Package agenthttp holds the HTTP plumbing the client's enroll and checkin
// clients share: the transport that optionally trusts an operator CA bundle,
// and the bounded response-body drain.
package agenthttp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
)

// NewTransport clones http.DefaultTransport. When caCertPath is set it trusts
// that PEM bundle instead of the system pool, at TLS 1.2 or later. Errors
// carry no package prefix; callers add their own.
func NewTransport(caCertPath string) (*http.Transport, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caCertPath == "" {
		return transport, nil
	}
	pem, err := os.ReadFile(caCertPath) //nolint:gosec // G304: operator-provided CA bundle path (--ca-cert), not request input
	if err != nil {
		return nil, fmt.Errorf("read ca cert %s: %w", caCertPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", caCertPath)
	}
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return transport, nil
}

// DrainClose discards up to 64 KiB of rc so the connection can be reused,
// then closes it. The bound keeps a hostile endless body from pinning the
// caller.
func DrainClose(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, 1<<16))
	_ = rc.Close()
}
