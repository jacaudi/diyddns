package agenthttp

import (
	"crypto/tls"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewTransport_NoCAUsesTheSystemPool(t *testing.T) {
	tr, err := NewTransport("")
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	if tr.TLSClientConfig != nil && tr.TLSClientConfig.RootCAs != nil {
		t.Error("RootCAs is set, want nil (system roots)")
	}
	if tr == http.DefaultTransport {
		t.Error("NewTransport returned http.DefaultTransport itself, want a clone")
	}
}

// A CA bundle replaces the system pool, and the resulting transport really
// trusts a server whose certificate that bundle holds.
func TestNewTransport_TrustsTheCABundle(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	path := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	tr, err := NewTransport(path)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLSClientConfig = %+v, want RootCAs and MinVersion TLS 1.2", tr.TLSClientConfig)
	}
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL) //nolint:bodyclose // closed by DrainClose below
	if err != nil {
		t.Fatalf("GET through the CA-bundle transport: %v", err)
	}
	DrainClose(resp.Body)
}

func TestNewTransport_BadCABundle(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ name, path, want string }{
		{"missing file", filepath.Join(dir, "missing.pem"), "read ca cert"},
		{"no certificates", notPEM, "no certificates in"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewTransport(tt.path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("NewTransport(%s) = %v, want an error containing %q", tt.path, err, tt.want)
			}
		})
	}
}

type countingBody struct {
	io.Reader
	closed bool
}

func (b *countingBody) Close() error { b.closed = true; return nil }

// DrainClose reads at most 64 KiB, so a hostile endless body cannot pin the
// caller, and always closes.
func TestDrainClose_BoundedReadThenClose(t *testing.T) {
	r := strings.NewReader(strings.Repeat("x", 1<<17))
	body := &countingBody{Reader: r}
	DrainClose(body)
	if !body.closed {
		t.Error("DrainClose did not close the body")
	}
	if got := r.Len(); got != 1<<17-1<<16 {
		t.Errorf("unread bytes = %d, want %d (a 64 KiB drain)", got, 1<<17-1<<16)
	}
}
