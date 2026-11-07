// Package mtls holds the client's agent-port mTLS state: the single
// mtls.json file (device key, device cert, pinned CA bundle, agent URL) and
// the key/CSR generation that feeds it. Everything here is stdlib-only and
// must never import internal/server/ (guarded by cmd/diyddns-client's deps
// test).
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// FileName is the state file's name, next to credentials.json.
const FileName = "mtls.json"

// ErrNotFound means there is no usable mTLS state: the file is absent, or it
// was ignored and deleted (wrong device, corrupt, unparseable cert).
var ErrNotFound = errors.New("mtls: no usable state")

// State is the on-disk mtls.json. It is one file so a single rename swaps the
// whole state: a crash leaves the old state or the new, never a mix.
// KeyPEM is secret; State is never logged.
type State struct {
	// DeviceID is the device this state belongs to; Load ignores the file
	// for any other device.
	DeviceID    string `json:"device_id"`
	KeyPEM      string `json:"key_pem"`
	CertPEM     string `json:"cert_pem"`
	CABundlePEM string `json:"ca_bundle_pem"`
	AgentURL    string `json:"agent_url"`
	// Committed is false during probation (cert provisioned, agent port not
	// yet proven) and true after the first successful agent-port request;
	// from then on only the agent port is used.
	Committed bool `json:"committed"`
}

// PathFor returns where mtls.json lives for the given credentials file.
func PathFor(credPath string) string {
	return filepath.Join(filepath.Dir(credPath), FileName)
}

// Load reads the state at path for deviceID. It returns ErrNotFound when the
// file is absent. When the file belongs to another device, cannot be parsed,
// or holds a certificate that does not parse, it logs a WARN, deletes the file
// and returns ErrNotFound, so the caller provisions again instead of looping
// on a bad file. Any other read failure is returned as is.
func Load(path, deviceID string, log *slog.Logger) (State, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is derived from the operator-provided credentials-file location, not untrusted input.
	if errors.Is(err, os.ErrNotExist) {
		return State{}, ErrNotFound
	}
	if err != nil {
		return State{}, fmt.Errorf("mtls: read %s: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, discard(path, "unparseable", err, log)
	}
	if s.DeviceID != deviceID {
		return State{}, discard(path, "belongs to another device", nil, log)
	}
	if _, err := s.Leaf(); err != nil {
		return State{}, discard(path, "certificate unusable", err, log)
	}
	return s, nil
}

// discard WARNs, deletes the unusable file and returns ErrNotFound. A failed
// delete is logged too and not returned: the next Save replaces the file
// through a rename regardless. cause, when set, never carries file contents:
// json and x509 parse errors describe structure, not values.
func discard(path, reason string, cause error, log *slog.Logger) error {
	attrs := []any{"path", path, "reason", reason}
	if cause != nil {
		attrs = append(attrs, "error", cause)
	}
	if err := Remove(path); err != nil {
		attrs = append(attrs, "remove_error", err)
	}
	log.Warn("mtls state ignored and deleted; will provision again", attrs...)
	return ErrNotFound
}

// Save writes s to path as mode 0600. It writes a temp file in the same
// directory, fsyncs it, renames it over path in one step and fsyncs the
// directory, so a crash leaves the old file or the whole new one.
func Save(path string, s State) (err error) {
	data, err := json.Marshal(s) // #nosec G117 -- persisting the device key to mtls.json is the design (0600, atomic); the agent needs it on disk to present its client cert.
	if err != nil {
		return fmt.Errorf("mtls: marshal state: %w", err)
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+FileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("mtls: create temp in %s: %w", dir, err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("mtls: write %s: %w", tmp, err)
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("mtls: sync %s: %w", tmp, err)
	}
	if err = f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("mtls: chmod %s: %w", tmp, err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("mtls: close %s: %w", tmp, err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("mtls: rename into %s: %w", path, err)
	}
	return syncDir(dir)
}

// syncDir fsyncs dir so the rename survives power loss.
func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- directory of the operator-provided credentials file.
	if err != nil {
		return fmt.Errorf("mtls: open dir %s for sync: %w", dir, err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("mtls: sync dir %s: %w", dir, err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("mtls: close dir %s: %w", dir, err)
	}
	return nil
}

// Remove deletes the state file. An absent file is not an error.
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("mtls: remove %s: %w", path, err)
	}
	return nil
}

// Leaf parses the device certificate (the first CERTIFICATE block of CertPEM).
func (s State) Leaf() (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(s.CertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("mtls: cert_pem holds no PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse device certificate: %w", err)
	}
	return cert, nil
}

// TLSConfig returns the client config for the agent port: TLS 1.3, this
// device's key pair as the client certificate, and RootCAs set to the stored
// bundle alone. System roots are never consulted, so only a server chaining to
// the pinned CA is accepted.
func (s State) TLSConfig() (*tls.Config, error) {
	pair, err := tls.X509KeyPair([]byte(s.CertPEM), []byte(s.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("mtls: load key pair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(s.CABundlePEM)) {
		return nil, errors.New("mtls: ca_bundle_pem holds no PEM certificate")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		RootCAs:      pool,
	}, nil
}
