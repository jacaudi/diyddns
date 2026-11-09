package agenttls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"path/filepath"
	"slices"
	"time"

	"github.com/jacaudi/diyddns/internal/shared/atomicfile"
)

// LoadOrIssueServingCert returns the agent listener's TLS server certificate:
// dir/agent.crt and dir/agent.key, re-issued when the pair is missing,
// unreadable, or fails needsReissue. host is the public_url hostname the
// certificate must name. It runs once, at startup: the certificate is valid
// for the active CA's lifetime, and a host or CA change only happens across a
// restart, so nothing renews it at runtime. The caller owns the dir lock.
func LoadOrIssueServingCert(dir, host string, ca *CA, now time.Time, log *slog.Logger) (tls.Certificate, error) {
	if host == "" {
		return tls.Certificate{}, errors.New("agenttls: serving certificate needs a host to name")
	}
	if cert := loadServing(dir, log); cert != nil && !needsReissue(cert.Leaf, host, ca.Active, now) {
		return *cert, nil
	}
	cert, err := issueServing(dir, host, ca, now)
	if err != nil {
		return tls.Certificate{}, err
	}
	log.Info("agent serving certificate issued", "not_after", cert.Leaf.NotAfter, "host", host)
	return *cert, nil
}

// load reads the pair from disk. A missing pair is quietly nil; one that
// exists but cannot be used is nil with a WARN, so it is replaced.
func loadServing(dir string, log *slog.Logger) *tls.Certificate {
	crt, key := filepath.Join(dir, AgentCertFile), filepath.Join(dir, AgentKeyFile)
	cert, err := tls.LoadX509KeyPair(crt, key)
	switch {
	case err == nil:
		return &cert
	case errors.Is(err, fs.ErrNotExist):
		return nil
	default:
		log.Warn("agent serving certificate unusable, re-issuing", "cert", crt, "key", key, "error", err)
		return nil
	}
}

// issueServing signs a serving certificate for host with a fresh key under the
// active CA, expiring with it, and writes agent.key then agent.crt. The key
// goes first: a crash between the two leaves a mismatched pair, which
// loadServing reports as unusable and replaces.
func issueServing(dir, host string, ca *CA, now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("agenttls: generate serving key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-clockBackdate),
		NotAfter:              ca.Active.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Active, &key.PublicKey, ca.ActiveKey)
	if err != nil {
		return nil, fmt.Errorf("agenttls: sign serving certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("agenttls: parse serving certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("agenttls: marshal serving key: %w", err)
	}
	if err := atomicfile.WriteFile(dir, AgentKeyFile, pem.EncodeToMemory(&pem.Block{Type: ecKeyPEMType, Bytes: keyDER})); err != nil {
		return nil, err
	}
	if err := atomicfile.WriteFile(dir, AgentCertFile, certPEM(leaf)); err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// needsReissue reports whether leaf must be replaced: it expires before the
// active CA (which also replaces a one-year leaf written before the serving
// certificate stopped renewing at runtime), its SANs are not exactly host, or
// it does not chain to the active CA.
func needsReissue(leaf *x509.Certificate, host string, active *x509.Certificate, now time.Time) bool {
	if leaf.NotAfter.Before(active.NotAfter) || !sansAreExactly(leaf, host) {
		return true
	}
	roots := x509.NewCertPool()
	roots.AddCert(active)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err != nil
}

// sansAreExactly reports whether leaf names host and nothing else: one IP SAN
// for an IP literal, one DNS SAN otherwise.
func sansAreExactly(leaf *x509.Certificate, host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 1 && leaf.IPAddresses[0].Equal(ip)
	}
	return len(leaf.IPAddresses) == 0 && slices.Equal(leaf.DNSNames, []string{host})
}
