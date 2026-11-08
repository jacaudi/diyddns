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
	"sync/atomic"
	"time"

	"github.com/jacaudi/diyddns/internal/shared/atomicfile"
)

// ServingCert is the agent listener's TLS server certificate. GetCertificate
// hands out whatever Refresh last stored, so a renewal needs no restart.
type ServingCert struct {
	dir, host string
	ca        *CA
	cur       atomic.Pointer[tls.Certificate]
	log       *slog.Logger
}

// NewServingCert loads dir/agent.crt and dir/agent.key and re-issues the pair
// when it is missing, unreadable, or fails needsReissue. host is the
// public_url hostname the certificate must name. The caller owns the dir lock.
func NewServingCert(dir, host string, ca *CA, now time.Time, log *slog.Logger) (*ServingCert, error) {
	if host == "" {
		return nil, errors.New("agenttls: serving certificate needs a host to name")
	}
	s := &ServingCert{dir: dir, host: host, ca: ca, log: log}
	if _, err := s.Refresh(now); err != nil {
		return nil, err
	}
	return s, nil
}

// GetCertificate is the tls.Config.GetCertificate callback.
func (s *ServingCert) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.cur.Load(), nil
}

// Refresh re-issues the serving certificate when needsReissue says so and
// reports whether it did. The first call loads the pair from disk. It is safe
// against concurrent GetCertificate calls but not against another Refresh;
// the pruner tick is its only caller after construction.
func (s *ServingCert) Refresh(now time.Time) (reissued bool, err error) {
	cert := s.cur.Load()
	if cert == nil {
		cert = s.load()
	}
	if cert != nil && !needsReissue(cert.Leaf, s.host, s.ca.Active, now) {
		s.cur.Store(cert)
		return false, nil
	}
	cert, err = s.issue(now)
	if err != nil {
		return false, err
	}
	s.cur.Store(cert)
	s.log.Info("agent serving certificate issued", "not_after", cert.Leaf.NotAfter, "host", s.host)
	return true, nil
}

// load reads the pair from disk. A missing pair is quietly nil; one that
// exists but cannot be used is nil with a WARN, so it is replaced.
func (s *ServingCert) load() *tls.Certificate {
	crt, key := filepath.Join(s.dir, AgentCertFile), filepath.Join(s.dir, AgentKeyFile)
	cert, err := tls.LoadX509KeyPair(crt, key)
	switch {
	case err == nil:
		return &cert
	case errors.Is(err, fs.ErrNotExist):
		return nil
	default:
		s.log.Warn("agent serving certificate unusable, re-issuing", "cert", crt, "key", key, "error", err)
		return nil
	}
}

// issue signs a serving certificate for a fresh key under the active CA and
// writes agent.key then agent.crt. The key goes first: a crash between the two
// leaves a mismatched pair, which load reports as unusable and replaces.
func (s *ServingCert) issue(now time.Time) (*tls.Certificate, error) {
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
		Subject:               pkix.Name{CommonName: s.host},
		NotBefore:             now.Add(-clockBackdate),
		NotAfter:              now.AddDate(LeafLifetimeYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if ip := net.ParseIP(s.host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{s.host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca.Active, &key.PublicKey, s.ca.ActiveKey)
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
	if err := atomicfile.WriteFile(s.dir, AgentKeyFile, pem.EncodeToMemory(&pem.Block{Type: ecKeyPEMType, Bytes: keyDER})); err != nil {
		return nil, err
	}
	if err := atomicfile.WriteFile(s.dir, AgentCertFile, certPEM(leaf)); err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// needsReissue reports whether leaf must be replaced: fewer than RenewBefore of
// validity left, SANs that are not exactly host, or no chain to the active CA.
func needsReissue(leaf *x509.Certificate, host string, active *x509.Certificate, now time.Time) bool {
	if leaf.NotAfter.Sub(now) < RenewBefore || !sansAreExactly(leaf, host) {
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
