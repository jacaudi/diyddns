package agenttls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

const (
	// DeviceURIPrefix starts the single URI SAN of every device certificate;
	// the device ID follows it.
	DeviceURIPrefix = "urn:diyddns:device:"
	// LeafLifetimeYears is the validity of device certificates. The serving
	// certificate instead expires with the active CA.
	LeafLifetimeYears = 1
)

// ErrBadCSR means the certificate request could not be used: it is not a PEM
// CERTIFICATE REQUEST, its signature does not verify, or its key is not
// ECDSA P-256.
var ErrBadCSR = errors.New("agenttls: invalid CSR")

// Issued describes a freshly issued device certificate.
type Issued struct {
	CertPEM  []byte
	Serial   string // SerialHex of the certificate serial
	NotAfter time.Time
}

// SerialHex is the one text form of a certificate serial that is stored and
// compared.
func SerialHex(n *big.Int) string { return n.Text(16) }

// IssueDevice signs a client certificate for deviceID. Only the CSR's public
// key is used; its subject, SANs and extensions are ignored.
func (c *CA) IssueDevice(csrPEM []byte, deviceID string, now time.Time) (Issued, error) {
	pub, err := csrPublicKey(csrPEM)
	if err != nil {
		return Issued{}, err
	}
	uri, err := url.Parse(DeviceURIPrefix + deviceID)
	if err != nil {
		return Issued{}, fmt.Errorf("agenttls: device URI for %q: %w", deviceID, err)
	}
	serial, err := newSerial()
	if err != nil {
		return Issued{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: deviceID},
		URIs:                  []*url.URL{uri},
		NotBefore:             now.Add(-clockBackdate),
		NotAfter:              now.AddDate(LeafLifetimeYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Active, pub, c.ActiveKey)
	if err != nil {
		return Issued{}, fmt.Errorf("agenttls: sign device certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Issued{}, fmt.Errorf("agenttls: parse device certificate: %w", err)
	}
	return Issued{CertPEM: certPEM(cert), Serial: SerialHex(cert.SerialNumber), NotAfter: cert.NotAfter}, nil
}

// csrPublicKey checks csrPEM and returns its public key, which must be ECDSA
// P-256. Every failure wraps ErrBadCSR.
func csrPublicKey(csrPEM []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: not a PEM CERTIFICATE REQUEST", ErrBadCSR)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %w", ErrBadCSR, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: signature: %w", ErrBadCSR, err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: key must be ECDSA P-256", ErrBadCSR)
	}
	return pub, nil
}

// VerifyClient checks that leaf chains to the active CA, never the backup,
// and is valid for client authentication at now.
func (c *CA) VerifyClient(leaf *x509.Certificate, now time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(c.Active)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

// DeviceIDFromCert returns the device ID carried in leaf's single URI SAN.
func DeviceIDFromCert(leaf *x509.Certificate) (string, bool) {
	if len(leaf.URIs) != 1 {
		return "", false
	}
	id, ok := strings.CutPrefix(leaf.URIs[0].String(), DeviceURIPrefix)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}
