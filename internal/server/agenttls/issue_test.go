package agenttls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

const testDeviceID = "dev-0123"

// testCA builds an in-memory CA pair valid at now.
func testCA(t *testing.T, now time.Time) *CA {
	t.Helper()
	active, activeKey, err := newCACert(now)
	if err != nil {
		t.Fatalf("active CA: %v", err)
	}
	backup, _, err := newCACert(now)
	if err != nil {
		t.Fatalf("backup CA: %v", err)
	}
	return &CA{Active: active, ActiveKey: activeKey, Backup: backup}
}

// csrPEM signs a certificate request for key with tmpl.
func csrPEM(t *testing.T, key crypto.Signer, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func p256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

func parseCertPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("issued PEM is not a CERTIFICATE block: %q", certPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// signLeaf signs tmpl for a fresh P-256 key under parent/parentKey. A nil
// parent self-signs.
func signLeaf(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	leafKey := p256Key(t)
	if parent == nil {
		parent, parentKey = tmpl, leafKey
	}
	tmpl.SerialNumber = mustSerial(t)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &leafKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func mustSerial(t *testing.T) *big.Int {
	t.Helper()
	s, err := newSerial()
	if err != nil {
		t.Fatalf("newSerial: %v", err)
	}
	return s
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func TestIssueDevice_Profile(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 123456789, time.UTC)
	ca := testCA(t, now)
	key := p256Key(t)
	csr := csrPEM(t, key, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "evil"},
		DNSNames:       []string{"evil.example"},
		IPAddresses:    []net.IP{net.IPv4(10, 0, 0, 1)},
		URIs:           []*url.URL{mustURL(t, "urn:x")},
		EmailAddresses: []string{"evil@example.com"},
	})

	got, err := ca.IssueDevice(csr, testDeviceID, now)
	if err != nil {
		t.Fatalf("IssueDevice: %v", err)
	}
	cert := parseCertPEM(t, got.CertPEM)

	if cert.Subject.CommonName != testDeviceID {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, testDeviceID)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != DeviceURIPrefix+testDeviceID {
		t.Errorf("URIs = %v, want exactly [%s%s]", cert.URIs, DeviceURIPrefix, testDeviceID)
	}
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 {
		t.Errorf("DNS=%v IP=%v email=%v, want none (CSR SANs must be ignored)", cert.DNSNames, cert.IPAddresses, cert.EmailAddresses)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", cert.ExtKeyUsage)
	}
	if cert.IsCA {
		t.Error("IsCA = true, want false")
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Error("certificate public key is not the CSR key")
	}
	if want := now.AddDate(LeafLifetimeYears, 0, 0).Truncate(time.Second); !cert.NotAfter.Equal(want) {
		t.Errorf("NotAfter = %v, want %v", cert.NotAfter, want)
	}
	if want := SerialHex(cert.SerialNumber); got.Serial != want {
		t.Errorf("Serial = %q, want %q", got.Serial, want)
	}
	if !got.NotAfter.Equal(cert.NotAfter) {
		t.Errorf("Issued.NotAfter = %v, want cert NotAfter %v", got.NotAfter, cert.NotAfter)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.Active)
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Errorf("issued cert does not chain to the active CA: %v", err)
	}
}

func TestIssueDevice_BackdatedNotBefore(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	ca := testCA(t, now)
	csr := csrPEM(t, p256Key(t), &x509.CertificateRequest{})

	got, err := ca.IssueDevice(csr, testDeviceID, now)
	if err != nil {
		t.Fatalf("IssueDevice: %v", err)
	}
	cert := parseCertPEM(t, got.CertPEM)

	if want := now.Add(-time.Hour); !cert.NotBefore.Equal(want) {
		t.Errorf("NotBefore = %v, want %v", cert.NotBefore, want)
	}
	if err := ca.VerifyClient(cert, now.Add(-59*time.Minute)); err != nil {
		t.Errorf("VerifyClient 59m before issuance: %v, want nil", err)
	}
}

func TestIssueDevice_RejectsBadCSR(t *testing.T) {
	now := time.Now()
	ca := testCA(t, now)

	p256CSR := csrPEM(t, p256Key(t), &x509.CertificateRequest{})
	block, _ := pem.Decode(p256CSR)
	tampered := append([]byte(nil), block.Bytes...)
	tampered[len(tampered)-1] ^= 0xff // last byte of the signature

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("P-384 GenerateKey: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	tests := []struct {
		name string
		csr  []byte
	}{
		{"not PEM", []byte("not a pem block")},
		{"wrong PEM type", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})},
		{"tampered signature", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered})},
		{"RSA-2048", csrPEM(t, rsaKey, &x509.CertificateRequest{})},
		{"ECDSA P-384", csrPEM(t, p384Key, &x509.CertificateRequest{})},
		{"Ed25519", csrPEM(t, edKey, &x509.CertificateRequest{})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ca.IssueDevice(tt.csr, testDeviceID, now)
			if !errors.Is(err, ErrBadCSR) {
				t.Errorf("IssueDevice error = %v, want ErrBadCSR", err)
			}
		})
	}
}

func TestVerifyClient(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	ca := testCA(t, now)

	issued, err := ca.IssueDevice(csrPEM(t, p256Key(t), &x509.CertificateRequest{}), testDeviceID, now)
	if err != nil {
		t.Fatalf("IssueDevice: %v", err)
	}
	good := parseCertPEM(t, issued.CertPEM)

	// The CA struct never holds the backup private key, so generate a CA in
	// the test and pin it as Backup: a leaf signed by its key is otherwise a
	// perfect device cert and must still be refused.
	backup, backupKey, err := newCACert(now)
	if err != nil {
		t.Fatalf("backup CA: %v", err)
	}
	ca.Backup = backup
	deviceTmpl := func() *x509.Certificate {
		return &x509.Certificate{
			Subject:     pkix.Name{CommonName: testDeviceID},
			URIs:        []*url.URL{mustURL(t, DeviceURIPrefix+testDeviceID)},
			NotBefore:   now.Add(-time.Hour),
			NotAfter:    now.AddDate(1, 0, 0),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
	}
	serverOnly := deviceTmpl()
	serverOnly.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	tests := []struct {
		name    string
		leaf    *x509.Certificate
		at      time.Time
		wantErr bool
	}{
		{"issued leaf", good, now, false},
		{"signed by backup CA key", signLeaf(t, backup, backupKey, deviceTmpl()), now, true},
		{"self-signed", signLeaf(t, nil, nil, deviceTmpl()), now, true},
		{"expired", good, good.NotAfter.Add(time.Second), true},
		{"server auth only", signLeaf(t, ca.Active, ca.ActiveKey, serverOnly), now, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ca.VerifyClient(tt.leaf, tt.at)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyClient error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDeviceIDFromCert(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	ca := testCA(t, now)
	issued, err := ca.IssueDevice(csrPEM(t, p256Key(t), &x509.CertificateRequest{}), testDeviceID, now)
	if err != nil {
		t.Fatalf("IssueDevice: %v", err)
	}

	withURIs := func(uris ...string) *x509.Certificate {
		c := &x509.Certificate{}
		for _, u := range uris {
			c.URIs = append(c.URIs, mustURL(t, u))
		}
		return c
	}
	tests := []struct {
		name   string
		leaf   *x509.Certificate
		wantID string
		wantOK bool
	}{
		{"issued leaf", parseCertPEM(t, issued.CertPEM), testDeviceID, true},
		{"no URI", withURIs(), "", false},
		{"two URIs", withURIs(DeviceURIPrefix+"a", DeviceURIPrefix+"b"), "", false},
		{"wrong prefix", withURIs("urn:other:device:a"), "", false},
		{"empty device id", withURIs(DeviceURIPrefix), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, ok := DeviceIDFromCert(tt.leaf)
			if id != tt.wantID || ok != tt.wantOK {
				t.Errorf("DeviceIDFromCert = (%q, %v), want (%q, %v)", id, ok, tt.wantID, tt.wantOK)
			}
		})
	}
}
