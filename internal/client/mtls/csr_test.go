package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestNewKeyAndCSR(t *testing.T) {
	keyPEM, csrPEM, err := NewKeyAndCSR("dev-1")
	if err != nil {
		t.Fatalf("NewKeyAndCSR: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("CSR is not a PEM CERTIFICATE REQUEST: %q", csrPEM)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature: %v", err)
	}
	if got, want := csr.Subject.CommonName, "dev-1"; got != want {
		t.Errorf("CSR CN = %q, want %q", got, want)
	}
	if n := len(csr.DNSNames) + len(csr.IPAddresses) + len(csr.URIs) + len(csr.EmailAddresses); n != 0 {
		t.Errorf("CSR carries %d SANs, want none", n)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("CSR public key = %T, want ECDSA P-256", csr.PublicKey)
	}

	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		t.Fatalf("key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		t.Fatalf("ParseECPrivateKey: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Errorf("key curve = %s, want P-256", key.Curve.Params().Name)
	}
	if !key.PublicKey.Equal(pub) {
		t.Errorf("key does not match the CSR public key")
	}
}

func TestNewKeyAndCSR_FreshKeyEachCall(t *testing.T) {
	a, _, err := NewKeyAndCSR("dev-1")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	b, _, err := NewKeyAndCSR("dev-1")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if string(a) == string(b) {
		t.Errorf("two calls returned the same key")
	}
}
