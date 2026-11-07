package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

const (
	keyPEMType = "EC PRIVATE KEY"
	csrPEMType = "CERTIFICATE REQUEST"
)

// NewKeyAndCSR generates an ECDSA P-256 key on this device and a CSR for it.
// The CSR carries the public key and subject CN=deviceID only; the server
// ignores everything else and derives the certificate's identity itself.
func NewKeyAndCSR(deviceID string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("mtls: generate key: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("mtls: marshal key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: deviceID},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("mtls: create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: keyPEMType, Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: csrPEMType, Bytes: csrDER}),
		nil
}
