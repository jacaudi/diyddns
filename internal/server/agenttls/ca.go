// Package agenttls holds the agent-port TLS state: the CA pair, the key files
// on disk, and the exclusive lock on agent.tls.dir (#173).
package agenttls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// clockBackdate is how far every certificate's NotBefore is moved into the
// past, so a client clock slightly behind the server still accepts it.
const clockBackdate = time.Hour

// caLifetimeYears is the validity of both CA certificates.
const caLifetimeYears = 10

// CA is the agent CA pair. ActiveKey signs device and serving certificates;
// the backup private key is never loaded, only its certificate is pinned.
type CA struct {
	Active    *x509.Certificate
	ActiveKey *ecdsa.PrivateKey
	Backup    *x509.Certificate
}

// Bundle returns the PEM of the active then the backup certificate: the pin
// set clients verify the agent port against.
func (c *CA) Bundle() []byte {
	return append(certPEM(c.Active), certPEM(c.Backup)...)
}

func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// newSerial returns a random certificate serial in [1, 2^128).
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit.Sub(limit, big.NewInt(1)))
	if err != nil {
		return nil, fmt.Errorf("agenttls: certificate serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

// newCACert generates a self-signed P-256 CA valid from now-clockBackdate for
// ten years. The subject CN carries the first 8 hex characters of the SHA-256
// of the SubjectPublicKeyInfo, so two CAs never share a subject.
func newCACert(now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("agenttls: generate CA key: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("agenttls: marshal CA public key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(spki)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "diyddns agent CA " + hex.EncodeToString(sum[:])[:8]},
		NotBefore:             now.Add(-clockBackdate),
		NotAfter:              now.AddDate(caLifetimeYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("agenttls: sign CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("agenttls: parse CA certificate: %w", err)
	}
	return cert, key, nil
}
