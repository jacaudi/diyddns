package agenttls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

var caSubjectRE = regexp.MustCompile(`^diyddns agent CA [0-9a-f]{8}$`)

func TestNewCACert_Profile(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 123456789, time.UTC)
	cert, key, err := newCACert(now)
	if err != nil {
		t.Fatalf("newCACert: %v", err)
	}

	if !cert.IsCA {
		t.Error("IsCA = false, want true")
	}
	if want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign; cert.KeyUsage&want != want {
		t.Errorf("KeyUsage = %b, want CertSign|CRLSign set", cert.KeyUsage)
	}
	if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Errorf("MaxPathLen = %d, MaxPathLenZero = %v, want 0, true", cert.MaxPathLen, cert.MaxPathLenZero)
	}
	if key.Curve != elliptic.P256() {
		t.Errorf("key curve = %v, want P-256", key.Curve.Params().Name)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Error("certificate public key does not match the returned private key")
	}
	if want := now.Add(-time.Hour).Truncate(time.Second); !cert.NotBefore.Equal(want) {
		t.Errorf("NotBefore = %v, want %v", cert.NotBefore, want)
	}
	if want := now.AddDate(10, 0, 0).Truncate(time.Second); !cert.NotAfter.Equal(want) {
		t.Errorf("NotAfter = %v, want %v", cert.NotAfter, want)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("not self-signed: %v", err)
	}

	cn := cert.Subject.CommonName
	if !caSubjectRE.MatchString(cn) {
		t.Errorf("CN = %q, want match %s", cn, caSubjectRE)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if want := "diyddns agent CA " + hex.EncodeToString(sum[:])[:8]; cn != want {
		t.Errorf("CN = %q, want %q (sha256 of SubjectPublicKeyInfo)", cn, want)
	}

	other, _, err := newCACert(now)
	if err != nil {
		t.Fatalf("second newCACert: %v", err)
	}
	if other.Subject.CommonName == cn {
		t.Errorf("two CAs share CN %q, want distinct subjects", cn)
	}
}

func TestNewSerial_Range(t *testing.T) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for range 100 {
		s, err := newSerial()
		if err != nil {
			t.Fatalf("newSerial: %v", err)
		}
		if s.Sign() <= 0 || s.Cmp(limit) >= 0 {
			t.Fatalf("serial %v outside [1, 2^128)", s)
		}
	}
}

func TestBundle_ActiveThenBackup(t *testing.T) {
	now := time.Now()
	active, activeKey, err := newCACert(now)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	backup, _, err := newCACert(now)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	ca := &CA{Active: active, ActiveKey: activeKey, Backup: backup}

	var got []*x509.Certificate
	rest := ca.Bundle()
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			t.Fatalf("PEM type = %q, want CERTIFICATE", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		got = append(got, c)
	}
	if len(got) != 2 {
		t.Fatalf("Bundle has %d certs, want 2", len(got))
	}
	if !got[0].Equal(active) || !got[1].Equal(backup) {
		t.Error("Bundle order is not Active then Backup")
	}
}

func TestReadKey_RejectsNonP256(t *testing.T) {
	dir := t.TempDir()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := writePending(dir, "k", k); err != nil {
		t.Fatalf("writePending: %v", err)
	}
	if _, err := readKey(filepath.Join(dir, ".k.pending")); err == nil {
		t.Error("readKey accepted a P-384 key, want an error")
	}
}
