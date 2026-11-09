package agenttls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/logtest"
)

// servingNow is a whole-second instant so x509's second truncation never
// makes an expected NotBefore/NotAfter differ from the certificate's.
var servingNow = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

// newServing runs LoadOrIssueServingCert and returns the served leaf with the
// log it wrote.
func newServing(t *testing.T, dir, host string, ca *CA, now time.Time) (*x509.Certificate, string) {
	t.Helper()
	var buf bytes.Buffer
	cert, err := LoadOrIssueServingCert(dir, host, ca, now, slog.New(slog.NewJSONHandler(&buf, nil)))
	if err != nil {
		t.Fatalf("LoadOrIssueServingCert: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("LoadOrIssueServingCert returned a certificate without Leaf set")
	}
	return cert.Leaf, buf.String()
}

func TestLoadOrIssueServingCert_IssuesWhenMissing(t *testing.T) {
	dir, ca := t.TempDir(), testCA(t, servingNow)

	leaf, log := newServing(t, dir, "ddns.example.com", ca, servingNow)

	assertMode0600(t, filepath.Join(dir, AgentCertFile))
	assertMode0600(t, filepath.Join(dir, AgentKeyFile))
	if !slices.Equal(leaf.DNSNames, []string{"ddns.example.com"}) {
		t.Errorf("DNSNames = %v, want [ddns.example.com]", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 0 {
		t.Errorf("IPAddresses = %v, want none", leaf.IPAddresses)
	}
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("ExtKeyUsage = %v, want [ServerAuth]", leaf.ExtKeyUsage)
	}
	if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Errorf("public key = %T, want ECDSA P-256", leaf.PublicKey)
	}
	// Valid for the CA's lifetime: nothing renews it at runtime (#2).
	if want := ca.Active.NotAfter; !leaf.NotAfter.Equal(want) {
		t.Errorf("NotAfter = %v, want the active CA's %v", leaf.NotAfter, want)
	}
	if want := servingNow.Add(-time.Hour); !leaf.NotBefore.Equal(want) {
		t.Errorf("NotBefore = %v, want %v", leaf.NotBefore, want)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Active)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		DNSName:     "ddns.example.com",
		CurrentTime: servingNow,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("serving cert does not verify against the active CA: %v", err)
	}

	onDisk, err := tls.LoadX509KeyPair(filepath.Join(dir, AgentCertFile), filepath.Join(dir, AgentKeyFile))
	if err != nil {
		t.Fatalf("agent.crt/agent.key on disk are not a usable pair: %v", err)
	}
	if !bytes.Equal(onDisk.Certificate[0], leaf.Raw) {
		t.Error("agent.crt on disk is not the served certificate")
	}

	rec := logtest.Find(t, log, "agent serving certificate issued")
	if rec["level"] != "INFO" || rec["host"] != "ddns.example.com" || rec["not_after"] == nil {
		t.Errorf("issue record = %v, want INFO with host and not_after", rec)
	}
}

func TestLoadOrIssueServingCert_IPHostUsesIPSAN(t *testing.T) {
	leaf, _ := newServing(t, t.TempDir(), "192.0.2.1", testCA(t, servingNow), servingNow)

	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("IPAddresses = %v, want [192.0.2.1]", leaf.IPAddresses)
	}
	if len(leaf.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want none", leaf.DNSNames)
	}
}

func TestLoadOrIssueServingCert_EmptyHostRejected(t *testing.T) {
	_, err := LoadOrIssueServingCert(t.TempDir(), "", testCA(t, servingNow), servingNow, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("LoadOrIssueServingCert with empty host: nil error, want one (a certificate with no SAN verifies for nobody)")
	}
}

func TestLoadOrIssueServingCert_ReusesValid(t *testing.T) {
	dir, ca := t.TempDir(), testCA(t, servingNow)
	first, _ := newServing(t, dir, "ddns.example.com", ca, servingNow)
	crt := mustRead(t, filepath.Join(dir, AgentCertFile))
	key := mustRead(t, filepath.Join(dir, AgentKeyFile))

	second, log := newServing(t, dir, "ddns.example.com", ca, servingNow.Add(24*time.Hour))

	if got, want := second.SerialNumber, first.SerialNumber; got.Cmp(want) != 0 {
		t.Errorf("serial = %v, want the unchanged %v", got, want)
	}
	if !bytes.Equal(mustRead(t, filepath.Join(dir, AgentCertFile)), crt) {
		t.Error("agent.crt changed on a valid reuse")
	}
	if !bytes.Equal(mustRead(t, filepath.Join(dir, AgentKeyFile)), key) {
		t.Error("agent.key changed on a valid reuse")
	}
	if recs := logtest.Records(t, log); len(recs) != 0 {
		t.Errorf("reuse logged %v, want nothing", recs)
	}
}

func TestLoadOrIssueServingCert_CorruptPairIsReissued(t *testing.T) {
	dir, ca := t.TempDir(), testCA(t, servingNow)
	for _, name := range []string{AgentCertFile, AgentKeyFile} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not pem"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	leaf, log := newServing(t, dir, "ddns.example.com", ca, servingNow)

	if got := leaf.DNSNames; !slices.Equal(got, []string{"ddns.example.com"}) {
		t.Errorf("DNSNames = %v, want a fresh cert for ddns.example.com", got)
	}
	var warned bool
	for _, rec := range logtest.Records(t, log) {
		warned = warned || rec["level"] == "WARN"
	}
	if !warned {
		t.Errorf("corrupt pair logged no WARN:\n%s", log)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, AgentCertFile), filepath.Join(dir, AgentKeyFile)); err != nil {
		t.Errorf("pair on disk after re-issue is not usable: %v", err)
	}
}

func TestNeedsReissue(t *testing.T) {
	ca := testCA(t, servingNow)
	other := testCA(t, servingNow)
	leaf := func(signer *CA, san string, notAfter time.Time) *x509.Certificate {
		return signLeaf(t, signer.Active, signer.ActiveKey, &x509.Certificate{
			DNSNames:    []string{san},
			NotBefore:   servingNow.Add(-time.Hour),
			NotAfter:    notAfter,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
	}
	const host = "new.example.com"
	tests := []struct {
		name string
		leaf *x509.Certificate
		want bool
	}{
		{"one-year leaf from before #2", leaf(ca, host, servingNow.AddDate(1, 0, 0)), true},
		{"one second short of the CA", leaf(ca, host, ca.Active.NotAfter.Add(-time.Second)), true},
		{"expired", leaf(ca, host, servingNow.Add(-time.Minute)), true},
		{"SAN differs", leaf(ca, "old.example.com", ca.Active.NotAfter), true},
		{"signed by another CA", leaf(other, host, other.Active.NotAfter), true},
		{"matching SAN, chained, expires with the CA", leaf(ca, host, ca.Active.NotAfter), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := needsReissue(tt.leaf, host, ca.Active, servingNow); got != tt.want {
				t.Errorf("needsReissue = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNeedsReissue_HostKindChanges(t *testing.T) {
	ca := testCA(t, servingNow)
	issue := func(host string) *x509.Certificate {
		leaf, _ := newServing(t, t.TempDir(), host, ca, servingNow)
		return leaf
	}
	if !needsReissue(issue("192.0.2.1"), "ddns.example.com", ca.Active, servingNow) {
		t.Error("IP-SAN cert kept for a DNS host")
	}
	if !needsReissue(issue("ddns.example.com"), "192.0.2.1", ca.Active, servingNow) {
		t.Error("DNS-SAN cert kept for an IP host")
	}
	if needsReissue(issue("192.0.2.1"), "192.0.2.1", ca.Active, servingNow) {
		t.Error("matching IP-SAN cert flagged for re-issue")
	}
}

func TestLoadOrIssueServingCert_ReissuesWhenHostChanges(t *testing.T) {
	dir, ca := t.TempDir(), testCA(t, servingNow)
	first, _ := newServing(t, dir, "old.example.com", ca, servingNow)

	second, _ := newServing(t, dir, "new.example.com", ca, servingNow)

	if second.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Error("serial unchanged after the host changed")
	}
	if !slices.Equal(second.DNSNames, []string{"new.example.com"}) {
		t.Errorf("DNSNames = %v, want [new.example.com]", second.DNSNames)
	}
}

// A promote-backup or reset changes the active CA while the server is stopped;
// the next start must replace a leaf the new CA did not sign.
func TestLoadOrIssueServingCert_ReissuesWhenCAChanges(t *testing.T) {
	dir := t.TempDir()
	first, _ := newServing(t, dir, "ddns.example.com", testCA(t, servingNow), servingNow)
	next := testCA(t, servingNow)

	second, _ := newServing(t, dir, "ddns.example.com", next, servingNow.Add(24*time.Hour))

	if second.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Error("serial unchanged after the active CA changed")
	}
	roots := x509.NewCertPool()
	roots.AddCert(next.Active)
	if _, err := second.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: servingNow.Add(24 * time.Hour),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("re-issued leaf does not verify against the new active CA: %v", err)
	}
}
