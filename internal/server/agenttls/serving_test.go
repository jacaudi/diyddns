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
	"sync"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/logtest"
)

// servingNow is a whole-second instant so x509's second truncation never
// makes an expected NotBefore/NotAfter differ from the certificate's.
var servingNow = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

// newServing builds a ServingCert and returns it with the log it wrote.
func newServing(t *testing.T, dir, host string, ca *CA, now time.Time) (*ServingCert, string) {
	t.Helper()
	var buf bytes.Buffer
	s, err := NewServingCert(dir, host, ca, now, slog.New(slog.NewJSONHandler(&buf, nil)))
	if err != nil {
		t.Fatalf("NewServingCert: %v", err)
	}
	return s, buf.String()
}

func servedLeaf(t *testing.T, s *ServingCert) *x509.Certificate {
	t.Helper()
	cert, err := s.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil || cert.Leaf == nil {
		t.Fatalf("GetCertificate returned %v, want a certificate with Leaf set", cert)
	}
	return cert.Leaf
}

func TestNewServingCert_IssuesWhenMissing(t *testing.T) {
	dir, ca := t.TempDir(), testCA(t, servingNow)

	s, log := newServing(t, dir, "ddns.example.com", ca, servingNow)

	assertMode0600(t, filepath.Join(dir, AgentCertFile))
	assertMode0600(t, filepath.Join(dir, AgentKeyFile))
	leaf := servedLeaf(t, s)
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
	if want := servingNow.AddDate(1, 0, 0); !leaf.NotAfter.Equal(want) {
		t.Errorf("NotAfter = %v, want %v", leaf.NotAfter, want)
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

func TestNewServingCert_IPHostUsesIPSAN(t *testing.T) {
	s, _ := newServing(t, t.TempDir(), "192.0.2.1", testCA(t, servingNow), servingNow)

	leaf := servedLeaf(t, s)
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("IPAddresses = %v, want [192.0.2.1]", leaf.IPAddresses)
	}
	if len(leaf.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want none", leaf.DNSNames)
	}
}

func TestNewServingCert_EmptyHostRejected(t *testing.T) {
	_, err := NewServingCert(t.TempDir(), "", testCA(t, servingNow), servingNow, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("NewServingCert with empty host: nil error, want one (a certificate with no SAN verifies for nobody)")
	}
}

func TestNewServingCert_ReusesValid(t *testing.T) {
	dir, ca := t.TempDir(), testCA(t, servingNow)
	first, _ := newServing(t, dir, "ddns.example.com", ca, servingNow)
	crt := mustRead(t, filepath.Join(dir, AgentCertFile))
	key := mustRead(t, filepath.Join(dir, AgentKeyFile))

	second, log := newServing(t, dir, "ddns.example.com", ca, servingNow.Add(24*time.Hour))

	if got, want := servedLeaf(t, second).SerialNumber, servedLeaf(t, first).SerialNumber; got.Cmp(want) != 0 {
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

func TestNewServingCert_CorruptPairIsReissued(t *testing.T) {
	dir, ca := t.TempDir(), testCA(t, servingNow)
	for _, name := range []string{AgentCertFile, AgentKeyFile} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not pem"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	s, log := newServing(t, dir, "ddns.example.com", ca, servingNow)

	if got := servedLeaf(t, s).DNSNames; !slices.Equal(got, []string{"ddns.example.com"}) {
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
	leaf := func(signer *CA, san string, remaining time.Duration) *x509.Certificate {
		return signLeaf(t, signer.Active, signer.ActiveKey, &x509.Certificate{
			DNSNames:    []string{san},
			NotBefore:   servingNow.Add(-time.Hour),
			NotAfter:    servingNow.Add(remaining),
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
		{"59 days left", leaf(ca, host, 59*24*time.Hour), true},
		{"one second under 60 days", leaf(ca, host, RenewBefore-time.Second), true},
		{"exactly 60 days", leaf(ca, host, RenewBefore), false},
		{"61 days left", leaf(ca, host, 61*24*time.Hour), false},
		{"SAN differs", leaf(ca, "old.example.com", 200*24*time.Hour), true},
		{"signed by another CA", leaf(other, host, 200*24*time.Hour), true},
		{"matching SAN, chained, ample validity", leaf(ca, host, 200*24*time.Hour), false},
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
		s, _ := newServing(t, t.TempDir(), host, ca, servingNow)
		return servedLeaf(t, s)
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

func TestNewServingCert_ReissuesWhenHostChanges(t *testing.T) {
	dir, ca := t.TempDir(), testCA(t, servingNow)
	first, _ := newServing(t, dir, "old.example.com", ca, servingNow)

	second, _ := newServing(t, dir, "new.example.com", ca, servingNow)

	if servedLeaf(t, second).SerialNumber.Cmp(servedLeaf(t, first).SerialNumber) == 0 {
		t.Error("serial unchanged after the host changed")
	}
	if !slices.Equal(servedLeaf(t, second).DNSNames, []string{"new.example.com"}) {
		t.Errorf("DNSNames = %v, want [new.example.com]", servedLeaf(t, second).DNSNames)
	}
}

func TestRefresh_SwapsWithoutRestart(t *testing.T) {
	dir, ca := t.TempDir(), testCA(t, servingNow)
	s, _ := newServing(t, dir, "ddns.example.com", ca, servingNow)
	before, err := s.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	keyBefore := mustRead(t, filepath.Join(dir, AgentKeyFile))

	reissued, err := s.Refresh(servingNow.AddDate(0, 11, 0))
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !reissued {
		t.Fatal("Refresh = false, want true with ~1 month of validity left")
	}

	after, err := s.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate after Refresh: %v", err)
	}
	if after.Leaf.SerialNumber.Cmp(before.Leaf.SerialNumber) == 0 {
		t.Error("served serial unchanged after re-issue")
	}
	oldKey, _ := before.PrivateKey.(*ecdsa.PrivateKey)
	newKey, _ := after.PrivateKey.(*ecdsa.PrivateKey)
	if oldKey == nil || newKey == nil || oldKey.Equal(newKey) {
		t.Error("private key was not freshly generated on re-issue")
	}
	if bytes.Equal(mustRead(t, filepath.Join(dir, AgentKeyFile)), keyBefore) {
		t.Error("agent.key bytes unchanged after re-issue")
	}
	assertMode0600(t, filepath.Join(dir, AgentKeyFile))
	assertMode0600(t, filepath.Join(dir, AgentCertFile))
}

func TestRefresh_NoopWhenValid(t *testing.T) {
	s, _ := newServing(t, t.TempDir(), "ddns.example.com", testCA(t, servingNow), servingNow)

	reissued, err := s.Refresh(servingNow.AddDate(0, 1, 0))
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if reissued {
		t.Error("Refresh = true, want false with 11 months of validity left")
	}
}

func TestRefresh_ConcurrentGetCertificate(t *testing.T) {
	s, _ := newServing(t, t.TempDir(), "ddns.example.com", testCA(t, servingNow), servingNow)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				cert, err := s.GetCertificate(nil)
				if err != nil || cert == nil {
					t.Errorf("GetCertificate = (%v, %v), want a certificate", cert, err)
					return
				}
			}
		})
	}
	// Each step is a further 11 months out, so every Refresh finds <60 days
	// left on what the previous one issued and re-issues.
	at := servingNow
	for range 3 {
		at = at.AddDate(0, 11, 0)
		if reissued, err := s.Refresh(at); err != nil || !reissued {
			t.Errorf("Refresh(%v) = (%v, %v), want (true, nil)", at, reissued, err)
		}
	}
	close(stop)
	wg.Wait()
}
