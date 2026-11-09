package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/server/agenttls"
	"github.com/jacaudi/diyddns/internal/store"
)

const testAgentURL = "https://ddns.example.com:8443"

// newCertSvc returns a CertService over a real agenttls CA in a temp dir, plus
// the store and one seeded device.
func newCertSvc(t *testing.T) (*store.Store, *CertService, *agenttls.CA, store.Device) {
	t.Helper()
	st := openTestStore(t)
	ca, err := agenttls.LoadOrInit(t.Context(), st, t.TempDir(), time.Now(), discardLogger())
	if err != nil {
		t.Fatalf("LoadOrInit: %v", err)
	}
	usr := seedUser(t, st, "owner@x", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	return st, NewCertService(st, ca, testAgentURL, NewAuditWriter(st)), ca, dev
}

// testCSR returns a PEM CSR over a fresh ECDSA P-256 key.
func testCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func getDevice(t *testing.T, st *store.Store, id string) store.Device {
	t.Helper()
	d, err := st.Devices().GetByID(t.Context(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	return d
}

// certIssuedDetails is the shape of a device.cert_issued audit row's details.
type certIssuedDetails struct {
	Listener string `json:"listener"`
	Serial   string `json:"serial"`
	NotAfter int64  `json:"not_after"`
}

func parseCertPEM(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("no PEM block in %q", certPEM)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return c
}

func TestCertService_MainIssuesWhenNone(t *testing.T) {
	st, svc, ca, dev := newCertSvc(t)

	got, err := svc.Issue(t.Context(), dev.ID, testCSR(t), CertListenerMain)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got.CertificatePEM == "" || got.CABundlePEM == "" {
		t.Fatalf("empty PEM in %+v", got)
	}
	if got.CABundlePEM != string(ca.Bundle()) {
		t.Fatalf("CABundlePEM = %q, want the CA bundle", got.CABundlePEM)
	}
	if got.AgentURL != testAgentURL {
		t.Fatalf("AgentURL = %q, want %q", got.AgentURL, testAgentURL)
	}
	leaf := parseCertPEM(t, got.CertificatePEM)
	serial := agenttls.SerialHex(leaf.SerialNumber)

	row := getDevice(t, st, dev.ID)
	if row.CertSerial != serial || row.CertNotAfter != leaf.NotAfter.Unix() {
		t.Fatalf("row cert = (%q, %d), want (%q, %d)", row.CertSerial, row.CertNotAfter, serial, leaf.NotAfter.Unix())
	}

	rows := adminAuditRows(t, st, "device.cert_issued")
	if len(rows) != 1 {
		t.Fatalf("device.cert_issued rows = %d, want 1", len(rows))
	}
	if rows[0].TargetType != "device" || rows[0].TargetID != dev.ID {
		t.Fatalf("row = %+v, want target device/%s", rows[0], dev.ID)
	}
	var d certIssuedDetails
	if err := json.Unmarshal([]byte(rows[0].DetailsJSON), &d); err != nil {
		t.Fatalf("DetailsJSON %q: %v", rows[0].DetailsJSON, err)
	}
	if want := (certIssuedDetails{Listener: "main", Serial: serial, NotAfter: leaf.NotAfter.Unix()}); d != want {
		t.Fatalf("details = %+v, want %+v", d, want)
	}
}

func TestCertService_MainLiveIs409(t *testing.T) {
	st, svc, _, dev := newCertSvc(t)
	if _, err := svc.Issue(t.Context(), dev.ID, testCSR(t), CertListenerMain); err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	before := getDevice(t, st, dev.ID)

	_, err := svc.Issue(t.Context(), dev.ID, testCSR(t), CertListenerMain)
	if !errors.Is(err, ErrCertAlreadyIssued) {
		t.Fatalf("err = %v, want ErrCertAlreadyIssued", err)
	}
	if n := len(adminAuditRows(t, st, "device.cert_issued")); n != 1 {
		t.Fatalf("device.cert_issued rows = %d, want 1", n)
	}
	if after := getDevice(t, st, dev.ID); after.CertSerial != before.CertSerial || after.CertNotAfter != before.CertNotAfter {
		t.Fatalf("row changed: %+v -> %+v", before, after)
	}
}

func TestCertService_MainAfterExpiryIssues(t *testing.T) {
	st, svc, _, dev := newCertSvc(t)
	if _, err := svc.Issue(t.Context(), dev.ID, testCSR(t), CertListenerMain); err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	old := getDevice(t, st, dev.ID)
	svc.now = func() time.Time { return time.Unix(old.CertNotAfter, 0).Add(time.Second) }

	if _, err := svc.Issue(t.Context(), dev.ID, testCSR(t), CertListenerMain); err != nil {
		t.Fatalf("Issue after expiry: %v", err)
	}
	if now := getDevice(t, st, dev.ID); now.CertSerial == old.CertSerial {
		t.Fatalf("serial unchanged after reissue: %q", now.CertSerial)
	}
}

func TestCertService_AgentAlwaysIssues(t *testing.T) {
	st, svc, _, dev := newCertSvc(t)
	if _, err := svc.Issue(t.Context(), dev.ID, testCSR(t), CertListenerMain); err != nil {
		t.Fatalf("main Issue: %v", err)
	}
	old := getDevice(t, st, dev.ID)

	got, err := svc.Issue(t.Context(), dev.ID, testCSR(t), CertListenerAgent)
	if err != nil {
		t.Fatalf("agent Issue: %v", err)
	}
	serial := agenttls.SerialHex(parseCertPEM(t, got.CertificatePEM).SerialNumber)
	if now := getDevice(t, st, dev.ID); now.CertSerial != serial || serial == old.CertSerial {
		t.Fatalf("row serial = %q, want new serial %q (old %q)", now.CertSerial, serial, old.CertSerial)
	}
	rows := adminAuditRows(t, st, "device.cert_issued")
	if len(rows) != 2 {
		t.Fatalf("device.cert_issued rows = %d, want 2", len(rows))
	}
	var d certIssuedDetails // newest first
	if err := json.Unmarshal([]byte(rows[0].DetailsJSON), &d); err != nil {
		t.Fatalf("DetailsJSON %q: %v", rows[0].DetailsJSON, err)
	}
	if d.Listener != "agent" || d.Serial != serial {
		t.Fatalf("details = %+v, want listener=agent serial=%s", d, serial)
	}
}

func TestCertService_MainRaceSecondIs409(t *testing.T) {
	st, svc, _, dev := newCertSvc(t)
	csrs := [2][]byte{testCSR(t), testCSR(t)}

	var wg sync.WaitGroup
	errs := make([]error, len(csrs))
	for i := range csrs {
		wg.Go(func() {
			_, errs[i] = svc.Issue(t.Context(), dev.ID, csrs[i], CertListenerMain)
		})
	}
	wg.Wait()

	var ok, conflict int
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrCertAlreadyIssued):
			conflict++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("ok=%d conflict=%d, want 1 and 1 (errs %v)", ok, conflict, errs)
	}
	if n := len(adminAuditRows(t, st, "device.cert_issued")); n != 1 {
		t.Fatalf("device.cert_issued rows = %d, want 1", n)
	}
}

func TestCertService_BadCSR(t *testing.T) {
	st, svc, _, dev := newCertSvc(t)

	_, err := svc.Issue(t.Context(), dev.ID, []byte("not a csr"), CertListenerMain)
	if !errors.Is(err, agenttls.ErrBadCSR) {
		t.Fatalf("err = %v, want ErrBadCSR", err)
	}
	if row := getDevice(t, st, dev.ID); row.CertSerial != "" || row.CertNotAfter != 0 {
		t.Fatalf("row written despite bad CSR: %+v", row)
	}
	if n := len(adminAuditRows(t, st, "device.cert_issued")); n != 0 {
		t.Fatalf("device.cert_issued rows = %d, want 0", n)
	}
}

// The store's compare-and-set no longer tells a missing device from a live
// certificate (#8), so the not-found answer must come from Issue's own read.
func TestCertService_UnknownDeviceNotFound(t *testing.T) {
	for _, l := range []CertListener{CertListenerMain, CertListenerAgent} {
		t.Run(string(l), func(t *testing.T) {
			st, svc, _, _ := newCertSvc(t)

			_, err := svc.Issue(t.Context(), "no-such-device", testCSR(t), l)
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("err = %v, want store.ErrNotFound", err)
			}
			if n := len(adminAuditRows(t, st, "device.cert_issued")); n != 0 {
				t.Fatalf("device.cert_issued rows = %d, want 0", n)
			}
		})
	}
}
