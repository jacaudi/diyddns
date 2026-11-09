package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/server/agenttls"
	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

// agentListener is the agent mTLS listener under test: api.BuildAgent behind
// api.ClientCertMiddleware on a TLS 1.3 server that requests any client
// certificate, exactly as the production listener is assembled. main is the
// plain main-port harness over the same store, used only to enroll devices.
type agentListener struct {
	url  string // https://localhost:<port>
	main agentHarness
	ca   *agenttls.CA
	st   *store.Store
	logs *logCapture
}

func newAgentListener(t *testing.T) agentListener {
	t.Helper()
	st, deps := buildServerDeps(t)
	logs := &logCapture{}
	deps.Log = logs.logger()
	var ca *agenttls.CA
	withAgentMTLS(t, false, &ca)(&deps)

	mainMux := http.NewServeMux()
	api.Build(mainMux, deps)
	mainSrv := httptest.NewServer(mainMux)
	t.Cleanup(mainSrv.Close)

	serving, err := agenttls.LoadOrIssueServingCert(t.TempDir(), "localhost", ca, time.Now(), deps.Log)
	if err != nil {
		t.Fatalf("LoadOrIssueServingCert: %v", err)
	}
	agentMux := http.NewServeMux()
	api.BuildAgent(agentMux, deps)
	srv := httptest.NewUnstartedServer(api.ClientCertMiddleware(ca, st.Devices(), deps.Log)(agentMux))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // handshake rejections are expected
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAnyClientCert,
		Certificates: []tls.Certificate{serving},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return agentListener{
		url:  "https://localhost:" + port,
		main: agentHarness{srv: mainSrv, st: st, enroll: deps.Enroll, checkin: deps.Checkin},
		ca:   ca,
		st:   st,
		logs: logs,
	}
}

// client returns an HTTP client that pins the agent CA bundle, speaks TLS 1.3
// only and presents certs.
func (l agentListener) client(t *testing.T, certs ...tls.Certificate) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(l.ca.Bundle()) {
		t.Fatal("CA bundle has no certificates")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: certs}}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

// testDevice is an enrolled device holding a live recorded certificate.
type testDevice struct {
	id     string
	secret []byte
	cert   tls.Certificate
}

// newDevice enrolls a device and records a certificate from ca.IssueDevice on
// its row, as the main-port /cert flow would have.
func (l agentListener) newDevice(t *testing.T, email string) testDevice {
	t.Helper()
	id, secret := enrollViaHTTP(t, l.main, email, "laptop")
	cert := issueClientCert(t, l.ca, id)
	l.record(t, id, cert)
	return testDevice{id: id, secret: secret, cert: cert}
}

// record stores cert's serial and expiry as the device's live certificate.
func (l agentListener) record(t *testing.T, id string, cert tls.Certificate) {
	t.Helper()
	if err := l.st.Devices().SetCert(t.Context(), id, agenttls.SerialHex(cert.Leaf.SerialNumber), cert.Leaf.NotAfter.Unix()); err != nil {
		t.Fatalf("SetCert: %v", err)
	}
}

// send makes an HMAC-signed request as (id, secret) over c.
func (l agentListener) send(t *testing.T, c *http.Client, method, path, id string, secret []byte, body any) (int, []byte) {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	nonceSeq++
	return do(t, c, signedRequest(t, method, l.url, path, id, secret, raw, "agent-nonce-"+strconv.Itoa(nonceSeq)))
}

// sendUnsigned makes a request with no HMAC headers over c.
func (l agentListener) sendUnsigned(t *testing.T, c *http.Client, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, l.url+path, rd)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return do(t, c, req)
}

func do(t *testing.T, c *http.Client, req *http.Request) (int, []byte) {
	t.Helper()
	resp, err := c.Do(req.WithContext(t.Context()))
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, out
}

func newP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// issueClientCert returns a certificate from ca.IssueDevice for id together
// with the key behind it.
func issueClientCert(t *testing.T, ca *agenttls.CA, id string) tls.Certificate {
	t.Helper()
	key := newP256Key(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	issued, err := ca.IssueDevice(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), id, time.Now())
	if err != nil {
		t.Fatalf("IssueDevice: %v", err)
	}
	block, _ := pem.Decode(issued.CertPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key, Leaf: leaf}
}

// newTestCA returns a self-signed CA unrelated to the agent CA.
func newTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "unrelated CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	key := newP256Key(t)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate(CA): %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(CA): %v", err)
	}
	return cert, key
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return n.Add(n, big.NewInt(1))
}

// deviceCertTmpl is the profile of a device certificate for id, to be edited by
// a test that needs a defective one.
func deviceCertTmpl(t *testing.T, id string) *x509.Certificate {
	t.Helper()
	uri, err := url.Parse(agenttls.DeviceURIPrefix + id)
	if err != nil {
		t.Fatalf("parse URI: %v", err)
	}
	return &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: id},
		URIs:                  []*url.URL{uri},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
}

// signCert signs tmpl for a fresh key under parent.
func signCert(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, tmpl *x509.Certificate) tls.Certificate {
	t.Helper()
	key := newP256Key(t)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// wantCertRejected asserts the response is the coded 401 client_cert_rejected.
func wantCertRejected(t *testing.T, status int, body []byte) {
	t.Helper()
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
	if got := problemCode(t, body); got != shared.CodeClientCertRejected {
		t.Errorf("code = %q, want %q, body=%s", got, shared.CodeClientCertRejected, body)
	}
}

func TestAgentListener_CheckinWithCertAndHMAC(t *testing.T) {
	l := newAgentListener(t)
	d := l.newDevice(t, "agent-ok@example.com")

	status, body := l.send(t, l.client(t, d.cert), http.MethodPost, "/agent/v1/checkin", d.id, d.secret, map[string]string{"ipv4": "1.2.3.4"})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	var got checkinView
	decodeJSON(t, body, &got)
	if got.DeviceID != d.id || got.CurrentIPv4 != "1.2.3.4" {
		t.Errorf("checkin = %+v, want device %s at 1.2.3.4", got, d.id)
	}
}

func TestAgentListener_UnknownSerialIs401Coded(t *testing.T) {
	l := newAgentListener(t)
	d := l.newDevice(t, "agent-serial@example.com")
	if err := l.st.Devices().SetCert(t.Context(), d.id, "deadbeef", time.Now().AddDate(1, 0, 0).Unix()); err != nil {
		t.Fatalf("SetCert: %v", err)
	}

	status, body := l.send(t, l.client(t, d.cert), http.MethodGet, "/agent/v1/self", d.id, d.secret, nil)
	wantCertRejected(t, status, body)
}

func TestAgentListener_UnknownDeviceIs401Coded(t *testing.T) {
	l := newAgentListener(t)
	ghost := issueClientCert(t, l.ca, "no-such-device")

	status, body := l.sendUnsigned(t, l.client(t, ghost), http.MethodGet, "/agent/v1/self", "")
	wantCertRejected(t, status, body)
}

func TestAgentListener_ForeignCAIs401Coded(t *testing.T) {
	l := newAgentListener(t)
	foreignCA, foreignKey := newTestCA(t)
	// The agent CA never holds the backup private key, so stand one up: a leaf
	// signed by it is a perfect device cert and must still be refused.
	backupCA, backupKey := newTestCA(t)
	l.ca.Backup = backupCA

	tests := []struct {
		name   string
		parent *x509.Certificate
		key    *ecdsa.PrivateKey
	}{
		{"unrelated CA", foreignCA, foreignKey},
		{"backup CA key", backupCA, backupKey},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := l.newDevice(t, "agent-foreign-"+strconv.Itoa(i)+"@example.com")
			cert := signCert(t, tt.parent, tt.key, deviceCertTmpl(t, d.id))
			l.record(t, d.id, cert) // serial matches, so only the chain can fail

			status, body := l.send(t, l.client(t, cert), http.MethodGet, "/agent/v1/self", d.id, d.secret, nil)
			wantCertRejected(t, status, body)
		})
	}
}

// TestAgentListener_LeafUsageIs401Coded pins the defense in depth over
// VerifyClient: x509.Verify accepts a leaf with no ExtKeyUsage for any usage,
// and a CA flagged leaf is still a leaf to it.
func TestAgentListener_LeafUsageIs401Coded(t *testing.T) {
	l := newAgentListener(t)

	tests := []struct {
		name string
		edit func(*x509.Certificate)
	}{
		{"CA leaf", func(c *x509.Certificate) {
			c.IsCA = true
			c.KeyUsage |= x509.KeyUsageCertSign
		}},
		{"no ExtKeyUsage", func(c *x509.Certificate) { c.ExtKeyUsage = nil }},
		{"server auth only", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := l.newDevice(t, "agent-usage-"+strconv.Itoa(i)+"@example.com")
			tmpl := deviceCertTmpl(t, d.id)
			tt.edit(tmpl)
			cert := signCert(t, l.ca.Active, l.ca.ActiveKey, tmpl)
			l.record(t, d.id, cert)

			status, body := l.send(t, l.client(t, cert), http.MethodGet, "/agent/v1/self", d.id, d.secret, nil)
			wantCertRejected(t, status, body)
		})
	}
}

func TestAgentListener_CertDeviceMismatchIs401Coded(t *testing.T) {
	l := newAgentListener(t)
	a := l.newDevice(t, "agent-a@example.com")
	b := l.newDevice(t, "agent-b@example.com")

	// Device A's valid certificate, device B's valid HMAC.
	status, body := l.send(t, l.client(t, a.cert), http.MethodGet, "/agent/v1/self", b.id, b.secret, nil)
	wantCertRejected(t, status, body)
}

func TestAgentListener_NoHMACIs401Plain(t *testing.T) {
	l := newAgentListener(t)
	d := l.newDevice(t, "agent-nohmac@example.com")

	status, body := l.sendUnsigned(t, l.client(t, d.cert), http.MethodPost, "/agent/v1/checkin", `{"ipv4":"1.2.3.4"}`)
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
	if got := problemCode(t, body); got == shared.CodeClientCertRejected {
		t.Errorf("code = %q, want an HMAC 401 without the cert code, body=%s", got, body)
	}
}

// TestAgentListener_EveryRouteRequiresHMAC proves the listener never trusts the
// certificate alone: registerCheckinOps and registerCertOps rely on BuildAgent
// passing hmacMW, so a route registered without it would answer a bare cert.
func TestAgentListener_EveryRouteRequiresHMAC(t *testing.T) {
	l := newAgentListener(t)
	d := l.newDevice(t, "agent-routes@example.com")
	c := l.client(t, d.cert)

	tests := []struct{ method, path, body string }{
		{http.MethodPost, "/agent/v1/checkin", `{"ipv4":"1.2.3.4"}`},
		{http.MethodGet, "/agent/v1/self", ""},
		{http.MethodPost, "/agent/v1/cert", `{"csr":"x"}`},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			status, body := l.sendUnsigned(t, c, tt.method, tt.path, tt.body)
			if status != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401, body=%s", status, body)
			}
		})
	}
}

func TestAgentListener_OnlyThreeRoutes(t *testing.T) {
	l := newAgentListener(t)
	d := l.newDevice(t, "agent-404@example.com")
	c := l.client(t, d.cert)

	tests := []struct{ method, path string }{
		{http.MethodGet, "/agent/v1/capabilities"},
		{http.MethodPost, "/agent/v1/enroll/code"},
		{http.MethodGet, "/agent/v1/openapi.json"},
		{http.MethodGet, "/agent/v1/docs"},
		{http.MethodGet, "/api/v1/devices"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			status, body := l.send(t, c, tt.method, tt.path, d.id, d.secret, nil)
			if status != http.StatusNotFound {
				t.Errorf("status = %d, want 404, body=%s", status, body)
			}
		})
	}
}

func TestAgentListener_RenewOnAgentPort(t *testing.T) {
	l := newAgentListener(t)
	d := l.newDevice(t, "agent-renew@example.com")
	before, err := l.st.Devices().GetByID(t.Context(), d.id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}

	status, body := l.send(t, l.client(t, d.cert), http.MethodPost, "/agent/v1/cert", d.id, d.secret, map[string]string{"csr": testCSR(t)})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	after, err := l.st.Devices().GetByID(t.Context(), d.id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if after.CertSerial == before.CertSerial {
		t.Errorf("cert serial unchanged at %q after renewal", after.CertSerial)
	}
}

func TestAgentListener_NoClientCertFailsHandshake(t *testing.T) {
	l := newAgentListener(t)
	d := l.newDevice(t, "agent-nocert@example.com")

	req := signedRequest(t, http.MethodGet, l.url, "/agent/v1/self", d.id, d.secret, nil, "agent-nocert-nonce")
	resp, err := l.client(t).Do(req.WithContext(t.Context()))
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("Do succeeded with status %d, want a TLS failure", resp.StatusCode)
	}
}

// TestAgentListener_StoreErrorIs500 pins that a failing device lookup is a
// server fault: a coded 401 would make a healthy client discard its
// certificate and re-provision during a database outage.
func TestAgentListener_StoreErrorIs500(t *testing.T) {
	l := newAgentListener(t)
	d := l.newDevice(t, "agent-dberr@example.com")
	if err := l.st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	status, body := l.sendUnsigned(t, l.client(t, d.cert), http.MethodGet, "/agent/v1/self", "")
	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", status, body)
	}
	if strings.Contains(string(body), shared.CodeClientCertRejected) {
		t.Errorf("body names %q, want no cert-rejected code: %s", shared.CodeClientCertRejected, body)
	}
}

func TestAgentListener_RejectionLog(t *testing.T) {
	long := strings.Repeat("a", 200)
	tests := []struct {
		name        string
		deviceID    string
		wantReason  string
		wantClaimed string
	}{
		{"unknown device", "ghost-device", "unknown_device", "ghost-device"},
		{"over-long claim is not logged", long, "unknown_device", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newAgentListener(t)
			ghost := issueClientCert(t, l.ca, tt.deviceID)

			status, body := l.sendUnsigned(t, l.client(t, ghost), http.MethodGet, "/agent/v1/self", "")
			wantCertRejected(t, status, body)

			recs := withMsg(atLevel(l.logs.records(t), "WARN"), "agent client certificate rejected")
			if len(recs) != 1 {
				t.Fatalf("got %d rejection records, want 1: %s", len(recs), l.logs.String())
			}
			if got := recs[0]["reason"]; got != tt.wantReason {
				t.Errorf("reason = %v, want %q", got, tt.wantReason)
			}
			if got := recs[0]["claimed_device_id"]; got != tt.wantClaimed {
				t.Errorf("claimed_device_id = %v, want %q", got, tt.wantClaimed)
			}
		})
	}
}

// TestAgentListener_CertRejectionCarriesTheChallenge: the coded 401 from both
// places the agent port rejects a client certificate (ClientCertMiddleware and
// certBindingMW) names the agent port's credential, HMAC (RFC 9110 §15.5.2, #191).
func TestAgentListener_CertRejectionCarriesTheChallenge(t *testing.T) {
	l := newAgentListener(t)
	a := l.newDevice(t, "agent-challenge-a@example.com")
	b := l.newDevice(t, "agent-challenge-b@example.com")
	ghost := issueClientCert(t, l.ca, "no-such-device")

	tests := []struct {
		name string
		cert tls.Certificate
		req  *http.Request
	}{
		{"certificate names no device", ghost,
			signedRequest(t, http.MethodGet, l.url, "/agent/v1/self", a.id, a.secret, nil, "challenge-nonce-1")},
		{"certificate and HMAC name different devices", a.cert,
			signedRequest(t, http.MethodGet, l.url, "/agent/v1/self", b.id, b.secret, nil, "challenge-nonce-2")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := l.client(t, tt.cert).Do(tt.req.WithContext(t.Context()))
			if err != nil {
				t.Fatalf("%s: %v", tt.req.URL.Path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if got := resp.Header.Get("WWW-Authenticate"); got != challengeHMAC {
				t.Errorf("WWW-Authenticate = %q, want %q", got, challengeHMAC)
			}
		})
	}
}
