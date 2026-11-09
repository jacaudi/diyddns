package checkin

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/shared"
)

// serverCheckinBody mirrors the SERVER's wire tags (internal/server/api/checkin.go)
// so the test guards the D7-duplicated contract against tag drift (SGE I2).
type serverCheckinBody struct {
	IPv4          string `json:"ipv4,omitempty"`
	IPv6          string `json:"ipv6,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	OS            string `json:"os,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
}

func TestClient_Checkin_SignsAndParsesFieldParity(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	secretB64 := base64.StdEncoding.EncodeToString(key)
	const deviceID = "dev-123"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// (a) Verify the client's signature exactly as the server would.
		canonical := shared.CanonicalRequest(r.Method, r.URL.Path,
			r.Header.Get(shared.HeaderTimestamp), r.Header.Get(shared.HeaderNonce), shared.BodyHashHex(body))
		if got, want := r.Header.Get(shared.HeaderSignature), shared.Sign(key, canonical); got != want {
			t.Errorf("signature mismatch: got %s want %s", got, want)
		}
		if r.Header.Get(shared.HeaderDevice) != deviceID {
			t.Errorf("device header = %q", r.Header.Get(shared.HeaderDevice))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		// (b) Tag-parity: body decodes into the SERVER's struct with expected fields.
		var sb serverCheckinBody
		if err := json.Unmarshal(body, &sb); err != nil {
			t.Fatalf("server-side decode: %v", err)
		}
		if sb.IPv4 != "203.0.113.7" || sb.IPv6 != "" {
			t.Errorf("decoded body = %+v, want IPv4 only", sb)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_id": deviceID, "current_ipv4": "203.0.113.7", "current_ipv6": "", "stored": true,
		})
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, deviceID, secretB64, Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) } // white-box seam
	res, err := c.Checkin(t.Context(), Report{IPv4: "203.0.113.7"})
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if !res.Stored || res.CurrentIPv4 != "203.0.113.7" {
		t.Errorf("Result = %+v", res)
	}
}

func TestNewClient_BadSecret(t *testing.T) {
	if _, err := NewClient("https://x", "d", "!!!not-base64!!!", Options{}); err == nil {
		t.Error("want error for non-base64 secret")
	}
}

func TestClient_Checkin_StatusMapping(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	for _, tt := range []struct {
		code    int
		wantErr error
	}{
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusInternalServerError, ErrServer},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tt.code)
		}))
		c, _ := NewClient(srv.URL, "d", key, Options{})
		_, err := c.Checkin(t.Context(), Report{IPv4: "203.0.113.7"})
		if !errors.Is(err, tt.wantErr) {
			t.Errorf("status %d → err %v, want %v", tt.code, err, tt.wantErr)
		}
		srv.Close()
	}
}

const (
	testDeviceID = "dev-123"
	testSecret   = "0123456789abcdef0123456789abcdef"
)

// newCodedClient serves status and body for every request and returns a client
// pointed at it.
func newCodedClient(t *testing.T, status int, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, testDeviceID, base64.StdEncoding.EncodeToString([]byte(testSecret)), Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// verifySigned checks r carries the HMAC headers for body, exactly as the
// server verifies them.
func verifySigned(t *testing.T, r *http.Request, body []byte) {
	t.Helper()
	canonical := shared.CanonicalRequest(r.Method, r.URL.Path,
		r.Header.Get(shared.HeaderTimestamp), r.Header.Get(shared.HeaderNonce), shared.BodyHashHex(body))
	if got, want := r.Header.Get(shared.HeaderSignature), shared.Sign([]byte(testSecret), canonical); got != want {
		t.Errorf("signature mismatch: got %q want %q", got, want)
	}
	if got := r.Header.Get(shared.HeaderDevice); got != testDeviceID {
		t.Errorf("device header = %q, want %q", got, testDeviceID)
	}
	if r.Header.Get(shared.HeaderNonce) == "" || r.Header.Get(shared.HeaderTimestamp) == "" {
		t.Errorf("missing nonce or timestamp header")
	}
}

func checkinErr(t *testing.T, status int, body string) error {
	t.Helper()
	_, err := newCodedClient(t, status, body).Checkin(t.Context(), Report{IPv4: "203.0.113.7"})
	return err
}

// A cert rejection on the agent port is not a rejected HMAC credential: the
// poller's 3-strike ErrUnauthorized stop must not see it.
func TestCheckin_401CodedIsNotErrUnauthorized(t *testing.T) {
	err := checkinErr(t, 401, `{"code":"client_cert_rejected"}`)
	if !errors.Is(err, ErrClientCertRejected) {
		t.Errorf("err = %v, want ErrClientCertRejected", err)
	}
	if errors.Is(err, ErrUnauthorized) {
		t.Errorf("err = %v must not match ErrUnauthorized", err)
	}
}

func TestCheckin_401PlainIsErrUnauthorized(t *testing.T) {
	for _, body := range []string{``, `{"detail":"unauthorized"}`} {
		err := checkinErr(t, 401, body)
		if !errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrClientCertRejected) {
			t.Errorf("body %q: err = %v, want ErrUnauthorized only", body, err)
		}
	}
}

func TestCheckin_403MTLSRequired(t *testing.T) {
	err := checkinErr(t, 403, `{"code":"mtls_required","detail":"this server requires mTLS on the agent port: upgrade this client"}`)
	if !errors.Is(err, ErrMTLSRequired) {
		t.Fatalf("err = %v, want ErrMTLSRequired", err)
	}
	if got, want := err.Error(), "checkin: server requires mTLS: upgrade this client"; got != want {
		t.Errorf("err = %q, want %q", got, want)
	}
}

func TestCheckin_403UncodedIsServerError(t *testing.T) {
	err := checkinErr(t, 403, `{"detail":"nope"}`)
	if !errors.Is(err, ErrServer) || errors.Is(err, ErrMTLSRequired) {
		t.Errorf("err = %v, want ErrServer only", err)
	}
}

func TestCheckin_OtherStatusIncludesDetail(t *testing.T) {
	err := checkinErr(t, 500, `{"detail":"check-in failed"}`)
	if !errors.Is(err, ErrServer) {
		t.Fatalf("err = %v, want ErrServer", err)
	}
	for _, want := range []string{"check-in failed", "500"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to contain %q", err, want)
		}
	}
}

func TestCheckin_NonJSONErrorBodyIsServerError(t *testing.T) {
	if err := checkinErr(t, 500, `<html>boom</html>`); !errors.Is(err, ErrServer) {
		t.Errorf("err = %v, want ErrServer", err)
	}
}

func TestSelf_SignedGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/agent/v1/self" {
			t.Errorf("request = %s %s, want GET /agent/v1/self", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Errorf("body = %q, want empty", body)
		}
		verifySigned(t, r, nil)
		_ = json.NewEncoder(w).Encode(map[string]any{"device_id": testDeviceID})
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, testDeviceID, base64.StdEncoding.EncodeToString([]byte(testSecret)), Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Self(t.Context()); err != nil {
		t.Fatalf("Self: %v", err)
	}
}

func TestSelf_ClientCertRejected(t *testing.T) {
	c := newCodedClient(t, 401, `{"code":"client_cert_rejected"}`)
	if err := c.Self(t.Context()); !errors.Is(err, ErrClientCertRejected) {
		t.Errorf("Self err = %v, want ErrClientCertRejected", err)
	}
}

func TestRequestCert_RoundTrip(t *testing.T) {
	const csr = "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/agent/v1/cert" {
			t.Errorf("request = %s %s, want POST /agent/v1/cert", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		verifySigned(t, r, body)
		var in struct {
			CSR string `json:"csr"`
		}
		if err := json.Unmarshal(body, &in); err != nil || in.CSR != csr {
			t.Errorf("body = %q (decode err %v), want csr %q", body, err, csr)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificate": "CERT", "ca_bundle": "BUNDLE", "agent_url": "https://ddns.example.com:8443",
		})
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, testDeviceID, base64.StdEncoding.EncodeToString([]byte(testSecret)), Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got, err := c.RequestCert(t.Context(), []byte(csr))
	if err != nil {
		t.Fatalf("RequestCert: %v", err)
	}
	want := CertResponse{Certificate: "CERT", CABundle: "BUNDLE", AgentURL: "https://ddns.example.com:8443"}
	if got != want {
		t.Errorf("RequestCert = %+v, want %+v", got, want)
	}
}

func TestRequestCert_ErrorMapping(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"409 coded", 409, `{"code":"cert_already_issued","detail":"x"}`, ErrCertAlreadyIssued},
		{"401 plain", 401, `{"detail":"unauthorized"}`, ErrUnauthorized},
		{"400 bad csr", 400, `{"detail":"invalid CSR"}`, ErrServer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCodedClient(t, tt.status, tt.body)
			if _, err := c.RequestCert(t.Context(), []byte("csr")); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestRequestCert_BadSuccessBody(t *testing.T) {
	c := newCodedClient(t, 200, `not json`)
	if _, err := c.RequestCert(t.Context(), []byte("csr")); err == nil {
		t.Error("want decode error for a non-JSON 200 body")
	}
}

func TestNewClient_TLSConfigOverridesCACert(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"device_id": testDeviceID})
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	c, err := NewClient(srv.URL, testDeviceID, base64.StdEncoding.EncodeToString([]byte(testSecret)), Options{
		CACertPath: filepath.Join(t.TempDir(), "missing.pem"), // ignored when TLSConfig is set
		TLSConfig:  &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Self(t.Context()); err != nil {
		t.Fatalf("Self over pinned TLS: %v", err)
	}
}

func TestClient_BaseURL(t *testing.T) {
	c, err := NewClient("https://ddns.example.com:8443/", testDeviceID, base64.StdEncoding.EncodeToString([]byte(testSecret)), Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got, want := c.BaseURL(), "https://ddns.example.com:8443"; got != want {
		t.Errorf("BaseURL = %q, want %q", got, want)
	}
}

// ipSourceClient serves status 200 with body and records the posted body.
func ipSourceClient(t *testing.T, body string, posted *string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if posted != nil {
			*posted = string(b)
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, testDeviceID, base64.StdEncoding.EncodeToString([]byte(testSecret)), Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestCheckinDecodesIPSource(t *testing.T) {
	tests := []struct {
		name string
		body string
		want IPSource
	}{
		{"observed v4", `{"device_id":"d","ip_source":{"ipv4":"observed"}}`, IPSource{IPv4: "observed"}},
		{"both families", `{"ip_source":{"ipv4":"reported","ipv6":"none"}}`, IPSource{IPv4: "reported", IPv6: "none"}},
		{"old server, no ip_source", `{"device_id":"d","stored":true}`, IPSource{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ipSourceClient(t, tt.body, nil).Checkin(t.Context(), Report{})
			if err != nil {
				t.Fatalf("Checkin: %v", err)
			}
			if res.IPSource != tt.want {
				t.Errorf("IPSource = %+v, want %+v", res.IPSource, tt.want)
			}
		})
	}
}

func TestCheckinEmptyReportSendsEmptyObject(t *testing.T) {
	var posted string
	if _, err := ipSourceClient(t, `{}`, &posted).Checkin(t.Context(), Report{}); err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if posted != `{}` {
		t.Errorf("posted body = %q, want %q", posted, `{}`)
	}
}

// localhostServer serves a check-in 200 on 127.0.0.1 only and returns its URL
// with the host spelled "localhost", which resolves to both families.
func localhostServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"device_id":"d"}`)
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	return "http://localhost:" + port
}

func TestNetworkPinsDial(t *testing.T) {
	base := localhostServer(t)
	secret := base64.StdEncoding.EncodeToString([]byte(testSecret))

	c6, err := NewClient(base, testDeviceID, secret, Options{Network: "tcp6"})
	if err != nil {
		t.Fatalf("NewClient tcp6: %v", err)
	}
	if _, err := c6.Checkin(t.Context(), Report{}); !IsDialSkip(err) {
		t.Errorf("tcp6 against an IPv4-only listener: IsDialSkip(%v) = false, want true", err)
	}

	c4, err := NewClient(base, testDeviceID, secret, Options{Network: "tcp4"})
	if err != nil {
		t.Fatalf("NewClient tcp4: %v", err)
	}
	if _, err := c4.Checkin(t.Context(), Report{}); err != nil {
		t.Errorf("tcp4 against an IPv4 listener: %v", err)
	}
}

func TestNewClientRejectsUnknownNetwork(t *testing.T) {
	_, err := NewClient("http://x", testDeviceID, base64.StdEncoding.EncodeToString([]byte(testSecret)), Options{Network: "udp"})
	if err == nil {
		t.Fatal("want error for Network \"udp\"")
	}
}

func TestPinnedDialerTimeout(t *testing.T) {
	if PinnedDialTimeout != 5*time.Second {
		t.Errorf("PinnedDialTimeout = %v, want 5s", PinnedDialTimeout)
	}
	if got := newPinnedDialer("tcp6").Timeout; got != PinnedDialTimeout {
		t.Errorf("newPinnedDialer(tcp6).Timeout = %v, want %v", got, PinnedDialTimeout)
	}
}

func TestNewClientTransportNotShared(t *testing.T) {
	pool := x509.NewCertPool()
	tc := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	secret := base64.StdEncoding.EncodeToString([]byte(testSecret))
	a, err := NewClient("https://x", testDeviceID, secret, Options{TLSConfig: tc, Network: "tcp4"})
	if err != nil {
		t.Fatalf("NewClient a: %v", err)
	}
	b, err := NewClient("https://x", testDeviceID, secret, Options{TLSConfig: tc, Network: "tcp6"})
	if err != nil {
		t.Fatalf("NewClient b: %v", err)
	}
	ta, tb := a.http.Transport.(*http.Transport), b.http.Transport.(*http.Transport)
	if ta == tb {
		t.Error("two clients share one *http.Transport")
	}
	if ta.TLSClientConfig == tb.TLSClientConfig || ta.TLSClientConfig == tc {
		t.Error("a *tls.Config is shared across transports; net/http mutates it when it enables h2")
	}
	if ta.TLSClientConfig.RootCAs != pool || ta.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Error("the transport's TLS config is not a copy of Options.TLSConfig")
	}
}

func TestIsDialSkip(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"dial deadline exceeded", &url.Error{Err: &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}}, true},
		{"wrapped dial refusal", fmt.Errorf("checkin: POST: %w", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}), true},
		{"read error", &url.Error{Err: &net.OpError{Op: "read"}}, false},
		{"unauthorized", ErrUnauthorized, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDialSkip(tt.err); got != tt.want {
				t.Errorf("IsDialSkip(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
