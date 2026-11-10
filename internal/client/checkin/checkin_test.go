package checkin

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/shared"
)

// serverCheckinBody mirrors the SERVER's wire tags (internal/server/api/checkin.go)
// so the test guards the D7-duplicated contract against tag drift (SGE I2).
type serverCheckinBody struct {
	IPv4          string   `json:"ipv4,omitempty"`
	IPv6          string   `json:"ipv6,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	OS            string   `json:"os,omitempty"`
	ClientVersion string   `json:"client_version,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
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

	c, err := NewClient(srv.URL, deviceID, mustKeys(t, secretB64), Options{})
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

func TestNewKeys_Bad(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte(testSecret))
	tests := []struct {
		name, secret, pending, want string
	}{
		{"bad secret", "!!!not-base64!!!", "", "checkin: secret is not valid base64"},
		{"empty secret", "", "", "checkin: secret is not valid base64"},
		{"bad pending", good, "!!!not-base64!!!", "checkin: pending secret is not valid base64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewKeys(tt.secret, tt.pending); err == nil || err.Error() != tt.want {
				t.Errorf("NewKeys err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestNewKeys_Good(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	k, err := NewKeys(b64(keyA), "")
	if err != nil {
		t.Fatalf("NewKeys: %v", err)
	}
	if !bytes.Equal(k.Current, keyA) || k.Pending != nil {
		t.Errorf("keys = %s with Pending %v, want Current A and nil Pending", k, k.Pending)
	}
	if k, err = NewKeys(b64(keyA), b64(keyB)); err != nil {
		t.Fatalf("NewKeys with pending: %v", err)
	}
	if !bytes.Equal(k.Current, keyA) || !bytes.Equal(k.Pending, keyB) {
		t.Errorf("keys = %s, want Current A and Pending B", k)
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
		c, _ := NewClient(srv.URL, "d", mustKeys(t, key), Options{})
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

var testSecretB64 = base64.StdEncoding.EncodeToString([]byte(testSecret))

// mustKeys builds a Keys from a wire-base64 secret with no pending secret.
func mustKeys(t *testing.T, secretB64 string) *Keys {
	t.Helper()
	k, err := NewKeys(secretB64, "")
	if err != nil {
		t.Fatalf("NewKeys: %v", err)
	}
	return k
}

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
	c, err := NewClient(srv.URL, testDeviceID, mustKeys(t, testSecretB64), Options{})
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

	c, err := NewClient(srv.URL, testDeviceID, mustKeys(t, testSecretB64), Options{})
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

	c, err := NewClient(srv.URL, testDeviceID, mustKeys(t, testSecretB64), Options{})
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

	c, err := NewClient(srv.URL, testDeviceID, mustKeys(t, testSecretB64), Options{
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
	c, err := NewClient("https://ddns.example.com:8443/", testDeviceID, mustKeys(t, testSecretB64), Options{})
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
	c, err := NewClient(srv.URL, testDeviceID, mustKeys(t, testSecretB64), Options{})
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

	c6, err := NewClient(base, testDeviceID, mustKeys(t, secret), Options{Network: "tcp6"})
	if err != nil {
		t.Fatalf("NewClient tcp6: %v", err)
	}
	if _, err := c6.Checkin(t.Context(), Report{}); !IsDialSkip(err) {
		t.Errorf("tcp6 against an IPv4-only listener: IsDialSkip(%v) = false, want true", err)
	}

	c4, err := NewClient(base, testDeviceID, mustKeys(t, secret), Options{Network: "tcp4"})
	if err != nil {
		t.Fatalf("NewClient tcp4: %v", err)
	}
	if _, err := c4.Checkin(t.Context(), Report{}); err != nil {
		t.Errorf("tcp4 against an IPv4 listener: %v", err)
	}
}

func TestNewClientRejectsUnknownNetwork(t *testing.T) {
	_, err := NewClient("http://x", testDeviceID, mustKeys(t, testSecretB64), Options{Network: "udp"})
	if err == nil {
		t.Fatal("want error for Network \"udp\"")
	}
}

func TestPinnedDialerTimeout(t *testing.T) {
	if PinnedDialTimeout != 5*time.Second {
		t.Errorf("PinnedDialTimeout = %v, want 5s", PinnedDialTimeout)
	}
	if got := newPinnedDialer().Timeout; got != PinnedDialTimeout {
		t.Errorf("newPinnedDialer().Timeout = %v, want %v", got, PinnedDialTimeout)
	}
}

func TestNewClientTransportNotShared(t *testing.T) {
	pool := x509.NewCertPool()
	tc := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	secret := base64.StdEncoding.EncodeToString([]byte(testSecret))
	a, err := NewClient("https://x", testDeviceID, mustKeys(t, secret), Options{TLSConfig: tc, Network: "tcp4"})
	if err != nil {
		t.Fatalf("NewClient a: %v", err)
	}
	b, err := NewClient("https://x", testDeviceID, mustKeys(t, secret), Options{TLSConfig: tc, Network: "tcp6"})
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

var keyA, keyB = bytes.Repeat([]byte{0xA}, 32), bytes.Repeat([]byte{0xB}, 32)

// keySrv answers check-in-shaped requests and records which of its known keys
// signed each one.
type keySrv struct {
	URL     string
	accept  map[string]bool
	fail500 string

	mu         sync.Mutex
	signedWith []string // per request: the matching key's name, "" if none
	routes     []string
	secretBody string
	override   func(route string) (status int, code string)
}

// keyServer starts a server that names the known key behind each request's
// signature. It answers 500 to fail500's key, 401 to any key not in accept and
// 200 otherwise; srv.setOverride can force a status per route first.
func keyServer(t *testing.T, known map[string][]byte, accept map[string]bool, fail500 string) *keySrv {
	t.Helper()
	s := &keySrv{accept: accept, fail500: fail500}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		canonical := shared.CanonicalRequest(r.Method, r.URL.Path,
			r.Header.Get(shared.HeaderTimestamp), r.Header.Get(shared.HeaderNonce), shared.BodyHashHex(body))
		name := ""
		for n, k := range known {
			if shared.Sign(k, canonical) == r.Header.Get(shared.HeaderSignature) {
				name = n
			}
		}
		route := r.Method + " " + r.URL.Path
		s.mu.Lock()
		s.signedWith = append(s.signedWith, name)
		s.routes = append(s.routes, route)
		if route == "POST /agent/v1/rotation/secret" {
			s.secretBody = string(body)
		}
		override := s.override
		s.mu.Unlock()

		if override != nil {
			if status, code := override(route); status != 0 {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
				return
			}
		}
		switch {
		case s.fail500 != "" && name == s.fail500:
			w.WriteHeader(http.StatusInternalServerError)
		case !s.accept[name]:
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"device_id":"d","rotation":{"secret":false,"cert":false}}`)
		}
	}))
	t.Cleanup(ts.Close)
	s.URL = ts.URL
	return s
}

func (s *keySrv) setOverride(f func(route string) (int, string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.override = f
}

func (s *keySrv) signed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.signedWith)
}

func (s *keySrv) step3() (routes []string, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.routes), s.secretBody
}

var knownKeys = map[string][]byte{"A": keyA, "B": keyB}

func keyClient(t *testing.T, srv *keySrv, keys *Keys) *Client {
	t.Helper()
	c, err := NewClient(srv.URL, testDeviceID, keys, Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func wantSigned(t *testing.T, srv *keySrv, want ...string) {
	t.Helper()
	if got := srv.signed(); !slices.Equal(got, want) {
		t.Errorf("signed with %q, want %q", got, want)
	}
}

func TestKeys_PendingFirstThenCurrent(t *testing.T) {
	srv := keyServer(t, knownKeys, map[string]bool{"A": true}, "")
	keys := &Keys{Current: keyA, Pending: keyB}
	if _, err := keyClient(t, srv, keys).Checkin(t.Context(), Report{}); err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	wantSigned(t, srv, "B", "A")
	if !bytes.Equal(keys.Current, keyA) || !bytes.Equal(keys.Pending, keyB) {
		t.Errorf("keys = %s, want both kept", keys)
	}
}

func TestKeys_PendingAcceptedPromotes(t *testing.T) {
	srv := keyServer(t, knownKeys, map[string]bool{"B": true}, "")
	calls := 0
	keys := &Keys{Current: keyA, Pending: keyB, Promoted: func() error { calls++; return nil }}
	if _, err := keyClient(t, srv, keys).Checkin(t.Context(), Report{}); err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	wantSigned(t, srv, "B")
	if calls != 1 {
		t.Errorf("Promoted calls = %d, want 1", calls)
	}
	if !bytes.Equal(keys.Current, keyB) || keys.Pending != nil {
		t.Errorf("keys = %s, want Current B and no pending", keys)
	}
}

func TestKeys_BothRejectedIsErrUnauthorized(t *testing.T) {
	srv := keyServer(t, knownKeys, map[string]bool{}, "")
	keys := &Keys{Current: keyA, Pending: keyB}
	_, err := keyClient(t, srv, keys).Checkin(t.Context(), Report{})
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
	wantSigned(t, srv, "B", "A")
}

func TestKeys_PromotedErrorFailsRequest(t *testing.T) {
	srv := keyServer(t, knownKeys, map[string]bool{"B": true}, "")
	keys := &Keys{Current: keyA, Pending: keyB, Promoted: func() error { return errors.New("disk full") }}
	_, err := keyClient(t, srv, keys).Checkin(t.Context(), Report{})
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("err = %v, want it to carry %q", err, "disk full")
	}
	if !bytes.Equal(keys.Current, keyB) {
		t.Errorf("Current = %x, want B: the swap precedes the save so memory matches the server", keys.Current)
	}
}

func TestKeys_ServerErrorOnPendingKeepsBoth(t *testing.T) {
	srv := keyServer(t, knownKeys, map[string]bool{"A": true, "B": true}, "B")
	keys := &Keys{Current: keyA, Pending: keyB}
	_, err := keyClient(t, srv, keys).Checkin(t.Context(), Report{})
	if !errors.Is(err, ErrServer) {
		t.Errorf("err = %v, want ErrServer", err)
	}
	wantSigned(t, srv, "B")
	if !bytes.Equal(keys.Current, keyA) || !bytes.Equal(keys.Pending, keyB) {
		t.Errorf("keys = %s, want both kept", keys)
	}
}

func TestKeys_SharedAcrossClients(t *testing.T) {
	srv := keyServer(t, knownKeys, map[string]bool{"B": true}, "")
	calls := 0
	keys := &Keys{Current: keyA, Pending: keyB, Promoted: func() error { calls++; return nil }}
	c1, c2 := keyClient(t, srv, keys), keyClient(t, srv, keys)
	if _, err := c1.Checkin(t.Context(), Report{}); err != nil {
		t.Fatalf("c1 Checkin: %v", err)
	}
	if err := c2.Self(t.Context()); err != nil {
		t.Fatalf("c2 Self: %v", err)
	}
	wantSigned(t, srv, "B", "B") // c2 never tried A
	if calls != 1 {
		t.Errorf("Promoted calls = %d, want 1 across both clients", calls)
	}
}

func TestKeys_RedactedInFormatting(t *testing.T) {
	keys := &Keys{Current: keyA, Pending: keyB}
	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("keys", "keys", keys)
	outs := []string{fmt.Sprint(keys), logged.String()}
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		outs = append(outs, fmt.Sprintf(f, keys))
	}
	secrets := []string{
		hex.EncodeToString(keyA), hex.EncodeToString(keyB),
		base64.StdEncoding.EncodeToString(keyA), base64.StdEncoding.EncodeToString(keyB),
	}
	for _, out := range outs {
		if !strings.Contains(out, "pending:set") {
			t.Errorf("output %q lacks %q", out, "pending:set")
		}
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("output %q leaks key material %q", out, s)
			}
		}
	}
	if got, want := (&Keys{Current: keyA}).String(), "checkin.Keys{current:set, pending:none}"; got != want {
		t.Errorf("String = %q, want %q", got, want)
	}
}

func TestSubmitPendingSecret(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   string
		want   error
	}{
		{"accepted", 0, "", nil},
		{"409 coded", http.StatusConflict, shared.CodeNoSecretRotationPending, ErrNoSecretRotationPending},
		{"409 uncoded", http.StatusConflict, "", ErrServer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := keyServer(t, knownKeys, map[string]bool{"A": true}, "")
			srv.setOverride(func(string) (int, string) { return tt.status, tt.code })
			keys := &Keys{Current: keyA, Pending: keyB}
			err := keyClient(t, srv, keys).SubmitPendingSecret(t.Context())
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
			if got := errors.Is(err, ErrNoSecretRotationPending); got != errors.Is(tt.want, ErrNoSecretRotationPending) {
				t.Errorf("errors.Is(err, ErrNoSecretRotationPending) = %v for %v", got, err)
			}
			wantSigned(t, srv, "A") // Current only, never Pending
			routes, body := srv.step3()
			if want := []string{"POST /agent/v1/rotation/secret"}; !slices.Equal(routes, want) {
				t.Errorf("routes = %q, want %q", routes, want)
			}
			if want := `{"secret":"` + base64.StdEncoding.EncodeToString(keyB) + `"}`; body != want {
				t.Errorf("body = %s, want %s", body, want)
			}
		})
	}
}

func TestSubmitPendingSecret_NoPendingSendsNothing(t *testing.T) {
	srv := keyServer(t, knownKeys, map[string]bool{"A": true}, "")
	err := keyClient(t, srv, &Keys{Current: keyA}).SubmitPendingSecret(t.Context())
	if err == nil {
		t.Error("want an error with no pending secret")
	}
	wantSigned(t, srv)
}

func TestCheckin_CapabilitiesOnlyWhenSet(t *testing.T) {
	tests := []struct {
		name string
		rep  Report
		want string
	}{
		{"unset", Report{}, `{}`},
		{"set", Report{Capabilities: []string{"rotation"}}, `{"capabilities":["rotation"]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var posted string
			if _, err := ipSourceClient(t, `{}`, &posted).Checkin(t.Context(), tt.rep); err != nil {
				t.Fatalf("Checkin: %v", err)
			}
			if posted != tt.want {
				t.Errorf("posted = %s, want %s", posted, tt.want)
			}
		})
	}
}

func TestCheckin_DecodesRotation(t *testing.T) {
	tests := []struct {
		name string
		body string
		want Rotation
	}{
		{"secret requested", `{"rotation":{"secret":true,"cert":false}}`, Rotation{Secret: true}},
		{"both", `{"rotation":{"secret":true,"cert":true}}`, Rotation{Secret: true, Cert: true}},
		{"old server, no rotation", `{"device_id":"d"}`, Rotation{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ipSourceClient(t, tt.body, nil).Checkin(t.Context(), Report{})
			if err != nil {
				t.Fatalf("Checkin: %v", err)
			}
			if res.Rotation != tt.want {
				t.Errorf("Rotation = %+v, want %+v", res.Rotation, tt.want)
			}
		})
	}
}

// pendingSigned answers every request with h and returns a client whose Keys
// hold a Pending key, so the first request is signed with it.
func pendingSigned(t *testing.T, h http.HandlerFunc) (*Client, *Keys, *int) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	promoted := 0
	keys := &Keys{Current: keyA, Pending: keyB, Promoted: func() error { promoted++; return nil }}
	c, err := NewClient(srv.URL, testDeviceID, keys, Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, keys, &promoted
}

// A pending key is promoted only by a response that is the server's: a 2xx that
// is not JSON (a captive portal, a proxy's HTML page) must keep both keys.
func TestKeys_PendingSigned2xxNotJSONKeepsBoth(t *testing.T) {
	tests := []struct {
		name, contentType, body string
	}{
		{"html 200", "text/html; charset=utf-8", "<html>login</html>"},
		{"json content type, junk body", "application/json", "<html>login</html>"},
		{"json body, wrong content type", "text/plain", `{"device_id":"d"}`},
		{"empty 200", "application/json", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, keys, promoted := pendingSigned(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				_, _ = io.WriteString(w, tt.body)
			})
			_, err := c.Checkin(t.Context(), Report{})
			if !errors.Is(err, ErrServer) {
				t.Errorf("err = %v, want ErrServer", err)
			}
			if !bytes.Equal(keys.Current, keyA) || !bytes.Equal(keys.Pending, keyB) || *promoted != 0 {
				t.Errorf("keys = %s, promoted %d times; want both kept and no promote", keys, *promoted)
			}
		})
	}
}

// signedByPending reports whether r was signed with the pending key B.
func signedByPending(r *http.Request) bool {
	body, _ := io.ReadAll(r.Body)
	canonical := shared.CanonicalRequest(r.Method, r.URL.Path,
		r.Header.Get(shared.HeaderTimestamp), r.Header.Get(shared.HeaderNonce), shared.BodyHashHex(body))
	return shared.Sign(keyB, canonical) == r.Header.Get(shared.HeaderSignature)
}

// A redirect on a pending-signed request is never followed and never promotes:
// a login page behind it would answer 200 and promote a key the server never
// accepted. The cycle falls back to Current (like a 401), so a device behind an
// http to https 308 proxy keeps reporting while a pending secret is held.
func TestKeys_PendingSignedRedirectFallsBackToCurrent(t *testing.T) {
	tests := []struct {
		name   string
		status int
		// proxied: the redirect applies to Current-signed requests too, as a
		// proxy's does; the Current request follows it to the final hop.
		proxied bool
	}{
		{"login redirect, only the pending key", http.StatusFound, false},
		{"308 proxy, every request", http.StatusPermanentRedirect, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var pendingAtTarget bool
			c, keys, promoted := pendingSigned(t, func(w http.ResponseWriter, r *http.Request) {
				pending := signedByPending(r)
				if r.URL.Query().Get("hop") != "" {
					if pending {
						mu.Lock()
						pendingAtTarget = true
						mu.Unlock()
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"device_id":"d"}`)
					return
				}
				if pending || tt.proxied {
					http.Redirect(w, r, r.URL.Path+"?hop=1", tt.status)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"device_id":"d"}`)
			})

			res, err := c.Checkin(t.Context(), Report{})

			if err != nil || res.DeviceID != "d" {
				t.Fatalf("Checkin = %+v, %v; want success through the Current key", res, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if pendingAtTarget {
				t.Error("the pending-signed request followed the redirect")
			}
			if !bytes.Equal(keys.Current, keyA) || !bytes.Equal(keys.Pending, keyB) || *promoted != 0 {
				t.Errorf("keys = %s, promoted %d times; want both kept and no promote", keys, *promoted)
			}
		})
	}
}

// A request signed with Current keeps net/http's redirect handling, so an
// http to https 308 in front of the server still works.
func TestKeys_CurrentSignedRedirectFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("hop") == "" {
			http.Redirect(w, r, r.URL.Path+"?hop=1", http.StatusPermanentRedirect)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"device_id":"d"}`)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, testDeviceID, &Keys{Current: keyA}, Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	res, err := c.Checkin(t.Context(), Report{})
	if err != nil || res.DeviceID != "d" {
		t.Errorf("Checkin = %+v, %v; want the redirect followed", res, err)
	}
}

// Step 3 carries the new secret, so it must never follow a redirect: the
// second server is not the configured one and must receive nothing.
func TestSubmitPendingSecret_RedirectNotFollowed(t *testing.T) {
	hits := 0
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	t.Cleanup(other.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	keys := &Keys{Current: keyA, Pending: keyB}
	c, err := NewClient(srv.URL, testDeviceID, keys, Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.SubmitPendingSecret(t.Context()); !errors.Is(err, ErrServer) {
		t.Errorf("err = %v, want ErrServer", err)
	}
	if hits != 0 {
		t.Errorf("the redirect target received %d request(s), want 0", hits)
	}
	if !bytes.Equal(keys.Current, keyA) || !bytes.Equal(keys.Pending, keyB) {
		t.Errorf("keys = %s, want both kept", keys)
	}
}

// Keys prints redacted as a value and as a nil pointer too, not only through a
// non-nil pointer.
func TestKeys_RedactedAsValueAndNilPointer(t *testing.T) {
	keys := Keys{Current: keyA, Pending: keyB}
	var nilKeys *Keys
	secrets := []string{
		hex.EncodeToString(keyA), hex.EncodeToString(keyB),
		base64.StdEncoding.EncodeToString(keyA), base64.StdEncoding.EncodeToString(keyB),
		fmt.Sprintf("%d", keyA), fmt.Sprintf("%d", keyB),
	}
	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("keys", "keys", keys)
	outs := []string{logged.String()}
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		outs = append(outs, fmt.Sprintf(f, keys), fmt.Sprintf(f, nilKeys))
	}
	for _, out := range outs {
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("output %q leaks key material %q", out, s)
			}
		}
	}
	if got := fmt.Sprintf("%v", keys); !strings.Contains(got, "pending:set") {
		t.Errorf("value output %q lacks %q", got, "pending:set")
	}
}

func TestNewKeys_PendingWrongLength(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	for _, n := range []int{1, 16, 33} {
		if _, err := NewKeys(b64(keyA), b64(make([]byte, n))); err == nil || !strings.Contains(err.Error(), "must be 32 bytes") {
			t.Errorf("pending of %d bytes: err = %v, want a length error", n, err)
		}
	}
}
