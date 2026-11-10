// Package checkin is an HMAC-signed HTTP client for POST /agent/v1/checkin. It
// signs each request with the device's HMAC secret (obtained at enrollment)
// using the shared request-signing wire contract. It never logs the secret.
package checkin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/client/agenthttp"
	"github.com/jacaudi/diyddns/internal/shared"
)

// ErrUnauthorized is returned when the server rejects the signature/device
// (401) — e.g. a rotated or invalid secret. ErrClientCertRejected is a 401 the
// agent port coded as a refused client certificate: the credential is fine, the
// certificate is not, so callers re-provision rather than count it as a
// rejected secret. ErrCertAlreadyIssued (409) means the device already holds a
// live certificate; ErrMTLSRequired (403) means the server refuses this port
// and the client must move to the agent port. ErrServer is any other non-2xx.
var (
	ErrUnauthorized       = errors.New("checkin: unauthorized")
	ErrClientCertRejected = errors.New("checkin: client certificate rejected")
	ErrCertAlreadyIssued  = errors.New("checkin: device already has a live certificate")
	ErrMTLSRequired       = errors.New("checkin: server requires mTLS")
	ErrServer             = errors.New("checkin: server error")
)

// ErrNoSecretRotationPending is the server's coded 409 to step 3: no secret
// rotation is requested for this device, so the client drops its pending secret.
var ErrNoSecretRotationPending = errors.New("checkin: no secret rotation pending")

// Report is the IP/metadata a device reports. Empty families are omitted so
// the server preserves the stored value (merge-on-empty). Capabilities lists the
// optional features this client speaks; empty is omitted from the wire.
type Report struct {
	IPv4, IPv6, Hostname, OS, ClientVersion string
	Capabilities                            []string
}

// IPSource says, per family the check-in carried, where the recorded address
// came from: "reported", "observed" or "none". A family the check-in did not
// carry is empty, as is both on a server that predates ip_source.
type IPSource struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

// Result mirrors the server's check-in response.
type Result struct {
	DeviceID    string
	CurrentIPv4 string
	CurrentIPv6 string
	Stored      bool
	IPSource    IPSource
	Rotation    Rotation
}

// Rotation says which tracks an admin asked this device to rotate. An old
// server omits it, which reads as no request.
type Rotation struct {
	Secret bool `json:"secret"`
	Cert   bool `json:"cert"`
}

// Options configures the client. CACertPath trusts a self-signed homelab CA.
// TLSConfig, when non-nil, is used verbatim (it carries the pinned roots, the
// client certificate and MinVersion) and CACertPath is ignored.
type Options struct {
	// Network pins every dial to one family: "tcp4" or "tcp6". Empty leaves the
	// transport unpinned.
	Network    string
	CACertPath string
	TLSConfig  *tls.Config
	Timeout    time.Duration
}

// checkinRequest / checkinResponse are the client-local wire structs (design
// D7). Their json tags MUST match internal/server/api/checkin.go exactly; the
// test decodes the posted body with the server's tag set to guard against drift.
type checkinRequest struct {
	IPv4          string   `json:"ipv4,omitempty"`
	IPv6          string   `json:"ipv6,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	OS            string   `json:"os,omitempty"`
	ClientVersion string   `json:"client_version,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
}

type checkinResponse struct {
	DeviceID    string   `json:"device_id"`
	CurrentIPv4 string   `json:"current_ipv4"`
	CurrentIPv6 string   `json:"current_ipv6"`
	Stored      bool     `json:"stored"`
	IPSource    IPSource `json:"ip_source"`
	Rotation    Rotation `json:"rotation"`
}

// Keys is the device's HMAC key pair, shared by every Client the Manager builds
// (single goroutine, no lock). Current signs when Pending is nil.
type Keys struct {
	Current, Pending []byte
	// Promoted runs after a Pending-signed 2xx swapped Pending into Current; nil
	// is a no-op. Its error fails that request (rule 4: persist before acting).
	Promoted func() error
}

// NewKeys decodes the wire-base64 secret and, when non-empty, the pending one.
// An empty pendingB64 leaves Pending nil.
func NewKeys(secretB64, pendingB64 string) (*Keys, error) {
	cur, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil || len(cur) == 0 {
		return nil, errors.New("checkin: secret is not valid base64")
	}
	k := &Keys{Current: cur}
	if pendingB64 != "" {
		if k.Pending, err = base64.StdEncoding.DecodeString(pendingB64); err != nil || len(k.Pending) == 0 {
			return nil, errors.New("checkin: pending secret is not valid base64")
		}
		if len(k.Pending) != shared.DeviceSecretLen {
			return nil, fmt.Errorf("checkin: pending secret must be %d bytes", shared.DeviceSecretLen)
		}
	}
	return k, nil
}

// The methods below take a value receiver, so a Keys printed by value, and a
// nil *Keys (which fmt renders as <nil>), are redacted as well as a *Keys.

// String reports which keys are held, never their bytes.
func (k Keys) String() string {
	state := func(b []byte) string {
		if b == nil {
			return "none"
		}
		return "set"
	}
	return fmt.Sprintf("checkin.Keys{current:%s, pending:%s}", state(k.Current), state(k.Pending))
}

// LogValue keeps the key bytes out of slog output.
func (k Keys) LogValue() slog.Value { return slog.StringValue(k.String()) }

// Format makes every fmt verb (%v, %+v, %#v, %s, %x) print String, so no verb
// reaches the key bytes.
func (k Keys) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

// Client signs and sends check-ins for one device.
type Client struct {
	baseURL  string
	deviceID string
	keys     *Keys
	now      func() time.Time
	http     *http.Client
	// noRedirect shares http's transport but returns a 3xx as the response. It
	// carries every request a redirect must not reach: one signed with a pending
	// key (a login page behind the redirect would answer 2xx and promote a key
	// the server never accepted) and step 3 (it carries the new secret).
	noRedirect *http.Client
}

// NewClient validates baseURL and (optionally) trusts a CA bundle. keys is
// shared with every other client built over it.
func NewClient(baseURL, deviceID string, keys *Keys, opts Options) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("checkin: server URL must be http(s): %q", baseURL)
	}
	var transport *http.Transport
	if opts.TLSConfig != nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
		// A copy per transport: net/http mutates its TLS config when it enables h2,
		// so one config must never back the transports of several families.
		transport.TLSClientConfig = opts.TLSConfig.Clone()
	} else if transport, err = agenthttp.NewTransport(opts.CACertPath); err != nil {
		return nil, fmt.Errorf("checkin: %w", err)
	}
	switch opts.Network {
	case "":
	case "tcp4", "tcp6":
		dialer := newPinnedDialer()
		// net/http asks for "tcp"; dial the pinned family instead.
		transport.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, opts.Network, addr)
		}
	default:
		return nil, fmt.Errorf("checkin: network must be \"\", \"tcp4\" or \"tcp6\", got %q", opts.Network)
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	follow := &http.Client{Timeout: timeout, Transport: transport}
	strict := *follow
	strict.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{
		baseURL:    baseURL,
		deviceID:   deviceID,
		keys:       keys,
		now:        time.Now,
		http:       follow,
		noRedirect: &strict,
	}, nil
}

// CertResponse is the 200 body of POST /agent/v1/cert: the issued device
// certificate, the CA bundle to trust, and the agent URL to use from now on.
type CertResponse struct {
	Certificate string `json:"certificate"`
	CABundle    string `json:"ca_bundle"`
	AgentURL    string `json:"agent_url"`
}

// BaseURL returns the server URL this client talks to, without a trailing slash.
func (c *Client) BaseURL() string { return c.baseURL }

// Checkin signs and POSTs one check-in.
func (c *Client) Checkin(ctx context.Context, r Report) (Result, error) {
	// I1: hash exactly the bytes we send — Marshal then read those bytes.
	// Report and checkinRequest share identical field name/type/order, so a
	// direct conversion is equivalent to (and simpler than) a field literal.
	body, err := json.Marshal(checkinRequest(r))
	if err != nil {
		return Result{}, fmt.Errorf("checkin: marshal: %w", err)
	}
	resp, err := c.do(ctx, http.MethodPost, "/agent/v1/checkin", body) //nolint:bodyclose // resp.Body IS closed, inside agenthttp.DrainClose below; bodyclose can't trace Close() through a named helper
	if err != nil {
		return Result{}, err
	}
	defer agenthttp.DrainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return Result{}, classify(resp)
	}
	var b checkinResponse
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		return Result{}, fmt.Errorf("checkin: decode: %w", err)
	}
	// checkinResponse and Result share identical field name/type/order.
	return Result(b), nil
}

// Self signs and sends GET /agent/v1/self. It reports only whether the server
// accepted the device's credentials (and, on the agent port, its certificate);
// the response body is not read.
func (c *Client) Self(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "/agent/v1/self", nil) //nolint:bodyclose // resp.Body IS closed, inside agenthttp.DrainClose below; bodyclose can't trace Close() through a named helper
	if err != nil {
		return err
	}
	defer agenthttp.DrainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return classify(resp)
	}
	return nil
}

// RequestCert signs and POSTs csrPEM to /agent/v1/cert and returns the issued
// certificate. A device that already holds a live certificate gets
// ErrCertAlreadyIssued.
func (c *Client) RequestCert(ctx context.Context, csrPEM []byte) (CertResponse, error) {
	body, err := json.Marshal(struct {
		CSR string `json:"csr"`
	}{CSR: string(csrPEM)})
	if err != nil {
		return CertResponse{}, fmt.Errorf("checkin: marshal: %w", err)
	}
	resp, err := c.do(ctx, http.MethodPost, "/agent/v1/cert", body) //nolint:bodyclose // resp.Body IS closed, inside agenthttp.DrainClose below; bodyclose can't trace Close() through a named helper
	if err != nil {
		return CertResponse{}, err
	}
	defer agenthttp.DrainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return CertResponse{}, classify(resp)
	}
	var out CertResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return CertResponse{}, fmt.Errorf("checkin: decode: %w", err)
	}
	return out, nil
}

// SubmitPendingSecret is step 3 of a secret rotation: it POSTs the pending
// secret to /agent/v1/rotation/secret, signed with Current only (rule 2), so the
// new secret travels only inside a request the server can already verify. A 2xx
// returns nil; a coded 409 is ErrNoSecretRotationPending. It never follows a
// redirect, so the secret reaches only the configured server (any 3xx is an
// error).
func (c *Client) SubmitPendingSecret(ctx context.Context) error {
	if c.keys.Pending == nil {
		return errors.New("checkin: no pending secret")
	}
	// A map, not a struct with a Secret field, keeps gosec G117 quiet.
	body, err := json.Marshal(map[string]string{"secret": base64.StdEncoding.EncodeToString(c.keys.Pending)})
	if err != nil {
		return fmt.Errorf("checkin: marshal: %w", err)
	}
	resp, err := c.send(ctx, c.keys.Current, false, http.MethodPost, "/agent/v1/rotation/secret", body) //nolint:bodyclose // resp.Body IS closed, inside agenthttp.DrainClose below; bodyclose can't trace Close() through a named helper
	if err != nil {
		return err
	}
	defer agenthttp.DrainClose(resp.Body)
	if resp.StatusCode/100 != 2 {
		return classify(resp)
	}
	return nil
}

// do sends one signed request. While a pending secret exists it signs with that
// first, never following a redirect; a 401 or a 3xx retries with Current in the
// same cycle (rule 5), which does follow redirects, so a device behind an
// http to https proxy keeps reporting while it holds a pending secret. A 2xx on
// the pending key promotes it (Pending becomes Current) and runs Promoted, but
// only once the response proves to be the server's (see promote); a transport
// failure or any other status keeps both keys (rule 7). A nil body is sent as an
// empty body (and hashed as such). The caller owns resp.Body.
func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	if p := c.keys.Pending; p != nil {
		resp, err := c.send(ctx, p, false, method, path, body)
		if err != nil {
			return nil, err // transport failure: keep both keys (rule 7)
		}
		switch {
		case resp.StatusCode/100 == 2:
			return c.promote(resp, p)
		case resp.StatusCode != http.StatusUnauthorized && resp.StatusCode/100 != 3:
			return resp, nil // 4xx/5xx: keep both keys (rule 7, SF-7)
		}
		agenthttp.DrainClose(resp.Body) // 401 or 3xx: retry with Current in this cycle (rule 5)
	}
	return c.send(ctx, c.keys.Current, true, method, path, body)
}

// maxPromoteBody bounds the 2xx body promote buffers; every agent response is a
// few KiB at most.
const maxPromoteBody = 1 << 20

// promote makes p the Current key after a pending-signed 2xx, but only when the
// response is the server's: a JSON body with a JSON content type. Anything else
// (a captive portal's or a proxy's HTML page) keeps both keys and fails the
// request, because promoting on it would drop the only secret the server knows.
// It returns resp with its body replaced by the buffered bytes.
func (c *Client) promote(resp *http.Response, p []byte) (*http.Response, error) {
	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxPromoteBody))
	agenthttp.DrainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("checkin: read response: %w", err)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/json" || !json.Valid(buf) {
		return nil, fmt.Errorf("%w: status %d: response is not the server's JSON; kept both keys", ErrServer, resp.StatusCode)
	}
	c.keys.Current, c.keys.Pending = p, nil
	if c.keys.Promoted != nil {
		if err := c.keys.Promoted(); err != nil {
			return nil, fmt.Errorf("checkin: save promoted secret: %w", err)
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(buf))
	return resp, nil
}

// send signs method+path+body with key and sends it, with a fresh timestamp and
// nonce per call. follow says whether a redirect is followed. The caller owns
// resp.Body.
func (c *Client) send(ctx context.Context, key []byte, follow bool, method, path string, body []byte) (*http.Response, error) {
	ts := strconv.FormatInt(c.now().Unix(), 10)
	nonce, err := randNonce()
	if err != nil {
		return nil, err
	}
	canonical := shared.CanonicalRequest(method, path, ts, nonce, shared.BodyHashHex(body))
	sig := shared.Sign(key, canonical)

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("checkin: request: %w", err)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(shared.HeaderDevice, c.deviceID)
	req.Header.Set(shared.HeaderTimestamp, ts)
	req.Header.Set(shared.HeaderNonce, nonce)
	req.Header.Set(shared.HeaderSignature, sig)

	hc := c.http
	if !follow {
		hc = c.noRedirect
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("checkin: %s %s: %w", method, path, err)
	}
	return resp, nil
}

// classify turns a non-200 response into a typed error. The server's problem
// JSON carries a stable `code` (shared.Code*) which, when present, wins over
// the bare status: a coded 401 is a rejected client certificate, not a rejected
// HMAC credential.
func classify(resp *http.Response) error {
	var p struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	// A body that is not problem JSON leaves p empty; the status still classifies.
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&p)

	switch {
	case resp.StatusCode == http.StatusUnauthorized && p.Code == shared.CodeClientCertRejected:
		return ErrClientCertRejected
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrUnauthorized
	case resp.StatusCode == http.StatusForbidden && p.Code == shared.CodeMTLSRequired:
		return fmt.Errorf("%w: upgrade this client", ErrMTLSRequired)
	case resp.StatusCode == http.StatusConflict && p.Code == shared.CodeCertAlreadyIssued:
		return ErrCertAlreadyIssued
	case resp.StatusCode == http.StatusConflict && p.Code == shared.CodeNoSecretRotationPending:
		return ErrNoSecretRotationPending
	default:
		return fmt.Errorf("%w: status %d: %s", ErrServer, resp.StatusCode, p.Detail)
	}
}

// randNonce returns a fresh 16-byte hex nonce (server replay-nonce table
// requires a unique value per request within the skew window).
func randNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("checkin: nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// PinnedDialTimeout bounds the connect of a family-pinned client. A family the
// host has no route for fails the dial here instead of hanging the cycle.
const PinnedDialTimeout = 5 * time.Second

// newPinnedDialer returns the dialer every family-pinned client connects with:
// it only bounds the connect by PinnedDialTimeout. It does not pin a family;
// NewClient's DialContext does that by dialing opts.Network.
func newPinnedDialer() *net.Dialer {
	return &net.Dialer{Timeout: PinnedDialTimeout}
}

// IsDialSkip reports whether err is a connect-stage failure: the address
// family is unreachable from this host, so the caller skips it. Any other
// error (a TLS or HTTP failure, a rejected signature) is a real error.
func IsDialSkip(err error) bool {
	opErr, ok := errors.AsType[*net.OpError](err)
	return ok && opErr.Op == "dial"
}
