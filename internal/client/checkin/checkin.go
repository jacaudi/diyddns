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

// Report is the IP/metadata a device reports. Empty families are omitted so
// the server preserves the stored value (merge-on-empty).
type Report struct{ IPv4, IPv6, Hostname, OS, ClientVersion string }

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
	IPv4          string `json:"ipv4,omitempty"`
	IPv6          string `json:"ipv6,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	OS            string `json:"os,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
}

type checkinResponse struct {
	DeviceID    string   `json:"device_id"`
	CurrentIPv4 string   `json:"current_ipv4"`
	CurrentIPv6 string   `json:"current_ipv6"`
	Stored      bool     `json:"stored"`
	IPSource    IPSource `json:"ip_source"`
}

// Client signs and sends check-ins for one device.
type Client struct {
	baseURL  string
	deviceID string
	key      []byte
	now      func() time.Time
	http     *http.Client
}

// NewClient validates baseURL, decodes the wire-base64 secret to the raw HMAC
// key, and (optionally) trusts a CA bundle.
func NewClient(baseURL, deviceID, secretB64 string, opts Options) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("checkin: server URL must be http(s): %q", baseURL)
	}
	key, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("checkin: secret is not valid base64")
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
		dialer := newPinnedDialer(opts.Network)
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
	return &Client{
		baseURL:  baseURL,
		deviceID: deviceID,
		key:      key,
		now:      time.Now,
		http:     &http.Client{Timeout: timeout, Transport: transport},
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

// do signs method+path+body with the device secret and sends it. A nil body
// is sent as an empty body (and hashed as such). The caller owns resp.Body.
func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	ts := strconv.FormatInt(c.now().Unix(), 10)
	nonce, err := randNonce()
	if err != nil {
		return nil, err
	}
	canonical := shared.CanonicalRequest(method, path, ts, nonce, shared.BodyHashHex(body))
	sig := shared.Sign(c.key, canonical)

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

	resp, err := c.http.Do(req)
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

// newPinnedDialer returns the dialer for a client pinned to network ("tcp4" or
// "tcp6"). The family itself is chosen by the DialContext that calls it, which
// dials network in place of the "tcp" net/http asks for.
func newPinnedDialer(network string) *net.Dialer { //nolint:unparam // network is the spec'd seam signature; both families share one bound today, a per-family bound would branch on it
	return &net.Dialer{Timeout: PinnedDialTimeout}
}

// IsDialSkip reports whether err is a connect-stage failure: the address
// family is unreachable from this host, so the caller skips it. Any other
// error (a TLS or HTTP failure, a rejected signature) is a real error.
func IsDialSkip(err error) bool {
	opErr, ok := errors.AsType[*net.OpError](err)
	return ok && opErr.Op == "dial"
}
