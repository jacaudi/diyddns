// Package checkin is an HMAC-signed HTTP client for POST /agent/v1/checkin. It
// signs each request with the device's HMAC secret (obtained at enrollment)
// using the shared request-signing wire contract. It never logs the secret.
package checkin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/shared"
)

// ErrUnauthorized is returned when the server rejects the signature/device
// (401) — e.g. a rotated or invalid secret. ErrServer is any other non-2xx.
var (
	ErrUnauthorized = errors.New("checkin: unauthorized")
	ErrServer       = errors.New("checkin: server error")
)

// Report is the IP/metadata a device reports. Empty families are omitted so
// the server preserves the stored value (merge-on-empty).
type Report struct{ IPv4, IPv6, Hostname, OS, ClientVersion string }

// Result mirrors the server's check-in response.
type Result struct {
	DeviceID    string
	CurrentIPv4 string
	CurrentIPv6 string
	Stored      bool
}

// Options configures the client. CACertPath trusts a self-signed homelab CA.
type Options struct {
	CACertPath string
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
	DeviceID    string `json:"device_id"`
	CurrentIPv4 string `json:"current_ipv4"`
	CurrentIPv6 string `json:"current_ipv6"`
	Stored      bool   `json:"stored"`
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
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.CACertPath != "" {
		pem, err := os.ReadFile(opts.CACertPath) // operator-provided CA bundle path (enroll/client.go reads the same way, no #nosec needed — gosec does not flag this pattern here)
		if err != nil {
			return nil, fmt.Errorf("checkin: read ca cert %s: %w", opts.CACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("checkin: no certificates in %s", opts.CACertPath)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
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

// Checkin signs and POSTs one check-in.
func (c *Client) Checkin(ctx context.Context, r Report) (Result, error) {
	// I1: hash exactly the bytes we send — Marshal then read those bytes.
	// Report and checkinRequest share identical field name/type/order, so a
	// direct conversion is equivalent to (and simpler than) a field literal.
	body, err := json.Marshal(checkinRequest(r))
	if err != nil {
		return Result{}, fmt.Errorf("checkin: marshal: %w", err)
	}
	const path = "/agent/v1/checkin"
	ts := strconv.FormatInt(c.now().Unix(), 10)
	nonce, err := randNonce()
	if err != nil {
		return Result{}, err
	}
	canonical := shared.CanonicalRequest(http.MethodPost, path, ts, nonce, shared.BodyHashHex(body))
	sig := shared.Sign(c.key, canonical)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("checkin: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(shared.HeaderDevice, c.deviceID)
	req.Header.Set(shared.HeaderTimestamp, ts)
	req.Header.Set(shared.HeaderNonce, nonce)
	req.Header.Set(shared.HeaderSignature, sig)

	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("checkin: post: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16)); _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		var b checkinResponse
		if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
			return Result{}, fmt.Errorf("checkin: decode: %w", err)
		}
		// checkinResponse and Result share identical field name/type/order.
		return Result(b), nil
	case http.StatusUnauthorized:
		return Result{}, ErrUnauthorized
	default:
		return Result{}, fmt.Errorf("%w: status %d", ErrServer, resp.StatusCode)
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
