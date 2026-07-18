// Package enroll implements an unauthenticated HTTP client for the diyddns
// server's /agent/v1 enroll surface (capabilities, OIDC device-code start and
// poll). It never signs requests or verifies tokens itself — enrollment is
// how a device first obtains the HMAC secret it will use for every
// subsequent authenticated request.
package enroll

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Capabilities is the subset of GET /agent/v1/capabilities the client reads.
type Capabilities struct {
	ServerVersion     string `json:"server_version"`
	OIDCEnabled       bool   `json:"oidc_enabled"`
	OIDCDeviceEnabled bool   `json:"oidc_device_enabled"`
}

// DeviceStart is the 200 body of POST /agent/v1/enroll/oidc/start.
type DeviceStart struct {
	FlowID                  string `json:"flow_id"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

type pollKind int

const (
	pollPending pollKind = iota
	pollSlowDown
	pollComplete
)

// PollResult is the classified outcome of one successful (200) poll. On
// pollComplete, DeviceID and Secret are non-empty and Secret is valid base64
// carried verbatim from the wire.
type PollResult struct {
	Kind     pollKind
	DeviceID string
	Secret   string
}

// ClientOptions configures the enroll HTTP client.
type ClientOptions struct {
	CACertPath string        // optional PEM bundle to trust (self-signed servers)
	Timeout    time.Duration // per-request timeout; 0 → 10s
}

// Client is an unauthenticated HTTP client for the server's /agent/v1 enroll
// surface. It never signs requests — enrollment is how a device first obtains
// its secret.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient validates baseURL (http/https), builds an HTTP client, and — if
// opts.CACertPath is set — trusts that CA bundle instead of only the system pool.
func NewClient(baseURL string, opts ClientOptions) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("enroll: server URL must be http(s): %q", baseURL)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.CACertPath != "" {
		pem, err := os.ReadFile(opts.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("enroll: read ca cert %s: %w", opts.CACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("enroll: no certificates in %s", opts.CACertPath)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Client{baseURL: baseURL, http: &http.Client{Timeout: timeout, Transport: transport}}, nil
}

// Capabilities fetches GET /agent/v1/capabilities.
func (c *Client) Capabilities(ctx context.Context) (Capabilities, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/agent/v1/capabilities", http.NoBody)
	if err != nil {
		return Capabilities{}, fmt.Errorf("enroll: capabilities request: %w", err)
	}
	resp, err := c.http.Do(req) //nolint:bodyclose // resp.Body IS closed, inside drainClose below; bodyclose can't trace Close() through a named helper
	if err != nil {
		return Capabilities{}, fmt.Errorf("enroll: capabilities: %w", err)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return Capabilities{}, fmt.Errorf("enroll: capabilities: unexpected status %d", resp.StatusCode)
	}
	var caps Capabilities
	if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
		return Capabilities{}, fmt.Errorf("enroll: capabilities decode: %w", err)
	}
	return caps, nil
}

// OIDCDeviceStart begins the device-authorization grant (POST .../start).
func (c *Client) OIDCDeviceStart(ctx context.Context) (DeviceStart, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/agent/v1/enroll/oidc/start", http.NoBody)
	if err != nil {
		return DeviceStart{}, fmt.Errorf("enroll: start request: %w", err)
	}
	resp, err := c.http.Do(req) //nolint:bodyclose // resp.Body IS closed, inside drainClose below; bodyclose can't trace Close() through a named helper
	if err != nil {
		return DeviceStart{}, fmt.Errorf("enroll: start: %w", err)
	}
	defer drainClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		var ds DeviceStart
		if err := json.NewDecoder(resp.Body).Decode(&ds); err != nil {
			return DeviceStart{}, fmt.Errorf("enroll: start decode: %w", err)
		}
		return ds, nil
	case http.StatusNotImplemented:
		return DeviceStart{}, ErrDeviceUnsupported
	case http.StatusBadGateway:
		return DeviceStart{}, ErrBadGateway
	default:
		return DeviceStart{}, fmt.Errorf("%w: start status %d", ErrServer, resp.StatusCode)
	}
}

// OIDCDevicePoll performs one poll (POST .../poll). Terminal transport statuses
// surface as sentinels; 200 bodies classify into a PollResult.
func (c *Client) OIDCDevicePoll(ctx context.Context, flowID string) (PollResult, error) {
	payload, err := json.Marshal(struct {
		FlowID string `json:"flow_id"`
	}{FlowID: flowID})
	if err != nil {
		return PollResult{}, fmt.Errorf("enroll: poll marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/agent/v1/enroll/oidc/poll", bytes.NewReader(payload))
	if err != nil {
		return PollResult{}, fmt.Errorf("enroll: poll request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req) //nolint:bodyclose // resp.Body IS closed, inside drainClose below; bodyclose can't trace Close() through a named helper
	if err != nil {
		return PollResult{}, fmt.Errorf("enroll: poll: %w", err)
	}
	defer drainClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		var b struct {
			Status   string `json:"status"`
			DeviceID string `json:"device_id"`
			Secret   string `json:"secret"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
			return PollResult{}, fmt.Errorf("%w: poll decode: %w", ErrProtocol, err)
		}
		switch b.Status {
		case "pending":
			return PollResult{Kind: pollPending}, nil
		case "slow_down":
			return PollResult{Kind: pollSlowDown}, nil
		case "":
			if b.DeviceID == "" || b.Secret == "" {
				return PollResult{}, fmt.Errorf("%w: empty success body", ErrProtocol)
			}
			if _, err := base64.StdEncoding.DecodeString(b.Secret); err != nil {
				return PollResult{}, fmt.Errorf("%w: secret not base64", ErrProtocol)
			}
			return PollResult{Kind: pollComplete, DeviceID: b.DeviceID, Secret: b.Secret}, nil
		default:
			return PollResult{}, fmt.Errorf("%w: unknown status %q", ErrProtocol, b.Status)
		}
	case http.StatusGone:
		return PollResult{}, ErrFlowGone
	case http.StatusUnauthorized:
		return PollResult{}, ErrRejected
	case http.StatusBadGateway:
		return PollResult{}, ErrBadGateway
	default:
		return PollResult{}, fmt.Errorf("%w: poll status %d", ErrServer, resp.StatusCode)
	}
}

// EnrollCode enrolls this device with a one-time enrollment code
// (POST /agent/v1/enroll/code). On success it returns the new device id and
// its HMAC secret (wire base64, carried verbatim).
func (c *Client) EnrollCode(ctx context.Context, code string) (Result, error) {
	payload, err := json.Marshal(struct {
		Code string `json:"code"`
	}{Code: code})
	if err != nil {
		return Result{}, fmt.Errorf("enroll: code marshal: %w", err)
	}
	return c.doEnroll(ctx, "/agent/v1/enroll/code", payload)
}

// doEnroll POSTs a JSON enrollment request and classifies the response. Both
// code and credential enrollment share this contract: 200 →
// {device_id, secret(base64)}; a uniform 401 → ErrEnrollUnauthorized; any
// other non-2xx → ErrServer.
func (c *Client) doEnroll(ctx context.Context, path string, payload []byte) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return Result{}, fmt.Errorf("enroll: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req) //nolint:bodyclose // resp.Body IS closed, inside drainClose below; bodyclose can't trace Close() through a named helper
	if err != nil {
		return Result{}, fmt.Errorf("enroll: post %s: %w", path, err)
	}
	defer drainClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		var b struct {
			DeviceID string `json:"device_id"`
			Secret   string `json:"secret"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
			return Result{}, fmt.Errorf("%w: enroll decode: %w", ErrProtocol, err)
		}
		if b.DeviceID == "" || b.Secret == "" {
			return Result{}, fmt.Errorf("%w: empty success body", ErrProtocol)
		}
		if _, err := base64.StdEncoding.DecodeString(b.Secret); err != nil {
			return Result{}, fmt.Errorf("%w: secret not base64", ErrProtocol)
		}
		return Result{DeviceID: b.DeviceID, Secret: b.Secret}, nil
	case http.StatusUnauthorized:
		return Result{}, ErrEnrollUnauthorized
	default:
		return Result{}, fmt.Errorf("%w: enroll status %d", ErrServer, resp.StatusCode)
	}
}

// drainClose drains and closes a response body so the connection can be reused.
func drainClose(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, 1<<16))
	_ = rc.Close()
}
