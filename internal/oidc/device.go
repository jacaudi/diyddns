package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DeviceAuth is the device-authorization response handed (in part) to the agent.
// ExpiresAt is an ABSOLUTE unix expiry (the api layer stores it directly and
// derives the agent-facing expires_in = ExpiresAt - now).
type DeviceAuth struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresAt               int64
	Interval                int64
}

// PollStatus is the outcome of a single device-token poll.
type PollStatus int

const (
	// PollPending indicates the user has not yet approved the device code.
	PollPending PollStatus = iota
	// PollSlowDown indicates the caller should back off and keep polling.
	PollSlowDown
	// PollComplete indicates tokens were obtained; Claims is populated.
	PollComplete
	// PollDenied is terminal: the user denied consent or the device code
	// expired. The caller must stop polling.
	PollDenied
)

// PollResult carries the poll status and, when complete, the verified claims.
type PollResult struct {
	Status PollStatus
	Claims Claims
}

// timeNow is indirected so the zero-expiry fallback is testable; production is time.Now.
var timeNow = time.Now

// DeviceStart begins the device-authorization grant at the IdP.
func (m *Manager) DeviceStart(ctx context.Context) (DeviceAuth, error) {
	s := m.st.Load()
	if s == nil {
		return DeviceAuth{}, ErrNotReady
	}
	if s.deviceAuthURL == "" {
		return DeviceAuth{}, ErrDeviceUnsupported
	}
	cctx, cancel := context.WithTimeout(m.clientCtx(ctx), idpCallTimeout)
	defer cancel()

	resp, err := s.oauth2.DeviceAuth(cctx)
	if err != nil {
		return DeviceAuth{}, fmt.Errorf("oidc.DeviceStart: %w", err)
	}
	// oauth2 populates resp.Expiry (absolute) from the IdP's expires_in. Guard a
	// zero Expiry (some servers omit it) with a conservative 10-minute default so
	// the stored expires_at is never a huge negative value.
	expiry := resp.Expiry
	if expiry.IsZero() {
		expiry = timeNow().Add(10 * time.Minute)
	}
	return DeviceAuth{
		DeviceCode:              resp.DeviceCode,
		UserCode:                resp.UserCode,
		VerificationURI:         resp.VerificationURI,
		VerificationURIComplete: resp.VerificationURIComplete,
		ExpiresAt:               expiry.Unix(),
		Interval:                int64(resp.Interval),
	}, nil
}

// deviceTokenResponse is the subset of the token-endpoint JSON we read.
type deviceTokenResponse struct {
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// DevicePoll performs ONE non-blocking token-endpoint request for deviceCode.
// It is deliberately manual — oauth2.DeviceAccessToken self-polls and blocks,
// which is wrong for a per-request proxy endpoint.
func (m *Manager) DevicePoll(ctx context.Context, deviceCode string) (PollResult, error) {
	s := m.st.Load()
	if s == nil {
		return PollResult{}, ErrNotReady
	}
	cctx, cancel := context.WithTimeout(m.clientCtx(ctx), idpCallTimeout)
	defer cancel()

	form := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":   {deviceCode},
		"client_id":     {m.cfg.ClientID},
		"client_secret": {m.cfg.ClientSecret},
	}
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, s.oauth2.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return PollResult{}, fmt.Errorf("oidc.DevicePoll: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := m.hc.Do(req)
	if err != nil {
		return PollResult{}, fmt.Errorf("oidc.DevicePoll: do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return PollResult{}, fmt.Errorf("oidc.DevicePoll: read: %w", err)
	}

	var tr deviceTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return PollResult{}, fmt.Errorf("oidc.DevicePoll: decode (status %d): %w", resp.StatusCode, err)
	}
	switch tr.Error {
	case "authorization_pending":
		return PollResult{Status: PollPending}, nil
	case "slow_down":
		return PollResult{Status: PollSlowDown}, nil
	case "access_denied", "expired_token":
		// Terminal per RFC 8628 §3.5 — the caller must stop polling and drop the flow.
		return PollResult{Status: PollDenied}, nil
	case "":
		// success path below
	default:
		return PollResult{}, fmt.Errorf("oidc.DevicePoll: idp error: %s", tr.Error)
	}
	if tr.IDToken == "" {
		return PollResult{}, fmt.Errorf("oidc.DevicePoll: success response has no id_token")
	}
	idt, err := s.verifier.Verify(cctx, tr.IDToken)
	if err != nil {
		return PollResult{}, fmt.Errorf("oidc.DevicePoll: verify: %w", err)
	}
	// Device-flow ID tokens carry no nonce (RFC 8628 has no auth request) — no nonce check.
	claims, err := claimsFrom(idt)
	if err != nil {
		return PollResult{}, err
	}
	return PollResult{Status: PollComplete, Claims: claims}, nil
}
