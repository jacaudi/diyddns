package api

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/oidc"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// slowDownBumpSeconds is added to a flow's poll interval on a slow_down (RFC 8628 §3.5).
const slowDownBumpSeconds = 5

type oidcDeviceStartOutput struct {
	Body struct {
		FlowID                  string `json:"flow_id"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
		ExpiresIn               int64  `json:"expires_in"`
		Interval                int64  `json:"interval"`
	}
}

type oidcDevicePollInput struct {
	Body struct {
		FlowID string `json:"flow_id"`
	}
}

type oidcDevicePollOutput struct {
	Body struct {
		Status   string `json:"status,omitempty"` // "pending" | "slow_down" (omitted on success)
		DeviceID string `json:"device_id,omitempty"`
		Secret   string `json:"secret,omitempty"`
	}
}

// registerEnrollOIDCOps registers the two unauthenticated RFC 8628
// device-code enrollment operations onto a: POST /agent/v1/enroll/oidc/start
// and POST /agent/v1/enroll/oidc/poll. Neither carries HMAC middleware —
// like the other enroll ops, they run before a device has a secret. Each
// operation's business logic lives in its own function (startOIDCDevice,
// pollOIDCDevice) rather than inline closures, keeping this registration
// function's cyclomatic complexity independent of either handler's.
func registerEnrollOIDCOps(a huma.API, deps ServerDeps) {
	huma.Post(a, "/agent/v1/enroll/oidc/start", func(ctx context.Context, _ *struct{}) (*oidcDeviceStartOutput, error) {
		return startOIDCDevice(ctx, deps)
	})

	huma.Post(a, "/agent/v1/enroll/oidc/poll", func(ctx context.Context, in *oidcDevicePollInput) (*oidcDevicePollOutput, error) {
		return pollOIDCDevice(ctx, deps, in.Body.FlowID)
	})
}

// startOIDCDevice implements POST /agent/v1/enroll/oidc/start: begins the
// device-authorization grant at the IdP and persists a pending flow row.
func startOIDCDevice(ctx context.Context, deps ServerDeps) (*oidcDeviceStartOutput, error) {
	if !deps.OIDCMgr.DeviceEnabled() {
		return nil, huma.Error501NotImplemented("oidc device flow not available")
	}
	da, err := deps.OIDCMgr.DeviceStart(ctx)
	if err != nil {
		if errors.Is(err, oidc.ErrDeviceUnsupported) {
			return nil, huma.Error501NotImplemented("oidc device flow not available")
		}
		deps.Log.LogAttrs(ctx, slog.LevelError, "oidc device start failed", slog.Any("error", err))
		return nil, huma.Error502BadGateway("oidc device start failed")
	}
	flowID, err := auth.RandToken(32)
	if err != nil {
		deps.Log.LogAttrs(ctx, slog.LevelError, "oidc flow id gen failed", slog.Any("error", err))
		return nil, huma.Error500InternalServerError("internal error")
	}
	now := store.NowUnix()
	interval := da.Interval
	if interval < 5 {
		interval = 5 // design §6 default; also prevents a 0-interval disabling the pacing guard
	}
	if _, err := deps.Store.OIDCDeviceFlows().Create(ctx, store.OIDCDeviceFlow{
		FlowID:     flowID,
		DeviceCode: da.DeviceCode,
		Interval:   interval,
		ExpiresAt:  da.ExpiresAt, // absolute unix expiry from DeviceStart
		CreatedAt:  now,
	}); err != nil {
		deps.Log.LogAttrs(ctx, slog.LevelError, "oidc flow persist failed", slog.Any("error", err))
		return nil, huma.Error500InternalServerError("internal error")
	}
	out := &oidcDeviceStartOutput{}
	out.Body.FlowID = flowID
	out.Body.UserCode = da.UserCode
	out.Body.VerificationURI = da.VerificationURI
	out.Body.VerificationURIComplete = da.VerificationURIComplete
	out.Body.ExpiresIn = da.ExpiresAt - now
	out.Body.Interval = interval
	return out, nil
}

// pollOIDCDevice implements POST /agent/v1/enroll/oidc/poll: paces the poll
// via the flow's stored interval, checks the IdP, and on completion resolves
// the user and mints a device.
func pollOIDCDevice(ctx context.Context, deps ServerDeps, flowID string) (*oidcDevicePollOutput, error) {
	now := store.NowUnix()
	flow, allowed, err := deps.Store.OIDCDeviceFlows().TryPoll(ctx, flowID, now)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, huma.Error410Gone("device flow expired or unknown")
		}
		deps.Log.LogAttrs(ctx, slog.LevelError, "oidc flow trypoll failed", slog.Any("error", err))
		return nil, huma.Error500InternalServerError("internal error")
	}
	out := &oidcDevicePollOutput{}
	if !allowed {
		out.Body.Status = "slow_down"
		return out, nil
	}

	res, err := deps.OIDCMgr.DevicePoll(ctx, flow.DeviceCode)
	if err != nil {
		deps.Log.LogAttrs(ctx, slog.LevelError, "oidc device poll failed", slog.Any("error", err))
		return nil, huma.Error502BadGateway("oidc device poll failed")
	}
	switch res.Status {
	case oidc.PollPending:
		out.Body.Status = "pending"
		return out, nil
	case oidc.PollSlowDown:
		_ = deps.Store.OIDCDeviceFlows().BumpInterval(ctx, flow.FlowID, slowDownBumpSeconds)
		out.Body.Status = "slow_down"
		return out, nil
	case oidc.PollDenied:
		// Terminal: user denied or the IdP device_code expired. Drop the flow
		// and tell the agent to stop polling.
		_ = deps.Store.OIDCDeviceFlows().Delete(ctx, flow.FlowID)
		return nil, huma.Error410Gone("device authorization denied or expired")
	case oidc.PollComplete:
		// resolve user, mint device, delete the flow (below)
	}

	return completeOIDCDevice(ctx, deps, flow, res, out)
}

// completeOIDCDevice resolves the authenticated user and mints a device for
// a flow whose poll came back PollComplete, deleting the flow whether it
// succeeds or the user is rejected.
func completeOIDCDevice(ctx context.Context, deps ServerDeps, flow store.OIDCDeviceFlow, res oidc.PollResult, out *oidcDevicePollOutput) (*oidcDevicePollOutput, error) {
	user, err := deps.OIDC.LoginOrLink(ctx, deps.Cfg.OIDC.Issuer, res.Claims.Subject, res.Claims.Email, res.Claims.EmailVerified)
	if err != nil {
		deps.Log.LogAttrs(ctx, slog.LevelInfo, "oidc device enroll rejected", slog.Any("error", err))
		_ = deps.Store.OIDCDeviceFlows().Delete(ctx, flow.FlowID)
		return nil, huma.Error401Unauthorized("enrollment not authorized")
	}
	enr, err := deps.Enroll.EnrollForUser(ctx, user.ID, "device.enroll.oidc", service.ClientMeta{})
	if err != nil {
		deps.Log.LogAttrs(ctx, slog.LevelError, "oidc device mint failed", slog.Any("error", err))
		return nil, huma.Error500InternalServerError("internal error")
	}
	_ = deps.Store.OIDCDeviceFlows().Delete(ctx, flow.FlowID)
	out.Body.DeviceID = enr.DeviceID
	out.Body.Secret = base64.StdEncoding.EncodeToString(enr.Secret)
	return out, nil
}
