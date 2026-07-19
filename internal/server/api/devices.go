package api

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/store"
)

// mintCodeInput is the body of POST /api/v1/devices.
type mintCodeInput struct {
	Body struct {
		Label string `json:"label"`
	}
}

// mintCodeResponse is the freshly-minted enrollment code and its expiry,
// shown once to the caller so they can hand it to a new device (design §14's
// canonical enrollment path — see service.EnrollmentService.CreateCode).
type mintCodeResponse struct {
	Code      string `json:"code"`
	ExpiresAt int64  `json:"expires_at"`
}

type mintCodeOutput struct {
	Body mintCodeResponse
}

// deviceView is the non-secret device view returned by the device
// management list/get endpoints — mirrors store.Device minus SecretHash
// (never expose sealed key material) and UserID (redundant: every device in
// this response already belongs to the caller). It intentionally does not
// reuse checkin.go's selfResponse: that type is the agent's own view of
// itself (keyed by the authenticated device, no id field needed); this type
// is a user's view of one of their devices (keyed by id, since the caller
// may be looking at any of several). Same shape today, different consumer
// and different reason to change.
type deviceView struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	CurrentIPv4   string `json:"current_ipv4"`
	CurrentIPv6   string `json:"current_ipv6"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	ClientVersion string `json:"client_version"`
	LastSeenAt    int64  `json:"last_seen_at"`
	Disabled      bool   `json:"disabled"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
}

// newDeviceView converts a store.Device into its non-secret wire view.
func newDeviceView(d store.Device) deviceView {
	return deviceView{
		ID:            d.ID,
		Label:         d.Label,
		CurrentIPv4:   d.CurrentIPv4,
		CurrentIPv6:   d.CurrentIPv6,
		Hostname:      d.Hostname,
		OS:            d.OS,
		ClientVersion: d.ClientVersion,
		LastSeenAt:    d.LastSeenAt,
		Disabled:      d.Disabled,
		CreatedAt:     d.CreatedAt,
		UpdatedAt:     d.UpdatedAt,
	}
}

type listDevicesOutput struct {
	Body []deviceView
}

// getDeviceInput carries the {id} path parameter of GET /api/v1/devices/{id}.
type getDeviceInput struct {
	ID string `path:"id"`
}

type getDeviceOutput struct {
	Body deviceView
}

// registerDeviceOps registers the session-authenticated device management
// operations onto apiAPI: POST /api/v1/devices mints an enrollment code
// (mutating, so it also requires CSRF); GET /api/v1/devices lists the
// caller's own devices; GET /api/v1/devices/{id} returns one device.
// Ownership scoping (a device belonging to another user is indistinguishable
// from a nonexistent one) is enforced by service.DeviceService, not here.
func registerDeviceOps(a huma.API, deps ServerDeps) {
	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/devices",
		DefaultStatus: http.StatusOK,
		Middlewares: huma.Middlewares{
			sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName),
			csrfMiddleware(a),
		},
	}, func(ctx context.Context, in *mintCodeInput) (*mintCodeOutput, error) {
		u := UserFrom(ctx)
		code, expiresAt, err := deps.Enroll.CreateCode(ctx, u.ID, in.Body.Label)
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "mint enrollment code failed",
				slog.String("user_id", u.ID), slog.Any("error", err))
			return nil, huma.Error500InternalServerError("failed to mint enrollment code")
		}
		return &mintCodeOutput{Body: mintCodeResponse{Code: code, ExpiresAt: expiresAt}}, nil
	})

	huma.Register(a, huma.Operation{
		Method:      http.MethodGet,
		Path:        "/api/v1/devices",
		Middlewares: huma.Middlewares{sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName)},
	}, func(ctx context.Context, _ *struct{}) (*listDevicesOutput, error) {
		u := UserFrom(ctx)
		devices, err := deps.Devices.List(ctx, u.ID)
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "list devices failed",
				slog.String("user_id", u.ID), slog.Any("error", err))
			return nil, huma.Error500InternalServerError("failed to list devices")
		}
		views := make([]deviceView, len(devices))
		for i, d := range devices {
			views[i] = newDeviceView(d)
		}
		return &listDevicesOutput{Body: views}, nil
	})

	huma.Register(a, huma.Operation{
		Method:      http.MethodGet,
		Path:        "/api/v1/devices/{id}",
		Middlewares: huma.Middlewares{sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName)},
	}, func(ctx context.Context, in *getDeviceInput) (*getDeviceOutput, error) {
		u := UserFrom(ctx)
		dev, err := deps.Devices.Get(ctx, u.ID, in.ID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, huma.Error404NotFound("device not found")
			}
			deps.Log.LogAttrs(ctx, slog.LevelError, "get device failed",
				slog.String("user_id", u.ID), slog.String("device_id", in.ID), slog.Any("error", err))
			return nil, huma.Error500InternalServerError("failed to get device")
		}
		return &getDeviceOutput{Body: newDeviceView(dev)}, nil
	})
}

// patchDeviceInput is the body of PATCH /api/v1/devices/{id}. Both fields are
// optional: a nil pointer means "leave unchanged", so disabling (Disabled=false)
// is distinguishable from "not supplied".
type patchDeviceInput struct {
	ID   string `path:"id"`
	Body struct {
		Label    *string `json:"label,omitempty"`
		Disabled *bool   `json:"disabled,omitempty"`
	}
}

type deleteDeviceInput struct {
	ID string `path:"id"`
}

// deleteDeviceOutput carries no body; huma emits 204 via DefaultStatus.
type deleteDeviceOutput struct{}

type rotateSecretInput struct {
	ID string `path:"id"`
}

// rotateSecretResponse carries the fresh plaintext HMAC secret, base64-encoded
// (matching enroll.go's enrollResponse), shown to the caller exactly once.
type rotateSecretResponse struct {
	Secret string `json:"secret"`
}

type rotateSecretOutput struct {
	Body rotateSecretResponse
}

type historyInput struct {
	ID     string `path:"id"`
	Cursor string `query:"cursor"`
	Limit  int    `query:"limit"`
}

type historyRow struct {
	ObservedAt    int64  `json:"observed_at"`
	IPv4          string `json:"ipv4"`
	IPv6          string `json:"ipv6"`
	ClientVersion string `json:"client_version"`
}

type historyResponse struct {
	Rows       []historyRow `json:"rows"`
	NextCursor string       `json:"next_cursor"`
}

type historyOutput struct {
	Body historyResponse
}

// registerDeviceMgmtOps registers the owner-scoped device management operations
// onto apiAPI: PATCH (rename / enable-disable), DELETE, POST rotate-secret (all
// mutating → session + CSRF), and GET history (session only). Ownership scoping
// (foreign device → 404) is enforced by service.DeviceService.
func registerDeviceMgmtOps(a huma.API, deps ServerDeps) {
	session := func() huma.Middlewares {
		return huma.Middlewares{sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName)}
	}
	sessionCSRF := func() huma.Middlewares {
		return huma.Middlewares{
			sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName),
			csrfMiddleware(a),
		}
	}

	huma.Register(a, huma.Operation{
		Method:      http.MethodPatch,
		Path:        "/api/v1/devices/{id}",
		Middlewares: sessionCSRF(),
	}, func(ctx context.Context, in *patchDeviceInput) (*getDeviceOutput, error) {
		u := UserFrom(ctx)
		dev := store.Device{}
		var err error
		changed := false
		if in.Body.Label != nil {
			if *in.Body.Label == "" {
				return nil, huma.Error422UnprocessableEntity("label must not be empty")
			}
			dev, err = deps.Devices.Rename(ctx, u.ID, in.ID, *in.Body.Label)
			if err != nil {
				return nil, deviceMgmtErr(ctx, deps, "rename device", u.ID, in.ID, err)
			}
			changed = true
		}
		if in.Body.Disabled != nil {
			dev, err = deps.Devices.SetEnabled(ctx, u.ID, in.ID, *in.Body.Disabled)
			if err != nil {
				return nil, deviceMgmtErr(ctx, deps, "set device enabled", u.ID, in.ID, err)
			}
			changed = true
		}
		if !changed {
			// Nothing to change: return the current device (also enforces ownership).
			dev, err = deps.Devices.Get(ctx, u.ID, in.ID)
			if err != nil {
				return nil, deviceMgmtErr(ctx, deps, "get device", u.ID, in.ID, err)
			}
		}
		return &getDeviceOutput{Body: newDeviceView(dev)}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodDelete,
		Path:          "/api/v1/devices/{id}",
		DefaultStatus: http.StatusNoContent,
		Middlewares:   sessionCSRF(),
	}, func(ctx context.Context, in *deleteDeviceInput) (*deleteDeviceOutput, error) {
		u := UserFrom(ctx)
		if err := deps.Devices.Delete(ctx, u.ID, in.ID); err != nil {
			return nil, deviceMgmtErr(ctx, deps, "delete device", u.ID, in.ID, err)
		}
		return &deleteDeviceOutput{}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/devices/{id}/rotate-secret",
		DefaultStatus: http.StatusOK,
		Middlewares:   sessionCSRF(),
	}, func(ctx context.Context, in *rotateSecretInput) (*rotateSecretOutput, error) {
		u := UserFrom(ctx)
		secret, err := deps.Devices.RotateSecret(ctx, u.ID, in.ID)
		if err != nil {
			return nil, deviceMgmtErr(ctx, deps, "rotate device secret", u.ID, in.ID, err)
		}
		return &rotateSecretOutput{Body: rotateSecretResponse{
			Secret: base64.StdEncoding.EncodeToString(secret),
		}}, nil
	})

	huma.Register(a, huma.Operation{
		Method:      http.MethodGet,
		Path:        "/api/v1/devices/{id}/history",
		Middlewares: session(),
	}, func(ctx context.Context, in *historyInput) (*historyOutput, error) {
		u := UserFrom(ctx)
		page, err := deps.Devices.History(ctx, u.ID, in.ID, in.Cursor, in.Limit)
		if err != nil {
			return nil, deviceMgmtErr(ctx, deps, "get device history", u.ID, in.ID, err)
		}
		rows := make([]historyRow, len(page.Rows))
		for i, hr := range page.Rows {
			rows[i] = historyRow{ObservedAt: hr.ObservedAt, IPv4: hr.IPv4, IPv6: hr.IPv6, ClientVersion: hr.ClientVersion}
		}
		return &historyOutput{Body: historyResponse{Rows: rows, NextCursor: page.NextCursor}}, nil
	})
}

// deviceMgmtErr maps a service error to the right huma response: ownership /
// missing → 404, label conflict → 409, everything else → logged 500.
func deviceMgmtErr(ctx context.Context, deps ServerDeps, action, userID, deviceID string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return huma.Error404NotFound("device not found")
	case errors.Is(err, store.ErrConflict):
		return huma.Error409Conflict("a device with that label already exists")
	default:
		deps.Log.LogAttrs(ctx, slog.LevelError, action+" failed",
			slog.String("user_id", userID), slog.String("device_id", deviceID), slog.Any("error", err))
		return huma.Error500InternalServerError("failed to " + action)
	}
}
