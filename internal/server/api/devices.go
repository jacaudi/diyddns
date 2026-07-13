package api

import (
	"context"
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
