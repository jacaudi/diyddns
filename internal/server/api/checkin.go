package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/server/service"
)

// checkinBody is the JSON wire shape of POST /agent/v1/checkin. It exists
// separately from service.CheckinReport because CheckinReport carries no
// json tags (it is a pure Go-to-Go service contract) and encoding/json's
// case-insensitive fallback does not bridge "client_version" to
// ClientVersion. The handler copies these fields into a CheckinReport
// unchanged — no defaulting or merge logic lives here; that belongs to
// CheckinService.Checkin (T7's merge-on-empty semantics).
type checkinBody struct {
	IPv4          string `json:"ipv4,omitempty"`
	IPv6          string `json:"ipv6,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	OS            string `json:"os,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
}

type checkinInput struct {
	Body checkinBody
}

// checkinResponse mirrors service.CheckinResult for JSON transport.
type checkinResponse struct {
	DeviceID    string `json:"device_id"`
	CurrentIPv4 string `json:"current_ipv4"`
	CurrentIPv6 string `json:"current_ipv6"`
	Stored      bool   `json:"stored"`
}

type checkinOutput struct {
	Body checkinResponse
}

// selfResponse is the device view returned by GET /agent/v1/self — the
// fields a device itself needs to see, mirroring store.Device minus the
// internal SecretHash and UserID.
type selfResponse struct {
	DeviceID      string `json:"device_id"`
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

type selfOutput struct {
	Body selfResponse
}

// registerCheckinOps registers the two HMAC-authenticated agent operations
// onto a: POST /agent/v1/checkin and GET /agent/v1/self. Both attach
// hmacMiddleware and read the authenticated device id via DeviceIDFrom.
func registerCheckinOps(a huma.API, deps ServerDeps) {
	huma.Register(a, huma.Operation{
		Method:      http.MethodPost,
		Path:        "/agent/v1/checkin",
		Middlewares: huma.Middlewares{hmacMiddleware(a, deps.Verifier, maxAgentBody)},
	}, func(ctx context.Context, in *checkinInput) (*checkinOutput, error) {
		deviceID := DeviceIDFrom(ctx)
		res, err := deps.Checkin.Checkin(ctx, deviceID, service.CheckinReport{
			IPv4:          in.Body.IPv4,
			IPv6:          in.Body.IPv6,
			Hostname:      in.Body.Hostname,
			OS:            in.Body.OS,
			ClientVersion: in.Body.ClientVersion,
		})
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "checkin failed",
				slog.String("device_id", deviceID), slog.Any("error", err))
			return nil, huma.Error500InternalServerError("check-in failed")
		}
		return &checkinOutput{Body: checkinResponse{
			DeviceID:    res.DeviceID,
			CurrentIPv4: res.CurrentIPv4,
			CurrentIPv6: res.CurrentIPv6,
			Stored:      res.Stored,
		}}, nil
	})

	huma.Register(a, huma.Operation{
		Method:      http.MethodGet,
		Path:        "/agent/v1/self",
		Middlewares: huma.Middlewares{hmacMiddleware(a, deps.Verifier, maxAgentBody)},
	}, func(ctx context.Context, _ *struct{}) (*selfOutput, error) {
		deviceID := DeviceIDFrom(ctx)
		dev, err := deps.Checkin.Self(ctx, deviceID)
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "self lookup failed",
				slog.String("device_id", deviceID), slog.Any("error", err))
			return nil, huma.Error500InternalServerError("self lookup failed")
		}
		return &selfOutput{Body: selfResponse{
			DeviceID:      dev.ID,
			Label:         dev.Label,
			CurrentIPv4:   dev.CurrentIPv4,
			CurrentIPv6:   dev.CurrentIPv6,
			Hostname:      dev.Hostname,
			OS:            dev.OS,
			ClientVersion: dev.ClientVersion,
			LastSeenAt:    dev.LastSeenAt,
			Disabled:      dev.Disabled,
			CreatedAt:     dev.CreatedAt,
			UpdatedAt:     dev.UpdatedAt,
		}}, nil
	})
}
