package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/server/clientip"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/shared"
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
	// Capabilities lists what the client supports; unknown entries are ignored.
	Capabilities []string `json:"capabilities,omitempty"`
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
	// IPSource says, per family this check-in carried, where the recorded
	// address came from. It is {} when the check-in carried no family.
	IPSource ipSourceBody `json:"ip_source"`
	// Rotation says which tracks an admin asked this device to rotate. It is
	// always emitted; a client that does not know it ignores it.
	Rotation rotationFlags `json:"rotation"`
}

// rotationFlags is the per-track rotation request a check-in answers with.
type rotationFlags struct {
	Secret bool `json:"secret"`
	Cert   bool `json:"cert"`
}

// ipSourceBody is the per-family source of a check-in's recorded address:
// "reported", "observed" or "none". A family the check-in did not carry is
// absent.
type ipSourceBody struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
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

// addrOrEmpty is a.String(), or "" for the zero Addr (whose String is "invalid IP").
func addrOrEmpty(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// registerCheckinOps registers the two HMAC-authenticated agent operations
// onto a: POST /agent/v1/checkin and GET /agent/v1/self. Both attach mws (which
// must include HMAC verification) and read the authenticated device id via
// DeviceIDFrom.
func registerCheckinOps(a huma.API, deps ServerDeps, mws huma.Middlewares, viaAgent bool) {
	huma.Register(a, huma.Operation{
		Method:      http.MethodPost,
		Path:        "/agent/v1/checkin",
		Middlewares: mws,
	}, func(ctx context.Context, in *checkinInput) (*checkinOutput, error) {
		deviceID := DeviceIDFrom(ctx)
		obs := clientip.ObservationFrom(ctx)
		var observed netip.Addr
		if obs.OK {
			observed = obs.Addr
		}
		res, err := deps.Checkin.Checkin(ctx, deviceID, service.CheckinReport{
			IPv4:             in.Body.IPv4,
			IPv6:             in.Body.IPv6,
			Hostname:         in.Body.Hostname,
			OS:               in.Body.OS,
			ClientVersion:    in.Body.ClientVersion,
			SupportsRotation: slices.Contains(in.Body.Capabilities, shared.CapabilityRotation),
			ViaAgent:         viaAgent,
			Observed:         observed,
			Peer:             obs.Peer,
		})
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "checkin failed",
				slog.String("device_id", deviceID), slog.Any("error", err))
			return nil, huma.Error500InternalServerError("check-in failed")
		}
		// Empty strings, not "invalid IP", when there is no peer or observation.
		deps.Log.LogAttrs(ctx, slog.LevelInfo, "check-in",
			slog.String("device_id", deviceID),
			slog.String("peer", addrOrEmpty(obs.Peer)),
			slog.String("observed", addrOrEmpty(observed)),
			slog.String("ipv4_source", string(res.SourceV4)),
			slog.String("ipv6_source", string(res.SourceV6)))
		return &checkinOutput{Body: checkinResponse{
			DeviceID:    res.DeviceID,
			CurrentIPv4: res.CurrentIPv4,
			CurrentIPv6: res.CurrentIPv6,
			Stored:      res.Stored,
			IPSource:    ipSourceBody{IPv4: string(res.SourceV4), IPv6: string(res.SourceV6)},
			Rotation:    rotationFlags{Secret: res.RotateSecret, Cert: res.RotateCert},
		}}, nil
	})

	huma.Register(a, huma.Operation{
		Method:      http.MethodGet,
		Path:        "/agent/v1/self",
		Middlewares: mws,
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
