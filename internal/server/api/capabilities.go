package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/version"
)

// hmacSkewWindowSeconds mirrors the HMAC timestamp skew window from the design
// spec (§5A). Kept as a constant until the auth config section lands.
const hmacSkewWindowSeconds = 120

// Capabilities is the public shape returned by GET /agent/v1/capabilities. The
// client reads it to decide enrollment paths. Fields the skeleton cannot yet
// determine dynamically (OIDCEnabled) are static; later plans make them live.
type Capabilities struct {
	ServerVersion     string   `json:"server_version"`
	SkewWindowSeconds int      `json:"skew_window_seconds"`
	AddressFamilies   []string `json:"address_families"`
	OIDCEnabled       bool     `json:"oidc_enabled"`
}

type capabilitiesOutput struct {
	Body Capabilities
}

func registerCapabilities(a huma.API, info version.Info) {
	huma.Get(a, "/agent/v1/capabilities", func(_ context.Context, _ *struct{}) (*capabilitiesOutput, error) {
		return &capabilitiesOutput{Body: Capabilities{
			ServerVersion:     info.Version,
			SkewWindowSeconds: hmacSkewWindowSeconds,
			AddressFamilies:   []string{"ipv4", "ipv6"},
			OIDCEnabled:       false,
		}}, nil
	})
}
