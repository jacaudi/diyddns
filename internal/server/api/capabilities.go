package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"
)

// Capabilities is the public shape returned by GET /agent/v1/capabilities. The
// client reads it to decide enrollment paths. OIDCEnabled and
// OIDCDeviceEnabled are read live from deps.OIDCMgr on every request.
type Capabilities struct {
	ServerVersion     string   `json:"server_version"`
	SkewWindowSeconds int      `json:"skew_window_seconds"`
	AddressFamilies   []string `json:"address_families"`
	OIDCEnabled       bool     `json:"oidc_enabled"`
	OIDCDeviceEnabled bool     `json:"oidc_device_enabled"`
	// AgentMTLS is present only when the agent listener is enabled (#173).
	AgentMTLS *AgentMTLSCapability `json:"agent_mtls,omitempty"`
}

// AgentMTLSCapability tells a client where the mTLS agent listener lives.
type AgentMTLSCapability struct {
	AgentURL string `json:"agent_url"`
}

type capabilitiesOutput struct {
	Body Capabilities
}

func registerCapabilities(a huma.API, deps ServerDeps) {
	huma.Get(a, "/agent/v1/capabilities", func(_ context.Context, _ *struct{}) (*capabilitiesOutput, error) {
		caps := Capabilities{
			ServerVersion:     deps.Info.Version,
			SkewWindowSeconds: int(deps.Cfg.HMAC.SkewWindow.Seconds()),
			AddressFamilies:   []string{"ipv4", "ipv6"},
			OIDCEnabled:       deps.OIDCMgr.Enabled(),
			OIDCDeviceEnabled: deps.OIDCMgr.DeviceEnabled(),
		}
		if deps.AgentURL != "" {
			caps.AgentMTLS = &AgentMTLSCapability{AgentURL: deps.AgentURL}
		}
		return &capabilitiesOutput{Body: caps}, nil
	})
}
