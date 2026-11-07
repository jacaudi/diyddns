package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jacaudi/diyddns/internal/oidc/oidctest"
	"github.com/jacaudi/diyddns/internal/server/api"
)

// oidcCapabilities is the subset of the /agent/v1/capabilities body this file
// cares about.
type oidcCapabilities struct {
	OIDCEnabled       bool `json:"oidc_enabled"`
	OIDCDeviceEnabled bool `json:"oidc_device_enabled"`
}

// getCapabilities GETs /agent/v1/capabilities off srvURL and decodes the
// fields this file asserts on.
func getCapabilities(t *testing.T, srvURL string) oidcCapabilities {
	t.Helper()
	resp, err := http.Get(srvURL + "/agent/v1/capabilities")
	if err != nil {
		t.Fatalf("get capabilities: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("capabilities status = %d", resp.StatusCode)
	}
	var caps oidcCapabilities
	if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	return caps
}

// TestCapabilities_ReflectsOIDCManager asserts that oidc_enabled and
// oidc_device_enabled track the wired OIDC manager: both true when OIDC and
// device support are configured, both false (no panic) when no manager is
// wired at all.
func TestCapabilities_ReflectsOIDCManager(t *testing.T) {
	t.Run("enabled with device support", func(t *testing.T) {
		idp := oidctest.New(t, oidctest.Options{SupportDevice: true})
		h := newOIDCHarness(t, oidcTestCfg(idp))

		caps := getCapabilities(t, h.srv.URL)
		if !caps.OIDCEnabled {
			t.Error("OIDCEnabled = false, want true")
		}
		if !caps.OIDCDeviceEnabled {
			t.Error("OIDCDeviceEnabled = false, want true")
		}
	})

	t.Run("disabled when no manager wired", func(t *testing.T) {
		h := newFullHarness(t)

		caps := getCapabilities(t, h.srv.URL)
		if caps.OIDCEnabled {
			t.Error("OIDCEnabled = true, want false")
		}
		if caps.OIDCDeviceEnabled {
			t.Error("OIDCDeviceEnabled = true, want false")
		}
	})
}

func TestCapabilities_AgentMTLS(t *testing.T) {
	get := func(t *testing.T, h agentHarness) map[string]json.RawMessage {
		t.Helper()
		resp, err := http.Get(h.srv.URL + "/agent/v1/capabilities")
		if err != nil {
			t.Fatalf("get capabilities: %v", err)
		}
		defer resp.Body.Close()
		var m map[string]json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return m
	}

	t.Run("agent url set", func(t *testing.T) {
		h := newAgentHarnessWith(t, func(d *api.ServerDeps) { d.AgentURL = testAgentURL })
		raw, ok := get(t, h)["agent_mtls"]
		if !ok {
			t.Fatal("agent_mtls key absent, want present")
		}
		var got struct {
			AgentURL string `json:"agent_url"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("decode agent_mtls: %v", err)
		}
		if got.AgentURL != testAgentURL {
			t.Errorf("agent_url = %q, want %q", got.AgentURL, testAgentURL)
		}
	})

	t.Run("agent url unset", func(t *testing.T) {
		h := newAgentHarness(t)
		if _, ok := get(t, h)["agent_mtls"]; ok {
			t.Error("agent_mtls key present, want absent")
		}
	})
}
