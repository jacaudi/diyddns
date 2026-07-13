package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jacaudi/diyddns/internal/oidc/oidctest"
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
