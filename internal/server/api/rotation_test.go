package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jacaudi/diyddns/internal/shared"
)

func TestCheckin_CapabilityWritesSupportsRotation(t *testing.T) {
	h := newAgentHarness(t)
	id, secret := enrollViaHTTP(t, h, "rot-cap@example.com", "laptop")

	tests := []struct {
		name string
		body map[string]any
		want bool
	}{
		{"advertised", map[string]any{"ipv4": "203.0.113.5", "capabilities": []string{shared.CapabilityRotation}}, true},
		{"omitted clears it", map[string]any{"ipv4": "203.0.113.5"}, false},
		{"unknown entry ignored", map[string]any{"ipv4": "203.0.113.5", "capabilities": []string{"future"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := doSigned(t, h, http.MethodPost, "/agent/v1/checkin", id, secret, tt.body)
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200, body=%s", status, body)
			}
			dev, err := h.st.Devices().GetByID(t.Context(), id)
			if err != nil {
				t.Fatalf("GetByID: %v", err)
			}
			if dev.SupportsRotation != tt.want {
				t.Errorf("SupportsRotation = %v, want %v", dev.SupportsRotation, tt.want)
			}
			if dev.LastCheckinMTLS {
				t.Error("LastCheckinMTLS = true on the main port, want false")
			}
		})
	}
}

func TestCheckin_ResponseRotationFromPrev(t *testing.T) {
	h := newAgentHarness(t)
	id, secret := enrollViaHTTP(t, h, "rot-resp@example.com", "laptop")

	type rotation struct {
		Secret bool `json:"secret"`
		Cert   bool `json:"cert"`
	}
	checkin := func(t *testing.T) rotation {
		t.Helper()
		status, body := doSigned(t, h, http.MethodPost, "/agent/v1/checkin", id, secret, map[string]string{"ipv4": "203.0.113.5"})
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", status, body)
		}
		var got struct {
			Rotation *rotation `json:"rotation"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Rotation == nil {
			t.Fatalf("rotation key absent, want always emitted, body=%s", body)
		}
		return *got.Rotation
	}

	if got := checkin(t); got != (rotation{}) {
		t.Errorf("unmarked rotation = %+v, want both false", got)
	}
	if err := h.st.Devices().MarkRotation(t.Context(), id, true, false, 1); err != nil {
		t.Fatalf("MarkRotation: %v", err)
	}
	// The check-in above sent no capability: the flags still ride (P6).
	if got := checkin(t); got != (rotation{Secret: true}) {
		t.Errorf("marked rotation = %+v, want secret only", got)
	}
}
