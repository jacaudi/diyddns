package notify

import (
	"encoding/json"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

func TestRenderIPChanged_AbsentFamilyIsNullNotEmptyString(t *testing.T) {
	ev := store.IPChangeEvent{
		EventID:    4821,
		OccurredAt: 1755153174,
		Device: store.Device{
			ID: "dev1", Label: "test 1", Hostname: "h", OS: "linux", ClientVersion: "v0.1.0",
		},
		PrevIPv4: "50.125.255.12", CurrIPv4: "50.125.255.69",
		PrevIPv6: "", CurrIPv6: "", // this device has no v6
	}

	b, err := RenderIPChanged(ev)
	if err != nil {
		t.Fatalf("RenderIPChanged: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if got["version"] != float64(1) {
		t.Errorf("version = %v, want 1", got["version"])
	}
	if got["type"] != "device.ip_changed" {
		t.Errorf("type = %v", got["type"])
	}
	if got["id"] != float64(4821) {
		t.Errorf("id = %v, want 4821", got["id"])
	}
	// 1755153174 is 2025-08-14T06:32:54Z. Verified, not assumed — the design's
	// §4.1 example renders it as 2026-… which is wrong; this is the value the
	// code must produce.
	if got["occurred_at"] != "2025-08-14T06:32:54Z" {
		t.Errorf("occurred_at = %v, want 2025-08-14T06:32:54Z", got["occurred_at"])
	}
	curr := got["current"].(map[string]any)
	if curr["ipv6"] != nil {
		t.Errorf("current.ipv6 = %#v, want JSON null", curr["ipv6"])
	}
	if curr["ipv4"] != "50.125.255.69" {
		t.Errorf("current.ipv4 = %v", curr["ipv4"])
	}
	changed := got["changed"].([]any)
	if len(changed) != 1 || changed[0] != "ipv4" {
		t.Errorf("changed = %v, want [ipv4]", changed)
	}
	if _, present := got["user_id"]; present {
		t.Error("user_id must not appear in the payload")
	}
}

func TestRenderIPChanged_BothFamiliesMoved(t *testing.T) {
	ev := store.IPChangeEvent{
		EventID: 1, Device: store.Device{ID: "d"},
		PrevIPv4: "1.1.1.1", CurrIPv4: "2.2.2.2",
		PrevIPv6: "2001:db8::1", CurrIPv6: "2001:db8::2",
	}
	b, err := RenderIPChanged(ev)
	if err != nil {
		t.Fatalf("RenderIPChanged: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	changed := got["changed"].([]any)
	if len(changed) != 2 {
		t.Errorf("changed = %v, want both families", changed)
	}
}
