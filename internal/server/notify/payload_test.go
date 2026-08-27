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

// TestRenderIPChanged_NoChangedFamiliesMarshalsEmptyArray is the regression
// guard for the `if changed == nil { changed = []string{} }` fallback in
// RenderIPChanged: json.Marshal of a nil []string emits JSON null, but the
// wire contract (README) promises "changed" is always an array. Every other
// payload test seeds at least one changed family, so removing the fallback
// left all of them passing.
func TestRenderIPChanged_NoChangedFamiliesMarshalsEmptyArray(t *testing.T) {
	ev := store.IPChangeEvent{
		EventID: 7, Device: store.Device{ID: "d"},
		PrevIPv4: "1.1.1.1", CurrIPv4: "1.1.1.1", // unchanged
		PrevIPv6: "", CurrIPv6: "", // unchanged (both absent)
	}
	b, err := RenderIPChanged(ev)
	if err != nil {
		t.Fatalf("RenderIPChanged: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	changed, ok := got["changed"].([]any)
	if !ok {
		t.Fatalf("changed = %#v, want a JSON array, not null", got["changed"])
	}
	if len(changed) != 0 {
		t.Errorf("changed = %v, want an empty array", changed)
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

// TestRenderTest pins RenderTest's envelope: nothing in this package
// referenced RenderTest before this test, despite the webui /test route
// (Task 8) consuming it in production.
func TestRenderTest(t *testing.T) {
	const now = 1755153174 // 2025-08-14T06:32:54Z, same fixture value as the other payload tests

	b, err := RenderTest(now)
	if err != nil {
		t.Fatalf("RenderTest: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if got["version"] != float64(1) {
		t.Errorf("version = %v, want 1", got["version"])
	}
	if got["type"] != "endpoint.test" {
		t.Errorf("type = %v, want endpoint.test", got["type"])
	}
	if got["id"] != float64(0) {
		t.Errorf("id = %v, want 0", got["id"])
	}
	if got["occurred_at"] != "2025-08-14T06:32:54Z" {
		t.Errorf("occurred_at = %v, want 2025-08-14T06:32:54Z", got["occurred_at"])
	}
	if device, present := got["device"]; present && device != nil {
		t.Errorf("device = %v, want absent/null: a test event has no device", device)
	}
	changed, ok := got["changed"].([]any)
	if !ok {
		t.Fatalf("changed = %#v, want a JSON array, not null", got["changed"])
	}
	if len(changed) != 0 {
		t.Errorf("changed = %v, want an empty array", changed)
	}
}
