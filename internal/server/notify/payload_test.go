package notify

import (
	"encoding/json"
	"strings"
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

// TestRenderIPChanged_DeviceObjectIsIDAndLabelOnly is design D22: the
// device object carries exactly {id, label}. hostname, os and client_version
// left the contract with #106 so a feed-token holder learns nothing from a
// delta that the snapshot does not disclose.
func TestRenderIPChanged_DeviceObjectIsIDAndLabelOnly(t *testing.T) {
	ev := store.IPChangeEvent{
		EventID: 1, Device: store.Device{ID: "dev1", Label: "router", Hostname: "h", OS: "linux", ClientVersion: "v1"},
		PrevIPv4: "1.1.1.1", CurrIPv4: "2.2.2.2",
	}
	b, err := RenderIPChanged(ev)
	if err != nil {
		t.Fatalf("RenderIPChanged: %v", err)
	}
	var got struct {
		Device map[string]any `json:"device"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if len(got.Device) != 2 || got.Device["id"] != "dev1" || got.Device["label"] != "router" {
		t.Errorf("device = %v, want exactly {id: dev1, label: router}", got.Device)
	}
}

// TestRenderAddedAndRemoved pins the two membership events (design §6.1):
// same envelope, id = feed_state.seq, added has null previous and the
// device's addresses as current; removed is the mirror image.
func TestRenderAddedAndRemoved(t *testing.T) {
	const now = 1755153174 // 2025-08-14T06:32:54Z
	dev := store.Device{ID: "dev1", Label: "router", CurrentIPv4: "203.0.113.9", CurrentIPv6: ""}

	type addrs struct {
		IPv4 *string `json:"ipv4"`
		IPv6 *string `json:"ipv6"`
	}
	type payload struct {
		Version    int            `json:"version"`
		Type       string         `json:"type"`
		ID         int64          `json:"id"`
		OccurredAt string         `json:"occurred_at"`
		Device     map[string]any `json:"device"`
		Changed    []string       `json:"changed"`
		Current    addrs          `json:"current"`
		Previous   addrs          `json:"previous"`
	}
	decode := func(b []byte) payload {
		t.Helper()
		var p payload
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatalf("payload is not valid JSON: %v", err)
		}
		return p
	}

	added, err := RenderAdded(41, now, dev)
	if err != nil {
		t.Fatalf("RenderAdded: %v", err)
	}
	a := decode(added)
	if a.Version != 1 || a.Type != EventAdded || a.ID != 41 || a.OccurredAt != "2025-08-14T06:32:54Z" {
		t.Errorf("added envelope = %+v", a)
	}
	if a.Device["id"] != "dev1" || a.Device["label"] != "router" || len(a.Device) != 2 {
		t.Errorf("added device = %v, want {id,label}", a.Device)
	}
	if a.Current.IPv4 == nil || *a.Current.IPv4 != "203.0.113.9" || a.Current.IPv6 != nil {
		t.Errorf("added current = %+v, want ipv4 203.0.113.9 and ipv6 null", a.Current)
	}
	if a.Previous.IPv4 != nil || a.Previous.IPv6 != nil {
		t.Errorf("added previous = %+v, want both null", a.Previous)
	}
	if len(a.Changed) != 1 || a.Changed[0] != "ipv4" {
		t.Errorf("added changed = %v, want [ipv4] (the families present)", a.Changed)
	}

	removed, err := RenderRemoved(42, now, dev)
	if err != nil {
		t.Fatalf("RenderRemoved: %v", err)
	}
	r := decode(removed)
	if r.Type != EventRemoved || r.ID != 42 {
		t.Errorf("removed envelope = %+v", r)
	}
	if r.Current.IPv4 != nil || r.Current.IPv6 != nil {
		t.Errorf("removed current = %+v, want both null", r.Current)
	}
	if r.Previous.IPv4 == nil || *r.Previous.IPv4 != "203.0.113.9" || r.Previous.IPv6 != nil {
		t.Errorf("removed previous = %+v, want ipv4 203.0.113.9 and ipv6 null", r.Previous)
	}
	if len(r.Changed) != 1 || r.Changed[0] != "ipv4" {
		t.Errorf("removed changed = %v, want [ipv4] (the families removed)", r.Changed)
	}
	if strings.Contains(string(added), `""`) || strings.Contains(string(removed), `""`) {
		t.Error("an absent family must be JSON null, never \"\"")
	}
}
