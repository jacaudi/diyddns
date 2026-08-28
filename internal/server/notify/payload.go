package notify

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

// payloadVersion is the wire-contract version. Consumers depend on this
// document; adding fields is safe, changing their meaning is not.
const payloadVersion = 1

// Event type strings. Consumers must ignore unknown types rather than erroring.
const (
	EventIPChanged = "device.ip_changed"
	EventTest      = "endpoint.test"
)

type addrs struct {
	IPv4 *string `json:"ipv4"`
	IPv6 *string `json:"ipv6"`
}

type devicePayload struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	ClientVersion string `json:"client_version"`
}

type event struct {
	Version    int            `json:"version"`
	Type       string         `json:"type"`
	ID         int64          `json:"id"`
	OccurredAt string         `json:"occurred_at"`
	Device     *devicePayload `json:"device"`
	Changed    []string       `json:"changed"`
	Current    addrs          `json:"current"`
	Previous   addrs          `json:"previous"`
}

// nullable maps "" to JSON null. The columns are nullable TEXT and Go reads
// them as "", so emitting "" would make "this device has no IPv6"
// indistinguishable from "IPv6 was not part of this event" — and a consumer
// writing an empty record off that is a real failure, not a cosmetic one.
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// RenderIPChanged produces the exact bytes that will be signed and sent. The
// result is frozen into the outbox row, so every retry sends byte-identical
// content and consumers can dedupe on (type, id).
func RenderIPChanged(ev store.IPChangeEvent) ([]byte, error) {
	changed := ev.Changed()
	if changed == nil {
		changed = []string{} // marshal as [], never null
	}
	e := event{
		Version:    payloadVersion,
		Type:       EventIPChanged,
		ID:         ev.EventID,
		OccurredAt: time.Unix(ev.OccurredAt, 0).UTC().Format(time.RFC3339),
		Device: &devicePayload{
			ID:            ev.Device.ID,
			Label:         ev.Device.Label,
			Hostname:      ev.Device.Hostname,
			OS:            ev.Device.OS,
			ClientVersion: ev.Device.ClientVersion,
		},
		Changed:  changed,
		Current:  addrs{IPv4: nullable(ev.CurrIPv4), IPv6: nullable(ev.CurrIPv6)},
		Previous: addrs{IPv4: nullable(ev.PrevIPv4), IPv6: nullable(ev.PrevIPv6)},
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("notify: render ip_changed: %w", err)
	}
	return b, nil
}

// RenderTest produces an endpoint.test event: same envelope, no device, no
// addresses. Without it the only way to verify an endpoint is to wait for a
// real IP change, which may be days away.
func RenderTest(now int64) ([]byte, error) {
	e := event{
		Version:    payloadVersion,
		Type:       EventTest,
		ID:         0,
		OccurredAt: time.Unix(now, 0).UTC().Format(time.RFC3339),
		Device:     nil,
		Changed:    []string{},
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("notify: render test: %w", err)
	}
	return b, nil
}
