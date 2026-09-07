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
// One rule covers the three device events (design #106 §6.1): the device's
// allowed set is now `current`; an all-null `current` means delete.
const (
	EventIPChanged = "device.ip_changed"
	EventAdded     = "device.added"
	EventRemoved   = "device.removed"
	EventTest      = "endpoint.test"
)

type addrs struct {
	IPv4 *string `json:"ipv4"`
	IPv6 *string `json:"ipv6"`
}

// devicePayload is the event's device object: exactly {id, label} (design
// D22). hostname, os and client_version are deliberately absent so a delta
// discloses nothing the feed snapshot does not.
type devicePayload struct {
	ID    string `json:"id"`
	Label string `json:"label"`
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

// familiesPresent names the address families d carries, in the payload's
// "changed" order.
func familiesPresent(d store.Device) []string {
	out := []string{}
	if d.CurrentIPv4 != "" {
		out = append(out, "ipv4")
	}
	if d.CurrentIPv6 != "" {
		out = append(out, "ipv6")
	}
	return out
}

func rfc3339(unix int64) string {
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

func marshal(e event, what string) ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("notify: render %s: %w", what, err)
	}
	return b, nil
}

// RenderIPChanged produces the exact bytes that will be signed and sent. The
// result is frozen into the outbox row, so every retry sends byte-identical
// content and consumers can dedupe on (type, id).
func RenderIPChanged(ev store.IPChangeEvent) ([]byte, error) {
	changed := ev.Changed()
	if changed == nil {
		changed = []string{} // marshal as [], never null
	}
	return marshal(event{
		Version:    payloadVersion,
		Type:       EventIPChanged,
		ID:         ev.EventID,
		OccurredAt: rfc3339(ev.OccurredAt),
		Device:     &devicePayload{ID: ev.Device.ID, Label: ev.Device.Label},
		Changed:    changed,
		Current:    addrs{IPv4: nullable(ev.CurrIPv4), IPv6: nullable(ev.CurrIPv6)},
		Previous:   addrs{IPv4: nullable(ev.PrevIPv4), IPv6: nullable(ev.PrevIPv6)},
	}, "ip_changed")
}

// RenderAdded produces a device.added event: d has just joined the feed
// (re-enabled, or its owner re-enabled), so previous is all-null and current
// is d's addresses. seq is the feed_state seq the fan-out obtained for it —
// the event's id under the (type, id) dedupe rule. Callers must pass only a
// device that satisfies the feed-membership predicate (design D18), which
// requires at least one current address — otherwise current would be
// all-null too, indistinguishable from a delete.
func RenderAdded(seq, now int64, d store.Device) ([]byte, error) {
	return marshal(event{
		Version:    payloadVersion,
		Type:       EventAdded,
		ID:         seq,
		OccurredAt: rfc3339(now),
		Device:     &devicePayload{ID: d.ID, Label: d.Label},
		Changed:    familiesPresent(d),
		Current:    addrs{IPv4: nullable(d.CurrentIPv4), IPv6: nullable(d.CurrentIPv6)},
		Previous:   addrs{},
	}, "added")
}

// RenderRemoved produces a device.removed event: d has just left the feed
// (disabled, deleted, owner disabled or deleted), so current is all-null and
// previous is the addresses being withdrawn.
func RenderRemoved(seq, now int64, d store.Device) ([]byte, error) {
	return marshal(event{
		Version:    payloadVersion,
		Type:       EventRemoved,
		ID:         seq,
		OccurredAt: rfc3339(now),
		Device:     &devicePayload{ID: d.ID, Label: d.Label},
		Changed:    familiesPresent(d),
		Current:    addrs{},
		Previous:   addrs{IPv4: nullable(d.CurrentIPv4), IPv6: nullable(d.CurrentIPv6)},
	}, "removed")
}

// RenderTest produces an endpoint.test event: same envelope, no device, no
// addresses. Without it the only way to verify an endpoint is to wait for a
// real IP change, which may be days away.
func RenderTest(now int64) ([]byte, error) {
	return marshal(event{
		Version:    payloadVersion,
		Type:       EventTest,
		ID:         0,
		OccurredAt: rfc3339(now),
		Device:     nil,
		Changed:    []string{},
	}, "test")
}
