package service

import (
	"context"
	"fmt"

	"github.com/jacaudi/diyddns/internal/store"
)

// CheckinReport is the IP/metadata a device reports on each check-in.
type CheckinReport struct {
	IPv4, IPv6, Hostname, OS, ClientVersion string
}

// CheckinResult is returned to a device after a check-in. Stored reports
// whether the check-in changed the device's recorded IP addresses (and thus
// appended an ip_history row); it is false for a routine, unchanged
// check-in.
type CheckinResult struct {
	DeviceID                 string
	CurrentIPv4, CurrentIPv6 string
	Stored                   bool
}

// Notifier is fired after a check-in that actually changed a device's recorded
// addresses. It is enqueue-only: implementations must not perform network I/O
// and must not return errors to the check-in path, because /agent/v1/checkin is
// the device liveness path and must survive a broken or hostile hook.
//
// Declared here, at its consumer, and parameterised on store.IPChangeEvent —
// so implementations satisfy it structurally and never import this package.
//
// This is deliberately NOT an AuditSink. An AuditSink records security-relevant
// events; a Notifier says "this address changed, go tell someone". Same shape,
// different knowledge — see the design's §11 and issue #11.
type Notifier interface {
	IPChanged(ctx context.Context, ev store.IPChangeEvent)
}

// CheckinService records device check-ins, persisting a new ip_history row
// only when the reported IP addresses differ from what's already stored.
type CheckinService struct {
	st     *store.Store
	notify Notifier
}

// NewCheckinService constructs a CheckinService. notify is fired only when a
// check-in actually changes the device's recorded addresses.
func NewCheckinService(st *store.Store, notify Notifier) *CheckinService {
	return &CheckinService{st: st, notify: notify}
}

// Checkin records a device's reported IP addresses using merge-on-empty
// semantics: an omitted family (empty IPv4 or IPv6 in the report) means "not
// asserted this cycle" and preserves the device's stored value — it does not
// clear it. Change detection runs on these merged effective values; if they
// match what's already stored, nothing is appended and CheckinResult.Stored
// is false. Otherwise the device's IP/metadata fields (and last_seen_at) are
// updated to the effective values and a new ip_history row is appended.
//
// The device read, the merge, the per-family assertion (a non-empty RAW
// field) and the write all happen inside store.RecordIPChange's single
// transaction, so two concurrent per-family check-ins for one device cannot
// revert each other. The merge is load-bearing for a DDNS tracker: the
// /checkin IP fields are optional (design §5A, "omit if unconfirmed"), and
// writing raw report values would clobber a stored family a single-stack
// client simply didn't confirm this cycle — silent data loss.
//
// Routine check-ins are not audited — auditing is reserved for security-
// relevant events, and a routine IP report is not one of them.
func (s *CheckinService) Checkin(ctx context.Context, deviceID string, r CheckinReport) (CheckinResult, error) {
	// One transaction: the device row and its ip_history row land together or
	// not at all. Writing them separately let a failure between the two leave
	// a device showing an address with no history row for it, so the device
	// page and the history page disagreed and "last change" — derived from
	// the latest history row — silently skipped the change (#97).
	out, err := s.st.RecordIPChange(ctx, store.IPChange{
		DeviceID:      deviceID,
		IPv4:          r.IPv4,
		IPv6:          r.IPv6,
		ClientVersion: r.ClientVersion,
		Hostname:      r.Hostname,
		OS:            r.OS,
	})
	if err != nil {
		return CheckinResult{}, fmt.Errorf("service.Checkin: %w", err)
	}

	if out.Changed {
		// Best-effort by design: IPChanged returns nothing, so a failed enqueue is
		// logged by the implementation and the check-in still succeeds. Durability
		// starts at the outbox row, not at the check-in.
		s.fireNotify(ctx, store.IPChangeEvent{
			EventID:    out.Row.ID,
			OccurredAt: out.Row.ObservedAt,
			Device:     out.Prev,
			PrevIPv4:   out.Prev.CurrentIPv4,
			PrevIPv6:   out.Prev.CurrentIPv6,
			CurrIPv4:   out.CurrIPv4,
			CurrIPv6:   out.CurrIPv6,
		})
	}

	return CheckinResult{
		DeviceID:    out.Prev.ID,
		CurrentIPv4: out.CurrIPv4,
		CurrentIPv6: out.CurrIPv6,
		Stored:      out.Changed,
	}, nil
}

// fireNotify calls the notifier and swallows a panic from it. A Notifier
// returning no error is not enough on its own: a nil logger or nil repository
// inside an implementation panics, and without this recover it would propagate
// out of Checkin and turn a device's liveness call into a 500 — the one thing
// /agent/v1/checkin must never do.
//
// The recover wraps ONLY the notifier call. Putting `defer recover()` at the
// top of Checkin instead would also swallow store panics, which must surface.
func (s *CheckinService) fireNotify(ctx context.Context, ev store.IPChangeEvent) {
	defer func() { _ = recover() }()
	s.notify.IPChanged(ctx, ev)
}

// Self returns the device identified by deviceID.
func (s *CheckinService) Self(ctx context.Context, deviceID string) (store.Device, error) {
	dev, err := s.st.Devices().GetByID(ctx, deviceID)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.Self: %w", err)
	}
	return dev, nil
}
