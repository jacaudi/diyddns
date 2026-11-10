package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/jacaudi/diyddns/internal/shared/ipclass"
	"github.com/jacaudi/diyddns/internal/store"
)

// CheckinReport is the IP/metadata a device reports on each check-in, plus the
// address the server observed the request coming from. IPv4/IPv6 are the RAW
// reported strings; Observed is the zero Addr when no origin was resolved. Peer
// is the connection peer, carried for logging only.
type CheckinReport struct {
	IPv4, IPv6, Hostname, OS, ClientVersion string
	Observed, Peer                          netip.Addr

	// SupportsRotation is set when the client advertised the rotation capability
	// on this check-in; ViaAgent when the request arrived over the mTLS agent
	// listener (#175).
	SupportsRotation, ViaAgent bool
}

// IPSource says where a family's recorded address came from on one check-in.
// The empty value means the check-in did not carry that family.
type IPSource string

const (
	// SourceReported means the client reported a public address for the family.
	SourceReported IPSource = "reported"
	// SourceObserved means the server observed a public origin address for the family.
	SourceObserved IPSource = "observed"
	// SourceNone means the family was carried but nothing public was recorded.
	SourceNone IPSource = "none"
)

// CheckinResult is returned to a device after a check-in. Stored reports
// whether the check-in changed the device's recorded IP addresses (and thus
// appended an ip_history row); it is false for a routine, unchanged
// check-in.
type CheckinResult struct {
	DeviceID                 string
	CurrentIPv4, CurrentIPv6 string
	Stored                   bool
	// SourceV4 and SourceV6 report, per family, how this check-in's address
	// was decided. "" means the family was not carried.
	SourceV4, SourceV6 IPSource
	// RotateSecret and RotateCert say an admin has requested a rotation on that
	// track, read from the device as it was before this check-in (#175).
	RotateSecret, RotateCert bool
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
	log    *slog.Logger
	now    func() time.Time

	// One limiter per WARN kind, so a device's no-origin WARN does not
	// suppress its dropped-family WARN. droppedWarn is keyed per device and
	// family, so dropping v4 does not hide the v6 drop.
	noOriginWarn, droppedWarn warnLimiter
}

// NewCheckinService constructs a CheckinService. notify is fired only when a
// check-in actually changes the device's recorded addresses. log and now drive
// the per-device WARN rate limit; they are injected so tests can capture the
// log and fake the clock.
func NewCheckinService(st *store.Store, notify Notifier, log *slog.Logger, now func() time.Time) *CheckinService {
	return &CheckinService{st: st, notify: notify, log: log, now: now}
}

// Checkin records a device check-in. What it stores per family is decided on the
// raw report first (see decide): reported wins, a reported or observed address
// that is not public is dropped, and CheckinResult.SourceV4/SourceV6 say which.
//
// The stored values use merge-on-empty semantics: an omitted family (empty
// after decide) means "not asserted this cycle" and preserves the
// device's stored value — it does not clear it. Change detection runs on these merged effective values; if they
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
	v4, v6 := s.decide(deviceID, r)

	// One transaction: the device row and its ip_history row land together or
	// not at all. Writing them separately let a failure between the two leave
	// a device showing an address with no history row for it, so the device
	// page and the history page disagreed and "last change" — derived from
	// the latest history row — silently skipped the change (#97).
	out, err := s.st.RecordIPChange(ctx, store.IPChange{
		DeviceID:         deviceID,
		IPv4:             v4.ip,
		IPv6:             v6.ip,
		ClientVersion:    r.ClientVersion,
		Hostname:         r.Hostname,
		OS:               r.OS,
		SupportsRotation: r.SupportsRotation,
		ViaAgent:         r.ViaAgent,
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
		DeviceID:     out.Prev.ID,
		CurrentIPv4:  out.CurrIPv4,
		CurrentIPv6:  out.CurrIPv6,
		Stored:       out.Changed,
		SourceV4:     v4.src,
		SourceV6:     v6.src,
		RotateSecret: out.Prev.RotateSecretAt != 0,
		RotateCert:   out.Prev.RotateCertAt != 0,
	}, nil
}

// familyChoice is the address one check-in stores for a family ("" = none) and
// where it came from.
type familyChoice struct {
	ip  string
	src IPSource
}

// decide picks, per family, the address this check-in records. It runs on the
// RAW report: a non-empty ipv4 or ipv6 means the client reported, and the
// observation is then ignored entirely (reported wins). A reported family that
// is unparseable, of the wrong family or not public is dropped (never replaced
// by the observation) and marked none. With nothing reported, a public
// observation fills its own family; any other observation records nothing.
func (s *CheckinService) decide(deviceID string, r CheckinReport) (v4, v6 familyChoice) {
	if r.IPv4 != "" || r.IPv6 != "" {
		return s.reported(deviceID, "ipv4", r.IPv4, netip.Addr.Is4), s.reported(deviceID, "ipv6", r.IPv6, isNative6)
	}
	if r.Observed.IsValid() && ipclass.Public(r.Observed) {
		o := r.Observed.Unmap()
		if o.Is4() {
			return familyChoice{o.String(), SourceObserved}, familyChoice{}
		}
		return familyChoice{}, familyChoice{o.String(), SourceObserved}
	}
	if s.noOriginWarn.allow(deviceID, s.now()) {
		s.log.Warn("check-in had no public origin address",
			"device_id", deviceID, "peer", r.Peer, "observed", r.Observed,
			"hint", "server.trusted_proxies may not cover your proxy, or the device reaches the server over a private path (LAN/VPN); its client falls back to lookup in auto mode")
	}
	switch {
	case !r.Observed.IsValid():
		return familyChoice{}, familyChoice{}
	case r.Observed.Unmap().Is4():
		return familyChoice{src: SourceNone}, familyChoice{}
	default:
		return familyChoice{}, familyChoice{src: SourceNone}
	}
}

// isNative6 reports whether a is a real IPv6 address, not an IPv4-mapped one.
func isNative6(a netip.Addr) bool { return a.Is6() && !a.Is4In6() }

// reported validates one reported family. raw == "" means the client did not
// carry the family; inFamily rejects an address of the wrong family.
func (s *CheckinService) reported(deviceID, family, raw string, inFamily func(netip.Addr) bool) familyChoice {
	if raw == "" {
		return familyChoice{}
	}
	a, err := netip.ParseAddr(raw)
	if err != nil || !inFamily(a) || !ipclass.Public(a) {
		if s.droppedWarn.allow(deviceID+"/"+family, s.now()) {
			s.log.Warn("check-in reported a non-public address; dropped",
				"device_id", deviceID, "family", family, "reported", raw)
		}
		return familyChoice{src: SourceNone}
	}
	return familyChoice{a.String(), SourceReported}
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
