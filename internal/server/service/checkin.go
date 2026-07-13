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

// CheckinService records device check-ins, persisting a new ip_history row
// only when the reported IP addresses differ from what's already stored.
type CheckinService struct {
	st    *store.Store
	audit AuditSink
}

// NewCheckinService constructs a CheckinService. audit is accepted for
// Shared Contract / wiring consistency with the other services; routine
// check-ins are not audited (see Checkin).
func NewCheckinService(st *store.Store, audit AuditSink) *CheckinService {
	return &CheckinService{st: st, audit: audit}
}

// Checkin records a device's reported IP addresses using merge-on-empty
// semantics: an omitted family (empty IPv4 or IPv6 in the report) means "not
// asserted this cycle" and preserves the device's stored value — it does not
// clear it. Change detection runs on these merged effective values; if they
// match what's already stored, nothing is written and CheckinResult.Stored
// is false. Otherwise the device's IP/metadata fields (and last_seen_at) are
// updated to the effective values and a new ip_history row is appended.
//
// The merge is load-bearing for a DDNS tracker: the /checkin IP fields are
// optional (design §5A, "omit if unconfirmed"), and Devices.UpdateIP maps
// empty→NULL, so writing raw report values would clobber a stored family a
// single-stack client simply didn't confirm this cycle — silent data loss.
//
// Routine check-ins are not audited — auditing is reserved for security-
// relevant events, and a routine IP report is not one of them.
func (s *CheckinService) Checkin(ctx context.Context, deviceID string, r CheckinReport) (CheckinResult, error) {
	dev, err := s.st.Devices().GetByID(ctx, deviceID)
	if err != nil {
		return CheckinResult{}, fmt.Errorf("service.Checkin: %w", err)
	}

	// An omitted family preserves the stored value rather than clearing it.
	effV4 := r.IPv4
	if effV4 == "" {
		effV4 = dev.CurrentIPv4
	}
	effV6 := r.IPv6
	if effV6 == "" {
		effV6 = dev.CurrentIPv6
	}

	if effV4 == dev.CurrentIPv4 && effV6 == dev.CurrentIPv6 {
		return CheckinResult{
			DeviceID:    dev.ID,
			CurrentIPv4: dev.CurrentIPv4,
			CurrentIPv6: dev.CurrentIPv6,
			Stored:      false,
		}, nil
	}

	if err := s.st.Devices().UpdateIP(ctx, dev.ID, effV4, effV6, r.ClientVersion, r.Hostname, r.OS, store.NowUnix()); err != nil {
		return CheckinResult{}, fmt.Errorf("service.Checkin: %w", err)
	}
	if _, err := s.st.IPHistory().Append(ctx, store.IPHistory{
		DeviceID:      dev.ID,
		IPv4:          effV4,
		IPv6:          effV6,
		ObservedAt:    store.NowUnix(),
		ClientVersion: r.ClientVersion,
	}); err != nil {
		return CheckinResult{}, fmt.Errorf("service.Checkin: %w", err)
	}

	return CheckinResult{
		DeviceID:    dev.ID,
		CurrentIPv4: effV4,
		CurrentIPv6: effV6,
		Stored:      true,
	}, nil
}

// Self returns the device identified by deviceID.
func (s *CheckinService) Self(ctx context.Context, deviceID string) (store.Device, error) {
	dev, err := s.st.Devices().GetByID(ctx, deviceID)
	if err != nil {
		return store.Device{}, fmt.Errorf("service.Self: %w", err)
	}
	return dev, nil
}
