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

// Checkin records a device's reported IP addresses. If r.IPv4/r.IPv6 match
// the device's currently-stored addresses, nothing is written and
// CheckinResult.Stored is false. Otherwise the device's IP/metadata fields
// (and last_seen_at) are updated and a new ip_history row is appended.
// Routine check-ins are not audited — auditing is reserved for security-
// relevant events, and a routine IP report is not one of them.
func (s *CheckinService) Checkin(ctx context.Context, deviceID string, r CheckinReport) (CheckinResult, error) {
	dev, err := s.st.Devices().GetByID(ctx, deviceID)
	if err != nil {
		return CheckinResult{}, fmt.Errorf("service.Checkin: %w", err)
	}

	if r.IPv4 == dev.CurrentIPv4 && r.IPv6 == dev.CurrentIPv6 {
		return CheckinResult{
			DeviceID:    dev.ID,
			CurrentIPv4: dev.CurrentIPv4,
			CurrentIPv6: dev.CurrentIPv6,
			Stored:      false,
		}, nil
	}

	if err := s.st.Devices().UpdateIP(ctx, dev.ID, r.IPv4, r.IPv6, r.ClientVersion, r.Hostname, r.OS, store.NowUnix()); err != nil {
		return CheckinResult{}, fmt.Errorf("service.Checkin: %w", err)
	}
	if _, err := s.st.IPHistory().Append(ctx, store.IPHistory{
		DeviceID:      dev.ID,
		IPv4:          r.IPv4,
		IPv6:          r.IPv6,
		ObservedAt:    store.NowUnix(),
		ClientVersion: r.ClientVersion,
	}); err != nil {
		return CheckinResult{}, fmt.Errorf("service.Checkin: %w", err)
	}

	return CheckinResult{
		DeviceID:    dev.ID,
		CurrentIPv4: r.IPv4,
		CurrentIPv6: r.IPv6,
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
