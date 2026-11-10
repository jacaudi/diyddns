package store

import (
	"context"
	"fmt"
)

// IPChange is a device's RAW check-in report: IPv4 and IPv6 are exactly what
// the client (or the server's observation of it) asserted, with "" meaning
// "not asserted this cycle". They are never pre-merged with the stored
// addresses. RecordIPChange does the merge itself, inside its transaction, and
// treats a non-empty raw value as the assertion that advances that family's
// confirmation instant and resets its warning level.
//
// Merging outside the transaction is the bug this shape prevents: two
// per-family check-ins for one device would each read the stored row, merge
// against a stale copy, and the later write would revert the earlier one's
// family.
type IPChange struct {
	DeviceID      string
	IPv4, IPv6    string
	ClientVersion string
	Hostname, OS  string

	// SupportsRotation is set when the client advertised the rotation capability
	// this cycle; ViaAgent when the request arrived over mTLS (#175).
	SupportsRotation, ViaAgent bool
}

// IPChangeOutcome is what RecordIPChange decided and wrote. Prev is the device
// as read inside the transaction, before the write; CurrIPv4/CurrIPv6 are the
// merged effective addresses. Row is the appended ip_history row and is the
// zero value unless Changed.
type IPChangeOutcome struct {
	Prev               Device
	Row                IPHistory
	CurrIPv4, CurrIPv6 string
	Changed            bool
}

// RecordIPChange reads the device, merges the raw report over its stored
// addresses (an omitted family keeps the stored value), and writes the result
// inside ONE transaction, so a check-in can never half-succeed and two
// concurrent check-ins for one device cannot revert each other (#97, #174).
// If the merged addresses equal the stored ones it only touches the device
// (liveness plus the asserted families' confirmation); otherwise it updates
// the device row and appends the matching ip_history row. It returns
// ErrNotFound if no device matches c.DeviceID.
//
// The transaction is opened, used and committed entirely inside this
// function, and every statement runs on tx. That is deliberate rather than
// incidental. Open caps the pool at a single connection, so a transaction
// holds the process's ONLY connection for its whole lifetime. An exported
// "run this callback in a transaction" helper would let arbitrary caller
// code run inside that window, and any store call it made through the pool
// would deadlock rather than wait. With no callback there is no window.
func (s *Store) RecordIPChange(ctx context.Context, c IPChange) (IPChangeOutcome, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IPChangeOutcome{}, fmt.Errorf("store.RecordIPChange: begin: %w", err)
	}
	// No-op once Commit has succeeded; returns ErrTxDone, which is discarded.
	defer func() { _ = tx.Rollback() }()

	prev, err := getDeviceTx(ctx, tx, c.DeviceID)
	if err != nil {
		return IPChangeOutcome{}, fmt.Errorf("store.RecordIPChange: %w", err)
	}

	// An omitted family preserves the stored value rather than clearing it:
	// updateDeviceIP maps empty to NULL, so writing the raw report would
	// clobber a family a single-stack client simply didn't confirm this cycle.
	out := IPChangeOutcome{Prev: prev, CurrIPv4: c.IPv4, CurrIPv6: c.IPv6}
	if out.CurrIPv4 == "" {
		out.CurrIPv4 = prev.CurrentIPv4
	}
	if out.CurrIPv6 == "" {
		out.CurrIPv6 = prev.CurrentIPv6
	}
	// Assertion is the RAW field, never the merged value: the merge makes
	// both families non-empty, and asserting both on every check-in would
	// silently disable per-family expiry.
	v4Asserted, v6Asserted := c.IPv4 != "", c.IPv6 != ""

	// One timestamp for every row: last_seen_at, updated_at and observed_at
	// describe the same event, so separate NowUnix() calls would record it
	// one second apart whenever the check-in straddles a second boundary.
	now := NowUnix()

	if out.CurrIPv4 == prev.CurrentIPv4 && out.CurrIPv6 == prev.CurrentIPv6 {
		// Unchanged is still a contact: advance last_seen_at so a stable-IP
		// device is distinguishable from a dead one (#12).
		if err := touchDevice(ctx, tx, c.DeviceID, v4Asserted, v6Asserted, now, c.SupportsRotation, c.ViaAgent); err != nil {
			return IPChangeOutcome{}, fmt.Errorf("store.RecordIPChange: %w", err)
		}
	} else {
		if err := updateDeviceIP(ctx, tx, c.DeviceID, out.CurrIPv4, out.CurrIPv6, c.ClientVersion, c.Hostname, c.OS,
			v4Asserted, v6Asserted, now, now, c.SupportsRotation, c.ViaAgent); err != nil {
			return IPChangeOutcome{}, fmt.Errorf("store.RecordIPChange: %w", err)
		}
		out.Row, err = appendIPHistory(ctx, tx, IPHistory{
			DeviceID:      c.DeviceID,
			IPv4:          out.CurrIPv4,
			IPv6:          out.CurrIPv6,
			ObservedAt:    now,
			ClientVersion: c.ClientVersion,
		})
		if err != nil {
			return IPChangeOutcome{}, fmt.Errorf("store.RecordIPChange: %w", err)
		}
		out.Changed = true
	}
	if err := tx.Commit(); err != nil {
		return IPChangeOutcome{}, fmt.Errorf("store.RecordIPChange: commit: %w", err)
	}
	return out, nil
}
