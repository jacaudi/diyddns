package store

import (
	"context"
	"fmt"
)

// IPChange is a device's effective post-merge state at a check-in that
// actually changed its recorded addresses.
type IPChange struct {
	DeviceID      string
	IPv4, IPv6    string
	ClientVersion string
	Hostname, OS  string
}

// RecordIPChange updates the device row and appends the matching ip_history
// row inside ONE transaction, so a check-in can never half-succeed: either
// both writes land or neither does (#97). It returns the appended history
// row, and ErrNotFound if no device matches c.DeviceID.
//
// The transaction is opened, used and committed entirely inside this
// function, and every statement runs on tx. That is deliberate rather than
// incidental. Open caps the pool at a single connection, so a transaction
// holds the process's ONLY connection for its whole lifetime. An exported
// "run this callback in a transaction" helper would let arbitrary caller
// code run inside that window, and any store call it made through the pool
// would deadlock rather than wait. With no callback there is no window.
func (s *Store) RecordIPChange(ctx context.Context, c IPChange) (IPHistory, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IPHistory{}, fmt.Errorf("store.RecordIPChange: begin: %w", err)
	}
	// No-op once Commit has succeeded; returns ErrTxDone, which is discarded.
	defer func() { _ = tx.Rollback() }()

	// One timestamp for both rows: last_seen_at, updated_at and observed_at
	// describe the same event, so separate NowUnix() calls would record it
	// one second apart whenever the check-in straddles a second boundary.
	now := NowUnix()

	if err := updateDeviceIP(ctx, tx, c.DeviceID, c.IPv4, c.IPv6, c.ClientVersion, c.Hostname, c.OS, now, now); err != nil {
		return IPHistory{}, fmt.Errorf("store.RecordIPChange: %w", err)
	}
	row, err := appendIPHistory(ctx, tx, IPHistory{
		DeviceID:      c.DeviceID,
		IPv4:          c.IPv4,
		IPv6:          c.IPv6,
		ObservedAt:    now,
		ClientVersion: c.ClientVersion,
	})
	if err != nil {
		return IPHistory{}, fmt.Errorf("store.RecordIPChange: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return IPHistory{}, fmt.Errorf("store.RecordIPChange: commit: %w", err)
	}
	return row, nil
}
