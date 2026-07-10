package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Device is the persisted shape of an enrolled device (matches the devices
// table columns 1:1; null-safe). CurrentIPv4, CurrentIPv6, Hostname, OS, and
// ClientVersion are empty when unset; empty Go strings map to SQL NULL on
// write (see nullOrString). LastSeenAt is 0 when the device has never
// checked in; SQL NULL maps to Go 0 (see nullOrZeroInt64).
type Device struct {
	ID            string
	UserID        string
	Label         string
	SecretHash    string
	CurrentIPv4   string
	CurrentIPv6   string
	Hostname      string
	OS            string
	ClientVersion string
	LastSeenAt    int64
	Disabled      bool
	CreatedAt     int64
	UpdatedAt     int64
}

// DeviceRepo is the repository for the devices table.
type DeviceRepo struct{ db *sql.DB }

// Devices returns the repository for the devices table.
func (s *Store) Devices() *DeviceRepo { return &DeviceRepo{db: s.db} }

// nullOrZeroInt64 returns nil for a zero value (so it binds as SQL NULL) or
// v itself otherwise. Used for the nullable devices.last_seen_at column,
// where 0 means "never reported".
func nullOrZeroInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// scanDevice scans a single devices row, in column order, into a Device.
// The five nullable text columns are scanned into sql.NullString and
// last_seen_at into sql.NullInt64, converted back to Go zero values when
// NULL.
func scanDevice(scan func(dest ...any) error) (Device, error) {
	var (
		d                                       Device
		ipv4, ipv6, hostname, os, clientVersion sql.NullString
		lastSeenAt                              sql.NullInt64
	)
	err := scan(
		&d.ID, &d.UserID, &d.Label, &d.SecretHash,
		&ipv4, &ipv6, &hostname, &os, &clientVersion, &lastSeenAt,
		&d.Disabled, &d.CreatedAt, &d.UpdatedAt,
	)
	if err != nil {
		return Device{}, err
	}
	d.CurrentIPv4 = ipv4.String
	d.CurrentIPv6 = ipv6.String
	d.Hostname = hostname.String
	d.OS = os.String
	d.ClientVersion = clientVersion.String
	d.LastSeenAt = lastSeenAt.Int64
	return d, nil
}

const selectDeviceColumns = `id, user_id, label, secret_hash, current_ipv4, current_ipv6, hostname, os, client_version, last_seen_at, disabled, created_at, updated_at`

// Create inserts d, assigning a new UUIDv7 ID if d.ID is empty and setting
// CreatedAt/UpdatedAt to the current time. It returns the saved row.
func (r *DeviceRepo) Create(ctx context.Context, d Device) (Device, error) {
	if d.ID == "" {
		d.ID = NewID()
	}
	now := NowUnix()
	d.CreatedAt = now
	d.UpdatedAt = now

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO devices (`+selectDeviceColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.UserID, d.Label, d.SecretHash,
		nullOrString(d.CurrentIPv4), nullOrString(d.CurrentIPv6), nullOrString(d.Hostname),
		nullOrString(d.OS), nullOrString(d.ClientVersion), nullOrZeroInt64(d.LastSeenAt),
		d.Disabled, d.CreatedAt, d.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return Device{}, fmt.Errorf("store: create device %q for user %q: %w", d.Label, d.UserID, ErrConflict)
		}
		return Device{}, fmt.Errorf("store: create device %q for user %q: %w", d.Label, d.UserID, err)
	}
	return d, nil
}

// GetByID returns the device with the given id.
func (r *DeviceRepo) GetByID(ctx context.Context, id string) (Device, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+selectDeviceColumns+` FROM devices WHERE id = ?`, id)
	d, err := scanDevice(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Device{}, fmt.Errorf("store: get device %q: %w", id, ErrNotFound)
		}
		return Device{}, fmt.Errorf("store: get device %q: %w", id, err)
	}
	return d, nil
}

// GetByUserAndLabel returns the device with the given user id and label.
func (r *DeviceRepo) GetByUserAndLabel(ctx context.Context, userID, label string) (Device, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+selectDeviceColumns+` FROM devices WHERE user_id = ? AND label = ?`,
		userID, label,
	)
	d, err := scanDevice(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Device{}, fmt.Errorf("store: get device %s/%s: %w", userID, label, ErrNotFound)
		}
		return Device{}, fmt.Errorf("store: get device %s/%s: %w", userID, label, err)
	}
	return d, nil
}

// ListByUser returns all devices belonging to userID, ordered by label
// ascending.
func (r *DeviceRepo) ListByUser(ctx context.Context, userID string) ([]Device, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+selectDeviceColumns+` FROM devices WHERE user_id = ? ORDER BY label ASC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list devices for user %q: %w", userID, err)
	}
	defer func() { _ = rows.Close() }()

	var devices []Device
	for rows.Next() {
		d, err := scanDevice(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("store: list devices for user %q: scan: %w", userID, err)
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list devices for user %q: %w", userID, err)
	}
	return devices, nil
}

// ListAll returns every device across all users, ordered by created_at
// descending, for admin UI display.
func (r *DeviceRepo) ListAll(ctx context.Context) ([]Device, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+selectDeviceColumns+` FROM devices ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list all devices: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var devices []Device
	for rows.Next() {
		d, err := scanDevice(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("store: list all devices: scan: %w", err)
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list all devices: %w", err)
	}
	return devices, nil
}

// UpdateIP updates the device's current network/metadata fields and
// last_seen_at, bumping updated_at to the current time. Used by the
// checkin flow. Returns ErrNotFound if no row matches id.
func (r *DeviceRepo) UpdateIP(ctx context.Context, id, ipv4, ipv6, clientVersion, hostname, os string, lastSeenAt int64) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE devices
		SET current_ipv4 = ?, current_ipv6 = ?, client_version = ?, hostname = ?, os = ?,
		    last_seen_at = ?, updated_at = ?
		WHERE id = ?`,
		nullOrString(ipv4), nullOrString(ipv6), nullOrString(clientVersion),
		nullOrString(hostname), nullOrString(os), nullOrZeroInt64(lastSeenAt),
		NowUnix(), id,
	)
	if err != nil {
		return fmt.Errorf("store: update ip for device %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: update ip for device %q: rows affected: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("store: update ip for device %q: %w", id, ErrNotFound)
	}
	return nil
}

// Rename changes the device's label. Returns ErrConflict if the new label
// collides with another device owned by the same user, or ErrNotFound if
// no row matches id.
func (r *DeviceRepo) Rename(ctx context.Context, id, newLabel string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE devices SET label = ?, updated_at = ? WHERE id = ?`,
		newLabel, NowUnix(), id,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("store: rename device %q: %w", id, ErrConflict)
		}
		return fmt.Errorf("store: rename device %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rename device %q: rows affected: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("store: rename device %q: %w", id, ErrNotFound)
	}
	return nil
}

// RotateSecret replaces the device's secret hash, bumping updated_at.
// Returns ErrNotFound if no row matches id.
func (r *DeviceRepo) RotateSecret(ctx context.Context, id, newSecretHash string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE devices SET secret_hash = ?, updated_at = ? WHERE id = ?`,
		newSecretHash, NowUnix(), id,
	)
	if err != nil {
		return fmt.Errorf("store: rotate secret for device %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rotate secret for device %q: rows affected: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("store: rotate secret for device %q: %w", id, ErrNotFound)
	}
	return nil
}

// SetDisabled sets the disabled flag for the device with the given id.
func (r *DeviceRepo) SetDisabled(ctx context.Context, id string, disabled bool) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE devices SET disabled = ?, updated_at = ? WHERE id = ?`,
		disabled, NowUnix(), id,
	)
	if err != nil {
		return fmt.Errorf("store: set disabled for device %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: set disabled for device %q: rows affected: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("store: set disabled for device %q: %w", id, ErrNotFound)
	}
	return nil
}

// Delete removes the device with the given id. Foreign-key cascades remove
// the device's ip_history rows. Returns ErrNotFound if no row matches.
func (r *DeviceRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete device %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete device %q: rows affected: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("store: delete device %q: %w", id, ErrNotFound)
	}
	return nil
}
