package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Device represents a registered client device in DIYDDNS.
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
	LastSeenAt    int64 // 0 if never reported; stored as NULL in SQLite
	Disabled      bool
	CreatedAt     int64
	UpdatedAt     int64
}

// DeviceRepo provides persistence operations for Device records.
type DeviceRepo struct{ db *sql.DB }

// Devices returns a DeviceRepo bound to this Store's database.
func (s *Store) Devices() *DeviceRepo { return &DeviceRepo{db: s.db} }

// nullIfZero converts a zero int64 to nil for SQL NULL inserts.
// last_seen_at is stored as NULL when the device has never reported.
func nullIfZero(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

// scanInt64 scans a possibly-NULL INTEGER column to a Go int64 (0 if NULL).
func scanInt64(n sql.NullInt64) int64 {
	if n.Valid {
		return n.Int64
	}
	return 0
}

const deviceColumns = `id, user_id, label, secret_hash,
	current_ipv4, current_ipv6, hostname, os, client_version,
	last_seen_at, disabled, created_at, updated_at`

func scanDevice(row interface {
	Scan(dest ...any) error
}) (Device, error) {
	var d Device
	var currentIPv4, currentIPv6, hostname, osCol, clientVersion sql.NullString
	var lastSeenAt sql.NullInt64
	var disabled int64

	err := row.Scan(
		&d.ID,
		&d.UserID,
		&d.Label,
		&d.SecretHash,
		&currentIPv4,
		&currentIPv6,
		&hostname,
		&osCol,
		&clientVersion,
		&lastSeenAt,
		&disabled,
		&d.CreatedAt,
		&d.UpdatedAt,
	)
	if err != nil {
		return Device{}, err
	}
	d.CurrentIPv4 = scanString(currentIPv4)
	d.CurrentIPv6 = scanString(currentIPv6)
	d.Hostname = scanString(hostname)
	d.OS = scanString(osCol)
	d.ClientVersion = scanString(clientVersion)
	d.LastSeenAt = scanInt64(lastSeenAt)
	d.Disabled = disabled != 0
	return d, nil
}

// Create inserts a new device. If d.ID is empty, a new UUIDv7 is assigned.
// CreatedAt and UpdatedAt are set to the current unix second.
// Returns ErrConflict if (user_id, label) is already taken.
func (r *DeviceRepo) Create(ctx context.Context, d Device) (Device, error) {
	if d.ID == "" {
		d.ID = NewID()
	}
	now := NowUnix()
	d.CreatedAt = now
	d.UpdatedAt = now

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO devices
		 (id, user_id, label, secret_hash,
		  current_ipv4, current_ipv6, hostname, os, client_version,
		  last_seen_at, disabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID,
		d.UserID,
		d.Label,
		d.SecretHash,
		nullIfEmpty(d.CurrentIPv4),
		nullIfEmpty(d.CurrentIPv6),
		nullIfEmpty(d.Hostname),
		nullIfEmpty(d.OS),
		nullIfEmpty(d.ClientVersion),
		nullIfZero(d.LastSeenAt),
		boolToInt(d.Disabled),
		d.CreatedAt,
		d.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return Device{}, fmt.Errorf("devices.Create: %w", ErrConflict)
		}
		return Device{}, fmt.Errorf("devices.Create: %w", err)
	}
	return d, nil
}

// GetByID fetches a device by primary key.
// Returns ErrNotFound if no row exists.
func (r *DeviceRepo) GetByID(ctx context.Context, id string) (Device, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE id = ?`, id,
	)
	d, err := scanDevice(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Device{}, fmt.Errorf("devices.GetByID: %w", ErrNotFound)
		}
		return Device{}, fmt.Errorf("devices.GetByID: %w", err)
	}
	return d, nil
}

// GetByUserAndLabel fetches a device by (user_id, label).
// Returns ErrNotFound if no row exists.
func (r *DeviceRepo) GetByUserAndLabel(ctx context.Context, userID, label string) (Device, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE user_id = ? AND label = ?`,
		userID, label,
	)
	d, err := scanDevice(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Device{}, fmt.Errorf("devices.GetByUserAndLabel: %w", ErrNotFound)
		}
		return Device{}, fmt.Errorf("devices.GetByUserAndLabel: %w", err)
	}
	return d, nil
}

// ListByUser returns all devices for a user ordered by label ascending.
func (r *DeviceRepo) ListByUser(ctx context.Context, userID string) ([]Device, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE user_id = ? ORDER BY label ASC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("devices.ListByUser: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var devices []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("devices.ListByUser: scan: %w", err)
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("devices.ListByUser: rows: %w", err)
	}
	return devices, nil
}

// ListAll returns all devices ordered by created_at descending (admin view).
func (r *DeviceRepo) ListAll(ctx context.Context) ([]Device, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+deviceColumns+` FROM devices ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("devices.ListAll: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var devices []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("devices.ListAll: scan: %w", err)
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("devices.ListAll: rows: %w", err)
	}
	return devices, nil
}

// UpdateIP updates the IP address fields, metadata, and last_seen_at for a device.
// Returns ErrNotFound if no row matched.
func (r *DeviceRepo) UpdateIP(ctx context.Context, id, ipv4, ipv6, clientVersion, hostname, os string, lastSeenAt int64) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE devices
		 SET current_ipv4 = ?, current_ipv6 = ?, client_version = ?,
		     hostname = ?, os = ?, last_seen_at = ?, updated_at = ?
		 WHERE id = ?`,
		nullIfEmpty(ipv4),
		nullIfEmpty(ipv6),
		nullIfEmpty(clientVersion),
		nullIfEmpty(hostname),
		nullIfEmpty(os),
		nullIfZero(lastSeenAt),
		NowUnix(),
		id,
	)
	if err != nil {
		return fmt.Errorf("devices.UpdateIP: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("devices.UpdateIP: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("devices.UpdateIP: %w", ErrNotFound)
	}
	return nil
}

// Touch advances last_seen_at (and updated_at) for a device without changing
// its IP addresses — the liveness signal for a routine, unchanged check-in.
// Returns ErrNotFound if no row matched.
func (r *DeviceRepo) Touch(ctx context.Context, id string, lastSeenAt int64) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE devices SET last_seen_at = ?, updated_at = ? WHERE id = ?`,
		nullIfZero(lastSeenAt), NowUnix(), id,
	)
	if err != nil {
		return fmt.Errorf("devices.Touch: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("devices.Touch: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("devices.Touch: %w", ErrNotFound)
	}
	return nil
}

// Rename updates the label of a device.
// Returns ErrNotFound if no row matched, ErrConflict on UNIQUE violation.
func (r *DeviceRepo) Rename(ctx context.Context, id, newLabel string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE devices SET label = ?, updated_at = ? WHERE id = ?`,
		newLabel, NowUnix(), id,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("devices.Rename: %w", ErrConflict)
		}
		return fmt.Errorf("devices.Rename: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("devices.Rename: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("devices.Rename: %w", ErrNotFound)
	}
	return nil
}

// RotateSecret updates the secret_hash for a device.
// Returns ErrNotFound if no row matched.
func (r *DeviceRepo) RotateSecret(ctx context.Context, id, newSecretHash string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE devices SET secret_hash = ?, updated_at = ? WHERE id = ?`,
		newSecretHash, NowUnix(), id,
	)
	if err != nil {
		return fmt.Errorf("devices.RotateSecret: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("devices.RotateSecret: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("devices.RotateSecret: %w", ErrNotFound)
	}
	return nil
}

// SetDisabled toggles the disabled flag on a device.
// Returns ErrNotFound if no row matched.
func (r *DeviceRepo) SetDisabled(ctx context.Context, id string, disabled bool) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE devices SET disabled = ?, updated_at = ? WHERE id = ?`,
		boolToInt(disabled), NowUnix(), id,
	)
	if err != nil {
		return fmt.Errorf("devices.SetDisabled: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("devices.SetDisabled: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("devices.SetDisabled: %w", ErrNotFound)
	}
	return nil
}

// Delete removes a device by ID. Its ip_history rows are cascade-deleted,
// and any consumed enrollment_codes that referenced it have their device_id
// set NULL (the codes themselves survive for audit). Returns ErrNotFound if
// no row matched.
func (r *DeviceRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("devices.Delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("devices.Delete: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("devices.Delete: %w", ErrNotFound)
	}
	return nil
}
