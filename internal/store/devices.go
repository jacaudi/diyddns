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

	// V4ConfirmedAt and V6ConfirmedAt are the last check-in in which the
	// client ASSERTED that family; 0 if never, stored as NULL.
	//
	// These are NOT last_seen_at. Checkin treats an omitted family as "not
	// asserted this cycle" and preserves the stored value, while Touch
	// advances last_seen_at on any contact -- so a host that loses IPv6 and
	// keeps reporting IPv4 every five minutes is never silent, and measuring
	// expiry from last_seen_at would leave its stale IPv6 prefix in the feed
	// forever. This distinction is the whole basis of per-family expiry.
	V4ConfirmedAt int64
	V6ConfirmedAt int64

	// V4WarnLevel and V6WarnLevel are each family's own warning-ladder
	// position, 0-4. Per family rather than per device: with one window there
	// is no "which family is the ladder counting down to" question, so two
	// independent levels are simpler than one level plus a target plus a
	// tie-break plus a rule for which contacts reset it.
	V4WarnLevel int
	V6WarnLevel int
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
	last_seen_at, disabled, created_at, updated_at,
	v4_confirmed_at, v6_confirmed_at, v4_warn_level, v6_warn_level`

func scanDevice(row interface {
	Scan(dest ...any) error
}) (Device, error) {
	var d Device
	var currentIPv4, currentIPv6, hostname, osCol, clientVersion sql.NullString
	var lastSeenAt sql.NullInt64
	var disabled int64
	var v4Conf, v6Conf sql.NullInt64
	var v4Level, v6Level int64

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
		&v4Conf,
		&v6Conf,
		&v4Level,
		&v6Level,
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
	d.V4ConfirmedAt = scanInt64(v4Conf)
	d.V6ConfirmedAt = scanInt64(v6Conf)
	d.V4WarnLevel = int(v4Level)
	d.V6WarnLevel = int(v6Level)
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
		  last_seen_at, disabled, created_at, updated_at,
		  v4_confirmed_at, v6_confirmed_at, v4_warn_level, v6_warn_level)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
		nullIfZero(d.V4ConfirmedAt),
		nullIfZero(d.V6ConfirmedAt),
		d.V4WarnLevel,
		d.V6WarnLevel,
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
//
// A non-empty address counts as ASSERTED, so it advances that family's
// confirmation instant and resets its warning level. For a device whose
// instant was never set (the common case: this is often the first write for a
// newly seeded or newly enrolled device), passing false instead would leave
// it NULL, which scanInt64 maps to 0 and the sweep reads as "never
// confirmed", expiring the device on the next tick.
func (r *DeviceRepo) UpdateIP(ctx context.Context, id, ipv4, ipv6, clientVersion, hostname, os string, lastSeenAt int64) error {
	return updateDeviceIP(ctx, r.db, id, ipv4, ipv6, clientVersion, hostname, os,
		ipv4 != "", ipv6 != "", lastSeenAt, NowUnix())
}

// updateDeviceIP is the contact write for a check-in that CHANGED an address.
//
// Besides the addresses it advances the per-family confirmation instants for
// the families this check-in asserted, and resets those families' warning
// levels (D12). The reset rides an UNCONDITIONAL write on purpose: revision 8
// put it on a statement that only fired for an already-expired device, so a
// device that went quiet, took rungs 1 and 2, and came back before its window
// elapsed kept its stale level and would then fire nothing before removal.
// Reproduced against SQLite: that statement changed 0 rows for exactly that
// device.
//
// Takes updatedAt explicitly so a caller writing several rows for one event
// can stamp them all identically. Runs on the pool for UpdateIP and on the
// transaction for RecordIPChange.
// Each CASE WHEN ? binds a plain bool, not a set — database/sql cannot bind a
// set to one placeholder. A check-in asserting neither family is reachable
// (api/checkin.go has no "at least one family" validation); every CASE then
// takes its ELSE and the four per-family columns are unchanged, which is
// correct.
func updateDeviceIP(ctx context.Context, ex execer, id, ipv4, ipv6, clientVersion, hostname, os string,
	v4Asserted, v6Asserted bool, lastSeenAt, updatedAt int64) error {
	res, err := ex.ExecContext(ctx,
		`UPDATE devices
		 SET current_ipv4 = ?, current_ipv6 = ?, client_version = ?,
		     hostname = ?, os = ?, last_seen_at = ?, updated_at = ?,
		     v4_confirmed_at = CASE WHEN ? THEN ? ELSE v4_confirmed_at END,
		     v6_confirmed_at = CASE WHEN ? THEN ? ELSE v6_confirmed_at END,
		     v4_warn_level   = CASE WHEN ? THEN 0 ELSE v4_warn_level END,
		     v6_warn_level   = CASE WHEN ? THEN 0 ELSE v6_warn_level END
		 WHERE id = ?`,
		nullIfEmpty(ipv4), nullIfEmpty(ipv6), nullIfEmpty(clientVersion),
		nullIfEmpty(hostname), nullIfEmpty(os), nullIfZero(lastSeenAt), updatedAt,
		v4Asserted, lastSeenAt,
		v6Asserted, lastSeenAt,
		v4Asserted, v6Asserted,
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

// Touch is the contact write for a check-in that changed NOTHING. It carries
// the same instant advance and level reset as updateDeviceIP: the #127
// headline case -- a device silent past its window that comes back -- arrives
// on THIS branch whenever the device still holds its lease, which is the
// common case.
// Returns ErrNotFound if no row matched.
func (r *DeviceRepo) Touch(ctx context.Context, id string, v4Asserted, v6Asserted bool, lastSeenAt int64) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE devices
		 SET last_seen_at = ?, updated_at = ?,
		     v4_confirmed_at = CASE WHEN ? THEN ? ELSE v4_confirmed_at END,
		     v6_confirmed_at = CASE WHEN ? THEN ? ELSE v6_confirmed_at END,
		     v4_warn_level   = CASE WHEN ? THEN 0 ELSE v4_warn_level END,
		     v6_warn_level   = CASE WHEN ? THEN 0 ELSE v6_warn_level END
		 WHERE id = ?`,
		nullIfZero(lastSeenAt), NowUnix(),
		v4Asserted, lastSeenAt,
		v6Asserted, lastSeenAt,
		v4Asserted, v6Asserted,
		id,
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
// set NULL — the codes themselves survive this cascade, though the pruner's
// expiry sweep removes them once they expire. Returns ErrNotFound if no row
// matched.
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

// FeedDevice is one row of the gateway feed (design #106 §4.2): a member
// device's id, label, current addresses and last-seen time. It carries no
// user id (D21) and none of the device's other columns.
type FeedDevice struct {
	ID         string
	Label      string
	IPv4       string // "" when the family has never been reported (NULL)
	IPv6       string // "" when the family has never been reported (NULL)
	LastSeenAt int64  // 0 when NULL
}

// listFeedQuery is the executable half of the membership predicate (design
// D18): enabled device, enabled owner, at least one address. service.inFeed
// is the other half and must agree with it. Named so a test can EXPLAIN it.
const listFeedQuery = `SELECT d.id, d.label, d.current_ipv4, d.current_ipv6, d.last_seen_at
	  FROM devices d
	  JOIN users u ON u.id = d.user_id
	 WHERE d.disabled = 0
	   AND u.disabled = 0
	   AND (d.current_ipv4 IS NOT NULL OR d.current_ipv6 IS NOT NULL)
	 ORDER BY d.id`

// ListFeed returns every device currently in the gateway feed, ordered by id.
// One bounded read; the whole per-request cost of the feed.
func (r *DeviceRepo) ListFeed(ctx context.Context) ([]FeedDevice, error) {
	rows, err := r.db.QueryContext(ctx, listFeedQuery)
	if err != nil {
		return nil, fmt.Errorf("devices.ListFeed: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []FeedDevice
	for rows.Next() {
		var d FeedDevice
		var v4, v6 sql.NullString
		var seen sql.NullInt64
		if err := rows.Scan(&d.ID, &d.Label, &v4, &v6, &seen); err != nil {
			return nil, fmt.Errorf("devices.ListFeed: scan: %w", err)
		}
		d.IPv4 = scanString(v4)
		d.IPv6 = scanString(v6)
		d.LastSeenAt = scanInt64(seen)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("devices.ListFeed: rows: %w", err)
	}
	return out, nil
}
