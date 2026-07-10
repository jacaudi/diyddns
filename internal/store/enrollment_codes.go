package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// EnrollmentCode is the persisted shape of a single-use device enrollment
// code (matches the enrollment_codes table columns 1:1; null-safe). UsedAt
// is 0 when the code has not been consumed; DeviceID is empty when the code
// has not been consumed. Code is the primary key: a caller-supplied short
// random string, not a UUID.
type EnrollmentCode struct {
	Code      string
	UserID    string
	Label     string
	ExpiresAt int64
	UsedAt    int64
	DeviceID  string
}

// EnrollmentCodeRepo is the repository for the enrollment_codes table.
type EnrollmentCodeRepo struct{ db *sql.DB }

// EnrollmentCodes returns the repository for the enrollment_codes table.
func (s *Store) EnrollmentCodes() *EnrollmentCodeRepo { return &EnrollmentCodeRepo{db: s.db} }

const selectEnrollmentCodeColumns = `code, user_id, label, expires_at, used_at, device_id`

// scanEnrollmentCode scans a single enrollment_codes row, in column order,
// into an EnrollmentCode. used_at and device_id are nullable (unconsumed
// codes have both NULL) and are scanned into sql.NullInt64/sql.NullString,
// converted back to Go zero values (0 / "") when NULL.
func scanEnrollmentCode(scan func(dest ...any) error) (EnrollmentCode, error) {
	var (
		c        EnrollmentCode
		usedAt   sql.NullInt64
		deviceID sql.NullString
	)
	err := scan(&c.Code, &c.UserID, &c.Label, &c.ExpiresAt, &usedAt, &deviceID)
	if err != nil {
		return EnrollmentCode{}, err
	}
	c.UsedAt = usedAt.Int64
	c.DeviceID = deviceID.String
	return c, nil
}

// Create inserts c. Returns ErrConflict if c.Code already exists.
func (r *EnrollmentCodeRepo) Create(ctx context.Context, c EnrollmentCode) (EnrollmentCode, error) {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO enrollment_codes (`+selectEnrollmentCodeColumns+`)
		VALUES (?, ?, ?, ?, ?, ?)`,
		c.Code, c.UserID, c.Label, c.ExpiresAt, nullOrZeroInt64(c.UsedAt), nullOrString(c.DeviceID),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return EnrollmentCode{}, fmt.Errorf("store: create enrollment code %q: %w", c.Code, ErrConflict)
		}
		return EnrollmentCode{}, fmt.Errorf("store: create enrollment code %q: %w", c.Code, err)
	}
	return c, nil
}

// Get returns the enrollment code with the given code. Returns ErrNotFound
// if no row matches.
func (r *EnrollmentCodeRepo) Get(ctx context.Context, code string) (EnrollmentCode, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+selectEnrollmentCodeColumns+` FROM enrollment_codes WHERE code = ?`, code)
	c, err := scanEnrollmentCode(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EnrollmentCode{}, fmt.Errorf("store: get enrollment code %q: %w", code, ErrNotFound)
		}
		return EnrollmentCode{}, fmt.Errorf("store: get enrollment code %q: %w", code, err)
	}
	return c, nil
}

// Consume atomically marks code as used by deviceID at time now, and returns
// the post-update row. The single guarded UPDATE (used_at IS NULL AND
// expires_at > now) is the atomicity mechanism: there is no separate read
// before the write, so two concurrent callers cannot both succeed for the
// same code. Returns ErrNotFound if the code does not exist, has already
// been consumed, or has expired — these are indistinguishable to the caller
// by design.
func (r *EnrollmentCodeRepo) Consume(ctx context.Context, code, deviceID string, now int64) (EnrollmentCode, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE enrollment_codes
		SET used_at = ?, device_id = ?
		WHERE code = ? AND used_at IS NULL AND expires_at > ?`,
		now, deviceID, code, now,
	)
	if err != nil {
		return EnrollmentCode{}, fmt.Errorf("store: consume enrollment code %q: %w", code, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return EnrollmentCode{}, fmt.Errorf("store: consume enrollment code %q: rows affected: %w", code, err)
	}
	if n == 0 {
		return EnrollmentCode{}, fmt.Errorf("store: consume enrollment code %q: %w", code, ErrNotFound)
	}
	return r.Get(ctx, code)
}

// PruneExpired deletes unused enrollment codes whose expires_at is before
// now. Consumed codes are never deleted here — they are kept for audit
// until the parent user is deleted (ON DELETE CASCADE). Returns the number
// of rows deleted.
func (r *EnrollmentCodeRepo) PruneExpired(ctx context.Context, now int64) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM enrollment_codes WHERE expires_at < ? AND used_at IS NULL`, now)
	if err != nil {
		return 0, fmt.Errorf("store: prune expired enrollment codes: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune expired enrollment codes: rows affected: %w", err)
	}
	return int(n), nil
}
