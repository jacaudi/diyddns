package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// EnrollmentCode represents a single-use code that allows a device to register
// itself to a user account.
type EnrollmentCode struct {
	Code      string
	UserID    string
	Label     string
	ExpiresAt int64
	UsedAt    int64  // 0 if not consumed; stored as NULL in SQLite
	DeviceID  string // empty if not consumed; stored as NULL in SQLite
}

// EnrollmentCodeRepo provides persistence operations for EnrollmentCode records.
type EnrollmentCodeRepo struct{ db *sql.DB }

// EnrollmentCodes returns an EnrollmentCodeRepo bound to this Store's database.
func (s *Store) EnrollmentCodes() *EnrollmentCodeRepo { return &EnrollmentCodeRepo{db: s.db} }

const enrollmentCodeColumns = `code, user_id, label, expires_at, used_at, device_id`

func scanEnrollmentCode(row interface {
	Scan(dest ...any) error
}) (EnrollmentCode, error) {
	var c EnrollmentCode
	var usedAt sql.NullInt64
	var deviceID sql.NullString

	err := row.Scan(
		&c.Code,
		&c.UserID,
		&c.Label,
		&c.ExpiresAt,
		&usedAt,
		&deviceID,
	)
	if err != nil {
		return EnrollmentCode{}, err
	}
	c.UsedAt = scanInt64(usedAt)
	c.DeviceID = scanString(deviceID)
	return c, nil
}

// Create inserts a new enrollment code.
// Returns ErrConflict if the code (PK) already exists.
func (r *EnrollmentCodeRepo) Create(ctx context.Context, c EnrollmentCode) (EnrollmentCode, error) {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO enrollment_codes (code, user_id, label, expires_at, used_at, device_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		c.Code,
		c.UserID,
		c.Label,
		c.ExpiresAt,
		nullIfZero(c.UsedAt),
		nullIfEmpty(c.DeviceID),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return EnrollmentCode{}, fmt.Errorf("enrollment_codes.Create: %w", ErrConflict)
		}
		return EnrollmentCode{}, fmt.Errorf("enrollment_codes.Create: %w", err)
	}
	return c, nil
}

// Get fetches an enrollment code by its code string (primary key).
// Returns ErrNotFound if no row exists.
func (r *EnrollmentCodeRepo) Get(ctx context.Context, code string) (EnrollmentCode, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+enrollmentCodeColumns+` FROM enrollment_codes WHERE code = ?`, code,
	)
	c, err := scanEnrollmentCode(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EnrollmentCode{}, fmt.Errorf("enrollment_codes.Get: %w", ErrNotFound)
		}
		return EnrollmentCode{}, fmt.Errorf("enrollment_codes.Get: %w", err)
	}
	return c, nil
}

// Consume atomically marks an enrollment code as used.
// The UPDATE only matches rows where used_at IS NULL and expires_at > now,
// so expired and already-consumed codes all result in ErrNotFound.
// On success, returns the post-update row via Get.
func (r *EnrollmentCodeRepo) Consume(ctx context.Context, code, deviceID string, now int64) (EnrollmentCode, error) {
	res, err := r.db.ExecContext(ctx,
		`UPDATE enrollment_codes
		   SET used_at = ?, device_id = ?
		 WHERE code = ?
		   AND used_at IS NULL
		   AND expires_at > ?`,
		now, deviceID, code, now,
	)
	if err != nil {
		return EnrollmentCode{}, fmt.Errorf("store: enrollment_codes consume: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return EnrollmentCode{}, fmt.Errorf("store: enrollment_codes rows affected: %w", err)
	}
	if rows == 0 {
		return EnrollmentCode{}, fmt.Errorf("store: enrollment_codes consume: %w", ErrNotFound)
	}
	return r.Get(ctx, code)
}

// PruneExpired deletes enrollment codes that have expired and have not been
// consumed. Consumed codes are retained for audit purposes until the owning
// user is deleted (which cascades automatically via FK).
// Returns the number of rows deleted.
func (r *EnrollmentCodeRepo) PruneExpired(ctx context.Context, now int64) (int, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM enrollment_codes WHERE expires_at < ? AND used_at IS NULL`,
		now,
	)
	if err != nil {
		return 0, fmt.Errorf("enrollment_codes.PruneExpired: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("enrollment_codes.PruneExpired: RowsAffected: %w", err)
	}
	return int(n), nil
}
