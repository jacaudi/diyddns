package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Session represents a DIYDDNS user session.
type Session struct {
	ID         string
	UserID     string
	CSRFToken  string
	IP         string
	UserAgent  string
	CreatedAt  int64
	LastSeenAt int64
	ExpiresAt  int64
}

// SessionRepo provides persistence operations for Session records.
type SessionRepo struct{ db *sql.DB }

// Sessions returns a SessionRepo bound to this Store's database.
func (s *Store) Sessions() *SessionRepo { return &SessionRepo{db: s.db} }

const sessionColumns = `id, user_id, csrf_token, ip, user_agent, created_at, last_seen_at, expires_at`

func scanSession(row interface {
	Scan(dest ...any) error
}) (Session, error) {
	var sess Session
	var ip, userAgent sql.NullString
	err := row.Scan(
		&sess.ID,
		&sess.UserID,
		&sess.CSRFToken,
		&ip,
		&userAgent,
		&sess.CreatedAt,
		&sess.LastSeenAt,
		&sess.ExpiresAt,
	)
	if err != nil {
		return Session{}, err
	}
	sess.IP = scanString(ip)
	sess.UserAgent = scanString(userAgent)
	return sess, nil
}

// Create inserts a new session. If sess.ID is empty, a new UUIDv7 is assigned.
// CreatedAt is always set to NowUnix(). LastSeenAt is set to NowUnix() if zero.
// Returns the saved row.
func (r *SessionRepo) Create(ctx context.Context, sess Session) (Session, error) {
	if sess.ID == "" {
		sess.ID = NewID()
	}
	now := NowUnix()
	sess.CreatedAt = now
	if sess.LastSeenAt == 0 {
		sess.LastSeenAt = now
	}

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, csrf_token, ip, user_agent, created_at, last_seen_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID,
		sess.UserID,
		sess.CSRFToken,
		nullIfEmpty(sess.IP),
		nullIfEmpty(sess.UserAgent),
		sess.CreatedAt,
		sess.LastSeenAt,
		sess.ExpiresAt,
	)
	if err != nil {
		return Session{}, fmt.Errorf("sessions.Create: %w", err)
	}
	return sess, nil
}

// GetByID fetches a session by primary key.
// Returns ErrNotFound if no row exists.
func (r *SessionRepo) GetByID(ctx context.Context, id string) (Session, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE id = ?`, id,
	)
	sess, err := scanSession(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, fmt.Errorf("sessions.GetByID: %w", ErrNotFound)
		}
		return Session{}, fmt.Errorf("sessions.GetByID: %w", err)
	}
	return sess, nil
}

// Touch updates last_seen_at to now and sets expires_at to the given value.
// Returns ErrNotFound if no row matched.
func (r *SessionRepo) Touch(ctx context.Context, id string, expiresAt int64) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?`,
		NowUnix(), expiresAt, id,
	)
	if err != nil {
		return fmt.Errorf("sessions.Touch: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sessions.Touch: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("sessions.Touch: %w", ErrNotFound)
	}
	return nil
}

// Delete removes a session by ID.
// Returns ErrNotFound if no row matched.
func (r *SessionRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sessions.Delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sessions.Delete: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("sessions.Delete: %w", ErrNotFound)
	}
	return nil
}

// DeleteByUser removes all sessions for the given user ID.
// Returns the number of rows deleted. Zero rows is not an error.
func (r *SessionRepo) DeleteByUser(ctx context.Context, userID string) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	if err != nil {
		return 0, fmt.Errorf("sessions.DeleteByUser: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sessions.DeleteByUser: RowsAffected: %w", err)
	}
	return int(n), nil
}

// PruneExpired removes all sessions with expires_at < now.
// Returns the number of rows deleted.
func (r *SessionRepo) PruneExpired(ctx context.Context, now int64) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, now)
	if err != nil {
		return 0, fmt.Errorf("sessions.PruneExpired: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sessions.PruneExpired: RowsAffected: %w", err)
	}
	return int(n), nil
}
