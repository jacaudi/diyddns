package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Session is the persisted shape of a login session (matches the sessions
// table columns 1:1; null-safe). IP and UserAgent are empty when unset;
// empty Go strings map to SQL NULL on write (see nullOrString).
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

// SessionRepo is the repository for the sessions table.
type SessionRepo struct{ db *sql.DB }

// Sessions returns the repository for the sessions table.
func (s *Store) Sessions() *SessionRepo { return &SessionRepo{db: s.db} }

// scanSession scans a single sessions row, in column order, into a Session.
// The two nullable columns are scanned into sql.NullString and converted
// back to empty Go strings when NULL.
func scanSession(scan func(dest ...any) error) (Session, error) {
	var (
		sess          Session
		ip, userAgent sql.NullString
	)
	err := scan(
		&sess.ID, &sess.UserID, &sess.CSRFToken, &ip, &userAgent,
		&sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt,
	)
	if err != nil {
		return Session{}, err
	}
	sess.IP = ip.String
	sess.UserAgent = userAgent.String
	return sess, nil
}

const selectSessionColumns = `id, user_id, csrf_token, ip, user_agent, created_at, last_seen_at, expires_at`

// Create inserts sess, assigning a new UUIDv7 ID if sess.ID is empty and
// setting CreatedAt/LastSeenAt to the current time. It returns the saved
// row.
func (r *SessionRepo) Create(ctx context.Context, sess Session) (Session, error) {
	if sess.ID == "" {
		sess.ID = NewID()
	}
	now := NowUnix()
	sess.CreatedAt = now
	sess.LastSeenAt = now

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sessions (`+selectSessionColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.UserID, sess.CSRFToken, nullOrString(sess.IP), nullOrString(sess.UserAgent),
		sess.CreatedAt, sess.LastSeenAt, sess.ExpiresAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return Session{}, fmt.Errorf("store: create session %q: %w", sess.ID, ErrConflict)
		}
		return Session{}, fmt.Errorf("store: create session %q: %w", sess.ID, err)
	}
	return sess, nil
}

// GetByID returns the session with the given id.
func (r *SessionRepo) GetByID(ctx context.Context, id string) (Session, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+selectSessionColumns+` FROM sessions WHERE id = ?`, id)
	sess, err := scanSession(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, fmt.Errorf("store: get session %q: %w", id, ErrNotFound)
		}
		return Session{}, fmt.Errorf("store: get session %q: %w", id, err)
	}
	return sess, nil
}

// Touch slides the session's expiry: it sets last_seen_at to the current
// time and expires_at to expiresAt. Returns ErrNotFound if no row matches
// id.
func (r *SessionRepo) Touch(ctx context.Context, id string, expiresAt int64) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?`,
		NowUnix(), expiresAt, id,
	)
	if err != nil {
		return fmt.Errorf("store: touch session %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: touch session %q: rows affected: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("store: touch session %q: %w", id, ErrNotFound)
	}
	return nil
}

// Delete removes the session with the given id. Returns ErrNotFound if no
// row matches.
func (r *SessionRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete session %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete session %q: rows affected: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("store: delete session %q: %w", id, ErrNotFound)
	}
	return nil
}

// DeleteByUser removes all sessions belonging to userID (logout-all, or
// user disable). Returns the number of rows removed; zero is not an error.
func (r *SessionRepo) DeleteByUser(ctx context.Context, userID string) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	if err != nil {
		return 0, fmt.Errorf("store: delete sessions for user %q: %w", userID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: delete sessions for user %q: rows affected: %w", userID, err)
	}
	return int(n), nil
}

// PruneExpired removes every session whose expires_at is before now.
// Returns the number of rows removed; zero is not an error.
func (r *SessionRepo) PruneExpired(ctx context.Context, now int64) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, now)
	if err != nil {
		return 0, fmt.Errorf("store: prune expired sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune expired sessions: rows affected: %w", err)
	}
	return int(n), nil
}
