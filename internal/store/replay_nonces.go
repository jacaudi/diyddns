package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ReplayNonce represents a recorded HMAC signature used to detect replayed requests.
type ReplayNonce struct {
	Signature string
	ExpiresAt int64
}

// ReplayNonceRepo provides persistence operations for ReplayNonce records.
type ReplayNonceRepo struct{ db *sql.DB }

// ReplayNonces returns a ReplayNonceRepo bound to this Store's database.
func (s *Store) ReplayNonces() *ReplayNonceRepo { return &ReplayNonceRepo{db: s.db} }

// Insert records a new HMAC signature as seen. Returns ErrConflict if the
// signature already exists (the production replay-detection signal).
func (r *ReplayNonceRepo) Insert(ctx context.Context, signature string, expiresAt int64) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO replay_nonces (signature, expires_at) VALUES (?, ?)`,
		signature, expiresAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("store: replay_nonces insert: %w", ErrConflict)
		}
		return fmt.Errorf("store: replay_nonces insert: %w", err)
	}
	return nil
}

// Exists reports whether the given signature is present in the table.
func (r *ReplayNonceRepo) Exists(ctx context.Context, signature string) (bool, error) {
	var x int
	err := r.db.QueryRowContext(ctx,
		`SELECT 1 FROM replay_nonces WHERE signature = ?`, signature,
	).Scan(&x)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: replay_nonces exists: %w", err)
	}
	return true, nil
}

// PruneExpired removes all nonces with expires_at < now.
// Returns the number of rows deleted.
func (r *ReplayNonceRepo) PruneExpired(ctx context.Context, now int64) (int, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM replay_nonces WHERE expires_at < ?`, now,
	)
	if err != nil {
		return 0, fmt.Errorf("store: replay_nonces prune_expired: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: replay_nonces prune_expired rows_affected: %w", err)
	}
	return int(n), nil
}
