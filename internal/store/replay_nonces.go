package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ReplayNonce is the persisted shape of an HMAC replay-defense record
// (matches the replay_nonces table columns 1:1; no nullable columns). A row
// existing for a given Signature means that signature has already been used
// once; a second Insert of the same signature is the replay signal.
type ReplayNonce struct {
	Signature string
	ExpiresAt int64
}

// ReplayNonceRepo is the repository for the replay_nonces table.
type ReplayNonceRepo struct{ db *sql.DB }

// ReplayNonces returns the repository for the replay_nonces table.
func (s *Store) ReplayNonces() *ReplayNonceRepo { return &ReplayNonceRepo{db: s.db} }

// Insert records signature as seen, expiring at expiresAt. Returns
// ErrConflict if signature already exists — that collision on the PRIMARY
// KEY is the replay signal callers must reject on.
func (r *ReplayNonceRepo) Insert(ctx context.Context, signature string, expiresAt int64) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO replay_nonces (signature, expires_at) VALUES (?, ?)`,
		signature, expiresAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("store: insert replay nonce %q: %w", signature, ErrConflict)
		}
		return fmt.Errorf("store: insert replay nonce %q: %w", signature, err)
	}
	return nil
}

// Exists reports whether signature has already been recorded. This is a
// read-only convenience check, primarily for tests; production replay
// defense relies on Insert's ErrConflict signal instead of a separate
// existence check (which would leave a race between check and insert).
func (r *ReplayNonceRepo) Exists(ctx context.Context, signature string) (bool, error) {
	var found int
	err := r.db.QueryRowContext(ctx,
		`SELECT 1 FROM replay_nonces WHERE signature = ?`, signature,
	).Scan(&found)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("store: check replay nonce %q: %w", signature, err)
	}
	return true, nil
}

// PruneExpired deletes replay nonces whose expires_at is before now. Returns
// the number of rows deleted.
func (r *ReplayNonceRepo) PruneExpired(ctx context.Context, now int64) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM replay_nonces WHERE expires_at < ?`, now)
	if err != nil {
		return 0, fmt.Errorf("store: prune expired replay nonces: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune expired replay nonces: rows affected: %w", err)
	}
	return int(n), nil
}
