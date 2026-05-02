package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// BootstrapState holds the single-row bootstrap record used for the
// one-time admin claim flow. TokenHash is empty after the token is consumed.
type BootstrapState struct {
	TokenHash  string // empty after consumed
	CreatedAt  int64
	ConsumedAt int64 // 0 if not consumed
}

// BootstrapRepo provides persistence operations for the bootstrap record.
type BootstrapRepo struct{ db *sql.DB }

// Bootstrap returns a BootstrapRepo bound to this Store's database.
func (s *Store) Bootstrap() *BootstrapRepo { return &BootstrapRepo{db: s.db} }

// Get retrieves the current bootstrap state.
// Returns ErrNotFound if the row has never been set.
func (r *BootstrapRepo) Get(ctx context.Context) (BootstrapState, error) {
	var (
		tokenHash  sql.NullString
		consumedAt sql.NullInt64
		createdAt  int64
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT token_hash, created_at, consumed_at FROM bootstrap WHERE id = 1`,
	).Scan(&tokenHash, &createdAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return BootstrapState{}, fmt.Errorf("bootstrap.Get: %w", ErrNotFound)
	}
	if err != nil {
		return BootstrapState{}, fmt.Errorf("bootstrap.Get: %w", err)
	}
	return BootstrapState{
		TokenHash:  scanString(tokenHash),
		CreatedAt:  createdAt,
		ConsumedAt: scanInt64(consumedAt),
	}, nil
}

// SetTokenHash stores a new bootstrap token hash, replacing any existing row.
// created_at is set to NowUnix(); consumed_at is reset to NULL.
func (r *BootstrapRepo) SetTokenHash(ctx context.Context, tokenHash string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO bootstrap (id, token_hash, created_at, consumed_at)
		 VALUES (1, ?, ?, NULL)`,
		nullIfEmpty(tokenHash), NowUnix(),
	)
	if err != nil {
		return fmt.Errorf("bootstrap.SetTokenHash: %w", err)
	}
	return nil
}

// Consume marks the bootstrap token as used by clearing token_hash and
// recording consumed_at. Returns ErrNotFound if the row doesn't exist or has
// already been consumed (idempotency guard via consumed_at IS NULL predicate).
func (r *BootstrapRepo) Consume(ctx context.Context) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE bootstrap
		   SET token_hash = NULL, consumed_at = ?
		 WHERE id = 1 AND consumed_at IS NULL`,
		NowUnix(),
	)
	if err != nil {
		return fmt.Errorf("bootstrap.Consume: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("bootstrap.Consume rows_affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("bootstrap.Consume: %w", ErrNotFound)
	}
	return nil
}
