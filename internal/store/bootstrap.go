package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// BootstrapState is the persisted shape of the single-row bootstrap table,
// which tracks the one-time admin-bootstrap claim flow. TokenHash is empty
// once the token has been consumed (or before one has ever been set).
// ConsumedAt is 0 until Consume succeeds.
type BootstrapState struct {
	TokenHash  string
	CreatedAt  int64
	ConsumedAt int64
}

// BootstrapRepo is the repository for the bootstrap table. The table has
// exactly one row, keyed by the fixed id = 1 (enforced by a CHECK
// constraint), so every method operates on that row implicitly.
type BootstrapRepo struct{ db *sql.DB }

// Bootstrap returns the repository for the bootstrap table.
func (s *Store) Bootstrap() *BootstrapRepo { return &BootstrapRepo{db: s.db} }

// Get returns the current bootstrap state. Returns ErrNotFound if no row has
// been written yet (i.e. SetTokenHash has never been called).
func (r *BootstrapRepo) Get(ctx context.Context) (BootstrapState, error) {
	row := r.db.QueryRowContext(ctx, `SELECT token_hash, created_at, consumed_at FROM bootstrap WHERE id = 1`)

	var (
		state      BootstrapState
		tokenHash  sql.NullString
		consumedAt sql.NullInt64
	)
	err := row.Scan(&tokenHash, &state.CreatedAt, &consumedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return BootstrapState{}, fmt.Errorf("store: get bootstrap state: %w", ErrNotFound)
		}
		return BootstrapState{}, fmt.Errorf("store: get bootstrap state: %w", err)
	}
	state.TokenHash = tokenHash.String
	state.ConsumedAt = consumedAt.Int64
	return state, nil
}

// SetTokenHash writes tokenHash as the current bootstrap token, setting
// created_at to now and clearing consumed_at. It replaces any prior row
// (consumed or not), re-arming the one-time claim flow with a fresh token.
func (r *BootstrapRepo) SetTokenHash(ctx context.Context, tokenHash string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO bootstrap (id, token_hash, created_at, consumed_at)
		VALUES (1, ?, ?, NULL)`,
		nullOrString(tokenHash), NowUnix(),
	)
	if err != nil {
		return fmt.Errorf("store: set bootstrap token hash: %w", err)
	}
	return nil
}

// Consume atomically marks the bootstrap token as used, clearing token_hash
// and setting consumed_at to now. The single guarded UPDATE (WHERE
// consumed_at IS NULL) is the atomicity mechanism: there is no separate read
// before the write, so two concurrent callers cannot both succeed. Returns
// ErrNotFound if no token has ever been set, or if it has already been
// consumed — these are indistinguishable to the caller by design.
func (r *BootstrapRepo) Consume(ctx context.Context) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE bootstrap SET token_hash = NULL, consumed_at = ?
		WHERE id = 1 AND consumed_at IS NULL`,
		NowUnix(),
	)
	if err != nil {
		return fmt.Errorf("store: consume bootstrap: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: consume bootstrap: rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: consume bootstrap: %w", ErrNotFound)
	}
	return nil
}
