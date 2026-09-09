package store

import (
	"context"
	"database/sql"
	"fmt"
)

// FeedState is the single-row feed_state table: seq is bumped by every change
// to feed membership or a member's address, and is the `id` of
// device.added / device.removed events; changed_at backs the feed's
// Last-Modified header (design #106 §4.6).
type FeedState struct {
	Seq       int64
	ChangedAt int64
}

// FeedStateRepo provides persistence operations for the feed_state row.
type FeedStateRepo struct{ db *sql.DB }

// FeedState returns a FeedStateRepo bound to this Store's database.
func (s *Store) FeedState() *FeedStateRepo { return &FeedStateRepo{db: s.db} }

// Bump increments seq, stamps changed_at = now, and returns the new seq. One
// statement, atomic under the process's single connection: UPDATE … RETURNING
// (SQLite ≥ 3.35; the pinned modernc.org/sqlite is 3.53) rather than an
// UPDATE followed by a SELECT, because SetMaxOpenConns(1) serialises
// statements, not sequences.
func (r *FeedStateRepo) Bump(ctx context.Context, now int64) (int64, error) {
	var seq int64
	err := r.db.QueryRowContext(ctx,
		`UPDATE feed_state SET seq = seq + 1, changed_at = ? WHERE id = 1 RETURNING seq`, now,
	).Scan(&seq)
	if err != nil {
		return 0, fmt.Errorf("feed_state.Bump: %w", err)
	}
	return seq, nil
}

// Get returns the current feed state.
func (r *FeedStateRepo) Get(ctx context.Context) (FeedState, error) {
	var st FeedState
	err := r.db.QueryRowContext(ctx,
		`SELECT seq, changed_at FROM feed_state WHERE id = 1`,
	).Scan(&st.Seq, &st.ChangedAt)
	if err != nil {
		return FeedState{}, fmt.Errorf("feed_state.Get: %w", err)
	}
	return st, nil
}
