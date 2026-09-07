package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// FeedToken is one admin-minted, feed-read-only machine credential (design
// #106 §3). Only the SHA-256 hash is stored; the plaintext is shown once at
// mint time and never persisted.
type FeedToken struct {
	ID         string
	Label      string
	TokenHash  string
	CreatedBy  string // user id of the minting admin; "" once that user is deleted (ON DELETE SET NULL)
	CreatedAt  int64
	LastUsedAt int64 // 0 when never used; stored as NULL
}

// FeedTokenPrefix marks a feed token's plaintext ("ddf_…") so secret scanners
// recognise it and the feed middleware can reject non-tokens before a hash
// and a lookup. It lives here, not in service or feed, because both of those
// packages need it and neither may import the other (design #106 §2).
const FeedTokenPrefix = "ddf_"

// FeedTokenRepo provides persistence operations for FeedToken records.
type FeedTokenRepo struct{ db *sql.DB }

// FeedTokens returns a FeedTokenRepo bound to this Store's database.
func (s *Store) FeedTokens() *FeedTokenRepo { return &FeedTokenRepo{db: s.db} }

// feedAuthColumns is the SELECT list for the feed_tokens table, in
// scanFeedToken's order. It is deliberately NOT named …TokenColumns: gosec's
// G101 flags any constant whose NAME matches its credential heuristic
// (pass/pwd/secret/token/key/bearer/cred), and a column list is not a
// credential — renaming is the fix, never a //nolint.
const feedAuthColumns = `id, label, token_hash, created_by, created_at, last_used_at`

func scanFeedToken(row interface {
	Scan(dest ...any) error
}) (FeedToken, error) {
	var t FeedToken
	var createdBy sql.NullString
	var lastUsed sql.NullInt64
	if err := row.Scan(&t.ID, &t.Label, &t.TokenHash, &createdBy, &t.CreatedAt, &lastUsed); err != nil {
		return FeedToken{}, err
	}
	t.CreatedBy = scanString(createdBy)
	t.LastUsedAt = scanInt64(lastUsed)
	return t, nil
}

// Create inserts t. Returns ErrConflict when the label or the hash already
// exists (label is UNIQUE among live tokens; a revoked token's label may be
// reused).
func (r *FeedTokenRepo) Create(ctx context.Context, t FeedToken) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO feed_tokens (id, label, token_hash, created_by, created_at, last_used_at)
		 VALUES (?, ?, ?, ?, ?, NULL)`,
		t.ID, t.Label, t.TokenHash, nullIfEmpty(t.CreatedBy), t.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("feed_tokens.Create: %w", ErrConflict)
		}
		return fmt.Errorf("feed_tokens.Create: %w", err)
	}
	return nil
}

// GetByHash looks a token up by its SHA-256 hash. Returns ErrNotFound when no
// live token matches — a revoked token is deleted, so it is simply absent.
func (r *FeedTokenRepo) GetByHash(ctx context.Context, hash string) (FeedToken, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+feedAuthColumns+` FROM feed_tokens WHERE token_hash = ?`, hash)
	t, err := scanFeedToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return FeedToken{}, fmt.Errorf("feed_tokens.GetByHash: %w", ErrNotFound)
		}
		return FeedToken{}, fmt.Errorf("feed_tokens.GetByHash: %w", err)
	}
	return t, nil
}

// GetByID looks a token up by its primary key. Returns ErrNotFound when no
// live token matches — a revoked token is deleted, so it is simply absent.
// Used by the stream handler's post-subscribe revoke re-check (design #106,
// finding S1).
func (r *FeedTokenRepo) GetByID(ctx context.Context, id string) (FeedToken, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+feedAuthColumns+` FROM feed_tokens WHERE id = ?`, id)
	t, err := scanFeedToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return FeedToken{}, fmt.Errorf("feed_tokens.GetByID: %w", ErrNotFound)
		}
		return FeedToken{}, fmt.Errorf("feed_tokens.GetByID: %w", err)
	}
	return t, nil
}

// List returns every live token, oldest first.
func (r *FeedTokenRepo) List(ctx context.Context) ([]FeedToken, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+feedAuthColumns+` FROM feed_tokens ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("feed_tokens.List: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []FeedToken
	for rows.Next() {
		t, err := scanFeedToken(rows)
		if err != nil {
			return nil, fmt.Errorf("feed_tokens.List: scan: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("feed_tokens.List: rows: %w", err)
	}
	return out, nil
}

// Delete revokes a token by removing its row. Returns ErrNotFound if no row
// matched.
func (r *FeedTokenRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM feed_tokens WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("feed_tokens.Delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("feed_tokens.Delete: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("feed_tokens.Delete: %w", ErrNotFound)
	}
	return nil
}

// TouchLastUsed stamps last_used_at = now. Callers throttle this to at most
// once per minute per token (service.FeedService); on the process's single
// connection a write per poll would be a write per request.
func (r *FeedTokenRepo) TouchLastUsed(ctx context.Context, id string, now int64) error {
	if _, err := r.db.ExecContext(ctx,
		`UPDATE feed_tokens SET last_used_at = ? WHERE id = ?`, now, id); err != nil {
		return fmt.Errorf("feed_tokens.TouchLastUsed: %w", err)
	}
	return nil
}
