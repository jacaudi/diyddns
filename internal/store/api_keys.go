package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// APIKey is one user-minted bearer credential for programmatic /api/v1
// access (design #149). Only the SHA-256 hash is stored; the plaintext is
// shown once at mint time and never persisted. AdminScope is always false
// until #167 ships a real mint-time input for it (design D1's seam) --
// every Create call in this codebase today constructs the zero value.
type APIKey struct {
	ID         string
	UserID     string
	Label      string
	KeyHash    string
	AdminScope bool
	CreatedAt  int64
	LastUsedAt int64 // 0 when never used; stored as NULL
}

// APIKeyPrefix marks an API key's plaintext ("dak_...") so secret scanners
// recognise it and the auth middleware can reject non-keys before a hash and
// a lookup. Lives here, in store, alongside FeedTokenPrefix -- the domain
// package for every credential prefix constant in this codebase.
const APIKeyPrefix = "dak_"

// APIKeyRepo provides persistence operations for APIKey records.
type APIKeyRepo struct{ db *sql.DB }

// APIKeys returns an APIKeyRepo bound to this Store's database.
func (s *Store) APIKeys() *APIKeyRepo { return &APIKeyRepo{db: s.db} }

// apiAuthColumns is the SELECT list for the api_keys table, in
// scanAPIKey's order. Deliberately NOT named with "key" or "token" in it:
// gosec's G101 flags any constant whose NAME matches its credential
// heuristic (pass/pwd/secret/token/key/bearer/cred), and a column list is
// not a credential -- mirrors feed_tokens.go's identical feedAuthColumns
// naming, for the identical reason.
const apiAuthColumns = `id, user_id, label, key_hash, admin_scope, created_at, last_used_at`

func scanAPIKey(row interface {
	Scan(dest ...any) error
}) (APIKey, error) {
	var k APIKey
	var adminScope int
	var lastUsed sql.NullInt64
	if err := row.Scan(&k.ID, &k.UserID, &k.Label, &k.KeyHash, &adminScope, &k.CreatedAt, &lastUsed); err != nil {
		return APIKey{}, err
	}
	k.AdminScope = adminScope != 0
	k.LastUsedAt = scanInt64(lastUsed)
	return k, nil
}

// Create inserts k. Returns ErrConflict when (user_id, label) already exists
// or key_hash already exists.
func (r *APIKeyRepo) Create(ctx context.Context, k APIKey) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO api_keys (id, user_id, label, key_hash, admin_scope, created_at, last_used_at)
		 VALUES (?, ?, ?, ?, ?, ?, NULL)`,
		k.ID, k.UserID, k.Label, k.KeyHash, boolToInt(k.AdminScope), k.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("api_keys.Create: %w", ErrConflict)
		}
		return fmt.Errorf("api_keys.Create: %w", err)
	}
	return nil
}

// GetByHash looks a key up by its SHA-256 hash. Returns ErrNotFound when no
// live key matches -- a revoked key is deleted, so it is simply absent.
func (r *APIKeyRepo) GetByHash(ctx context.Context, hash string) (APIKey, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+apiAuthColumns+` FROM api_keys WHERE key_hash = ?`, hash)
	k, err := scanAPIKey(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return APIKey{}, fmt.Errorf("api_keys.GetByHash: %w", ErrNotFound)
		}
		return APIKey{}, fmt.Errorf("api_keys.GetByHash: %w", err)
	}
	return k, nil
}

// GetByID looks a key up by its primary key. Returns ErrNotFound when no
// live key matches. Ownership is NOT checked here -- the service layer
// checks UserID against the caller, mirroring DeviceService.ownedDevice's
// pattern (design D8).
func (r *APIKeyRepo) GetByID(ctx context.Context, id string) (APIKey, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+apiAuthColumns+` FROM api_keys WHERE id = ?`, id)
	k, err := scanAPIKey(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return APIKey{}, fmt.Errorf("api_keys.GetByID: %w", ErrNotFound)
		}
		return APIKey{}, fmt.Errorf("api_keys.GetByID: %w", err)
	}
	return k, nil
}

// List returns every live key owned by userID, oldest first.
func (r *APIKeyRepo) List(ctx context.Context, userID string) ([]APIKey, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+apiAuthColumns+` FROM api_keys WHERE user_id = ? ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, fmt.Errorf("api_keys.List: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, fmt.Errorf("api_keys.List: scan: %w", err)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("api_keys.List: rows: %w", err)
	}
	return out, nil
}

// Delete revokes a key by removing its row. Returns ErrNotFound if no row
// matched. Ownership is NOT checked here -- see GetByID's comment.
func (r *APIKeyRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("api_keys.Delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("api_keys.Delete: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("api_keys.Delete: %w", ErrNotFound)
	}
	return nil
}

// TouchLastUsed stamps last_used_at = now. Callers throttle this to at most
// once per lastUsedThrottle seconds per key (service.APIKeyService); on the
// process's single connection a write per request would be a write per
// request, full stop.
func (r *APIKeyRepo) TouchLastUsed(ctx context.Context, id string, now int64) error {
	if _, err := r.db.ExecContext(ctx,
		`UPDATE api_keys SET last_used_at = ? WHERE id = ?`, now, id); err != nil {
		return fmt.Errorf("api_keys.TouchLastUsed: %w", err)
	}
	return nil
}
