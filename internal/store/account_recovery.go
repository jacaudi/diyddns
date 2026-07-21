package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// RecoveryToken represents a single-use, hashed, expiring registration-grant
// token. It backs both admin invites and account recovery: a caller issues a
// token bound to a user for a specific reason, and consuming it is atomic
// and single-use.
type RecoveryToken struct {
	TokenHash string
	UserID    string
	Reason    string
	ExpiresAt int64
	UsedAt    int64 // 0 if not consumed; stored as NULL in SQLite
}

// AccountRecoveryRepo provides persistence operations for RecoveryToken records.
type AccountRecoveryRepo struct{ db *sql.DB }

// AccountRecovery returns an AccountRecoveryRepo bound to this Store's database.
func (s *Store) AccountRecovery() *AccountRecoveryRepo { return &AccountRecoveryRepo{db: s.db} }

const recoveryTokenColumns = `token_hash, user_id, reason, expires_at, used_at` // #nosec G101 -- SQL column list, not a credential value; gosec's keyword heuristic fires on "Token" in the identifier name

func scanRecoveryToken(row interface {
	Scan(dest ...any) error
}) (RecoveryToken, error) {
	var t RecoveryToken
	var usedAt sql.NullInt64

	err := row.Scan(
		&t.TokenHash,
		&t.UserID,
		&t.Reason,
		&t.ExpiresAt,
		&usedAt,
	)
	if err != nil {
		return RecoveryToken{}, err
	}
	t.UsedAt = scanInt64(usedAt)
	return t, nil
}

// Create inserts a new recovery token.
// Returns ErrConflict if the token_hash (PK) already exists.
func (r *AccountRecoveryRepo) Create(ctx context.Context, t RecoveryToken) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO account_recovery_tokens (token_hash, user_id, reason, expires_at, used_at)
		 VALUES (?, ?, ?, ?, ?)`,
		t.TokenHash,
		t.UserID,
		t.Reason,
		t.ExpiresAt,
		nullIfZero(t.UsedAt),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("account_recovery.Create: %w", ErrConflict)
		}
		return fmt.Errorf("account_recovery.Create: %w", err)
	}
	return nil
}

// get fetches a recovery token by its hash (primary key).
// Returns ErrNotFound if no row exists.
func (r *AccountRecoveryRepo) get(ctx context.Context, tokenHash string) (RecoveryToken, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+recoveryTokenColumns+` FROM account_recovery_tokens WHERE token_hash = ?`, tokenHash,
	)
	t, err := scanRecoveryToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RecoveryToken{}, fmt.Errorf("account_recovery.get: %w", ErrNotFound)
		}
		return RecoveryToken{}, fmt.Errorf("account_recovery.get: %w", err)
	}
	return t, nil
}

// Consume atomically marks a recovery token as used.
// The UPDATE only matches rows where used_at IS NULL and expires_at > now,
// so expired and already-consumed tokens all result in ErrNotFound.
// On success, returns the post-update row via get.
func (r *AccountRecoveryRepo) Consume(ctx context.Context, tokenHash string, now int64) (RecoveryToken, error) {
	res, err := r.db.ExecContext(ctx,
		`UPDATE account_recovery_tokens
		   SET used_at = ?
		 WHERE token_hash = ?
		   AND used_at IS NULL
		   AND expires_at > ?`,
		now, tokenHash, now,
	)
	if err != nil {
		return RecoveryToken{}, fmt.Errorf("account_recovery.Consume: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return RecoveryToken{}, fmt.Errorf("account_recovery.Consume rows_affected: %w", err)
	}
	if rows == 0 {
		return RecoveryToken{}, fmt.Errorf("account_recovery.Consume: %w", ErrNotFound)
	}
	return r.get(ctx, tokenHash)
}

// PruneExpired deletes recovery tokens that have expired and have not been
// consumed. Consumed tokens are retained for audit purposes until the owning
// user is deleted (which cascades automatically via FK).
// Returns the number of rows deleted.
func (r *AccountRecoveryRepo) PruneExpired(ctx context.Context, now int64) (int, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM account_recovery_tokens WHERE expires_at < ? AND used_at IS NULL`,
		now,
	)
	if err != nil {
		return 0, fmt.Errorf("account_recovery.PruneExpired: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("account_recovery.PruneExpired: RowsAffected: %w", err)
	}
	return int(n), nil
}
