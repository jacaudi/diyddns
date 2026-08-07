package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// WebAuthnCredential represents a single registered passkey. CredentialJSON
// holds the full go-webauthn Credential as an opaque JSON blob; the store
// layer never inspects it, only persists and returns it unchanged.
type WebAuthnCredential struct {
	CredentialID   []byte
	UserID         string
	CredentialJSON []byte
	Name           string
	AAGUID         []byte // may be nil for authenticators that don't report one
	CreatedAt      int64
	LastUsedAt     int64 // 0 if never used; stored as NULL in SQLite
}

// WebAuthnCredentialRepo provides persistence operations for WebAuthnCredential records.
type WebAuthnCredentialRepo struct{ db *sql.DB }

// WebAuthnCredentials returns a WebAuthnCredentialRepo bound to this Store's database.
func (s *Store) WebAuthnCredentials() *WebAuthnCredentialRepo {
	return &WebAuthnCredentialRepo{db: s.db}
}

const webAuthnCredentialColumns = `credential_id, user_id, credential_json, name, aaguid, created_at, last_used_at` // #nosec G101 -- SQL column list, not a credential value; gosec's keyword heuristic fires on "credential" in the identifier name

func scanWebAuthnCredential(row interface {
	Scan(dest ...any) error
}) (WebAuthnCredential, error) {
	var c WebAuthnCredential
	var aaguid []byte
	var lastUsedAt sql.NullInt64

	err := row.Scan(
		&c.CredentialID,
		&c.UserID,
		&c.CredentialJSON,
		&c.Name,
		&aaguid,
		&c.CreatedAt,
		&lastUsedAt,
	)
	if err != nil {
		return WebAuthnCredential{}, err
	}
	c.AAGUID = aaguid
	c.LastUsedAt = scanInt64(lastUsedAt)
	return c, nil
}

// Create inserts a new WebAuthn credential.
// Returns ErrConflict if credential_id (PK) already exists.
func (r *WebAuthnCredentialRepo) Create(ctx context.Context, c WebAuthnCredential) (WebAuthnCredential, error) {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials (credential_id, user_id, credential_json, name, aaguid, created_at, last_used_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.CredentialID,
		c.UserID,
		c.CredentialJSON,
		c.Name,
		c.AAGUID,
		c.CreatedAt,
		nullIfZero(c.LastUsedAt),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return WebAuthnCredential{}, fmt.Errorf("webauthn_credentials.Create: %w", ErrConflict)
		}
		return WebAuthnCredential{}, fmt.Errorf("webauthn_credentials.Create: %w", err)
	}
	return c, nil
}

// GetByID fetches a WebAuthn credential by its credential_id (primary key).
// Returns ErrNotFound if no row exists.
func (r *WebAuthnCredentialRepo) GetByID(ctx context.Context, credentialID []byte) (WebAuthnCredential, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+webAuthnCredentialColumns+` FROM webauthn_credentials WHERE credential_id = ?`, credentialID,
	)
	c, err := scanWebAuthnCredential(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WebAuthnCredential{}, fmt.Errorf("webauthn_credentials.GetByID: %w", ErrNotFound)
		}
		return WebAuthnCredential{}, fmt.Errorf("webauthn_credentials.GetByID: %w", err)
	}
	return c, nil
}

// ListByUser returns all WebAuthn credentials for a user ordered by created_at ascending.
func (r *WebAuthnCredentialRepo) ListByUser(ctx context.Context, userID string) ([]WebAuthnCredential, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+webAuthnCredentialColumns+` FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn_credentials.ListByUser: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var creds []WebAuthnCredential
	for rows.Next() {
		c, err := scanWebAuthnCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("webauthn_credentials.ListByUser: scan: %w", err)
		}
		creds = append(creds, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("webauthn_credentials.ListByUser: rows: %w", err)
	}
	return creds, nil
}

// Rename updates the display name of a WebAuthn credential.
// Returns ErrNotFound if no row matched.
func (r *WebAuthnCredentialRepo) Rename(ctx context.Context, credentialID []byte, name string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET name = ? WHERE credential_id = ?`,
		name, credentialID,
	)
	if err != nil {
		return fmt.Errorf("webauthn_credentials.Rename: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("webauthn_credentials.Rename: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("webauthn_credentials.Rename: %w", ErrNotFound)
	}
	return nil
}

// Delete removes a WebAuthn credential by credential_id.
// Returns ErrNotFound if no row matched.
func (r *WebAuthnCredentialRepo) Delete(ctx context.Context, credentialID []byte) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE credential_id = ?`, credentialID)
	if err != nil {
		return fmt.Errorf("webauthn_credentials.Delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("webauthn_credentials.Delete: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("webauthn_credentials.Delete: %w", ErrNotFound)
	}
	return nil
}

// DeleteAllByUser removes every WebAuthn credential belonging to userID.
// Returns the number of rows deleted.
func (r *WebAuthnCredentialRepo) DeleteAllByUser(ctx context.Context, userID string) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE user_id = ?`, userID)
	if err != nil {
		return 0, fmt.Errorf("webauthn_credentials.DeleteAllByUser: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("webauthn_credentials.DeleteAllByUser: RowsAffected: %w", err)
	}
	return int(n), nil
}

// Update re-persists credential_json and last_used_at, typically after a
// successful login (updated sign count / clone-warning state and the new
// last-used timestamp). Name and aaguid are unaffected; use Rename to
// change the display name.
// Returns ErrNotFound if no row matched.
func (r *WebAuthnCredentialRepo) Update(ctx context.Context, c WebAuthnCredential) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET credential_json = ?, last_used_at = ? WHERE credential_id = ?`,
		c.CredentialJSON, nullIfZero(c.LastUsedAt), c.CredentialID,
	)
	if err != nil {
		return fmt.Errorf("webauthn_credentials.Update: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("webauthn_credentials.Update: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("webauthn_credentials.Update: %w", ErrNotFound)
	}
	return nil
}

// CountWebAuthnCredentials returns the number of WebAuthn credentials registered for userID.
func (r *WebAuthnCredentialRepo) CountWebAuthnCredentials(ctx context.Context, userID string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, userID,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("webauthn_credentials.CountWebAuthnCredentials: %w", err)
	}
	return n, nil
}
