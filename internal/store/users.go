package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// User represents a DIYDDNS user account.
type User struct {
	ID           string
	Email        string
	PasswordHash string // empty when OIDC-only
	Role         string // "admin" | "user"
	OIDCProvider string // empty when not linked
	OIDCSubject  string // empty when not linked
	Disabled     bool
	CreatedAt    int64
	UpdatedAt    int64
}

// UserRepo provides persistence operations for User records.
type UserRepo struct{ db *sql.DB }

// Users returns a UserRepo bound to this Store's database.
func (s *Store) Users() *UserRepo { return &UserRepo{db: s.db} }

// nullIfEmpty converts an empty Go string to nil for SQL NULL inserts.
// SQLite's UNIQUE index treats multiple NULLs as distinct, unlike empty
// strings which would trigger a constraint violation on the second insert.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// scanString scans a possibly-NULL TEXT column to a Go string ("" if NULL).
func scanString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

const userColumns = `id, email, password_hash, role, oidc_provider, oidc_subject, disabled, created_at, updated_at`

func scanUser(row interface {
	Scan(dest ...any) error
}) (User, error) {
	var u User
	var passwordHash, oidcProvider, oidcSubject sql.NullString
	var disabled int64
	err := row.Scan(
		&u.ID,
		&u.Email,
		&passwordHash,
		&u.Role,
		&oidcProvider,
		&oidcSubject,
		&disabled,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if err != nil {
		return User{}, err
	}
	u.PasswordHash = scanString(passwordHash)
	u.OIDCProvider = scanString(oidcProvider)
	u.OIDCSubject = scanString(oidcSubject)
	u.Disabled = disabled != 0
	return u, nil
}

// Create inserts a new user. If u.ID is empty, a new UUIDv7 is assigned.
// CreatedAt and UpdatedAt are set to the current unix second.
// Returns ErrConflict if email or (oidc_provider, oidc_subject) is already taken.
func (r *UserRepo) Create(ctx context.Context, u User) (User, error) {
	if u.ID == "" {
		u.ID = NewID()
	}
	now := NowUnix()
	u.CreatedAt = now
	u.UpdatedAt = now

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, role, oidc_provider, oidc_subject, disabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID,
		u.Email,
		nullIfEmpty(u.PasswordHash),
		u.Role,
		nullIfEmpty(u.OIDCProvider),
		nullIfEmpty(u.OIDCSubject),
		boolToInt(u.Disabled),
		u.CreatedAt,
		u.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, fmt.Errorf("users.Create: %w", ErrConflict)
		}
		return User{}, fmt.Errorf("users.Create: %w", err)
	}
	return u, nil
}

// GetByID fetches a user by primary key.
// Returns ErrNotFound if no row exists.
func (r *UserRepo) GetByID(ctx context.Context, id string) (User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ?`, id,
	)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, fmt.Errorf("users.GetByID: %w", ErrNotFound)
		}
		return User{}, fmt.Errorf("users.GetByID: %w", err)
	}
	return u, nil
}

// GetByEmail fetches a user by email address.
// Returns ErrNotFound if no row exists.
func (r *UserRepo) GetByEmail(ctx context.Context, email string) (User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = ?`, email,
	)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, fmt.Errorf("users.GetByEmail: %w", ErrNotFound)
		}
		return User{}, fmt.Errorf("users.GetByEmail: %w", err)
	}
	return u, nil
}

// GetByOIDC fetches a user by (oidc_provider, oidc_subject).
// Returns ErrNotFound if no row exists.
func (r *UserRepo) GetByOIDC(ctx context.Context, provider, subject string) (User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE oidc_provider = ? AND oidc_subject = ?`,
		provider, subject,
	)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, fmt.Errorf("users.GetByOIDC: %w", ErrNotFound)
		}
		return User{}, fmt.Errorf("users.GetByOIDC: %w", err)
	}
	return u, nil
}

// Update modifies all mutable columns for the given user.
// Returns ErrNotFound if no row matched, ErrConflict on UNIQUE violation.
func (r *UserRepo) Update(ctx context.Context, u User) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE users
		 SET email = ?, password_hash = ?, role = ?,
		     oidc_provider = ?, oidc_subject = ?, disabled = ?,
		     updated_at = ?
		 WHERE id = ?`,
		u.Email,
		nullIfEmpty(u.PasswordHash),
		u.Role,
		nullIfEmpty(u.OIDCProvider),
		nullIfEmpty(u.OIDCSubject),
		boolToInt(u.Disabled),
		NowUnix(),
		u.ID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("users.Update: %w", ErrConflict)
		}
		return fmt.Errorf("users.Update: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("users.Update: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("users.Update: %w", ErrNotFound)
	}
	return nil
}

// SetDisabled toggles the disabled flag on a user.
// Returns ErrNotFound if no row matched.
func (r *UserRepo) SetDisabled(ctx context.Context, id string, disabled bool) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE users SET disabled = ?, updated_at = ? WHERE id = ?`,
		boolToInt(disabled), NowUnix(), id,
	)
	if err != nil {
		return fmt.Errorf("users.SetDisabled: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("users.SetDisabled: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("users.SetDisabled: %w", ErrNotFound)
	}
	return nil
}

// Delete removes a user by ID. Cascades to sessions and devices via FK.
// Returns ErrNotFound if no row matched.
func (r *UserRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("users.Delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("users.Delete: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("users.Delete: %w", ErrNotFound)
	}
	return nil
}

// List returns all users ordered by email ascending.
func (r *UserRepo) List(ctx context.Context) ([]User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+userColumns+` FROM users ORDER BY email ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("users.List: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("users.List: scan: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("users.List: rows: %w", err)
	}
	return users, nil
}

// boolToInt converts a Go bool to SQLite's INTEGER representation (0/1).
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
