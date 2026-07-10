package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// User is the persisted shape of a user account (matches the users table
// columns 1:1). PasswordHash, OIDCProvider, and OIDCSubject are empty when
// unset; empty Go strings map to SQL NULL on write (see nullOrString) so
// that the UNIQUE(oidc_provider, oidc_subject) constraint never fires for
// two local (non-OIDC) users.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	Role         string
	OIDCProvider string
	OIDCSubject  string
	Disabled     bool
	CreatedAt    int64
	UpdatedAt    int64
}

// UserRepo is the repository for the users table.
type UserRepo struct{ db *sql.DB }

// Users returns the repository for the users table.
func (s *Store) Users() *UserRepo { return &UserRepo{db: s.db} }

// nullOrString returns nil for an empty string (so it binds as SQL NULL)
// or s itself otherwise. Used for the nullable users columns.
func nullOrString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// scanUser scans a single users row, in column order, into a User. The
// three nullable columns are scanned into sql.NullString and converted back
// to empty Go strings when NULL.
func scanUser(scan func(dest ...any) error) (User, error) {
	var (
		u                                       User
		passwordHash, oidcProvider, oidcSubject sql.NullString
	)
	err := scan(
		&u.ID, &u.Email, &passwordHash, &u.Role, &oidcProvider, &oidcSubject,
		&u.Disabled, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return User{}, err
	}
	u.PasswordHash = passwordHash.String
	u.OIDCProvider = oidcProvider.String
	u.OIDCSubject = oidcSubject.String
	return u, nil
}

const selectUserColumns = `id, email, password_hash, role, oidc_provider, oidc_subject, disabled, created_at, updated_at`

// Create inserts u, assigning a new UUIDv7 ID if u.ID is empty and setting
// CreatedAt/UpdatedAt to the current time. It returns the saved row.
func (r *UserRepo) Create(ctx context.Context, u User) (User, error) {
	if u.ID == "" {
		u.ID = NewID()
	}
	now := NowUnix()
	u.CreatedAt = now
	u.UpdatedAt = now

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (`+selectUserColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, nullOrString(u.PasswordHash), u.Role,
		nullOrString(u.OIDCProvider), nullOrString(u.OIDCSubject),
		u.Disabled, u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, fmt.Errorf("store: create user %q: %w", u.Email, ErrConflict)
		}
		return User{}, fmt.Errorf("store: create user %q: %w", u.Email, err)
	}
	return u, nil
}

// GetByID returns the user with the given id.
func (r *UserRepo) GetByID(ctx context.Context, id string) (User, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+selectUserColumns+` FROM users WHERE id = ?`, id)
	u, err := scanUser(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, fmt.Errorf("store: get user %q: %w", id, ErrNotFound)
		}
		return User{}, fmt.Errorf("store: get user %q: %w", id, err)
	}
	return u, nil
}

// GetByEmail returns the user with the given email.
func (r *UserRepo) GetByEmail(ctx context.Context, email string) (User, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+selectUserColumns+` FROM users WHERE email = ?`, email)
	u, err := scanUser(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, fmt.Errorf("store: get user by email %q: %w", email, ErrNotFound)
		}
		return User{}, fmt.Errorf("store: get user by email %q: %w", email, err)
	}
	return u, nil
}

// GetByOIDC returns the user linked to the given OIDC provider and subject.
func (r *UserRepo) GetByOIDC(ctx context.Context, provider, subject string) (User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+selectUserColumns+` FROM users WHERE oidc_provider = ? AND oidc_subject = ?`,
		provider, subject,
	)
	u, err := scanUser(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, fmt.Errorf("store: get user by oidc %s/%s: %w", provider, subject, ErrNotFound)
		}
		return User{}, fmt.Errorf("store: get user by oidc %s/%s: %w", provider, subject, err)
	}
	return u, nil
}

// Update overwrites all mutable columns of the user identified by u.ID and
// bumps updated_at to the current time. Returns ErrNotFound if no row
// matches u.ID.
func (r *UserRepo) Update(ctx context.Context, u User) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE users
		SET email = ?, password_hash = ?, role = ?, oidc_provider = ?, oidc_subject = ?,
		    disabled = ?, updated_at = ?
		WHERE id = ?`,
		u.Email, nullOrString(u.PasswordHash), u.Role,
		nullOrString(u.OIDCProvider), nullOrString(u.OIDCSubject),
		u.Disabled, NowUnix(), u.ID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("store: update user %q: %w", u.ID, ErrConflict)
		}
		return fmt.Errorf("store: update user %q: %w", u.ID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: update user %q: rows affected: %w", u.ID, err)
	}
	if n == 0 {
		return fmt.Errorf("store: update user %q: %w", u.ID, ErrNotFound)
	}
	return nil
}

// SetDisabled sets the disabled flag for the user with the given id.
func (r *UserRepo) SetDisabled(ctx context.Context, id string, disabled bool) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE users SET disabled = ?, updated_at = ? WHERE id = ?`,
		disabled, NowUnix(), id,
	)
	if err != nil {
		return fmt.Errorf("store: set disabled for user %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: set disabled for user %q: rows affected: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("store: set disabled for user %q: %w", id, ErrNotFound)
	}
	return nil
}

// Delete removes the user with the given id. Foreign-key cascades remove
// the user's sessions and devices. Returns ErrNotFound if no row matches.
func (r *UserRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete user %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete user %q: rows affected: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("store: delete user %q: %w", id, ErrNotFound)
	}
	return nil
}

// List returns all users ordered by email ascending, for admin UI display.
func (r *UserRepo) List(ctx context.Context) ([]User, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+selectUserColumns+` FROM users ORDER BY email ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []User
	for rows.Next() {
		u, err := scanUser(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("store: list users: scan: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	return users, nil
}
