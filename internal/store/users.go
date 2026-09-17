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
	Role         string // "admin" | "user"
	OIDCProvider string // empty when not linked
	OIDCSubject  string // empty when not linked
	Disabled     bool
	CreatedAt    int64
	UpdatedAt    int64
	// PendingEmail is a self-service address change waiting for the new
	// address to confirm (#131 D4), or "" when nothing is pending. It is
	// canonical (written from email.NormalizeAddress) and READ-ONLY here:
	// SetPendingEmail / ClearPendingEmail / ConfirmPendingEmail own it, and
	// Update never touches it. The confirmation token's hash is deliberately
	// not a field: only ConfirmPendingEmail reads it, in SQL.
	PendingEmail string
	// PendingEmailExpiresAt is the unix second PendingEmail stops being
	// confirmable; 0 when nothing is pending. A value in the past means the
	// pending change is dead: readers treat it as absent and the hourly
	// pruner clears it (ClearExpiredPendingEmails).
	PendingEmailExpiresAt int64
}

// IsEnabledAdmin reports whether u is an admin who can currently act as one --
// role "admin" and not disabled. The single source of a predicate that used
// to be copy-pasted at four production sites (buildSweeper's admin-digest
// filter in internal/server/server.go, GrantService.
// notifyAdminsOfSelfServiceRecovery, AdminService.enabledAdminCount, and the
// admin users page's LastAdmin derivation in internal/server/webui): each one
// independently re-typed `Role == "admin" && !Disabled`, and a fifth copy
// would have been the wrong response to that.
func (u User) IsEnabledAdmin() bool { return u.Role == "admin" && !u.Disabled }

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

const userColumns = `id, email, role, oidc_provider, oidc_subject, disabled, created_at, updated_at, pending_email, pending_email_expires_at`

func scanUser(row interface {
	Scan(dest ...any) error
}) (User, error) {
	var u User
	var oidcProvider, oidcSubject, pendingEmail sql.NullString
	var disabled int64
	var pendingExpires sql.NullInt64
	err := row.Scan(
		&u.ID,
		&u.Email,
		&u.Role,
		&oidcProvider,
		&oidcSubject,
		&disabled,
		&u.CreatedAt,
		&u.UpdatedAt,
		&pendingEmail,
		&pendingExpires,
	)
	if err != nil {
		return User{}, err
	}
	u.OIDCProvider = scanString(oidcProvider)
	u.OIDCSubject = scanString(oidcSubject)
	u.Disabled = disabled != 0
	u.PendingEmail = scanString(pendingEmail)
	u.PendingEmailExpiresAt = scanInt64(pendingExpires)
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
		`INSERT INTO users (id, email, role, oidc_provider, oidc_subject, disabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID,
		u.Email,
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
		 SET email = ?, role = ?,
		     oidc_provider = ?, oidc_subject = ?, disabled = ?,
		     updated_at = ?
		 WHERE id = ?`,
		u.Email,
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

// SetWebAuthnHandle sets the opaque per-user handle used to resolve a user
// during discoverable (usernameless) passkey login. The handle is the lookup
// key for GetByWebAuthnHandle and is enforced UNIQUE at the DB level.
// Returns ErrNotFound if no row matched, ErrConflict if the handle is already
// assigned to another user.
func (r *UserRepo) SetWebAuthnHandle(ctx context.Context, userID string, handle []byte) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE users SET webauthn_handle = ? WHERE id = ?`,
		handle, userID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("users.SetWebAuthnHandle: %w", ErrConflict)
		}
		return fmt.Errorf("users.SetWebAuthnHandle: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("users.SetWebAuthnHandle: RowsAffected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("users.SetWebAuthnHandle: %w", ErrNotFound)
	}
	return nil
}

// GetByWebAuthnHandle fetches a user by their WebAuthn handle. An empty
// handle is rejected before querying: webauthn_handle is NULL for every
// user that has not registered a passkey, and an empty/nil argument must
// never be treated as a match against those rows.
// Returns ErrNotFound if handle is empty or no row exists.
func (r *UserRepo) GetByWebAuthnHandle(ctx context.Context, handle []byte) (User, error) {
	if len(handle) == 0 {
		return User{}, fmt.Errorf("users.GetByWebAuthnHandle: %w", ErrNotFound)
	}
	row := r.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE webauthn_handle = ?`, handle,
	)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, fmt.Errorf("users.GetByWebAuthnHandle: %w", ErrNotFound)
		}
		return User{}, fmt.Errorf("users.GetByWebAuthnHandle: %w", err)
	}
	return u, nil
}

// GetWebAuthnHandle returns the WebAuthn handle for userID, or nil if the
// user has never registered a passkey (webauthn_handle is NULL). Callers
// registering a second (or later) passkey for the same user must reuse this
// exact value in the ceremony: the handle is baked into each authenticator's
// resident credential at registration time, so every credential a user owns
// must share the one handle stored on their row, or discoverable-login
// resolution (GetByWebAuthnHandle) breaks for whichever credential's handle
// isn't the one currently on the row.
// Returns ErrNotFound if no such user exists.
func (r *UserRepo) GetWebAuthnHandle(ctx context.Context, userID string) ([]byte, error) {
	var handle []byte
	err := r.db.QueryRowContext(ctx, `SELECT webauthn_handle FROM users WHERE id = ?`, userID).Scan(&handle)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("users.GetWebAuthnHandle: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("users.GetWebAuthnHandle: %w", err)
	}
	return handle, nil
}

// List returns all users ordered by email ascending.
func (r *UserRepo) List(ctx context.Context) ([]User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+userColumns+` FROM users ORDER BY email ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("users.List: %w", err)
	}
	defer func() { _ = rows.Close() }()

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

// requireMatched turns an UPDATE's RowsAffected into ErrNotFound when no row
// matched. op names the caller for the wrapped error. SQLite counts rows
// MATCHED by the WHERE clause, not rows whose values changed, so an UPDATE
// that writes the values a row already holds still counts as matched.
func requireMatched(res sql.Result, op string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: RowsAffected: %w", op, err)
	}
	if n == 0 {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}
	return nil
}

// SetPendingEmail stages a self-service address change on userID (#131 D4):
// the canonical new address, the hash of its confirmation token, and when
// that token expires. It replaces any pending change already staged. It does
// not bump updated_at: the pending columns are staging, not the record.
// Returns ErrNotFound if no row matched. Rejects an empty newEmail without
// writing anything: PendingEmail == "" is User's documented "nothing
// pending" sentinel, so staging "" would silently defeat every reader of
// that field (nullIfEmpty guards the same class of bug for OIDCProvider /
// OIDCSubject elsewhere in this file).
func (r *UserRepo) SetPendingEmail(ctx context.Context, userID, newEmail, tokenHash string, expiresAt int64) error {
	if nullIfEmpty(newEmail) == nil {
		return fmt.Errorf("users.SetPendingEmail: newEmail must not be empty")
	}
	res, err := r.db.ExecContext(ctx,
		`UPDATE users
		 SET pending_email = ?, pending_email_token_hash = ?, pending_email_expires_at = ?
		 WHERE id = ?`,
		newEmail, tokenHash, expiresAt, userID,
	)
	if err != nil {
		return fmt.Errorf("users.SetPendingEmail: %w", err)
	}
	return requireMatched(res, "users.SetPendingEmail")
}

// ClearPendingEmail discards userID's staged address change, if any. A row
// with nothing pending still matches and returns nil. Returns ErrNotFound
// only if no such user exists.
func (r *UserRepo) ClearPendingEmail(ctx context.Context, userID string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE users
		 SET pending_email = NULL, pending_email_token_hash = NULL, pending_email_expires_at = NULL
		 WHERE id = ?`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("users.ClearPendingEmail: %w", err)
	}
	return requireMatched(res, "users.ClearPendingEmail")
}

// ConfirmPendingEmail applies userID's staged change in ONE statement: the
// row's email becomes pending_email and the staging columns clear, but only
// if tokenHash matches the staged hash and the change has not expired. The
// single conditional UPDATE is both the single-use gate and the apply, so
// there is no "consumed but not applied" window (design D4). Returns
// ErrNotFound when nothing matched -- wrong token, expired, or nothing
// pending; callers must not distinguish -- and ErrConflict when another row
// already holds the address (the UNIQUE index is the binary race guard).
// updated_at is set to now.
func (r *UserRepo) ConfirmPendingEmail(ctx context.Context, userID, tokenHash string, now int64) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE users
		 SET email = pending_email,
		     pending_email = NULL, pending_email_token_hash = NULL, pending_email_expires_at = NULL,
		     updated_at = ?
		 WHERE id = ?
		   AND pending_email IS NOT NULL
		   AND pending_email_token_hash = ?
		   AND pending_email_expires_at > ?`,
		now, userID, tokenHash, now,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("users.ConfirmPendingEmail: %w", ErrConflict)
		}
		return fmt.Errorf("users.ConfirmPendingEmail: %w", err)
	}
	return requireMatched(res, "users.ConfirmPendingEmail")
}

// SetEmail writes userID's address directly (an admin set, or an IdP sync --
// #131 D3/D9) and discards any staged self-service change, which the direct
// write supersedes. updated_at is set to now. Returns ErrConflict when
// another row holds the address, ErrNotFound when no row matched. Rejects
// an empty email without writing anything: the column is NOT NULL, and an
// empty string would otherwise pass that constraint while leaving the
// account unreachable.
func (r *UserRepo) SetEmail(ctx context.Context, userID, email string, now int64) error {
	if nullIfEmpty(email) == nil {
		return fmt.Errorf("users.SetEmail: email must not be empty")
	}
	res, err := r.db.ExecContext(ctx,
		`UPDATE users
		 SET email = ?,
		     pending_email = NULL, pending_email_token_hash = NULL, pending_email_expires_at = NULL,
		     updated_at = ?
		 WHERE id = ?`,
		email, now, userID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("users.SetEmail: %w", ErrConflict)
		}
		return fmt.Errorf("users.SetEmail: %w", err)
	}
	return requireMatched(res, "users.SetEmail")
}

// ClearExpiredPendingEmails discards every staged address change whose
// confirmation window closed before now, and returns how many rows it
// cleared. Run by the hourly pruner (#131 D17): an expired pending address
// is very often a third party's address typed by mistake, and it must not
// sit on the row indefinitely.
func (r *UserRepo) ClearExpiredPendingEmails(ctx context.Context, now int64) (int, error) {
	res, err := r.db.ExecContext(ctx,
		`UPDATE users
		 SET pending_email = NULL, pending_email_token_hash = NULL, pending_email_expires_at = NULL
		 WHERE pending_email_expires_at IS NOT NULL AND pending_email_expires_at < ?`,
		now,
	)
	if err != nil {
		return 0, fmt.Errorf("users.ClearExpiredPendingEmails: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("users.ClearExpiredPendingEmails: RowsAffected: %w", err)
	}
	return int(n), nil
}
