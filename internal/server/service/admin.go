package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// Guard sentinels — mapped to HTTP 409/422 by the API layer.
var (
	// ErrLastAdmin is returned when an operation would leave zero enabled admins.
	ErrLastAdmin = errors.New("service: cannot remove the last admin")
	// ErrSelfLockout is returned when an admin tries to disable, delete, or
	// demote themselves.
	ErrSelfLockout = errors.New("service: cannot disable or delete your own account")
	// ErrOIDCNoPassword is returned when setting a local password on an OIDC-only account.
	ErrOIDCNoPassword = errors.New("service: user is OIDC-managed; no local password")
	// ErrInvalidRole is returned for a role outside {admin, user}.
	ErrInvalidRole = errors.New("service: invalid role")
	// ErrWeakPassword is returned when a password is shorter than the
	// configured policy minimum.
	ErrWeakPassword = errors.New("service: password too short")
	// ErrInvalidEmail is returned when an email address fails RFC parsing.
	ErrInvalidEmail = errors.New("service: invalid email address")
)

// CreateUserParams is the input to CreateUser. Role must be "admin" or "user".
type CreateUserParams struct {
	Email    string
	Password string
	Role     string
}

// UpdateUserParams is the partial-update input to UpdateUser. A nil field is
// left unchanged.
type UpdateUserParams struct {
	Role     *string
	Disabled *bool
	Password *string
}

// AdminService implements admin-only user management (with lockout guards),
// plus cross-user device and audit reads.
type AdminService struct {
	st           *store.Store
	argon2Params auth.Argon2Params
	minLength    int
	audit        AuditSink
}

// NewAdminService constructs an AdminService. pw supplies the argon2id params
// and minimum password length enforced when creating users or resetting
// passwords.
func NewAdminService(st *store.Store, pw config.PasswordCfg, audit AuditSink) *AdminService {
	return &AdminService{
		st:           st,
		argon2Params: auth.Argon2Params{Time: pw.Argon2Time, MemoryKiB: pw.Argon2MemoryKiB, Parallelism: pw.Argon2Parallelism},
		minLength:    pw.MinLength,
		audit:        audit,
	}
}

func validRole(r string) bool { return r == "admin" || r == "user" }

// enabledAdminCount returns how many enabled admins exist, and whether target
// is currently one of them.
func (s *AdminService) enabledAdminCount(ctx context.Context, targetID string) (count int, targetIsEnabledAdmin bool, err error) {
	users, err := s.st.Users().List(ctx)
	if err != nil {
		return 0, false, err
	}
	for _, u := range users {
		if u.Role == "admin" && !u.Disabled {
			count++
			if u.ID == targetID {
				targetIsEnabledAdmin = true
			}
		}
	}
	return count, targetIsEnabledAdmin, nil
}

// ListUsers returns all users ordered by email.
func (s *AdminService) ListUsers(ctx context.Context) ([]store.User, error) {
	users, err := s.st.Users().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("service.ListUsers: %w", err)
	}
	return users, nil
}

// CreateUser creates a local user with a hashed password.
func (s *AdminService) CreateUser(ctx context.Context, actorID string, p CreateUserParams) (store.User, error) {
	if !validRole(p.Role) {
		return store.User{}, fmt.Errorf("service.CreateUser: %w", ErrInvalidRole)
	}
	if _, err := mail.ParseAddress(p.Email); err != nil {
		return store.User{}, fmt.Errorf("service.CreateUser: %w", ErrInvalidEmail)
	}
	if len(p.Password) < s.minLength {
		return store.User{}, fmt.Errorf("service.CreateUser: %w", ErrWeakPassword)
	}
	hash, err := auth.HashPassword(p.Password, s.argon2Params)
	if err != nil {
		return store.User{}, fmt.Errorf("service.CreateUser: %w", err)
	}
	u, err := s.st.Users().Create(ctx, store.User{Email: p.Email, PasswordHash: hash, Role: p.Role})
	if err != nil {
		return store.User{}, fmt.Errorf("service.CreateUser: %w", err) // ErrConflict flows up
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: "user.created", TargetType: "user", TargetID: u.ID})
	return u, nil
}

// UpdateUser applies a partial update (role / disabled / password) with lockout
// guards. Disabling a user also revokes their active sessions.
func (s *AdminService) UpdateUser(ctx context.Context, actorID, targetID string, p UpdateUserParams) (store.User, error) {
	u, err := s.st.Users().GetByID(ctx, targetID)
	if err != nil {
		return store.User{}, fmt.Errorf("service.UpdateUser: %w", err) // ErrNotFound flows up
	}

	if err := s.guardUpdateUser(ctx, actorID, targetID, u, p); err != nil {
		return store.User{}, fmt.Errorf("service.UpdateUser: %w", err)
	}

	if err := s.applyRoleAndPassword(ctx, actorID, targetID, u, p); err != nil {
		return store.User{}, fmt.Errorf("service.UpdateUser: %w", err)
	}
	if err := s.applyDisabled(ctx, actorID, targetID, p); err != nil {
		return store.User{}, fmt.Errorf("service.UpdateUser: %w", err)
	}

	updated, err := s.st.Users().GetByID(ctx, targetID)
	if err != nil {
		return store.User{}, fmt.Errorf("service.UpdateUser: %w", err)
	}
	return updated, nil
}

// guardUpdateUser applies UpdateUser's lockout/validity guards: invalid
// role, self-demote, demoting/disabling the last enabled admin, self-disable,
// resetting a password on an OIDC-only account, and a too-short password. u
// is the target's pre-update row (read by the caller so its PasswordHash
// reflects current state).
func (s *AdminService) guardUpdateUser(ctx context.Context, actorID, targetID string, u store.User, p UpdateUserParams) error {
	if p.Role != nil {
		if !validRole(*p.Role) {
			return ErrInvalidRole
		}
		if *p.Role != "admin" {
			// Self-demote is blocked unconditionally — regardless of how many
			// other admins exist — before the last-admin guard even runs.
			if targetID == actorID {
				return ErrSelfLockout
			}
			if err := s.guardLastAdmin(ctx, targetID); err != nil {
				return err
			}
		}
	}
	if p.Disabled != nil && *p.Disabled {
		if targetID == actorID {
			return ErrSelfLockout
		}
		if err := s.guardLastAdmin(ctx, targetID); err != nil {
			return err
		}
	}
	if p.Password != nil {
		if u.PasswordHash == "" {
			return ErrOIDCNoPassword
		}
		if len(*p.Password) < s.minLength {
			return ErrWeakPassword
		}
	}
	return nil
}

// applyRoleAndPassword writes the role and/or password changes via Update
// (which writes all mutable columns) and audits each change made. u is the
// target's pre-update row, mutated in place before the write.
func (s *AdminService) applyRoleAndPassword(ctx context.Context, actorID, targetID string, u store.User, p UpdateUserParams) error {
	if p.Role == nil && p.Password == nil {
		return nil
	}
	if p.Role != nil {
		u.Role = *p.Role
	}
	if p.Password != nil {
		hash, err := auth.HashPassword(*p.Password, s.argon2Params)
		if err != nil {
			return err
		}
		u.PasswordHash = hash
	}
	if err := s.st.Users().Update(ctx, u); err != nil {
		return err
	}
	if p.Role != nil {
		s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: "user.role_change", TargetType: "user", TargetID: targetID})
	}
	if p.Password != nil {
		s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: "user.password_change", TargetType: "user", TargetID: targetID})
	}
	return nil
}

// applyDisabled writes the disabled flag via SetDisabled and, on disable,
// revokes the target's active sessions (auditing session.revoked only if any
// were actually deleted).
func (s *AdminService) applyDisabled(ctx context.Context, actorID, targetID string, p UpdateUserParams) error {
	if p.Disabled == nil {
		return nil
	}
	if err := s.st.Users().SetDisabled(ctx, targetID, *p.Disabled); err != nil {
		return err
	}
	event := "user.enabled"
	if *p.Disabled {
		event = "user.disabled"
		n, err := s.st.Sessions().DeleteByUser(ctx, targetID)
		if err != nil {
			return err
		}
		if n > 0 {
			s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: "session.revoked", TargetType: "user", TargetID: targetID})
		}
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: event, TargetType: "user", TargetID: targetID})
	return nil
}

// DeleteUser deletes a user (cascading sessions + devices + codes via FK), with
// last-admin and self-lockout guards.
func (s *AdminService) DeleteUser(ctx context.Context, actorID, targetID string) error {
	if targetID == actorID {
		return fmt.Errorf("service.DeleteUser: %w", ErrSelfLockout)
	}
	if err := s.guardLastAdmin(ctx, targetID); err != nil {
		return fmt.Errorf("service.DeleteUser: %w", err)
	}
	if err := s.st.Users().Delete(ctx, targetID); err != nil {
		return fmt.Errorf("service.DeleteUser: %w", err) // ErrNotFound flows up
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: actorID, EventType: "user.deleted", TargetType: "user", TargetID: targetID})
	return nil
}

// guardLastAdmin returns ErrLastAdmin if targetID is currently the only enabled
// admin (so removing/demoting/disabling it would lock everyone out).
func (s *AdminService) guardLastAdmin(ctx context.Context, targetID string) error {
	count, targetIsEnabledAdmin, err := s.enabledAdminCount(ctx, targetID)
	if err != nil {
		return err
	}
	if targetIsEnabledAdmin && count <= 1 {
		return ErrLastAdmin
	}
	return nil
}

// ListAllDevices returns every device across all users (admin view).
func (s *AdminService) ListAllDevices(ctx context.Context) ([]store.Device, error) {
	devices, err := s.st.Devices().ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("service.ListAllDevices: %w", err)
	}
	return devices, nil
}

// ListAudit returns a cursor-paginated page of audit-log entries.
func (s *AdminService) ListAudit(ctx context.Context, f store.AuditFilter, cursor string, limit int) (store.AuditPage, error) {
	page, err := s.st.AuditLog().ListPaginated(ctx, f, cursor, limit)
	if err != nil {
		return store.AuditPage{}, fmt.Errorf("service.ListAudit: %w", err)
	}
	return page, nil
}
