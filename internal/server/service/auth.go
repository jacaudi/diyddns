package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// errInvalidCreds is the single uniform error returned for every Login and
// ChangePassword credential-verification failure mode (unknown email, wrong
// password, disabled account, OIDC-only account with no local password) so
// callers cannot distinguish "no such user" from "wrong password". It is
// returned unwrapped, deliberately: wrapping with %w would let a caller
// unwrap through to store.ErrNotFound and leak account existence.
var errInvalidCreds = errors.New("service: invalid credentials")

// AuthService handles browser-session login, logout, and self-service
// password changes for local (email/password) accounts.
type AuthService struct {
	st           *store.Store
	sessions     *auth.SessionManager
	argon2Params auth.Argon2Params
	minLength    int
	decoy        string // fixed valid argon2id hash verified on every unknown-email/no-password-hash login to equalize timing
	audit        AuditSink
}

// NewAuthService constructs an AuthService. pw supplies the argon2id cost
// parameters and minimum password length. A decoy password hash is computed
// once here — not per-request — so Login's timing-equalization path costs
// the same as a real verification without re-hashing on every call.
func NewAuthService(st *store.Store, sessions *auth.SessionManager, pw config.PasswordCfg, audit AuditSink) (*AuthService, error) {
	params := auth.Argon2Params{Time: pw.Argon2Time, MemoryKiB: pw.Argon2MemoryKiB, Parallelism: pw.Argon2Parallelism}
	decoy, err := auth.HashPassword("x", params)
	if err != nil {
		return nil, fmt.Errorf("service.NewAuthService: %w", err)
	}
	return &AuthService{
		st:           st,
		sessions:     sessions,
		argon2Params: params,
		minLength:    pw.MinLength,
		decoy:        decoy,
		audit:        audit,
	}, nil
}

// Login authenticates email/password and mints a browser session on success.
// Every failure mode — unknown email, wrong password, disabled account, or an
// OIDC-only account with no local password — returns the identical
// errInvalidCreds and performs a decoy argon2id verification, so neither the
// error nor the response timing reveals whether the account exists.
func (s *AuthService) Login(ctx context.Context, email, pw, ip, ua string) (store.Session, error) {
	u, err := s.st.Users().GetByEmail(ctx, email)
	if err != nil {
		_, _ = auth.VerifyPassword(s.decoy, pw) // constant-work path; ignore result
		s.audit.Log(ctx, store.AuditEntry{EventType: "user.login.failed", IP: ip})
		return store.Session{}, errInvalidCreds
	}
	// Run the decoy path too when the user has no local password (OIDC-only,
	// empty hash) so timing does not distinguish those accounts once OIDC
	// lands (Plan 05).
	if u.PasswordHash == "" {
		_, _ = auth.VerifyPassword(s.decoy, pw)
		s.audit.Log(ctx, store.AuditEntry{EventType: "user.login.failed", IP: ip})
		return store.Session{}, errInvalidCreds
	}
	ok, _ := auth.VerifyPassword(u.PasswordHash, pw)
	if !ok || u.Disabled {
		// NOTE: omit ActorUserID so unknown-vs-known failures are indistinguishable in the log.
		s.audit.Log(ctx, store.AuditEntry{EventType: "user.login.failed", IP: ip})
		return store.Session{}, errInvalidCreds
	}
	sess, err := s.sessions.Create(ctx, u.ID, ip, ua)
	if err != nil {
		return store.Session{}, fmt.Errorf("service.Login: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: u.ID, EventType: "user.login.local", IP: ip})
	return sess, nil
}

// Logout destroys the browser session identified by sessionID. A missing
// session is not an error (see auth.SessionManager.Destroy).
func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	if err := s.sessions.Destroy(ctx, sessionID); err != nil {
		return fmt.Errorf("service.Logout: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{EventType: "user.logout"})
	return nil
}

// ChangePassword verifies oldPw against userID's current password, enforces
// the configured minimum length on newPw, and rehashes and stores the new
// password. Other user fields are preserved unchanged.
func (s *AuthService) ChangePassword(ctx context.Context, userID, oldPw, newPw string) error {
	u, err := s.st.Users().GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("service.ChangePassword: %w", err)
	}
	ok, err := auth.VerifyPassword(u.PasswordHash, oldPw)
	if err != nil || !ok {
		return errInvalidCreds
	}
	if len(newPw) < s.minLength {
		return fmt.Errorf("service.ChangePassword: new password must be at least %d characters, got %d", s.minLength, len(newPw))
	}
	hash, err := auth.HashPassword(newPw, s.argon2Params)
	if err != nil {
		return fmt.Errorf("service.ChangePassword: %w", err)
	}
	u.PasswordHash = hash
	if err := s.st.Users().Update(ctx, u); err != nil {
		return fmt.Errorf("service.ChangePassword: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: userID, EventType: "user.password_change"})
	return nil
}
