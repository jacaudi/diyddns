package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"

	// Aliased: LoginOrLink has a parameter named `email`, and revive's
	// import-shadowing rule fails on an unaliased import of the same name.
	emailpkg "github.com/jacaudi/diyddns/internal/email"
	"github.com/jacaudi/diyddns/internal/store"
)

// ErrOIDCRejected is the single generic rejection returned for every OIDC
// login/link/signup policy failure, so callers surface one uniform outcome and
// never leak which check failed or whether an account exists.
var ErrOIDCRejected = errors.New("service: oidc login rejected")

// OIDCService owns the OIDC link/signup policy: it resolves an authenticated
// OIDC identity to a local user (matching by subject, then verified email, then
// signup) and, for the browser flow, mints a session.
type OIDCService struct {
	st       *store.Store
	sessions *auth.SessionManager
	cfg      config.OIDCCfg
	audit    AuditSink
	log      *slog.Logger
}

// NewOIDCService constructs an OIDCService.
func NewOIDCService(st *store.Store, sessions *auth.SessionManager, cfg config.OIDCCfg, audit AuditSink, log *slog.Logger) *OIDCService {
	return &OIDCService{st: st, sessions: sessions, cfg: cfg, audit: audit, log: log}
}

// reject logs the specific policy-rejection reason server-side (so operators can
// see WHY a login failed, design §9) and returns the single generic sentinel.
func (s *OIDCService) reject(ctx context.Context, reason string) error {
	s.log.LogAttrs(ctx, slog.LevelInfo, "oidc login rejected", slog.String("reason", reason))
	return ErrOIDCRejected
}

// LoginOrLink resolves an authenticated OIDC identity to a local user. Order:
//  1. (issuer, subject) match → that user (rejected if disabled)
//  2. verified email + auto-link + existing non-admin, not-already-linked
//     local user → link + that user
//  3. signup allowed → create role=user
//  4. otherwise → ErrOIDCRejected
//
// Admins are never auto-created or auto-linked. Every reject is ErrOIDCRejected.
func (s *OIDCService) LoginOrLink(ctx context.Context, issuer, subject, email string, emailVerified bool) (store.User, error) {
	// 1. Existing linked identity.
	u, err := s.st.Users().GetByOIDC(ctx, issuer, subject)
	if err == nil {
		if u.Disabled {
			return store.User{}, s.reject(ctx, "linked user disabled")
		}
		return u, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, fmt.Errorf("service.LoginOrLink: %w", err)
	}

	// 2. Verified-email auto-link.
	email, err = s.normalizeClaim(ctx, email)
	if err != nil {
		return store.User{}, err
	}
	if emailVerified && s.cfg.AutoLinkByEmail {
		existing, err := s.st.Users().GetByEmail(ctx, email)
		switch {
		case err == nil:
			if existing.Role == "admin" || existing.OIDCSubject != "" {
				return store.User{}, s.reject(ctx, "email matches admin or already-linked account") // never auto-link admins or already-linked accounts
			}
			existing.OIDCProvider = issuer
			existing.OIDCSubject = subject
			if err := s.st.Users().Update(ctx, existing); err != nil {
				return store.User{}, fmt.Errorf("service.LoginOrLink: link: %w", err)
			}
			s.audit.Log(ctx, store.AuditEntry{ActorUserID: existing.ID, EventType: "user.oidc.linked", TargetType: "user", TargetID: existing.ID})
			return existing, nil
		case errors.Is(err, store.ErrNotFound):
			// fall through to signup
		default:
			return store.User{}, fmt.Errorf("service.LoginOrLink: %w", err)
		}
	}

	// 3. Signup.
	if !s.cfg.AllowOIDCSignup {
		return store.User{}, s.reject(ctx, "signup disabled")
	}
	created, err := s.st.Users().Create(ctx, store.User{
		Email: email, Role: "user", OIDCProvider: issuer, OIDCSubject: subject,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			// Email already exists but wasn't linkable above (unverified, auto-link off,
			// or already linked). Reject uniformly — never leak existence, never 500.
			return store.User{}, s.reject(ctx, "email exists but not linkable (unverified / auto-link off / already linked)")
		}
		return store.User{}, fmt.Errorf("service.LoginOrLink: create: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: created.ID, EventType: "user.created", TargetType: "user", TargetID: created.ID})
	return created, nil
}

// BrowserLogin resolves the identity via LoginOrLink and mints a browser
// session, auditing user.login.oidc.
func (s *OIDCService) BrowserLogin(ctx context.Context, issuer, subject, email string, emailVerified bool, ip, ua string) (store.Session, error) {
	u, err := s.LoginOrLink(ctx, issuer, subject, email, emailVerified)
	if err != nil {
		return store.Session{}, err
	}
	sess, err := s.sessions.Create(ctx, u.ID, ip, ua)
	if err != nil {
		return store.Session{}, fmt.Errorf("service.BrowserLogin: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: u.ID, EventType: "user.login.oidc", IP: ip})
	return sess, nil
}

// normalizeClaim answers one question — is this email claim usable at all? — and
// returns the canonical address if so. Both failures take the uniform
// ErrOIDCRejected via s.reject, which logs the specific reason at oidc.go:38 like
// every other rejection on this path.
//
// It is called from ONE place, deliberately: below path 1 and above BOTH the
// GetByEmail lookup and the Create.
//
// Not at the top of LoginOrLink: path 1 returns at line 57 without ever reading
// `email`, so a guard there would lock out an existing, ALREADY LINKED user whose
// IdP emits a non-ASCII claim — on a path that stores nothing.
//
// Not at the Create alone either: if signup stored addr.Address while the lookup
// still used the raw claim, a display-name-form claim would miss its own row,
// fall through to signup, hit store.ErrConflict and be rejected — a lockout
// manufactured by the very change meant to prevent one. Paths 2 and 3 must agree,
// so they share one normalized value.
//
// Extracted rather than inlined because LoginOrLink is at gocyclo 15, the
// configured ceiling; this keeps the branch count identical.
func (s *OIDCService) normalizeClaim(ctx context.Context, email string) (string, error) {
	if email == "" {
		return "", s.reject(ctx, "no email claim") // cannot link or sign up without an email
	}
	normalized, err := emailpkg.NormalizeAddress(email)
	if err != nil {
		return "", s.reject(ctx, "email claim is not a valid 7-bit ASCII address")
	}
	return normalized, nil
}
