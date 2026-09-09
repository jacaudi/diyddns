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
//  2. a local row already holds the claim's address → link it if the claim is
//     verified, auto-link is on and the row is a non-admin, not-already-linked
//     user; otherwise ErrOIDCRejected
//  3. no such row and signup allowed → create role=user
//  4. otherwise → ErrOIDCRejected
//
// Admins are never auto-created or auto-linked. Every reject is ErrOIDCRejected.
//
// The step-2 lookup is deliberately UNCONDITIONAL — it runs even when the claim
// is unverified or auto-link is off. Asking "does a row already hold this
// address?" exactly once is what keeps a login that cannot be linked from
// falling through to signup and quietly creating a second account (#93).
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

	// 2. A local row already holds this address.
	email, err = s.normalizeClaim(ctx, email)
	if err != nil {
		return store.User{}, err
	}
	existing, err := s.findByEmail(ctx, email)
	switch {
	case err == nil:
		return s.linkExisting(ctx, existing, issuer, subject, email, emailVerified)
	case errors.Is(err, store.ErrNotFound):
		// fall through to signup
	default:
		return store.User{}, fmt.Errorf("service.LoginOrLink: %w", err)
	}

	// 3. Signup.
	return s.signup(ctx, issuer, subject, email)
}

// linkExisting decides what happens when a local row already holds the claim's
// address: link it, or reject uniformly. It never falls through to signup —
// that is the whole point of resolving this question before Create runs.
//
// The link also REWRITES the row's stored address to the canonical form. On a
// row created before the boundary validations existed that is a repair, not a
// no-op: a display-name-form address is rejected by email.checkSendable, so
// such a user receives no invite and no recovery mail until it is rewritten.
// It costs nothing — the same Update already runs to store the OIDC identity.
func (s *OIDCService) linkExisting(ctx context.Context, existing store.User, issuer, subject, canonical string, emailVerified bool) (store.User, error) {
	if !emailVerified || !s.cfg.AutoLinkByEmail {
		return store.User{}, s.reject(ctx, "email exists but the claim is unverified or auto-link is off")
	}
	if existing.Role == "admin" || existing.OIDCSubject != "" {
		return store.User{}, s.reject(ctx, "email matches admin or already-linked account") // never auto-link admins or already-linked accounts
	}
	existing.Email = canonical
	existing.OIDCProvider = issuer
	existing.OIDCSubject = subject
	if err := s.st.Users().Update(ctx, existing); err != nil {
		return store.User{}, fmt.Errorf("service.linkExisting: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: existing.ID, EventType: "user.oidc.linked", TargetType: "user", TargetID: existing.ID})
	return existing, nil
}

// signup creates a role=user account for an address no local row holds.
//
// The ErrConflict branch is a RACE guard only: LoginOrLink has already
// established that no row holds this address, so a conflict here means a
// concurrent signup won. It is rejected uniformly rather than surfaced as a
// 500, and never leaks that the address now exists.
func (s *OIDCService) signup(ctx context.Context, issuer, subject, email string) (store.User, error) {
	if !s.cfg.AllowOIDCSignup {
		return store.User{}, s.reject(ctx, "signup disabled")
	}
	created, err := s.st.Users().Create(ctx, store.User{
		Email: email, Role: "user", OIDCProvider: issuer, OIDCSubject: subject,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.User{}, s.reject(ctx, "email taken by a concurrent signup")
		}
		return store.User{}, fmt.Errorf("service.signup: create: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: created.ID, EventType: "user.created", TargetType: "user", TargetID: created.ID})
	return created, nil
}

// findByEmail resolves a canonical address to the row that holds it, returning
// a store.ErrNotFound-wrapping error when none does.
//
// The indexed equality lookup answers it for every row written since the
// boundary validations existed, because every write site normalizes
// (service/admin.go, service/bootstrap.go and normalizeClaim below). The scan
// exists only for rows written BEFORE they did, which can hold a display-name
// or whitespace-padded form that no equality lookup can match (#93). Comparing
// canonical forms — rather than trying the raw claim as a second key — is what
// also catches the case the issue does not name: a legacy row meeting an
// ordinary canonical claim.
//
// The scan is O(users) and deliberately the FALLBACK, not the primary: it runs
// only when the indexed lookup misses, so an already-linked user never reaches
// it (LoginOrLink returns at path 1) and a returning linked user never pays for
// it. Indexing it away would mean storing a second canonical column, i.e. a
// migration over existing rows; that was considered and cut. A row that cannot
// be canonicalized at all — a non-ASCII address — never matches, so #87's
// declared lockout for those rows is untouched.
//
// Ordering is List's (email ASC), so if two legacy rows canonicalize to the
// same address — possible only because they were distinct strings under the
// UNIQUE index — the row that wins is deterministic rather than arbitrary.
func (s *OIDCService) findByEmail(ctx context.Context, canonical string) (store.User, error) {
	u, err := s.st.Users().GetByEmail(ctx, canonical)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, fmt.Errorf("service.findByEmail: %w", err)
	}
	users, err := s.st.Users().List(ctx)
	if err != nil {
		return store.User{}, fmt.Errorf("service.findByEmail: %w", err)
	}
	for _, legacy := range users {
		if stored, err := emailpkg.NormalizeAddress(legacy.Email); err == nil && stored == canonical {
			return legacy, nil
		}
	}
	return store.User{}, fmt.Errorf("service.findByEmail: %w", store.ErrNotFound)
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
// ErrOIDCRejected via s.reject, which logs the specific reason at oidc.go:42 like
// every other rejection on this path.
//
// It is called from ONE place, deliberately: below path 1 and above BOTH the
// findByEmail lookup and the Create.
//
// Not at the top of LoginOrLink: path 1 returns without ever reading `email`,
// so a guard there would lock out an existing, ALREADY LINKED user whose IdP
// emits a non-ASCII claim — on a path that stores nothing.
//
// Not at the Create alone either: if signup stored addr.Address while the lookup
// still used the raw claim, a display-name-form claim would miss its own row,
// fall through to signup, hit store.ErrConflict and be rejected — a lockout
// manufactured by the very change meant to prevent one. Paths 2 and 3 must agree,
// so they share one normalized value.
//
// Both of those cover the CLAIM side. The mirror direction is the STORED side,
// and this function is deliberately not where it is handled: a row written
// before these validations existed can hold "Bob <bob@example.test>" while the
// claim canonicalizes to bob@example.test, so an equality lookup misses the
// user's own row and signup quietly creates a second, empty account (#93).
// Rejecting the claim would be the wrong lever — the claim is perfectly valid,
// and what is stale is the row. findByEmail answers the stored side by
// comparing canonical forms; keep the two questions apart.
//
// Extracted rather than inlined because LoginOrLink was at gocyclo 15, the
// configured ceiling, when this was written.
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
