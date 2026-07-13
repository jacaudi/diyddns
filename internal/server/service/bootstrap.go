package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"slices"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// ErrBootstrapClosed is returned when bootstrap can no longer be claimed —
// an admin already exists, or the atomic Bootstrap.Consume lost the race.
// Maps to HTTP 410 Gone.
var ErrBootstrapClosed = errors.New("service: bootstrap closed")

// ErrBootstrapToken is returned when the supplied bootstrap token is
// missing, unset, or does not match the stored hash. Maps to HTTP 401.
var ErrBootstrapToken = errors.New("service: invalid bootstrap token")

// bootstrapTokenBytes is the byte length of the random bootstrap token
// minted by Startup's token path (before base64 encoding).
const bootstrapTokenBytes = 32

// BootstrapService creates the first admin account for a fresh DIYDDNS
// install. Startup runs once at process start: it creates an admin from
// env-supplied credentials if present, otherwise mints a single-use token.
// Consume redeems that token via an atomic single-use gate (design §5.3,
// applying the nomad-operator ACL bootstrap idempotency lesson: the durable
// success marker is "an admin user exists," never a marker written before
// the side effect succeeds).
type BootstrapService struct {
	st           *store.Store
	cfg          config.BootstrapCfg
	argon2Params auth.Argon2Params
	pwMinLen     int
	log          *slog.Logger
	audit        AuditSink
	emitToken    func(token string)
}

// NewBootstrapService constructs a BootstrapService. pw supplies the
// argon2id cost parameters (shared with AuthService) and minimum password
// length policy. emitToken delivers the freshly-minted bootstrap token to
// its operator-facing destination; pass nil to default to logging
// `BOOTSTRAP_TOKEN=<token> visit /bootstrap to claim admin (single use)` at
// info level. Tests inject a capturing sink instead.
func NewBootstrapService(st *store.Store, cfg config.BootstrapCfg, pw config.PasswordCfg, log *slog.Logger, audit AuditSink, emitToken func(token string)) *BootstrapService {
	s := &BootstrapService{
		st:           st,
		cfg:          cfg,
		argon2Params: auth.Argon2Params{Time: pw.Argon2Time, MemoryKiB: pw.Argon2MemoryKiB, Parallelism: pw.Argon2Parallelism},
		pwMinLen:     pw.MinLength,
		log:          log,
		audit:        audit,
	}
	if emitToken != nil {
		s.emitToken = emitToken
	} else {
		s.emitToken = s.logToken
	}
	return s
}

// logToken is the default emitToken sink: it prints the bootstrap token at
// info level. This is the delivery channel for the token — logging it here
// is intentional (never log the token *hash*, or any password).
func (s *BootstrapService) logToken(token string) {
	s.log.Info(fmt.Sprintf("BOOTSTRAP_TOKEN=%s visit /bootstrap to claim admin (single use)", token))
}

// AdminExists reports whether any user with role "admin" exists.
func (s *BootstrapService) AdminExists(ctx context.Context) (bool, error) {
	users, err := s.st.Users().List(ctx)
	if err != nil {
		return false, fmt.Errorf("service.AdminExists: %w", err)
	}
	return slices.ContainsFunc(users, func(u store.User) bool { return u.Role == "admin" }), nil
}

// Startup runs once at process start, before the server begins listening.
// If any user already exists, it is a no-op (repeated calls across restarts
// must not re-bootstrap). Otherwise it creates the admin from env-supplied
// credentials if both are set (headless path), or mints a single-use
// bootstrap token and delivers it via emitToken (interactive path). If an
// unconsumed token already exists from a prior run, it is left as-is — the
// plaintext cannot be reprinted, so Startup only logs a pending reminder.
func (s *BootstrapService) Startup(ctx context.Context) error {
	users, err := s.st.Users().List(ctx)
	if err != nil {
		return fmt.Errorf("service.Startup: %w", err)
	}
	if len(users) > 0 {
		return nil
	}

	if s.cfg.AdminEmail != "" && s.cfg.AdminPassword != "" {
		if _, err := s.createAdmin(ctx, s.cfg.AdminEmail, s.cfg.AdminPassword, "env"); err != nil {
			return fmt.Errorf("service.Startup: %w", err)
		}
		s.log.Info("admin created via env")
		return nil
	}

	bs, err := s.st.Bootstrap().Get(ctx)
	if err == nil && bs.TokenHash != "" && bs.ConsumedAt == 0 {
		s.log.Info("bootstrap pending; visit /bootstrap to claim admin")
		return nil
	}

	token, err := auth.RandToken(bootstrapTokenBytes)
	if err != nil {
		return fmt.Errorf("service.Startup: %w", err)
	}
	hash, err := auth.HashPassword(token, s.argon2Params)
	if err != nil {
		return fmt.Errorf("service.Startup: %w", err)
	}
	if err := s.st.Bootstrap().SetTokenHash(ctx, hash); err != nil {
		return fmt.Errorf("service.Startup: %w", err)
	}
	s.emitToken(token)
	return nil
}

// Consume redeems a bootstrap token to create the first admin account. The
// atomic ordering below closes the concurrent-double-admin race: checking
// "no admin exists" and then creating one is not atomic on its own, so two
// simultaneous requests with the same token and different emails could both
// pass an existence check and both succeed (distinct emails don't collide on
// the users table's UNIQUE(email)). Bootstrap.Consume's single-row,
// consumed_at-guarded UPDATE is the actual atomic gate — it admits exactly
// one caller; AdminExists is a fast pre-filter for the already-closed case.
func (s *BootstrapService) Consume(ctx context.Context, token, email, pw string) (store.User, error) {
	if _, err := mail.ParseAddress(email); err != nil {
		return store.User{}, fmt.Errorf("service.Consume: invalid email: %w", err)
	}
	if len(pw) < s.pwMinLen {
		return store.User{}, fmt.Errorf("service.Consume: password must be at least %d characters, got %d", s.pwMinLen, len(pw))
	}

	if ok, _ := s.AdminExists(ctx); ok {
		return store.User{}, ErrBootstrapClosed
	}

	bs, err := s.st.Bootstrap().Get(ctx)
	if err != nil || bs.TokenHash == "" {
		return store.User{}, ErrBootstrapToken
	}
	ok, err := auth.VerifyPassword(bs.TokenHash, token)
	if err != nil || !ok {
		return store.User{}, ErrBootstrapToken
	}

	if err := s.st.Bootstrap().Consume(ctx); err != nil {
		// ErrNotFound => already consumed, or this call lost the atomic race.
		return store.User{}, ErrBootstrapClosed
	}

	u, err := s.createAdmin(ctx, email, pw, "token")
	if err != nil {
		s.log.Error("BOOTSTRAP CRITICAL: token consumed but admin creation failed; recover by deleting the bootstrap row or using the env path", "err", err)
		return store.User{}, fmt.Errorf("service.Consume: %w", err)
	}
	return u, nil
}

// createAdmin hashes pw, creates the admin user, and appends the
// user.created audit entry (plus bootstrap.consumed when path == "token").
func (s *BootstrapService) createAdmin(ctx context.Context, email, pw, path string) (store.User, error) {
	hash, err := auth.HashPassword(pw, s.argon2Params)
	if err != nil {
		return store.User{}, fmt.Errorf("service.createAdmin: %w", err)
	}
	u, err := s.st.Users().Create(ctx, store.User{Email: email, PasswordHash: hash, Role: "admin"})
	if err != nil {
		return store.User{}, fmt.Errorf("service.createAdmin: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: u.ID, EventType: "user.created", TargetType: "user", TargetID: u.ID})
	if path == "token" {
		s.audit.Log(ctx, store.AuditEntry{ActorUserID: u.ID, EventType: "bootstrap.consumed", TargetType: "user", TargetID: u.ID})
	}
	return u, nil
}
