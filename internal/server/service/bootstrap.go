package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"slices"

	"github.com/go-webauthn/webauthn/webauthn"

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
	passkeys     *PasskeyService
	sealKey      []byte
}

// NewBootstrapService constructs a BootstrapService. pw supplies the
// argon2id cost parameters (shared with AuthService) and minimum password
// length policy, used by the existing env/token+password Consume path.
// emitToken delivers the freshly-minted bootstrap token to its
// operator-facing destination; pass nil to default to logToken, which prints
// the token and the endpoint that redeems it at info level. Tests inject a
// capturing sink instead.
//
// passkeys and sealKey drive the passkey-based claim path (BeginClaim /
// FinishClaim, design D9) — passkeys reuses PasskeyService's WebAuthn
// ceremony machinery rather than duplicating its Relying Party config, and
// sealKey (32 bytes, see auth.SealWithAAD) seals the claim's combined
// session+email cookie, shaped differently from PasskeyService's own
// SessionData-only cookie, so it cannot reuse PasskeyService's key
// indirectly. Both may be nil if WebAuthn is not configured; BeginClaim and
// FinishClaim then return ErrWebAuthnUnavailable rather than panicking.
func NewBootstrapService(st *store.Store, cfg config.BootstrapCfg, pw config.PasswordCfg, log *slog.Logger, audit AuditSink, emitToken func(token string), passkeys *PasskeyService, sealKey []byte) *BootstrapService {
	s := &BootstrapService{
		st:           st,
		cfg:          cfg,
		argon2Params: auth.Argon2Params{Time: pw.Argon2Time, MemoryKiB: pw.Argon2MemoryKiB, Parallelism: pw.Argon2Parallelism},
		pwMinLen:     pw.MinLength,
		log:          log,
		audit:        audit,
		passkeys:     passkeys,
		sealKey:      sealKey,
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
	s.log.Info(fmt.Sprintf("BOOTSTRAP_TOKEN=%s claim admin via POST /api/v1/auth/bootstrap with body token, email, password (single use)", token))
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
// If an admin already exists, it is a no-op (repeated calls across restarts
// must not re-bootstrap). Otherwise it creates the admin from env-supplied
// credentials if both are set (headless path), or mints a single-use
// bootstrap token and delivers it via emitToken (interactive path). If an
// unconsumed token already exists from a prior run, it is left as-is — the
// plaintext cannot be reprinted, so Startup only logs a pending reminder.
func (s *BootstrapService) Startup(ctx context.Context) error {
	hasAdmin, err := s.AdminExists(ctx)
	if err != nil {
		return fmt.Errorf("service.Startup: %w", err)
	}
	if hasAdmin {
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
		s.log.Info("bootstrap pending; claim admin via POST /api/v1/auth/bootstrap using the token from a previous start")
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

// bootstrapHandleBytes is the byte length of the WebAuthn handle minted for
// a claim ceremony's not-yet-existing admin identity.
const bootstrapHandleBytes = 32

// bootstrapClaimAAD domain-separates the sealed bootstrap-claim cookie
// (WebAuthn session data + target email) from other sealed cookies sharing
// the master key (the passkey ceremony challenge cookie, OIDC flow state).
var bootstrapClaimAAD = []byte("diyddns/bootstrap-claim-v1")

// claimSession is the sealed payload round-tripped between BeginClaim and
// FinishClaim: the in-flight WebAuthn ceremony state plus the target email
// validated at BeginClaim time (there is no user row yet to read it back
// from — that is the entire point of D9's deferred-consume ordering).
type claimSession struct {
	Email   string
	Session webauthn.SessionData
}

// sealClaim seals cs under sealKey, domain-separated by bootstrapClaimAAD.
func (s *BootstrapService) sealClaim(cs claimSession) (string, error) {
	raw, err := json.Marshal(cs)
	if err != nil {
		return "", fmt.Errorf("service.sealClaim: %w", err)
	}
	sealed, err := auth.SealWithAAD(s.sealKey, raw, bootstrapClaimAAD)
	if err != nil {
		return "", fmt.Errorf("service.sealClaim: %w", err)
	}
	return sealed, nil
}

// openClaim reverses sealClaim. Every failure — bad key, malformed payload,
// failed AEAD authentication — collapses to ErrPasskeyVerification, matching
// PasskeyService.openSession's uniform-failure contract.
func (s *BootstrapService) openClaim(sealed string) (claimSession, error) {
	raw, err := auth.OpenWithAAD(s.sealKey, sealed, bootstrapClaimAAD)
	if err != nil {
		return claimSession{}, ErrPasskeyVerification
	}
	var cs claimSession
	if err := json.Unmarshal(raw, &cs); err != nil {
		return claimSession{}, ErrPasskeyVerification
	}
	return cs, nil
}

// BeginClaim validates a bootstrap token + target email (constant-time
// token comparison, same as Consume) WITHOUT consuming the token, then
// starts a registration ceremony for a synthetic, not-yet-persisted admin
// identity (a freshly-minted WebAuthn handle + the validated email). It
// returns the sealed cookie (carrying both the ceremony session and the
// email — see claimSession) and the JSON creation options for the browser.
//
// Design D9/C1: the token is validated but NOT consumed here — consumption
// happens only in FinishClaim, after the passkey itself has verified. An
// abandoned ceremony (BeginClaim called, FinishClaim never called) therefore
// never spends the token.
func (s *BootstrapService) BeginClaim(ctx context.Context, token, email string) (string, []byte, error) {
	if s.passkeys == nil {
		return "", nil, ErrWebAuthnUnavailable
	}
	if ok, _ := s.AdminExists(ctx); ok {
		return "", nil, ErrBootstrapClosed
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return "", nil, fmt.Errorf("service.BeginClaim: invalid email: %w", err)
	}

	bs, err := s.st.Bootstrap().Get(ctx)
	if err != nil || bs.TokenHash == "" {
		return "", nil, ErrBootstrapToken
	}
	ok, err := auth.VerifyPassword(bs.TokenHash, token)
	if err != nil || !ok {
		return "", nil, ErrBootstrapToken
	}

	handle := make([]byte, bootstrapHandleBytes)
	if _, err := rand.Read(handle); err != nil {
		return "", nil, fmt.Errorf("service.BeginClaim: generate webauthn handle: %w", err)
	}
	optsJSON, sess, err := s.passkeys.beginRegistrationFor(email, handle)
	if err != nil {
		return "", nil, fmt.Errorf("service.BeginClaim: %w", err)
	}
	sealed, err := s.sealClaim(claimSession{Email: email, Session: *sess})
	if err != nil {
		return "", nil, fmt.Errorf("service.BeginClaim: %w", err)
	}
	return sealed, optsJSON, nil
}

// FinishClaim completes a passkey-based bootstrap claim. Ordering (design
// D9/C1, verify-before-consume, NO sql.Tx — the store's single-connection
// pool would deadlock a transaction wrapping these repos): re-check
// AdminExists (closes the concurrent-double-admin race, mirroring Consume)
// -> verify the passkey in memory (no DB write) -> Bootstrap.Consume (the
// atomic single-row gate) -> create the credential-less admin (NOT the
// password-hashing createAdmin — M1) -> persist the credential. Verifying
// before consuming means an abandoned ceremony never spends the token; the
// only residual risk is the credential INSERT failing after the admin
// INSERT succeeds (a single local write), which is logged BOOTSTRAP CRITICAL
// — recovery is deleting the admin + bootstrap rows and restarting (Startup
// re-mints).
func (s *BootstrapService) FinishClaim(ctx context.Context, sealedCookie string, r *http.Request, name string) (store.User, error) {
	if s.passkeys == nil {
		return store.User{}, ErrWebAuthnUnavailable
	}
	if ok, _ := s.AdminExists(ctx); ok {
		return store.User{}, ErrBootstrapClosed
	}

	cs, err := s.openClaim(sealedCookie)
	if err != nil {
		return store.User{}, err
	}
	if !s.passkeys.claimChallenge(cs.Session.Challenge, cs.Session.Expires) {
		return store.User{}, ErrPasskeyVerification
	}
	cred, err := s.passkeys.verifyRegistration(cs.Email, cs.Session.UserID, cs.Session, r)
	if err != nil {
		return store.User{}, err
	}

	if err := s.st.Bootstrap().Consume(ctx); err != nil {
		// ErrNotFound => already consumed, or this call lost the atomic race.
		return store.User{}, ErrBootstrapClosed
	}

	u, err := s.st.Users().Create(ctx, store.User{Email: cs.Email, Role: "admin"})
	if err != nil {
		s.log.Error("BOOTSTRAP CRITICAL: token consumed but admin creation failed; recover by deleting the bootstrap row and restarting", "err", err)
		return store.User{}, fmt.Errorf("service.FinishClaim: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: u.ID, EventType: "user.created", TargetType: "user", TargetID: u.ID})
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: u.ID, EventType: "bootstrap.consumed", TargetType: "user", TargetID: u.ID})

	if _, err := s.passkeys.persistCredential(ctx, u.ID, cs.Session.UserID, cred, name); err != nil {
		s.log.Error("BOOTSTRAP CRITICAL: admin created but credential persist failed; recover by deleting the admin + bootstrap rows and restarting", "err", err, "user_id", u.ID)
		return store.User{}, fmt.Errorf("service.FinishClaim: %w", err)
	}
	return u, nil
}
