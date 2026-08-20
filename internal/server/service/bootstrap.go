package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/jacaudi/diyddns/internal/auth"
	// Aliased: this file has a parameter named `email`, and revive's
	// import-shadowing rule (enabled repo-wide, and NOT excluded for any file)
	// fails on an unaliased import of the same name.
	emailpkg "github.com/jacaudi/diyddns/internal/email"
	"github.com/jacaudi/diyddns/internal/store"
)

// ErrBootstrapClosed is returned when bootstrap can no longer be claimed —
// an admin already exists, or the atomic Bootstrap.Consume lost the race.
// Maps to HTTP 410 Gone.
var ErrBootstrapClosed = errors.New("service: bootstrap closed")

// ErrBootstrapToken is returned when the supplied bootstrap token is
// missing, unset, or does not match the stored hash. Maps to HTTP 401.
var ErrBootstrapToken = errors.New("service: invalid bootstrap token")

// ErrBootstrapInvalidEmail is returned by BeginClaim when the supplied admin
// email fails RFC parsing. Maps to HTTP 422 (a client-fixable input error,
// not a token/closed condition) — kept a distinct exported sentinel so the
// API layer can report it as 422 rather than collapsing it into a logged
// 500, mirroring AdminService.ErrInvalidEmail.
var ErrBootstrapInvalidEmail = errors.New("service: invalid bootstrap email")

// bootstrapTokenBytes is the byte length of the random bootstrap token
// minted by Startup's token path (before base64 encoding).
const bootstrapTokenBytes = 32

// BootstrapService creates the first admin account for a fresh DIYDDNS
// install. Startup runs once at process start and mints a single-use token;
// the passkey-based claim flow (BeginClaim / FinishClaim, design D9) redeems
// that token via an atomic single-use gate (applying the nomad-operator ACL
// bootstrap idempotency lesson: the durable success marker is "an admin user
// exists," never a marker written before the side effect succeeds).
type BootstrapService struct {
	st        *store.Store
	log       *slog.Logger
	audit     AuditSink
	emitToken func(token string)
	passkeys  *PasskeyService
	sealKey   []byte
}

// NewBootstrapService constructs a BootstrapService. emitToken delivers the
// freshly-minted bootstrap token to its operator-facing destination; pass nil
// to default to logToken, which prints the token and the endpoint that
// redeems it at info level. Tests inject a capturing sink instead.
//
// passkeys and sealKey drive the passkey-based claim path (BeginClaim /
// FinishClaim, design D9) — passkeys reuses PasskeyService's WebAuthn
// ceremony machinery rather than duplicating its Relying Party config, and
// sealKey (32 bytes, see auth.SealWithAAD) seals the claim's combined
// session+email cookie, shaped differently from PasskeyService's own
// SessionData-only cookie, so it cannot reuse PasskeyService's key
// indirectly. Both may be nil if WebAuthn is not configured; BeginClaim and
// FinishClaim then return ErrWebAuthnUnavailable rather than panicking.
func NewBootstrapService(st *store.Store, log *slog.Logger, audit AuditSink, emitToken func(token string), passkeys *PasskeyService, sealKey []byte) *BootstrapService {
	s := &BootstrapService{
		st:       st,
		log:      log,
		audit:    audit,
		passkeys: passkeys,
		sealKey:  sealKey,
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
	s.log.Info(fmt.Sprintf("BOOTSTRAP_TOKEN=%s claim the first admin at /register, which drives POST /api/v1/register/begin (single use)", token))
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
// must not re-bootstrap). Otherwise it mints a single-use bootstrap token and
// delivers it via emitToken; the operator redeems it through the passkey
// claim flow (BeginClaim / FinishClaim). If an unconsumed token already
// exists from a prior run, it is left as-is — the plaintext cannot be
// reprinted, so Startup only logs a pending reminder.
func (s *BootstrapService) Startup(ctx context.Context) error {
	hasAdmin, err := s.AdminExists(ctx)
	if err != nil {
		return fmt.Errorf("service.Startup: %w", err)
	}
	if hasAdmin {
		return nil
	}

	bs, err := s.st.Bootstrap().Get(ctx)
	if err == nil && bs.TokenHash != "" && bs.ConsumedAt == 0 {
		s.log.Info("bootstrap pending; claim the first admin at /register, which drives POST /api/v1/register/begin, using the token from a previous start")
		return nil
	}

	token, err := auth.RandToken(bootstrapTokenBytes)
	if err != nil {
		return fmt.Errorf("service.Startup: %w", err)
	}
	if err := s.st.Bootstrap().SetTokenHash(ctx, auth.HashToken(token)); err != nil {
		return fmt.Errorf("service.Startup: %w", err)
	}
	s.emitToken(token)
	return nil
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
func (s *BootstrapService) openClaim(ctx context.Context, sealed string) (claimSession, error) {
	raw, err := auth.OpenWithAAD(s.sealKey, sealed, bootstrapClaimAAD)
	if err != nil {
		// See verifyRegistration: the cause is logged, never returned.
		// auth.OpenWithAAD reports the bare "ciphertext too short" for BOTH an
		// absent cookie and a truncated one -- the message alone does not
		// distinguish them. sealed_len does: 0 means the client sent no
		// cookie at all, >0 but still too-short means a truncated one. This
		// is the line that would have named #78's real failure immediately.
		s.log.LogAttrs(ctx, slog.LevelInfo, "bootstrap claim cookie could not be opened",
			slog.String("error", err.Error()), slog.Int("sealed_len", len(sealed)))
		return claimSession{}, ErrPasskeyVerification
	}
	var cs claimSession
	if err := json.Unmarshal(raw, &cs); err != nil {
		s.log.LogAttrs(ctx, slog.LevelInfo, "bootstrap claim cookie could not be decoded",
			slog.String("error", err.Error()))
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
	// Normalize as well as validate — see AdminService.CreateUserInvite. The
	// normalized value also flows into beginRegistrationFor below, so the
	// WebAuthn user/display name an authenticator shows becomes "bob@x" rather
	// than "Bob <bob@x>". That is an improvement, and it is a behaviour change.
	normalized, err := emailpkg.NormalizeAddress(email)
	if err != nil {
		return "", nil, fmt.Errorf("service.BeginClaim: %w", ErrBootstrapInvalidEmail)
	}
	email = normalized

	bs, err := s.st.Bootstrap().Get(ctx)
	if err != nil || bs.TokenHash == "" {
		return "", nil, ErrBootstrapToken
	}
	if !auth.VerifyToken(bs.TokenHash, token) {
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
// atomic single-row gate) -> create the credential-less admin (a local
// password never exists — the passkey persisted below is the only
// credential) -> persist the credential. Verifying before consuming means an
// abandoned ceremony never spends the token; the
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

	cs, err := s.openClaim(ctx, sealedCookie)
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
