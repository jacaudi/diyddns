package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// ErrLastCredential is returned by Remove when deleting the given credential
// would leave the user with zero passkeys and no OIDC link — i.e. no
// remaining way to sign in.
var ErrLastCredential = errors.New("service: cannot remove the last credential")

// ErrWebAuthnUnavailable is returned by callers that depend on a
// *PasskeyService instance (bootstrap claim, registration-grant redeem) when
// none was wired in — e.g. server.base_url could not be resolved to a
// WebAuthn Relying Party at startup. It means "not configured", never "wrong
// credential"; it is distinct from ErrPasskeyVerification.
var ErrWebAuthnUnavailable = errors.New("service: webauthn service unavailable")

// ErrPasskeyVerification is the single uniform error returned for every
// WebAuthn ceremony verification failure — a bad/expired/replayed challenge
// cookie, a failed FinishRegistration/FinishDiscoverableLogin, a sign-count
// clone-warning, or a disabled account — so callers cannot distinguish which
// check failed. It is returned unwrapped, deliberately: wrapping an
// underlying store.ErrNotFound (e.g. from an unresolvable webauthn_handle)
// with %w would let a caller unwrap through to it and leak account
// existence, mirroring errInvalidCreds in auth.go.
var ErrPasskeyVerification = errors.New("service: passkey verification failed")

// webauthnAAD domain-separates the sealed WebAuthn challenge cookie from the
// device-secret and OIDC flow-state cookies, which share the same master key.
var webauthnAAD = []byte("diyddns/webauthn-v1")

// webauthnUser adapts a store.User (by email and WebAuthn handle) and its
// decoded WebAuthn credentials to go-webauthn's User interface.
type webauthnUser struct {
	handle []byte
	email  string
	creds  []webauthn.Credential
}

// newWebauthnUser decodes each stored credential's CredentialJSON blob into
// a webauthn.Credential. creds may be nil (FinishRegistration and
// FinishDiscoverableLogin's clone-warning/counter checks only consult
// WebAuthnCredentials() during login and exclusion-list construction, not
// during registration verification).
func newWebauthnUser(email string, handle []byte, creds []store.WebAuthnCredential) (*webauthnUser, error) {
	decoded := make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		var wc webauthn.Credential
		if err := json.Unmarshal(c.CredentialJSON, &wc); err != nil {
			return nil, fmt.Errorf("service: decode stored credential %x: %w", c.CredentialID, err)
		}
		decoded = append(decoded, wc)
	}
	return &webauthnUser{handle: handle, email: email, creds: decoded}, nil
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.handle }
func (u *webauthnUser) WebAuthnName() string                       { return u.email }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.email }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// PasskeyService owns the WebAuthn registration and discoverable-login
// ceremonies: it wraps go-webauthn, carries ceremony challenges in a sealed,
// single-use cookie (D6), and maps verified credentials onto
// store.WebAuthnCredential rows.
type PasskeyService struct {
	st       *store.Store
	sessions *auth.SessionManager
	sealKey  []byte
	wa       *webauthn.WebAuthn
	audit    AuditSink
	// log records WHY a ceremony failed. The error returned to callers stays
	// uniform (ErrPasskeyVerification) so nothing can distinguish which check
	// failed; the cause goes here and nowhere else. Diagnosing #78 required
	// patching the binary precisely because this did not exist.
	log *slog.Logger

	usedMu sync.Mutex
	used   map[string]time.Time // challenge -> expiry, for single-use enforcement
}

// NewPasskeyService constructs a PasskeyService. rpID/rpOrigin are the
// resolved Relying Party identity (config.ResolveWebAuthn derives them from
// server.base_url when auth.webauthn.rp_id/rp_origin are left blank); cfg
// supplies the display name shown to authenticators and the ceremony
// timeout. sealKey must be 32 bytes (see auth.SealWithAAD).
func NewPasskeyService(st *store.Store, sessions *auth.SessionManager, sealKey []byte, cfg config.WebAuthnCfg, rpID, rpOrigin string, audit AuditSink, log *slog.Logger) (*PasskeyService, error) {
	// Enforce: true makes go-webauthn populate SessionData.Expires (used as
	// the used-challenge-map TTL below) and reject a Finish* call past it
	// server-side, in addition to the used-challenge check. A zero
	// cfg.Timeout is filled in by the library with its own sane default.
	// Login and Registration share the identical timeout policy.
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: cfg.Timeout, TimeoutUVD: cfg.Timeout}
	waCfg := &webauthn.Config{
		RPID:                  rpID,
		RPDisplayName:         cfg.RPDisplayName,
		RPOrigins:             []string{rpOrigin},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		},
		Timeouts: webauthn.TimeoutsConfig{Login: timeout, Registration: timeout},
	}
	wa, err := webauthn.New(waCfg)
	if err != nil {
		return nil, fmt.Errorf("service.NewPasskeyService: %w", err)
	}
	return &PasskeyService{
		st: st, sessions: sessions, sealKey: sealKey, wa: wa, audit: audit, log: log,
		used: make(map[string]time.Time),
	}, nil
}

// sealSession serializes a ceremony's SessionData and seals it into the
// cookie value returned to the caller.
func (s *PasskeyService) sealSession(sess *webauthn.SessionData) (string, error) {
	raw, err := json.Marshal(sess)
	if err != nil {
		return "", fmt.Errorf("service: marshal webauthn session: %w", err)
	}
	sealed, err := auth.SealWithAAD(s.sealKey, raw, webauthnAAD)
	if err != nil {
		return "", fmt.Errorf("service: seal webauthn session: %w", err)
	}
	return sealed, nil
}

// openSession reverses sealSession. Every failure — bad key, malformed
// payload, failed AEAD authentication — collapses to ErrPasskeyVerification;
// none of these are distinguishable to a caller without leaking verification
// internals.
func (s *PasskeyService) openSession(sealed string) (webauthn.SessionData, error) {
	raw, err := auth.OpenWithAAD(s.sealKey, sealed, webauthnAAD)
	if err != nil {
		return webauthn.SessionData{}, ErrPasskeyVerification
	}
	var sess webauthn.SessionData
	if err := json.Unmarshal(raw, &sess); err != nil {
		return webauthn.SessionData{}, ErrPasskeyVerification
	}
	return sess, nil
}

// claimChallenge enforces single-use: it reports whether challenge has not
// already been claimed within its (still-live) window, and if so records it
// through expires. Entries whose window has passed are pruned lazily on
// every call rather than by a background job (design D6).
func (s *PasskeyService) claimChallenge(challenge string, expires time.Time) bool {
	s.usedMu.Lock()
	defer s.usedMu.Unlock()

	now := time.Now()
	for k, exp := range s.used {
		if !exp.After(now) {
			delete(s.used, k)
		}
	}

	if exp, ok := s.used[challenge]; ok && exp.After(now) {
		return false
	}
	if expires.IsZero() {
		expires = now.Add(2 * time.Minute) // matches the library's own default ceremony timeout
	}
	s.used[challenge] = expires
	return true
}

// BeginLogin starts a discoverable (usernameless) login ceremony and returns
// the JSON assertion options for the browser plus the sealed challenge
// cookie to round-trip to FinishLogin.
func (s *PasskeyService) BeginLogin(ctx context.Context) ([]byte, string, error) {
	assertion, sess, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("service.BeginLogin: %w", err)
	}
	sealed, err := s.sealSession(sess)
	if err != nil {
		return nil, "", fmt.Errorf("service.BeginLogin: %w", err)
	}
	optsJSON, err := json.Marshal(assertion)
	if err != nil {
		return nil, "", fmt.Errorf("service.BeginLogin: marshal options: %w", err)
	}
	return optsJSON, sealed, nil
}

// FinishLogin completes a discoverable login: it opens and single-use-checks
// the challenge cookie, resolves the signing-in user by their WebAuthn
// handle, verifies the assertion, rejects a sign-count clone warning
// (auditing passkey.signcount_anomaly and minting no session), persists the
// credential's updated counter and last-used timestamp, and mints a browser
// session (audit user.login.passkey). Every rejection path returns the
// uniform ErrPasskeyVerification.
func (s *PasskeyService) FinishLogin(ctx context.Context, sealedCookie string, r *http.Request, ip, ua string) (store.Session, error) {
	sess, err := s.openSession(sealedCookie)
	if err != nil {
		return store.Session{}, err
	}
	if !s.claimChallenge(sess.Challenge, sess.Expires) {
		return store.Session{}, ErrPasskeyVerification
	}

	var resolved store.User
	var haveUser bool
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		u, err := s.st.Users().GetByWebAuthnHandle(ctx, userHandle)
		if err != nil {
			return nil, fmt.Errorf("resolve user by webauthn handle: %w", err)
		}
		creds, err := s.st.WebAuthnCredentials().ListByUser(ctx, u.ID)
		if err != nil {
			return nil, fmt.Errorf("list credentials for %s: %w", u.ID, err)
		}
		wu, err := newWebauthnUser(u.Email, userHandle, creds)
		if err != nil {
			return nil, err
		}
		resolved, haveUser = u, true
		return wu, nil
	}

	cred, err := s.wa.FinishDiscoverableLogin(handler, sess, r)
	if err != nil || !haveUser {
		return store.Session{}, ErrPasskeyVerification
	}

	if resolved.Disabled {
		return store.Session{}, ErrPasskeyVerification
	}

	if cred.Authenticator.CloneWarning {
		s.audit.Log(ctx, store.AuditEntry{
			ActorUserID: resolved.ID, EventType: "passkey.signcount_anomaly",
			TargetType: "webauthn_credential", TargetID: base64.RawURLEncoding.EncodeToString(cred.ID), IP: ip,
		})
		return store.Session{}, ErrPasskeyVerification
	}

	credJSON, err := json.Marshal(cred)
	if err != nil {
		return store.Session{}, fmt.Errorf("service.FinishLogin: marshal credential: %w", err)
	}
	if err := s.st.WebAuthnCredentials().Update(ctx, store.WebAuthnCredential{
		CredentialID: cred.ID, CredentialJSON: credJSON, LastUsedAt: store.NowUnix(),
	}); err != nil {
		return store.Session{}, fmt.Errorf("service.FinishLogin: update credential: %w", err)
	}

	newSess, err := s.sessions.Create(ctx, resolved.ID, ip, ua)
	if err != nil {
		return store.Session{}, fmt.Errorf("service.FinishLogin: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{ActorUserID: resolved.ID, EventType: "user.login.passkey", IP: ip})
	return newSess, nil
}

// BeginRegister starts a registration ceremony for userID and returns the
// JSON creation options for the browser plus the sealed challenge cookie to
// round-trip to FinishRegister. If userID has no WebAuthn handle yet, a
// fresh one is generated for this ceremony (embedded in the options'
// user.id field, and carried forward to FinishRegister via the sealed
// session — not persisted until the ceremony verifies). If userID already
// has a handle, it is reused: a resident credential's handle is fixed by the
// authenticator at registration time, so every credential a user registers
// must share the one handle already on their row, or FinishLogin's
// GetByWebAuthnHandle resolution breaks for their earlier credentials (see
// store.UserRepo.GetWebAuthnHandle).
func (s *PasskeyService) BeginRegister(ctx context.Context, userID string) ([]byte, string, error) {
	u, err := s.st.Users().GetByID(ctx, userID)
	if err != nil {
		return nil, "", fmt.Errorf("service.BeginRegister: %w", err)
	}
	creds, err := s.st.WebAuthnCredentials().ListByUser(ctx, userID)
	if err != nil {
		return nil, "", fmt.Errorf("service.BeginRegister: %w", err)
	}
	handle, err := s.st.Users().GetWebAuthnHandle(ctx, userID)
	if err != nil {
		return nil, "", fmt.Errorf("service.BeginRegister: %w", err)
	}
	if len(handle) == 0 {
		handle = make([]byte, 32)
		if _, err := rand.Read(handle); err != nil {
			return nil, "", fmt.Errorf("service.BeginRegister: generate webauthn handle: %w", err)
		}
	}

	wu, err := newWebauthnUser(u.Email, handle, creds)
	if err != nil {
		return nil, "", fmt.Errorf("service.BeginRegister: %w", err)
	}

	// go-webauthn never consults WebAuthnCredentials() on its own during
	// registration — WithExclusions is the only way to tell the browser
	// about a user's existing passkeys, so it can proactively refuse
	// re-registering the same physical authenticator instead of the ceremony
	// completing and only then failing on the credential_id PRIMARY KEY.
	exclude := make([]protocol.CredentialDescriptor, len(wu.creds))
	for i, c := range wu.creds {
		exclude[i] = c.Descriptor()
	}

	creation, sess, err := s.wa.BeginRegistration(wu, webauthn.WithExclusions(exclude))
	if err != nil {
		return nil, "", fmt.Errorf("service.BeginRegister: %w", err)
	}
	sealed, err := s.sealSession(sess)
	if err != nil {
		return nil, "", fmt.Errorf("service.BeginRegister: %w", err)
	}
	optsJSON, err := json.Marshal(creation)
	if err != nil {
		return nil, "", fmt.Errorf("service.BeginRegister: marshal options: %w", err)
	}
	return optsJSON, sealed, nil
}

// FinishRegister completes a registration ceremony: it opens and
// single-use-checks the challenge cookie, verifies the attestation, persists
// the webauthn_handle carried in the cookie (idempotent — it is always the
// user's existing handle, freshly minted or reused, see BeginRegister), and
// stores the new credential (audit passkey.registered).
func (s *PasskeyService) FinishRegister(ctx context.Context, userID, sealedCookie, name string, r *http.Request) (store.WebAuthnCredential, error) {
	sess, err := s.openSession(sealedCookie)
	if err != nil {
		return store.WebAuthnCredential{}, err
	}
	if !s.claimChallenge(sess.Challenge, sess.Expires) {
		return store.WebAuthnCredential{}, ErrPasskeyVerification
	}

	u, err := s.st.Users().GetByID(ctx, userID)
	if err != nil {
		return store.WebAuthnCredential{}, fmt.Errorf("service.FinishRegister: %w", err)
	}

	cred, err := s.verifyRegistration(u.Email, sess.UserID, sess, r)
	if err != nil {
		return store.WebAuthnCredential{}, err
	}
	return s.persistCredential(ctx, userID, sess.UserID, cred, name)
}

// beginRegistrationFor starts a registration ceremony for an identity
// (email + WebAuthn handle) that does not yet have a store.User row — used
// only by BootstrapService.BeginClaim (design D9), where the admin account
// is not created until after the atomic Bootstrap.Consume gate is won.
// Unlike BeginRegister, this never touches the store and does not seal the
// returned session: the caller (bootstrap.go) combines it with additional
// claim-specific data (the target email) into its own sealed cookie, since
// PasskeyService's own cookie format only carries webauthn.SessionData.
func (s *PasskeyService) beginRegistrationFor(email string, handle []byte) ([]byte, *webauthn.SessionData, error) {
	wu, err := newWebauthnUser(email, handle, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("service.beginRegistrationFor: %w", err)
	}
	creation, sess, err := s.wa.BeginRegistration(wu)
	if err != nil {
		return nil, nil, fmt.Errorf("service.beginRegistrationFor: %w", err)
	}
	optsJSON, err := json.Marshal(creation)
	if err != nil {
		return nil, nil, fmt.Errorf("service.beginRegistrationFor: marshal options: %w", err)
	}
	return optsJSON, sess, nil
}

// verifyRegistration performs go-webauthn's raw registration verification
// for (email, handle) against sess, returning the verified credential held
// only in memory — no store access. Callers that must gate persistence
// behind an atomic single-use token (BootstrapService.FinishClaim,
// GrantService.RedeemFinish — design C1) call this first, win their atomic
// consume, then call persistCredential. Every failure collapses to
// ErrPasskeyVerification, matching FinishRegister's uniform failure mode.
func (s *PasskeyService) verifyRegistration(email string, handle []byte, sess webauthn.SessionData, r *http.Request) (*webauthn.Credential, error) {
	wu, err := newWebauthnUser(email, handle, nil)
	if err != nil {
		return nil, fmt.Errorf("service.verifyRegistration: %w", err)
	}
	cred, err := s.wa.FinishRegistration(wu, sess, r)
	if err != nil {
		// Info, not Error: /register/finish is anonymous-reachable, so Error
		// would make log volume attacker-driveable. This matches the three
		// existing sites with the same shape (uniform sentinel returned,
		// specific reason logged): service/oidc.go:38, api/oidc.go:156,
		// api/enroll_oidc.go:154.
		//
		// The cause is written here and NOWHERE else. Do not wrap it with %w and
		// do not add a second return value: api/passkey.go:184 passes only the
		// fixed constant to huma.Error401Unauthorized, and that must stay true.
		s.log.LogAttrs(r.Context(), slog.LevelInfo, "passkey registration verification failed",
			slog.String("error", err.Error()))
		return nil, ErrPasskeyVerification
	}
	return cred, nil
}

// persistCredential stores a credential already verified by
// verifyRegistration: idempotently sets userID's webauthn_handle, inserts
// the credential row, and audits passkey.registered. userID must already
// exist as a row — callers gating persistence on an atomic token create or
// validate that row (BootstrapService.FinishClaim, GrantService.RedeemFinish)
// before calling this.
func (s *PasskeyService) persistCredential(ctx context.Context, userID string, handle []byte, cred *webauthn.Credential, name string) (store.WebAuthnCredential, error) {
	if err := s.st.Users().SetWebAuthnHandle(ctx, userID, handle); err != nil {
		return store.WebAuthnCredential{}, fmt.Errorf("service.persistCredential: %w", err)
	}

	credJSON, err := json.Marshal(cred)
	if err != nil {
		return store.WebAuthnCredential{}, fmt.Errorf("service.persistCredential: marshal credential: %w", err)
	}
	stored, err := s.st.WebAuthnCredentials().Create(ctx, store.WebAuthnCredential{
		CredentialID: cred.ID, UserID: userID, CredentialJSON: credJSON,
		Name: name, AAGUID: cred.Authenticator.AAGUID, CreatedAt: store.NowUnix(),
	})
	if err != nil {
		return store.WebAuthnCredential{}, fmt.Errorf("service.persistCredential: %w", err)
	}

	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "passkey.registered",
		TargetType: "webauthn_credential", TargetID: base64.RawURLEncoding.EncodeToString(cred.ID),
	})
	return stored, nil
}

// ListCredentials returns every passkey registered to userID.
func (s *PasskeyService) ListCredentials(ctx context.Context, userID string) ([]store.WebAuthnCredential, error) {
	creds, err := s.st.WebAuthnCredentials().ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("service.ListCredentials: %w", err)
	}
	return creds, nil
}

// Rename changes the display name of a credential owned by userID. Returns
// store.ErrNotFound if credID does not exist or belongs to a different user
// (never distinguishing the two, to avoid leaking another user's credential
// IDs).
func (s *PasskeyService) Rename(ctx context.Context, userID string, credID []byte, name string) error {
	cred, err := s.ownedCredential(ctx, userID, credID)
	if err != nil {
		return fmt.Errorf("service.Rename: %w", err)
	}
	if err := s.st.WebAuthnCredentials().Rename(ctx, cred.CredentialID, name); err != nil {
		return fmt.Errorf("service.Rename: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "passkey.renamed",
		TargetType: "webauthn_credential", TargetID: base64.RawURLEncoding.EncodeToString(credID),
	})
	return nil
}

// Remove deletes a credential owned by userID. Guard (design D8): refused
// with ErrLastCredential when doing so would leave the user with zero
// passkeys and no OIDC link, i.e. no remaining way to sign in. An
// OIDC-linked user may drop to zero passkeys safely.
func (s *PasskeyService) Remove(ctx context.Context, userID string, credID []byte) error {
	cred, err := s.ownedCredential(ctx, userID, credID)
	if err != nil {
		return fmt.Errorf("service.Remove: %w", err)
	}
	u, err := s.st.Users().GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("service.Remove: %w", err)
	}
	count, err := s.st.WebAuthnCredentials().CountWebAuthnCredentials(ctx, userID)
	if err != nil {
		return fmt.Errorf("service.Remove: %w", err)
	}
	if count <= 1 && u.OIDCSubject == "" {
		return ErrLastCredential
	}
	if err := s.st.WebAuthnCredentials().Delete(ctx, cred.CredentialID); err != nil {
		return fmt.Errorf("service.Remove: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: userID, EventType: "passkey.removed",
		TargetType: "webauthn_credential", TargetID: base64.RawURLEncoding.EncodeToString(credID),
	})
	return nil
}

// ownedCredential fetches credID and verifies it belongs to userID,
// returning store.ErrNotFound (uniformly, never distinguishing "no such
// credential" from "belongs to someone else") otherwise.
func (s *PasskeyService) ownedCredential(ctx context.Context, userID string, credID []byte) (store.WebAuthnCredential, error) {
	cred, err := s.st.WebAuthnCredentials().GetByID(ctx, credID)
	if err != nil {
		return store.WebAuthnCredential{}, err
	}
	if cred.UserID != userID {
		return store.WebAuthnCredential{}, store.ErrNotFound
	}
	return cred, nil
}
