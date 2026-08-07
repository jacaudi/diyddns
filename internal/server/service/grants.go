package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/email"
	"github.com/jacaudi/diyddns/internal/store"
)

// grantTokenBytes is the byte length of a registration-grant token (before
// base64 encoding), matching the bootstrap and enrollment-code tokens.
const grantTokenBytes = 32

// grantTTL is how long a freshly-minted registration grant (invite or
// recovery) stays redeemable.
const grantTTL = time.Hour

// ErrGrantInvalid is the single uniform error for every registration-grant
// redeem failure — unknown, expired, or already-consumed token — so callers
// cannot distinguish which. Maps to HTTP 401.
var ErrGrantInvalid = errors.New("service: registration grant invalid, expired, or already used")

// GrantService issues and redeems registration grants (design D10/D12/D15):
// a single-use, hashed, expiring token that drives a passkey registration
// ceremony for a target user carried in the token, not a session. One token
// shape and one redeem flow serve three issuers — admin invite, admin
// recovery, and self-service recovery — differing only in issuance side
// effects (see IssueInvite/IssueRecovery).
type GrantService struct {
	st       *store.Store
	passkeys *PasskeyService
	mailer   email.Mailer
	baseURL  string
	audit    AuditSink
	log      *slog.Logger
}

// NewGrantService constructs a GrantService. passkeys may be nil if WebAuthn
// is not configured (see ErrWebAuthnUnavailable) — IssueInvite/IssueRecovery
// never need it (they only mint a token), but RedeemBegin/RedeemFinish do.
// baseURL is prefixed to every minted link ("<baseURL>/register?token=...").
func NewGrantService(st *store.Store, passkeys *PasskeyService, mailer email.Mailer, baseURL string, audit AuditSink, log *slog.Logger) *GrantService {
	return &GrantService{st: st, passkeys: passkeys, mailer: mailer, baseURL: baseURL, audit: audit, log: log}
}

// issue mints a fresh single-use grant for userID with the given reason
// ("invite" | "recovery") and returns its one-time redeem link. It never
// audits or revokes — callers (IssueInvite/IssueRecovery) own those
// reason-specific side effects.
func (s *GrantService) issue(ctx context.Context, userID, reason string) (string, error) {
	token, err := auth.RandToken(grantTokenBytes)
	if err != nil {
		return "", fmt.Errorf("service.issue: %w", err)
	}
	now := store.NowUnix()
	t := store.RecoveryToken{
		TokenHash: auth.HashToken(token),
		UserID:    userID,
		Reason:    reason,
		ExpiresAt: now + int64(grantTTL.Seconds()),
	}
	if err := s.st.AccountRecovery().Create(ctx, t); err != nil {
		return "", fmt.Errorf("service.issue: %w", err)
	}
	return s.baseURL + "/register?token=" + token, nil
}

// IssueInvite mints an "invite" grant for userID (a freshly-created,
// credential-less user — see AdminService.CreateUserInvite, design D15).
// There is nothing to revoke: a new user has no existing passkeys.
func (s *GrantService) IssueInvite(ctx context.Context, actorID, userID string) (string, error) {
	link, err := s.issue(ctx, userID, "invite")
	if err != nil {
		return "", fmt.Errorf("service.IssueInvite: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: actorID, EventType: "passkey.invite_issued",
		TargetType: "user", TargetID: userID,
	})
	return link, nil
}

// mintRecoveryGrant creates a single-use "recovery" grant for userID and
// audits passkey.recovery_issued. It does NOT revoke any existing passkeys —
// revocation is the caller's decision and timing: admin recovery revokes at
// issue (IssueRecovery), while self-service recovery defers revocation to
// redeem (confirm-then-revoke — RedeemFinish revokes only once mailbox
// possession is proven, so a pre-auth request can never lock anyone out).
// actorID is recorded as the audit actor (the triggering admin, or the user
// themselves for self-service).
func (s *GrantService) mintRecoveryGrant(ctx context.Context, actorID, userID string) (string, error) {
	link, err := s.issue(ctx, userID, "recovery")
	if err != nil {
		return "", fmt.Errorf("service.mintRecoveryGrant: %w", err)
	}
	s.audit.Log(ctx, store.AuditEntry{
		ActorUserID: actorID, EventType: "passkey.recovery_issued",
		TargetType: "user", TargetID: userID,
	})
	return link, nil
}

// IssueRecovery is the admin recovery path: it revokes all of userID's
// existing passkeys immediately (design D10 — revoke-at-issue, the
// lost-or-stolen-device model, safe because the caller is an authenticated
// admin taking an intentional action) and mints a "recovery" grant. The
// self-service path (RequestSelfServiceRecovery) deliberately does NOT revoke
// at issue — see mintRecoveryGrant.
//
// It refuses (ErrWebAuthnUnavailable) when s.passkeys is nil: the minted
// link would 404 at redeem, since the register routes are gated off
// deps.Passkey != nil (server.go) — mirroring the same guard
// RedeemBegin/RedeemFinish already apply, just earlier, before a dead link
// is ever handed to an admin.
func (s *GrantService) IssueRecovery(ctx context.Context, actorID, userID string) (string, error) {
	if s.passkeys == nil {
		return "", fmt.Errorf("service.IssueRecovery: %w", ErrWebAuthnUnavailable)
	}
	if _, err := s.st.WebAuthnCredentials().DeleteAllByUser(ctx, userID); err != nil {
		return "", fmt.Errorf("service.IssueRecovery: %w", err)
	}
	link, err := s.mintRecoveryGrant(ctx, actorID, userID)
	if err != nil {
		return "", fmt.Errorf("service.IssueRecovery: %w", err)
	}
	return link, nil
}

// selfServiceRecoveryTimeout bounds the detached goroutine
// RequestSelfServiceRecovery spawns to perform its account-existence-
// sensitive work: generous enough for a real SMTP round-trip (plus the
// dial-timeout floor in internal/email's smtpMailer), but bounded so the
// goroutine can never leak forever if a downstream call wedges.
const selfServiceRecoveryTimeout = 30 * time.Second

// RequestSelfServiceRecovery is the pre-auth "Lost your passkey?" entry
// point. It ALWAYS returns nil IMMEDIATELY — before doing any
// account-specific work — so the caller's response is uniform in BOTH
// content and latency, and can never be used to enumerate accounts. A slow
// path (a real SMTP send takes 100s of ms) that ran on the caller's own
// request path would otherwise leak account existence through response
// timing alone, even with a uniform response body/status; the entire
// account-existence-sensitive body below therefore runs in a detached
// goroutine, on its own timeout context (never ctx, which is canceled the
// moment the HTTP handler returns).
//
// That body proceeds (mints a grant, emails the link, notifies admins) only
// when every one of these holds:
//   - the mailer is enabled (SMTP configured, D11)
//   - the account exists
//   - the account already has at least one passkey (SGE I2 — self-service
//     recovery can never mint a user's FIRST local credential via mailbox
//     possession alone, which would silently downgrade an OIDC/MFA account
//     to email control)
//
// It mints the grant but does NOT revoke the user's existing passkeys
// (confirm-then-revoke): revocation happens at redeem (RedeemFinish), gated
// by mailbox possession, so a pre-auth request from anyone who merely knows
// an email address can never lock that account out. Send failures are logged
// (audit email.send_failed) and never surfaced.
func (s *GrantService) RequestSelfServiceRecovery(_ context.Context, targetEmail, ip string) error {
	//nolint:gosec // G118: deliberate — ctx is the REQUEST context, canceled the instant the HTTP handler returns; using it here would abort doSelfServiceRecovery mid-flight and reopen exactly the account-enumeration timing channel this fix closes. doSelfServiceRecovery derives its own bounded context.Background()-rooted timeout instead (see its doc comment).
	go s.doSelfServiceRecovery(targetEmail, ip)
	return nil
}

// doSelfServiceRecovery is RequestSelfServiceRecovery's detached-goroutine
// body — see that method's doc comment for why it must never run on the
// caller's path.
func (s *GrantService) doSelfServiceRecovery(targetEmail, ip string) {
	ctx, cancel := context.WithTimeout(context.Background(), selfServiceRecoveryTimeout)
	defer cancel()

	if s.mailer == nil || !s.mailer.Enabled() {
		return
	}
	u, err := s.st.Users().GetByEmail(ctx, targetEmail)
	if err != nil {
		return
	}
	count, err := s.st.WebAuthnCredentials().CountWebAuthnCredentials(ctx, u.ID)
	if err != nil || count == 0 {
		return
	}

	link, err := s.mintRecoveryGrant(ctx, u.ID, u.ID)
	if err != nil {
		s.log.Error("self-service recovery: issue failed", "err", err)
		return
	}

	subj, body := email.RecoveryLinkBody(link)
	if err := s.mailer.Send(ctx, u.Email, subj, body); err != nil {
		s.audit.Log(ctx, store.AuditEntry{EventType: "email.send_failed", TargetType: "user", TargetID: u.ID, IP: ip})
	}

	admins, err := s.st.Users().List(ctx)
	if err != nil {
		s.log.Error("self-service recovery: list admins failed", "err", err)
		return
	}
	adminSubj, adminBody := email.AdminNotifyBody(u.Email)
	for _, a := range admins {
		if a.Role != "admin" || a.Disabled {
			continue
		}
		if err := s.mailer.Send(ctx, a.Email, adminSubj, adminBody); err != nil {
			s.audit.Log(ctx, store.AuditEntry{EventType: "email.send_failed", TargetType: "user", TargetID: a.ID, IP: ip})
		}
	}
}

// validGrant looks up token's grant and reports whether it is currently
// redeemable (exists, not expired, not consumed). This is a non-atomic
// pre-check — Consume remains the sole atomic single-use gate (design C1);
// validGrant exists so RedeemBegin can reject a dead token before spending
// an authenticator ceremony on it, and so RedeemFinish can resolve the
// target user before verifying.
//
// The Get lookup is keyed by the token's exact HashToken(token) primary key,
// so a returned row inherently authenticates the token — no separate
// constant-time VerifyToken is needed (it would always re-compare equal).
func (s *GrantService) validGrant(ctx context.Context, token string) (store.RecoveryToken, error) {
	grant, err := s.st.AccountRecovery().Get(ctx, auth.HashToken(token))
	if err != nil {
		return store.RecoveryToken{}, ErrGrantInvalid
	}
	if grant.UsedAt != 0 || grant.ExpiresAt <= store.NowUnix() {
		return store.RecoveryToken{}, ErrGrantInvalid
	}
	return grant, nil
}

// RedeemBegin validates token and starts a registration ceremony for its
// target user, returning the JSON creation options for the browser plus the
// sealed challenge cookie to round-trip to RedeemFinish. It does not consume
// the grant (see design C1 — verify-before-consume).
func (s *GrantService) RedeemBegin(ctx context.Context, token string) (string, []byte, string, error) {
	if s.passkeys == nil {
		return "", nil, "", ErrWebAuthnUnavailable
	}
	grant, err := s.validGrant(ctx, token)
	if err != nil {
		return "", nil, "", err
	}
	options, sealedCookie, err := s.passkeys.BeginRegister(ctx, grant.UserID)
	if err != nil {
		return "", nil, "", fmt.Errorf("service.RedeemBegin: %w", err)
	}
	return grant.UserID, options, sealedCookie, nil
}

// RedeemFinish completes a grant redeem. Ordering (design C1,
// verify-before-consume, NO sql.Tx — the store's single-connection pool
// would deadlock a transaction wrapping these repos): verify the passkey in
// memory (no DB write) -> Consume the grant (the atomic single-use gate) ->
// for a "recovery" grant, revoke the user's existing passkeys now that
// mailbox/link possession is proven (confirm-then-revoke) -> persist the new
// credential. The revoke happens BEFORE the persist so the freshly-registered
// passkey survives. An "invite" grant never revokes (a new user has no
// passkeys; a corner-case existing one is kept). A store failure after
// Consume spends the grant without completing registration — the admin must
// re-issue; this is documented, not a hang, and logged at CRITICAL.
func (s *GrantService) RedeemFinish(ctx context.Context, token, sealedCookie string, r *http.Request, name string) (store.User, error) {
	if s.passkeys == nil {
		return store.User{}, ErrWebAuthnUnavailable
	}
	grant, err := s.validGrant(ctx, token)
	if err != nil {
		return store.User{}, err
	}

	sess, err := s.passkeys.openSession(sealedCookie)
	if err != nil {
		return store.User{}, err
	}
	if !s.passkeys.claimChallenge(sess.Challenge, sess.Expires) {
		return store.User{}, ErrPasskeyVerification
	}

	u, err := s.st.Users().GetByID(ctx, grant.UserID)
	if err != nil {
		return store.User{}, fmt.Errorf("service.RedeemFinish: %w", err)
	}
	cred, err := s.passkeys.verifyRegistration(u.Email, sess.UserID, sess, r)
	if err != nil {
		return store.User{}, err
	}

	if _, err := s.st.AccountRecovery().Consume(ctx, auth.HashToken(token), store.NowUnix()); err != nil {
		return store.User{}, ErrGrantInvalid
	}

	if grant.Reason == "recovery" {
		if _, err := s.st.WebAuthnCredentials().DeleteAllByUser(ctx, grant.UserID); err != nil {
			s.log.Error("GRANT CRITICAL: recovery grant consumed but passkey revoke failed; admin must re-issue",
				"err", err, "user_id", grant.UserID)
			return store.User{}, fmt.Errorf("service.RedeemFinish: %w", err)
		}
	}

	if _, err := s.passkeys.persistCredential(ctx, grant.UserID, sess.UserID, cred, name); err != nil {
		s.log.Error("GRANT CRITICAL: grant consumed but credential persist failed; admin must re-issue",
			"err", err, "user_id", grant.UserID)
		return store.User{}, fmt.Errorf("service.RedeemFinish: %w", err)
	}

	if grant.Reason == "recovery" {
		s.audit.Log(ctx, store.AuditEntry{
			ActorUserID: grant.UserID, EventType: "passkey.recovery_redeemed",
			TargetType: "user", TargetID: grant.UserID,
		})
	}
	return u, nil
}
