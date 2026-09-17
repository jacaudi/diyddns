package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"

	// Aliased: this file has parameters named newEmail and locals derived from
	// them; revive's import-shadowing rule is enabled repo-wide and the alias
	// keeps every identifier named *email* unambiguous.
	emailpkg "github.com/jacaudi/diyddns/internal/email"
	"github.com/jacaudi/diyddns/internal/store"
)

// emailChangeTokenBytes is the byte length of an email-change confirmation
// token (before base64 encoding), matching grantTokenBytes and
// bootstrapTokenBytes -- separate constants because they are separate
// knowledge that happens to share a value.
const emailChangeTokenBytes = 32

// emailChangeTTL is how long a staged email change stays confirmable. Not
// grantTTL: a registration grant and a confirmation link are different
// things whose windows may diverge.
const emailChangeTTL = time.Hour

// Guard sentinels for an email change -- mapped to HTTP 422/503 by the web UI
// (webui.adminGuardMessage). All new in #131.
var (
	// ErrEmailUnchanged is returned when the requested address is the account's
	// current address (compared case-insensitively).
	ErrEmailUnchanged = errors.New("service: that is already the account's email address")
	// ErrEmailManagedByOIDC is returned when a self-service change is attempted
	// on an OIDC-linked account, whose address follows its identity provider
	// (design D9).
	ErrEmailManagedByOIDC = errors.New("service: email address is managed by the identity provider")
	// ErrEmailChangeInvalid is the single uniform error for every confirmation
	// failure -- wrong token, expired, nothing pending -- so callers cannot
	// distinguish which.
	ErrEmailChangeInvalid = errors.New("service: email change confirmation invalid, expired, or already used")
	// ErrMailerUnavailable is returned when a self-service change is requested
	// and no mailer is configured: there is nothing to confirm with.
	ErrMailerUnavailable = errors.New("service: email delivery is not configured")
	// ErrConfirmationNotSent is returned when the confirmation mail could not
	// be delivered; the staged change has been rolled back (or, if that
	// rollback also failed, is left for the pruner and the user's Cancel).
	ErrConfirmationNotSent = errors.New("service: confirmation email could not be sent")
)

// EmailChangeService owns every path that changes an account's email address
// (#131): the self-service request/cancel/confirm flow, an admin's direct set,
// and the sync from an OIDC identity provider. The "apply" side effects --
// deleting outstanding registration grants, auditing, notifying the old
// address -- therefore exist once.
type EmailChangeService struct {
	st      *store.Store
	mail    mailDeps
	baseURL string
}

// NewEmailChangeService constructs an EmailChangeService. mailer may be nil
// (the same supported state GrantService accepts): self-service requests then
// refuse with ErrMailerUnavailable and every notice is skipped. baseURL is
// prefixed to the confirmation link. mail.timeout is always set here; a zero
// value would make every send fail silently (see GrantService.deliveryTimeout).
func NewEmailChangeService(st *store.Store, mailer emailpkg.Mailer, baseURL string, audit AuditSink, log *slog.Logger) *EmailChangeService {
	return &EmailChangeService{
		st:      st,
		mail:    mailDeps{mailer: mailer, audit: audit, log: log, timeout: adminDeliveryTimeout},
		baseURL: baseURL,
	}
}

// addressHeld reports whether any row other than exceptID already holds
// canonical -- as its stored address, or as a pending change that has not
// expired -- comparing CANONICAL forms CASE-INSENSITIVELY. GetByEmail and the
// UNIQUE index are both exact and case-sensitive, so on their own they let
// Bob@x.test and bob@x.test become two accounts on one mailbox, and mail for
// both -- including passkey-recovery links -- then lands in that one mailbox.
// Pending addresses count because two users could otherwise request
// case-variants of one address and both confirm. Comparing canonical forms
// also catches a legacy display-name row (#93); a row that cannot be
// canonicalised (non-ASCII, #87) never matches. O(users), like findByEmail's
// fallback; every caller is a rare, human-paced operation. Every value
// compared is 7-bit ASCII, so EqualFold's Unicode folding cannot diverge.
func addressHeld(users []store.User, canonical, exceptID string, now int64) bool {
	for _, u := range users {
		if u.ID == exceptID {
			continue
		}
		if stored, err := emailpkg.NormalizeAddress(u.Email); err == nil && strings.EqualFold(stored, canonical) {
			return true
		}
		if u.PendingEmail != "" && u.PendingEmailExpiresAt > now && strings.EqualFold(u.PendingEmail, canonical) {
			return true
		}
	}
	return false
}

// emailChangeDetails renders the audit DetailsJSON every #131 event carries,
// in the shape the existing DetailsJSON writers use (service/feed.go,
// service/notification.go, notify/worker.go).
func emailChangeDetails(oldEmail, newEmail string) string {
	details, _ := json.Marshal(map[string]string{"old": oldEmail, "new": newEmail})
	return string(details)
}

func (s *EmailChangeService) mailerEnabled() bool {
	return s.mail.mailer != nil && s.mail.mailer.Enabled()
}

// validateRequest runs Request's guards in design order (§5.1 steps 1-5) and
// returns the canonical new address. Extracted so Request stays under the
// gocyclo ceiling, as normalizeClaim was.
func (s *EmailChangeService) validateRequest(ctx context.Context, u store.User, newEmail string, now int64) (string, error) {
	if !s.mailerEnabled() {
		return "", ErrMailerUnavailable
	}
	if u.OIDCSubject != "" {
		return "", ErrEmailManagedByOIDC
	}
	normalized, err := emailpkg.NormalizeAddress(newEmail)
	if err != nil {
		return "", ErrInvalidEmail
	}
	if strings.EqualFold(normalized, u.Email) {
		return "", ErrEmailUnchanged
	}
	users, err := s.st.Users().List(ctx)
	if err != nil {
		return "", fmt.Errorf("list users: %w", err)
	}
	if addressHeld(users, normalized, u.ID, now) {
		return "", store.ErrConflict
	}
	return normalized, nil
}

// Request stages a self-service change for u to newEmail (design §5.1): it
// validates, mints a single-use confirmation token, stores the change on the
// row, audits user.email_change_requested, mails the confirmation link to the
// NEW address and a heads-up to the OLD one. Nothing about the account changes
// until Confirm redeems the token; the old address stays authoritative.
//
// A repeat request for the address already pending (case-insensitively) and
// not yet expired returns nil without minting or mailing again (D12); a
// request for a different address replaces the pending one.
//
// If the confirmation mail cannot be sent, the staged change is rolled back
// and ErrConfirmationNotSent is returned: a pending change whose link never
// arrived would block retries under D12. The requested audit row is written
// before the send and survives the rollback -- the event log records what was
// asked for, not what stuck.
func (s *EmailChangeService) Request(ctx context.Context, u store.User, newEmail string) error {
	now := store.NowUnix()
	normalized, err := s.validateRequest(ctx, u, newEmail, now)
	if err != nil {
		return fmt.Errorf("service.Request: %w", err)
	}
	if strings.EqualFold(u.PendingEmail, normalized) && u.PendingEmailExpiresAt > now {
		return nil
	}
	token, err := auth.RandToken(emailChangeTokenBytes)
	if err != nil {
		return fmt.Errorf("service.Request: %w", err)
	}
	expiresAt := now + int64(emailChangeTTL.Seconds())
	if err := s.st.Users().SetPendingEmail(ctx, u.ID, normalized, auth.HashToken(token), expiresAt); err != nil {
		return fmt.Errorf("service.Request: %w", err)
	}
	s.mail.audit.Log(ctx, store.AuditEntry{
		ActorUserID: u.ID, EventType: "user.email_change_requested",
		TargetType: "user", TargetID: u.ID, DetailsJSON: emailChangeDetails(u.Email, normalized),
	})

	subject, body := emailpkg.ChangeConfirmBody(s.baseURL + "/account/email/confirm?token=" + token)
	if d := sendAdvisory(ctx, s.mail, u.ID, u.ID, normalized, subject, body); d.Err != nil {
		// context.WithoutCancel: sendAdvisory detaches the send from
		// cancellation for exactly this reason -- a slow SMTP peer can outlive
		// a client disconnect -- so a send that fails after the request
		// context was canceled is the expected shape here, not an edge case.
		// Reusing ctx for the rollback would hit the hazard recordSendFailure
		// already dodges (grants.go:120-134): database/sql rejects an
		// already-canceled context before the write reaches the driver,
		// silently leaving the dangling pending change this rollback exists
		// to remove.
		if cerr := s.st.Users().ClearPendingEmail(context.WithoutCancel(ctx), u.ID); cerr != nil {
			s.mail.log.ErrorContext(ctx, "email change: rollback of an unsent pending change failed; the pruner clears it within the hour",
				"error", cerr, "user_id", u.ID)
		}
		return fmt.Errorf("service.Request: %w", ErrConfirmationNotSent)
	}
	subject, body = emailpkg.ChangeNoticeBody(normalized)
	sendAdvisory(ctx, s.mail, u.ID, u.ID, u.Email, subject, body)
	return nil
}

// Cancel discards u's pending change, if any, and audits
// user.email_change_cancelled. With nothing pending it does nothing and
// returns nil.
func (s *EmailChangeService) Cancel(ctx context.Context, u store.User) error {
	if u.PendingEmail == "" {
		return nil
	}
	if err := s.st.Users().ClearPendingEmail(ctx, u.ID); err != nil {
		return fmt.Errorf("service.Cancel: %w", err)
	}
	s.mail.audit.Log(ctx, store.AuditEntry{
		ActorUserID: u.ID, EventType: "user.email_change_cancelled",
		TargetType: "user", TargetID: u.ID, DetailsJSON: emailChangeDetails(u.Email, u.PendingEmail),
	})
	return nil
}
