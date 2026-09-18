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
		// leaving the dangling pending change this rollback exists to remove.
		//
		// Bounded by auditWriteTimeout, the same pairing recordSendFailure
		// uses (grants.go:136): WithoutCancel alone has a nil Done() channel,
		// and the store caps its pool at one connection (store.go:44), so an
		// unbounded detached write here could block this request path
		// indefinitely if that one connection is held elsewhere (the hazard
		// notifications.go:481 documents). Reusing the constant rather than a
		// new one: this is the same shape -- a single detached, bounded write.
		rollbackCtx, rollbackCancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
		cerr := s.st.Users().ClearPendingEmail(rollbackCtx, u.ID)
		rollbackCancel()
		if cerr != nil {
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

// changedRow is the in-memory image of u after its address became newEmail at
// now, with any pending change cleared: exactly what ConfirmPendingEmail and
// SetEmail wrote. Nothing re-reads the row after a write (design §4): the
// store's predicate binds the address to the token, so this cannot diverge
// from what was written.
func changedRow(u store.User, newEmail string, now int64) store.User {
	u.Email = newEmail
	u.PendingEmail = ""
	u.PendingEmailExpiresAt = 0
	u.UpdatedAt = now
	return u
}

// applyChanged performs the two DATABASE side effects every completed change
// shares (design §5.4): it deletes the account's outstanding registration
// grants (D8 -- a link mailed to the old address must not survive the moment
// that address stops speaking for the account) and audits event with the
// old/new pair. Neither can fail the operation: the address is already
// changed, and reporting failure would tell the caller something false. The
// notice to the old address is the CALLER's job, because the three callers
// differ in body and in whether the send may sit on the request path.
func (s *EmailChangeService) applyChanged(ctx context.Context, actorID string, u store.User, oldEmail, event string) {
	if _, err := s.st.AccountRecovery().DeleteUnusedByUser(ctx, u.ID); err != nil {
		s.mail.log.ErrorContext(ctx, "email change: deleting outstanding registration grants failed; they expire within the hour",
			"error", err, "user_id", u.ID)
	}
	s.mail.audit.Log(ctx, store.AuditEntry{
		ActorUserID: actorID, EventType: event,
		TargetType: "user", TargetID: u.ID, DetailsJSON: emailChangeDetails(oldEmail, u.Email),
	})
}

// Confirm redeems token for u's pending change (design §5.2). The store's
// single conditional UPDATE is the single-use gate and the apply; every
// rejection -- wrong token, expired, nothing pending -- is ErrEmailChangeInvalid
// so the page cannot tell them apart. An OIDC-linked row is refused first:
// its address follows the identity provider (D9), and a pending change staged
// before the link is inert. The caller must pass the SESSION's user (D6): the
// link alone proves possession of the new mailbox, not of the account.
func (s *EmailChangeService) Confirm(ctx context.Context, u store.User, token string) error {
	if u.OIDCSubject != "" {
		return fmt.Errorf("service.Confirm: %w", ErrEmailManagedByOIDC)
	}
	now := store.NowUnix()
	if err := s.st.Users().ConfirmPendingEmail(ctx, u.ID, auth.HashToken(token), now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("service.Confirm: %w", ErrEmailChangeInvalid)
		}
		return fmt.Errorf("service.Confirm: %w", err) // store.ErrConflict flows up
	}
	updated := changedRow(u, u.PendingEmail, now)
	s.applyChanged(ctx, u.ID, updated, u.Email, "user.email_changed")
	subject, body := emailpkg.ChangedBody(updated.Email)
	sendAdvisory(ctx, s.mail, u.ID, u.ID, u.Email, subject, body)
	return nil
}

// AdminSet writes target's address directly, effective immediately (design
// §5.3, D3): the admin has authenticated as themselves and the support case
// is an address the user cannot receive mail at, so a confirmation step would
// be circular. Any pending self-service change is discarded (SetEmail). The
// old address is told (AdminChangedBody); that Delivery is returned so
// the page can say whether it was. A disabled target is still notified -- a
// heads-up is useful to a disabled account's owner in a way a registration
// link is not. Nothing here branches on actorID == target.ID (D21).
func (s *EmailChangeService) AdminSet(ctx context.Context, actorID string, target store.User, newEmail string) (store.User, Delivery, error) {
	now := store.NowUnix()
	normalized, err := emailpkg.NormalizeAddress(newEmail)
	if err != nil {
		return store.User{}, Delivery{}, fmt.Errorf("service.AdminSet: %w", ErrInvalidEmail)
	}
	if strings.EqualFold(normalized, target.Email) {
		return store.User{}, Delivery{}, fmt.Errorf("service.AdminSet: %w", ErrEmailUnchanged)
	}
	users, err := s.st.Users().List(ctx)
	if err != nil {
		return store.User{}, Delivery{}, fmt.Errorf("service.AdminSet: %w", err)
	}
	if addressHeld(users, normalized, target.ID, now) {
		return store.User{}, Delivery{}, fmt.Errorf("service.AdminSet: %w", store.ErrConflict)
	}
	if err := s.st.Users().SetEmail(ctx, target.ID, normalized, now); err != nil {
		return store.User{}, Delivery{}, fmt.Errorf("service.AdminSet: %w", err) // ErrConflict / ErrNotFound flow up
	}
	updated := changedRow(target, normalized, now)
	s.applyChanged(ctx, actorID, updated, target.Email, "user.email_changed_by_admin")
	subject, body := emailpkg.AdminChangedBody(normalized)
	return updated, sendAdvisory(ctx, s.mail, actorID, target.ID, target.Email, subject, body), nil
}

// SyncFromIDP makes a linked account's stored address follow its identity
// provider's raw email claim (design §5.6, D9) and returns the row as it now
// stands. It has NO error return by construction: nothing below can reject a
// login. A claim that is empty, does not normalise, equals the stored address
// (any case), is held by another account, or fails to write leaves the row
// alone and is logged. This is the #87/#93 guard-placement lesson kept
// intact -- a formatting rule or a collision must never lock out an
// already-linked user.
//
// On an actual change the database side effects run on the request path (local
// writes, microseconds) and the notice to the old address is DETACHED: a
// goroutine on context.Background, bounded by sendAdvisory's own timeout, so
// neither the browser login nor the device-enrollment poll ever waits on a
// mail server.
func (s *EmailChangeService) SyncFromIDP(ctx context.Context, u store.User, claim string) store.User {
	if claim == "" {
		s.mail.log.InfoContext(ctx, "oidc: linked user's IdP sent no email claim; keeping the stored address", "user_id", u.ID)
		return u
	}
	normalized, err := emailpkg.NormalizeAddress(claim)
	if err != nil {
		s.mail.log.InfoContext(ctx, "oidc: linked user's IdP email claim is not a usable address; keeping the stored address", "user_id", u.ID)
		return u
	}
	if strings.EqualFold(normalized, u.Email) {
		return u
	}
	now := store.NowUnix()
	users, err := s.st.Users().List(ctx)
	if err != nil {
		s.mail.log.ErrorContext(ctx, "oidc: email sync: list users failed; keeping the stored address", "error", err, "user_id", u.ID)
		return u
	}
	if addressHeld(users, normalized, u.ID, now) {
		s.mail.log.WarnContext(ctx, "oidc: IdP address is held by another account; keeping the stored address", "user_id", u.ID)
		return u
	}
	if err := s.st.Users().SetEmail(ctx, u.ID, normalized, now); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.mail.log.WarnContext(ctx, "oidc: IdP address is held by another account; keeping the stored address", "user_id", u.ID)
		} else {
			s.mail.log.ErrorContext(ctx, "oidc: email sync: write failed; keeping the stored address", "error", err, "user_id", u.ID)
		}
		return u
	}
	updated := changedRow(u, normalized, now)
	s.applyChanged(ctx, u.ID, updated, u.Email, "user.email_changed_by_oidc")
	subject, body := emailpkg.ChangedBody(normalized)
	//nolint:gosec // G118: deliberate -- ctx is the login request's context and the notice must outlive it; sendAdvisory bounds the goroutine with its own timeout (design §5.4).
	go sendAdvisory(context.Background(), s.mail, u.ID, u.ID, u.Email, subject, body)
	return updated
}
