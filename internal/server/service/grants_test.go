package service

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/email"
	"github.com/jacaudi/diyddns/internal/store"
)

// fakeMailer is a test double for email.Mailer: Send records every call
// instead of contacting a server, and Enabled is set by the test.
// RequestSelfServiceRecovery now runs its account-existence-sensitive work
// (including Send) in a detached goroutine (design fix wave, closing the
// account-enumeration timing channel — see grants.go), so Send may be
// invoked concurrently with a test's own goroutine reading sent: both the
// mutex and sendCh exist to make that race-safe and deterministic rather
// than requiring a sleep-and-hope poll.
type fakeMailer struct {
	enabled bool
	// sendErr, when non-nil, is returned by every Send — the seam that makes
	// the delivery-failure half of the Delivery matrix testable.
	sendErr error
	// sendDelay, when non-zero, is slept inside Send so a test can let the send
	// context expire before Send returns.
	sendDelay time.Duration
	// delayFromCall, when > 1, applies sendDelay only from the Nth Send onward
	// (1-based), so a test can let an EARLY send (the user's) return at once
	// and make only LATER ones (the admins') stall.
	// Zero and one both mean "every call", so existing literals are unaffected.
	delayFromCall int
	// sendErrFromCtx, when true, makes Send return ctx.Err() (nil when the
	// context is still live) after sendDelay instead of the unconditional
	// sendErr. sendErr alone cannot tell a send bound to a LIVE-READ timeout
	// from one bound to a value snapshotted once at construction, because it
	// fails every call regardless of the context's actual deadline; this field
	// makes the failure depend on whether sendCtx genuinely expired during
	// sendDelay, which only a live read of the timeout does.
	sendErrFromCtx bool
	// refuseNonASCII, when true, makes Send return email.ErrNotASCII for a
	// non-ASCII recipient, subject or body -- the clauses of internal/email's
	// send-path check (checkSendable) a rendered message can fail. The call is
	// still recorded, so a test can see what was attempted.
	refuseNonASCII bool
	// calls counts Send invocations, guarded by mu, for delayFromCall.
	calls int
	// sendCh, when non-nil, additionally receives every sentEmail so a test
	// can block on the goroutine actually calling Send instead of racing it.
	sendCh chan sentEmail
	// onSend, when non-nil, runs as the FIRST statement inside Send -- the one
	// point provably after every pre-send DB write a caller made (List,
	// SetPendingEmail, an audit Log) and before Send returns. A test uses it
	// to trigger something (typically canceling a context) deterministically
	// mid-send, instead of racing a fixed sleep against sendDelay: a fixed
	// sleep is flaky in exactly the direction that hides a regression (see
	// pollForAuditRows below, and #131 Task 4's review fix).
	onSend func()

	mu   sync.Mutex
	sent []sentEmail
	// lastCtxErr records ctx.Err() as observed INSIDE Send, so a test can prove
	// the send context is not the caller's canceled request context.
	lastCtxErr error
	// lastDeadlineLeft records how long the most recent Send's context had
	// left when Send was entered, or -1 when it carried no deadline. A test
	// uses it to prove a send is bounded, and bounded by its own
	// deliveryTimeout rather than a shorter shared budget (#83).
	lastDeadlineLeft time.Duration
}

type sentEmail struct{ to, subject, body string }

func (m *fakeMailer) Enabled() bool { return m.enabled }

func (m *fakeMailer) Send(ctx context.Context, to, subject, body string) error {
	if m.onSend != nil {
		m.onSend()
	}
	left := time.Duration(-1)
	if deadline, ok := ctx.Deadline(); ok {
		left = time.Until(deadline)
	}
	m.mu.Lock()
	m.calls++
	n := m.calls
	m.lastDeadlineLeft = left
	m.mu.Unlock()
	if m.sendDelay > 0 && n >= max(m.delayFromCall, 1) {
		time.Sleep(m.sendDelay)
	}
	e := sentEmail{to: to, subject: subject, body: body}
	m.mu.Lock()
	m.sent = append(m.sent, e)
	m.lastCtxErr = ctx.Err()
	m.mu.Unlock()
	if m.sendCh != nil {
		m.sendCh <- e
	}
	if m.refuseNonASCII && (!email.IsASCII(to) || !email.IsASCII(subject) || !email.IsASCII(body)) {
		return email.ErrNotASCII
	}
	if m.sendErrFromCtx {
		return ctx.Err()
	}
	return m.sendErr
}

// LastCtxErr reports ctx.Err() as seen inside the most recent Send.
func (m *fakeMailer) LastCtxErr() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastCtxErr
}

// LastDeadlineLeft reports how long the most recent Send's context had left
// when Send was entered, or -1 when it carried no deadline.
func (m *fakeMailer) LastDeadlineLeft() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastDeadlineLeft
}

// Sent returns a snapshot of every email recorded so far, safe to call
// concurrently with Send.
func (m *fakeMailer) Sent() []sentEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.sent)
}

var _ email.Mailer = (*fakeMailer)(nil)

// waitForSend blocks until ch delivers a sentEmail or timeout elapses,
// failing the test in the latter case. Used to deterministically wait for
// RequestSelfServiceRecovery's detached goroutine to reach a Send call,
// rather than racing it.
func waitForSend(t *testing.T, ch <-chan sentEmail, timeout time.Duration) sentEmail {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(timeout):
		t.Fatal("timed out waiting for Send")
		return sentEmail{}
	}
}

// assertNoSendWithin waits window for a send on ch and fails the test if one
// arrives — used to prove a guard-failure path (unknown account, no
// passkey, mailer disabled) never reaches Send, while still giving the
// detached goroutine time to actually run and hit that guard.
func assertNoSendWithin(t *testing.T, ch <-chan sentEmail, window time.Duration) {
	t.Helper()
	select {
	case e := <-ch:
		t.Fatalf("unexpected send: %+v", e)
	case <-time.After(window):
	}
}

// selfServiceRecoveryWaitTimeout is the safety-net upper bound for
// waitForSend: the detached goroutine's guard checks are local DB lookups
// with no network I/O, so this is only ever hit if the goroutine never runs
// at all (a real regression), not normal jitter.
const selfServiceRecoveryWaitTimeout = 5 * time.Second

// selfServiceRecoveryNoSendWindow is how long assertNoSendWithin actually
// waits before concluding a guard path never sends — long enough for the
// detached goroutine's local DB lookups to complete, short enough to keep
// the "no send" tests fast.
const selfServiceRecoveryNoSendWindow = 300 * time.Millisecond

// testLinkTTL is the registration-link lifetime every service test uses unless
// it is testing the lifetime itself: the production default.
const testLinkTTL = 15 * time.Minute

// newTestGrantService builds a GrantService bound to st, using the fixed
// base URL "https://ddns.example.com" so extractToken can round-trip a
// minted link back to its raw token.
func newTestGrantService(t *testing.T, st *store.Store, passkeys *PasskeyService, mailer email.Mailer, audit AuditSink) *GrantService {
	t.Helper()
	return NewGrantService(st, passkeys, mailer, "https://ddns.example.com", audit, discardLogger(), testLinkTTL)
}

// extractToken parses the raw token out of a grant link's "token" query
// parameter.
func extractToken(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse link %q: %v", link, err)
	}
	tok := u.Query().Get("token")
	if tok == "" {
		t.Fatalf("link %q missing token query param", link)
	}
	return tok
}

// extractLinkFromBody pulls the "https://..." recovery link out of an email
// body (as rendered by email.RecoveryLinkBody), so a test can drive the
// redeem exactly as a user clicking the emailed link would.
func extractLinkFromBody(t *testing.T, body string) string {
	t.Helper()
	_, rest, found := strings.Cut(body, "https://")
	if !found {
		t.Fatalf("email body has no https:// link: %q", body)
	}
	link := "https://" + rest
	if j := strings.IndexAny(link, " \r\n\t"); j >= 0 {
		link = link[:j]
	}
	return link
}

// driveRedeem completes a full RedeemBegin -> RedeemFinish ceremony for
// token via virtualwebauthn, returning RedeemFinish's error. Callers that
// need the redeemed user use driveRedeemUser.
func driveRedeem(t *testing.T, grants *GrantService, token, name string, rp virtualwebauthn.RelyingParty) error {
	t.Helper()
	_, err := driveRedeemUser(t, grants, token, name, rp)
	return err
}

// driveRedeemUser is driveRedeem plus the user RedeemFinish resolved, so a
// caller can assert the session-minting caller gets a real identity back.
func driveRedeemUser(t *testing.T, grants *GrantService, token, name string, rp virtualwebauthn.RelyingParty) (store.User, error) {
	t.Helper()

	_, optsJSON, sealed, err := grants.RedeemBegin(t.Context(), token)
	if err != nil {
		t.Fatalf("RedeemBegin: %v", err)
	}

	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(optsJSON))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v", err)
	}
	authr := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(attOpts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)
	attResp := virtualwebauthn.CreateAttestationResponse(rp, authr, cred, *attOpts)

	return grants.RedeemFinish(t.Context(), token, sealed, jsonRequest(attResp), name)
}

func TestGrantService_InviteRedeem_UserGainsPasskeyAndGrantConsumed(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	grants := newTestGrantService(t, st, passkeys, &fakeMailer{}, NewAuditWriter(st))
	u := seedUser(t, st, "alice@example.com", "user")
	rp := testRP()

	link, _, err := grants.IssueInvite(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	token := extractToken(t, link)

	if err := driveRedeem(t, grants, token, "My Key", rp); err != nil {
		t.Fatalf("driveRedeem: %v", err)
	}

	creds, err := st.WebAuthnCredentials().ListByUser(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("credentials after redeem = %d, want 1", len(creds))
	}

	grant, err := st.AccountRecovery().Get(t.Context(), auth.HashToken(token))
	if err != nil {
		t.Fatalf("AccountRecovery.Get: %v", err)
	}
	if grant.UsedAt == 0 {
		t.Error("grant.UsedAt = 0, want set (consumed)")
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "passkey.invite_issued"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("passkey.invite_issued entries = %d, want 1", len(page.Rows))
	}

	// Second redeem must fail: the grant was single-use.
	if _, _, _, err := grants.RedeemBegin(t.Context(), token); !errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("second RedeemBegin: got %v, want ErrGrantInvalid", err)
	}
}

// TestGrantService_IssueRecovery_NilPasskeys_ReturnsErrWebAuthnUnavailable
// proves IssueRecovery refuses to mint a recovery link when WebAuthn isn't
// configured (s.passkeys == nil) — such a link would 404 at redeem, since
// the register routes are gated off deps.Passkey != nil (server.go). Mirrors
// the same guard RedeemBegin/RedeemFinish already apply.
func TestGrantService_IssueRecovery_NilPasskeys_ReturnsErrWebAuthnUnavailable(t *testing.T) {
	st := openTestStore(t)
	grants := newTestGrantService(t, st, nil, &fakeMailer{}, NewAuditWriter(st))
	u := seedUser(t, st, "alice@example.com", "user")

	if _, _, err := grants.IssueRecovery(t.Context(), "admin-id", u); !errors.Is(err, ErrWebAuthnUnavailable) {
		t.Fatalf("IssueRecovery with nil passkeys: err = %v, want ErrWebAuthnUnavailable", err)
	}
}

func TestGrantService_RecoveryRedeem_RevokesThenRegistersFresh(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	grants := newTestGrantService(t, st, passkeys, &fakeMailer{}, NewAuditWriter(st))
	u := seedUser(t, st, "alice@example.com", "user")
	rp := testRP()

	oldStored, _, _ := registerPasskey(t, passkeys, u.ID, "Old Key", rp)

	link, _, err := grants.IssueRecovery(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueRecovery: %v", err)
	}

	// Revoked immediately at issue (D10), before any redeem.
	creds, err := st.WebAuthnCredentials().ListByUser(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("credentials after IssueRecovery = %d, want 0 (revoke-all-at-issue)", len(creds))
	}

	token := extractToken(t, link)
	if err := driveRedeem(t, grants, token, "New Key", rp); err != nil {
		t.Fatalf("driveRedeem: %v", err)
	}

	creds, err = st.WebAuthnCredentials().ListByUser(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("credentials after redeem = %d, want 1", len(creds))
	}
	if string(creds[0].CredentialID) == string(oldStored.CredentialID) {
		t.Error("redeemed credential has the same ID as the revoked one, want a fresh credential")
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "passkey.recovery_redeemed"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("passkey.recovery_redeemed entries = %d, want 1", len(page.Rows))
	}
}

func TestGrantService_RequestSelfServiceRecovery_UnknownEmail_NoEmailStillNil(t *testing.T) {
	st := openTestStore(t)
	mailer := &fakeMailer{enabled: true, sendCh: make(chan sentEmail, 4)}
	grants := newTestGrantService(t, st, nil, mailer, discardAudit{})

	if err := grants.RequestSelfServiceRecovery(t.Context(), "nobody@example.com", "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}
	assertNoSendWithin(t, mailer.sendCh, selfServiceRecoveryNoSendWindow)
}

func TestGrantService_RequestSelfServiceRecovery_OIDCOnlyNoPasskey_NoEmailNoGrant(t *testing.T) {
	st := openTestStore(t)
	mailer := &fakeMailer{enabled: true, sendCh: make(chan sentEmail, 4)}
	grants := newTestGrantService(t, st, nil, mailer, NewAuditWriter(st))
	u, err := st.Users().Create(t.Context(), store.User{
		Email: "oidc-only@example.com", Role: "user", OIDCProvider: "https://idp", OIDCSubject: "sub-1",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	if err := grants.RequestSelfServiceRecovery(t.Context(), u.Email, "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}
	assertNoSendWithin(t, mailer.sendCh, selfServiceRecoveryNoSendWindow)

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "passkey.recovery_issued"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 0 {
		t.Errorf("passkey.recovery_issued entries = %d, want 0 (no grant minted)", len(page.Rows))
	}
}

func TestGrantService_RequestSelfServiceRecovery_DisabledTarget_NoEmailNoGrant(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	mailer := &fakeMailer{enabled: true, sendCh: make(chan sentEmail, 4)}
	grants := newTestGrantService(t, st, passkeys, mailer, NewAuditWriter(st))

	u := seedUser(t, st, "disabled@example.com", "user")
	seedUser(t, st, "admin@example.com", "admin")
	registerPasskey(t, passkeys, u.ID, "Existing Key", testRP())
	if err := st.Users().SetDisabled(t.Context(), u.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}

	if err := grants.RequestSelfServiceRecovery(t.Context(), u.Email, "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}

	// #89: a disabled account keeps its passkeys (applyDisabled revokes
	// sessions only), so the passkey-count gate passes and, without a Disabled
	// check, the link is minted and mailed — and redeeming it revokes every
	// passkey for a login that is refused anyway. Nothing may go out: not the
	// recovery mail, not the admin notification.
	assertNoSendWithin(t, mailer.sendCh, selfServiceRecoveryNoSendWindow)

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "passkey.recovery_issued"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 0 {
		t.Errorf("passkey.recovery_issued entries = %d, want 0 (no grant minted for a disabled account)", len(page.Rows))
	}

	creds, err := st.WebAuthnCredentials().ListByUser(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("passkeys after request = %d, want 1 (untouched)", len(creds))
	}
}

func TestGrantService_RequestSelfServiceRecovery_HappyPath_EmailsUserAndAdmins(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	mailer := &fakeMailer{enabled: true, sendCh: make(chan sentEmail, 4)}
	grants := newTestGrantService(t, st, passkeys, mailer, discardAudit{})

	u := seedUser(t, st, "alice@example.com", "user")
	admin := seedUser(t, st, "admin@example.com", "admin")
	rp := testRP()
	registerPasskey(t, passkeys, u.ID, "Existing Key", rp)

	if err := grants.RequestSelfServiceRecovery(t.Context(), u.Email, "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}

	first := waitForSend(t, mailer.sendCh, selfServiceRecoveryWaitTimeout)
	second := waitForSend(t, mailer.sendCh, selfServiceRecoveryWaitTimeout)
	sent := []sentEmail{first, second}

	var gotUser, gotAdmin bool
	for _, m := range sent {
		switch m.to {
		case u.Email:
			gotUser = true
		case admin.Email:
			gotAdmin = true
		}
	}
	if !gotUser || !gotAdmin {
		t.Errorf("expected emails to %q and %q, got %+v", u.Email, admin.Email, sent)
	}

	// Confirm-then-revoke: the request must NOT revoke the user's existing
	// passkeys — revocation is deferred to redeem (proven mailbox possession),
	// so a pre-auth request cannot lock anyone out.
	creds, err := st.WebAuthnCredentials().ListByUser(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("passkeys after RequestSelfServiceRecovery = %d, want 1 (revoke deferred to redeem)", len(creds))
	}
}

func TestGrantService_SelfServiceRecoveryRedeem_RevokesOldRegistersOne(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	mailer := &fakeMailer{enabled: true, sendCh: make(chan sentEmail, 4)}
	grants := newTestGrantService(t, st, passkeys, mailer, NewAuditWriter(st))

	u := seedUser(t, st, "alice@example.com", "user")
	rp := testRP()
	oldStored, _, _ := registerPasskey(t, passkeys, u.ID, "Old Key", rp)

	if err := grants.RequestSelfServiceRecovery(t.Context(), u.Email, "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}
	// The self-service link is emailed to the user first (before any
	// admin-notify sends); wait for that send and recover its token to drive
	// the redeem, exactly as a user clicking the link would.
	userSend := waitForSend(t, mailer.sendCh, selfServiceRecoveryWaitTimeout)
	token := extractToken(t, extractLinkFromBody(t, userSend.body))

	if err := driveRedeem(t, grants, token, "New Key", rp); err != nil {
		t.Fatalf("driveRedeem: %v", err)
	}

	creds, err := st.WebAuthnCredentials().ListByUser(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("passkeys after self-service redeem = %d, want exactly 1 (old revoked, new registered)", len(creds))
	}
	if string(creds[0].CredentialID) == string(oldStored.CredentialID) {
		t.Error("surviving credential is the OLD one; want the freshly-registered credential (old must be revoked at redeem)")
	}
}

func TestGrantService_InviteRedeem_DoesNotRevokeExistingPasskeys(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	grants := newTestGrantService(t, st, passkeys, &fakeMailer{}, NewAuditWriter(st))

	u := seedUser(t, st, "alice@example.com", "user")
	rp := testRP()
	// A user who already has a passkey being invited (edge case): invite
	// redeem must ADD, never revoke — the reason-aware revoke fires only for
	// recovery grants.
	registerPasskey(t, passkeys, u.ID, "Existing Key", rp)

	link, _, err := grants.IssueInvite(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	if err := driveRedeem(t, grants, extractToken(t, link), "Invited Key", rp); err != nil {
		t.Fatalf("driveRedeem: %v", err)
	}

	creds, err := st.WebAuthnCredentials().ListByUser(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("passkeys after invite redeem = %d, want 2 (invite adds, never revokes)", len(creds))
	}
}

// slowMailer is a test double whose Send blocks until release is closed,
// simulating a real SMTP round-trip (100s of ms). Used to prove
// RequestSelfServiceRecovery's response latency does not depend on
// account-specific work (the account-enumeration timing channel this fix
// closes) — the caller must get its nil back long before Send unblocks.
type slowMailer struct {
	enabled bool
	release <-chan struct{}
}

func (m *slowMailer) Enabled() bool { return m.enabled }

func (m *slowMailer) Send(_ context.Context, _, _, _ string) error {
	<-m.release
	return nil
}

var _ email.Mailer = (*slowMailer)(nil)

func TestGrantService_RequestSelfServiceRecovery_ReturnsImmediately_BeforeSendCompletes(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) }) // let the detached goroutine's Send unblock so it doesn't leak past the test
	mailer := &slowMailer{enabled: true, release: release}
	grants := newTestGrantService(t, st, passkeys, mailer, discardAudit{})

	u := seedUser(t, st, "alice@example.com", "user")
	rp := testRP()
	registerPasskey(t, passkeys, u.ID, "Existing Key", rp)

	start := time.Now()
	if err := grants.RequestSelfServiceRecovery(t.Context(), u.Email, "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Fatalf("RequestSelfServiceRecovery took %v to return, want near-instant — the account-existence-sensitive work (including the slow Send) must run in a detached goroutine, not on the caller's path, or response latency leaks whether the account exists", elapsed)
	}
}

func TestGrantService_RequestSelfServiceRecovery_NilMailer_NoPanicNilError(t *testing.T) {
	st := openTestStore(t)
	// A nil email.Mailer must be treated as "not configured" — same uniform
	// no-op outcome as a disabled mailer, never a panic on s.mailer.Enabled().
	grants := NewGrantService(st, nil, nil, "https://ddns.example.com", discardAudit{}, discardLogger(), testLinkTTL)

	if err := grants.RequestSelfServiceRecovery(t.Context(), "anyone@example.com", "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery with nil mailer: %v, want nil", err)
	}
}

func TestGrantService_RequestSelfServiceRecovery_MailerDisabled_NoEmailNoGrant(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	mailer := &fakeMailer{enabled: false, sendCh: make(chan sentEmail, 4)}
	grants := newTestGrantService(t, st, passkeys, mailer, NewAuditWriter(st))

	u := seedUser(t, st, "alice@example.com", "user")
	rp := testRP()
	registerPasskey(t, passkeys, u.ID, "Existing Key", rp)

	if err := grants.RequestSelfServiceRecovery(t.Context(), u.Email, "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}
	assertNoSendWithin(t, mailer.sendCh, selfServiceRecoveryNoSendWindow)
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "passkey.recovery_issued"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 0 {
		t.Errorf("passkey.recovery_issued entries = %d, want 0 (mailer disabled, D11)", len(page.Rows))
	}
}

func TestIssueInvite_DeliversWhenMailerEnabled(t *testing.T) {
	st := openTestStore(t)
	mailer := &fakeMailer{enabled: true}
	grants := newTestGrantService(t, st, newTestPasskeyService(t, st, discardAudit{}), mailer, discardAudit{})
	u := seedUser(t, st, "invitee@x.com", "user")

	link, d, err := grants.IssueInvite(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	if link == "" {
		t.Fatal("IssueInvite returned an empty link")
	}
	if !d.Attempted || !d.Sent() || d.To != "invitee@x.com" {
		t.Errorf("Delivery = %+v, want Attempted=true Sent=true To=invitee@x.com", d)
	}
	sent := mailer.Sent()
	if len(sent) != 1 {
		t.Fatalf("mailer received %d messages, want 1", len(sent))
	}
	if !strings.Contains(sent[0].body, link) {
		t.Errorf("sent body does not contain the link\nbody: %s\nlink: %s", sent[0].body, link)
	}
}

// TestIssueInvite_SendFailureStillReturnsLink is THE load-bearing assertion of
// this change: a delivery failure must never cost the admin the link, because
// the link on screen is the only fallback.
func TestIssueInvite_SendFailureStillReturnsLink(t *testing.T) {
	st := openTestStore(t)
	mailer := &fakeMailer{enabled: true, sendErr: errors.New("smtp exploded")}
	grants := newTestGrantService(t, st, newTestPasskeyService(t, st, discardAudit{}), mailer, discardAudit{})
	u := seedUser(t, st, "invitee@x.com", "user")

	link, d, err := grants.IssueInvite(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueInvite returned an error for a SEND failure: %v — the send must never fail the call", err)
	}
	if link == "" {
		t.Fatal("IssueInvite returned an empty link after a send failure")
	}
	if !d.Attempted || d.Sent() || d.Err == nil {
		t.Errorf("Delivery = %+v, want Attempted=true Sent=false Err!=nil", d)
	}
}

// TestIssueInvite_SendFailureAuditsWithActor covers design D8: the failure must
// leave a trace naming the admin who triggered it.
func TestIssueInvite_SendFailureAuditsWithActor(t *testing.T) {
	st := openTestStore(t)
	mailer := &fakeMailer{enabled: true, sendErr: errors.New("smtp exploded")}
	grants := newTestGrantService(t, st, newTestPasskeyService(t, st, discardAudit{}), mailer, NewAuditWriter(st))
	u := seedUser(t, st, "invitee@x.com", "user")

	if _, _, err := grants.IssueInvite(t.Context(), "admin-id", u); err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "email.send_failed"}, "", 10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	// AuditPage's field is Rows, not Entries (store/audit_log.go:34-37). The
	// same idiom is already used at grants_test.go:493.
	if len(page.Rows) != 1 {
		t.Fatalf("email.send_failed entries = %d, want 1", len(page.Rows))
	}
	if got := page.Rows[0].ActorUserID; got != "admin-id" {
		t.Errorf("ActorUserID = %q, want admin-id", got)
	}
	if got := page.Rows[0].TargetID; got != u.ID {
		t.Errorf("TargetID = %q, want %q", got, u.ID)
	}
}

// TestIssueInvite_DisabledMailerReportsNotAttempted covers the default
// deployment. noopMailer.Send returns nil, so a nil error alone would read as
// "sent" — Attempted is what distinguishes them.
func TestIssueInvite_DisabledMailerReportsNotAttempted(t *testing.T) {
	st := openTestStore(t)
	mailer := &fakeMailer{enabled: false}
	grants := newTestGrantService(t, st, newTestPasskeyService(t, st, discardAudit{}), mailer, discardAudit{})
	u := seedUser(t, st, "invitee@x.com", "user")

	link, d, err := grants.IssueInvite(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	if link == "" {
		t.Fatal("IssueInvite returned an empty link")
	}
	if d.Attempted || d.Sent() {
		t.Errorf("Delivery = %+v, want Attempted=false Sent=false", d)
	}
	if len(mailer.Sent()) != 0 {
		t.Errorf("disabled mailer received %d messages, want 0", len(mailer.Sent()))
	}
}

// TestIssueInvite_NilMailerDoesNotPanic guards a supported state: grants.go
// already checks s.mailer == nil on the self-service path, and live
// constructions pass nil.
func TestIssueInvite_NilMailerDoesNotPanic(t *testing.T) {
	st := openTestStore(t)
	grants := newTestGrantService(t, st, newTestPasskeyService(t, st, discardAudit{}), nil, discardAudit{})
	u := seedUser(t, st, "invitee@x.com", "user")

	link, d, err := grants.IssueInvite(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueInvite with a nil mailer: %v", err)
	}
	if link == "" {
		t.Fatal("IssueInvite returned an empty link")
	}
	if d.Attempted {
		t.Error("Delivery.Attempted = true for a nil mailer, want false")
	}
}

// TestIssueRecovery_DeliversAdminRecoveryBody proves admin recovery uses its OWN
// body — the self-service one tells the reader they can safely ignore the email,
// which is false once the passkeys are revoked.
func TestIssueRecovery_DeliversAdminRecoveryBody(t *testing.T) {
	st := openTestStore(t)
	mailer := &fakeMailer{enabled: true}
	grants := newTestGrantService(t, st, newTestPasskeyService(t, st, discardAudit{}), mailer, discardAudit{})
	u := seedUser(t, st, "victim@x.com", "user")

	link, d, err := grants.IssueRecovery(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueRecovery: %v", err)
	}
	if !d.Sent() || d.To != "victim@x.com" {
		t.Errorf("Delivery = %+v, want Sent=true To=victim@x.com", d)
	}
	sent := mailer.Sent()
	if len(sent) != 1 {
		t.Fatalf("mailer received %d messages, want 1", len(sent))
	}
	if !strings.Contains(sent[0].body, link) {
		t.Error("sent body does not contain the link")
	}
	if strings.Contains(strings.ToLower(sent[0].body), "safely ignore") {
		t.Errorf("admin recovery used the SELF-SERVICE body:\n%s", sent[0].body)
	}
}

// TestIssueRecovery_IssuanceFailureSendsNothing covers design §6.1: when nothing
// was minted, nothing may be sent. A nil PasskeyService makes IssueRecovery fail
// its guard before minting.
func TestIssueRecovery_IssuanceFailureSendsNothing(t *testing.T) {
	st := openTestStore(t)
	mailer := &fakeMailer{enabled: true}
	grants := newTestGrantService(t, st, nil, mailer, discardAudit{})
	u := seedUser(t, st, "victim@x.com", "user")

	link, d, err := grants.IssueRecovery(t.Context(), "admin-id", u)
	if !errors.Is(err, ErrWebAuthnUnavailable) {
		t.Fatalf("err = %v, want ErrWebAuthnUnavailable", err)
	}
	if link != "" {
		t.Errorf("link = %q, want empty on issuance failure", link)
	}
	if d.Attempted {
		t.Error("Delivery.Attempted = true after an issuance failure, want false")
	}
	if len(mailer.Sent()) != 0 {
		t.Errorf("mailer received %d messages after an issuance failure, want 0", len(mailer.Sent()))
	}
}

// TestAuditSendFailure_WritesOnAnExpiredContext pins the invariant BOTH send
// paths depend on — deliver (admin) and doSelfServiceRecovery (self-service).
// An expired context must still produce a row, because the context that bounds
// a send is exactly the context that is dead when that send fails.
func TestAuditSendFailure_WritesOnAnExpiredContext(t *testing.T) {
	st := openTestStore(t)
	grants := newTestGrantService(t, st, newTestPasskeyService(t, st, discardAudit{}), &fakeMailer{}, NewAuditWriter(st))

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // stand in for a send context that has already run out

	grants.auditSendFailure(ctx, store.AuditEntry{
		EventType: "email.send_failed", TargetType: "user", TargetID: "u-1",
	})

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "email.send_failed"}, "", 10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("email.send_failed entries = %d, want 1 — an expired context must not lose the row", len(page.Rows))
	}
	if got := page.Rows[0].TargetID; got != "u-1" {
		t.Errorf("TargetID = %q, want u-1", got)
	}
}

// TestDeliver_AuditsEvenWhenTheSendContextExpires pins one thing: deliver must
// not bypass auditSendFailure. It reproduces the production shape a fast-failing
// mailer cannot — internal/email sets the connection deadline FROM the send
// context, so a stalled peer makes Send return at exactly the moment sendCtx
// expires — and requires a row anyway.
//
// It does NOT pin WHICH context deliver hands to auditSendFailure, and must not
// be read as if it did: deliver passes the live ctx (here t.Context()), so the
// expired sendCtx never reaches the audit path, and switching deliver to sendCtx
// does not fail this test either because auditSendFailure's own WithoutCancel
// rescues the write. Both routes are correct, so that mutant is equivalent. The
// dead-context guarantees live in TestAuditSendFailure_WritesOnAnExpiredContext
// (the helper alone) and TestDeliver_SurvivesCanceledRequestContext (a canceled
// request context through deliver).
func TestDeliver_AuditsEvenWhenTheSendContextExpires(t *testing.T) {
	st := openTestStore(t)
	mailer := &fakeMailer{enabled: true, sendErr: errors.New("stalled"), sendDelay: 20 * time.Millisecond}
	grants := newTestGrantService(t, st, newTestPasskeyService(t, st, discardAudit{}), mailer, NewAuditWriter(st))
	grants.deliveryTimeout = time.Millisecond // force sendCtx to expire during Send
	u := seedUser(t, st, "invitee@x.com", "user")

	d := grants.deliver(t.Context(), "admin-id", u, "subject", "body")
	if d.Err == nil {
		t.Fatal("Delivery.Err = nil, want the send failure")
	}

	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "email.send_failed"}, "", 10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("email.send_failed entries = %d, want 1 — the audit write must not reuse the expired send context", len(page.Rows))
	}
}

// TestDeliver_ReadsDeliveryTimeoutLiveNotAtConstruction pins the design's
// pass-3 ruling: (*GrantService).mail() must build mailDeps by reading
// s.deliveryTimeout AT CALL TIME — a method invoked per call, never a value
// snapshotted once into a field at construction. Task 4 gives
// EmailChangeService a cached `mail mailDeps` field by design, so a later
// "tidy-up" that gives GrantService the same cached field for symmetry must
// fail here, loudly, rather than pass silently.
//
// sendErrFromCtx (not the unconditional sendErr other tests use) is required
// to make this provable: it fails Send only when sendCtx has genuinely
// expired during sendDelay. grants.deliveryTimeout is shrunk to 1ms AFTER
// construction (which set it to the 12s adminDeliveryTimeout) — a live read
// sees the 1ms value and sendCtx expires mid-sendDelay; a value cached at
// construction would still carry 12s and sendCtx would never expire, so Send
// would return nil and this test would see Delivery.Err == nil instead.
func TestDeliver_ReadsDeliveryTimeoutLiveNotAtConstruction(t *testing.T) {
	st := openTestStore(t)
	mailer := &fakeMailer{enabled: true, sendDelay: 20 * time.Millisecond, sendErrFromCtx: true}
	grants := newTestGrantService(t, st, newTestPasskeyService(t, st, discardAudit{}), mailer, NewAuditWriter(st))
	grants.deliveryTimeout = time.Millisecond // set AFTER construction; a cached mail() would miss this
	u := seedUser(t, st, "invitee@x.com", "user")

	d := grants.deliver(t.Context(), "admin-id", u, "subject", "body")
	if d.Err == nil {
		t.Fatal("Delivery.Err = nil, want a context-deadline failure — deliver must read s.deliveryTimeout live, not a value cached at construction")
	}
}

// TestIssueRecovery_DisabledTargetIsNotEmailed is #82. Login is refused anyway
// (service/passkey.go, auth/session.go), so emailing a disabled user invites
// them into a flow that cannot succeed.
//
// The #52 invariant is preserved and asserted here: err == nil means the link is
// valid and MUST be shown, whatever Delivery says. The admin keeps the
// out-of-band path, so recover-then-re-enable still works as one flow.
func TestIssueRecovery_DisabledTargetIsNotEmailed(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	mailer := &fakeMailer{enabled: true, sendCh: make(chan sentEmail, 4)}
	grants := newTestGrantService(t, st, passkeys, mailer, discardAudit{})

	u := seedUser(t, st, "disabled@example.test", "user")
	u.Disabled = true
	if err := st.Users().Update(t.Context(), u); err != nil {
		t.Fatalf("Update: %v", err)
	}

	link, delivery, err := grants.IssueRecovery(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueRecovery: %v, want nil — the link must still be minted and shown", err)
	}
	if link == "" {
		t.Fatal("link is empty; #52's invariant is that err == nil means a valid link")
	}
	if delivery.Attempted {
		t.Error("Delivery.Attempted = true; no transport may be invoked for a disabled target")
	}
	if delivery.Sent() {
		t.Error("Delivery.Sent() = true for a suppressed send")
	}
	if delivery.Suppressed != SuppressUserDisabled {
		t.Errorf("Delivery.Suppressed = %q, want %q", delivery.Suppressed, SuppressUserDisabled)
	}
	if got := mailer.Sent(); len(got) != 0 {
		t.Errorf("mailer recorded %d sends, want 0: %+v", len(got), got)
	}
}

// TestIssueRecovery_EnabledTargetIsUnchanged keeps the guard honest: the change
// must not be satisfiable by suppressing every send.
func TestIssueRecovery_EnabledTargetIsUnchanged(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	mailer := &fakeMailer{enabled: true, sendCh: make(chan sentEmail, 4)}
	grants := newTestGrantService(t, st, passkeys, mailer, discardAudit{})
	u := seedUser(t, st, "active@example.test", "user")

	_, delivery, err := grants.IssueRecovery(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueRecovery: %v", err)
	}
	if !delivery.Sent() {
		t.Fatalf("Delivery.Sent() = false for an enabled target: %+v", delivery)
	}
	if delivery.Suppressed != SuppressNone {
		t.Errorf("Delivery.Suppressed = %q, want the zero value", delivery.Suppressed)
	}
}

// TestIssueRecovery_DisabledWinsOverNoMailer pins P2's precedence. A disabled
// target with no mailer configured reports user_disabled, not the
// email-not-configured state: it is the fact the admin can act on (re-enable the
// account), it is true regardless of SMTP, and it keeps the suppression
// contained inside IssueRecovery.
func TestIssueRecovery_DisabledWinsOverNoMailer(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	grants := newTestGrantService(t, st, passkeys, nil, discardAudit{})

	u := seedUser(t, st, "disabled@example.test", "user")
	u.Disabled = true
	if err := st.Users().Update(t.Context(), u); err != nil {
		t.Fatalf("Update: %v", err)
	}

	_, delivery, err := grants.IssueRecovery(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueRecovery: %v", err)
	}
	if delivery.Suppressed != SuppressUserDisabled {
		t.Errorf("Delivery.Suppressed = %q, want %q even with no mailer", delivery.Suppressed, SuppressUserDisabled)
	}
}

// TestIssueInvite_NeverSuppresses pins P3: #82 is scoped to IssueRecovery, but
// the field lands on the shared Delivery type. AdminService.CreateUserInvite
// creates store.User{Email, Role} with Disabled false, so an invited user is
// never disabled at issue. Pinned so a future change cannot drift it silently.
func TestIssueInvite_NeverSuppresses(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	mailer := &fakeMailer{enabled: true, sendCh: make(chan sentEmail, 4)}
	grants := newTestGrantService(t, st, passkeys, mailer, discardAudit{})
	u := seedUser(t, st, "invitee@example.test", "user")

	_, delivery, err := grants.IssueInvite(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	if delivery.Suppressed != SuppressNone {
		t.Errorf("Delivery.Suppressed = %q, want the zero value — IssueInvite is out of #82's scope", delivery.Suppressed)
	}
}

// TestDeliver_SurvivesCanceledRequestContext proves D6's context.WithoutCancel:
// if the admin's browser aborts, the response is lost but the user must still
// receive the link. This exercises deliver directly rather than through
// IssueInvite, because a canceled context fails at the DB insert long before the
// send — database/sql rejects an already-canceled context before reaching the
// driver, so the send would never be attempted at all.
func TestDeliver_SurvivesCanceledRequestContext(t *testing.T) {
	st := openTestStore(t)
	mailer := &fakeMailer{enabled: true, sendErr: errors.New("smtp exploded")}
	grants := newTestGrantService(t, st, newTestPasskeyService(t, st, discardAudit{}), mailer, NewAuditWriter(st))
	u := seedUser(t, st, "invitee@x.com", "user")

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // the browser has already gone away

	d := grants.deliver(ctx, "admin-id", u, "subject", "body")
	if d.Err == nil {
		t.Fatal("Delivery.Err = nil, want the injected send failure")
	}
	if err := mailer.LastCtxErr(); err != nil {
		t.Errorf("Send saw ctx.Err() = %v, want nil — WithoutCancel should have detached it", err)
	}
	// The combination D8's rationale actually describes: a CANCELED request
	// context AND a failed send. Neither the helper test nor the expiry test
	// covers it, and it is the client-disconnect path in production.
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "email.send_failed"}, "", 10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("email.send_failed entries = %d, want 1 — a canceled request context must not lose the row", len(page.Rows))
	}
}

// pollForAuditRows waits until eventType has at least want rows, or fails.
//
// The self-service flow runs in a DETACHED goroutine, so the audit write lands
// after the test's own call has returned. Polling is what makes that
// deterministic; a fixed sleep would be flaky in exactly the direction that
// hides a regression.
func pollForAuditRows(t *testing.T, st *store.Store, eventType string, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var got int
	for time.Now().Before(deadline) {
		page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: eventType}, "", 10)
		if err != nil {
			t.Fatalf("ListPaginated: %v", err)
		}
		if got = len(page.Rows); got >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s rows = %d after %v, want >= %d", eventType, got, timeout, want)
}

// selfServiceTestTimeout is the shrunk budget the #81 tests run on. It is a
// MEASUREMENT, not a guess: the pre-send work of the time (GetByEmail,
// CountWebAuthnCredentials, mintRecoveryGrant; Users().List has joined it
// since #83, design D12) was measured at 0.888-1.155ms
// under -race on go1.25.13 (see the #81 commit body), so this is ~216x the
// worst observation. Too small a value makes the flow stop BEFORE the send,
// which would pass for the wrong reason and pin nothing.
const selfServiceTestTimeout = 250 * time.Millisecond

// selfServiceTestStall is how long fakeMailer sleeps in the #81/#83 tests
// that need Send to outlast selfServiceTestTimeout. The margin (100ms) is the
// shared knowledge across both call sites: too small and a slow CI
// runner could let Send return before the budget actually expires, which
// would pass for the wrong reason and pin nothing.
const selfServiceTestStall = selfServiceTestTimeout + 100*time.Millisecond

// TestRequestSelfServiceRecovery_UserSendOutlivingTheBudgetStillNotifiesAdmins
// pins #83 and #81 together.
//
// #83: every send runs on its own deliveryTimeout (sendBounded), not on the
// store-work budget. The user's send here outlasts that budget
// (selfServiceTestStall > selfServiceTestTimeout), yet its own context must
// still be live when it returns, and the admin notice must still go out,
// because the admin list was read before any send (design D12). With the old
// shared budget, the send saw a dead context and List failed after it, so no
// admin was ever notified.
//
// #81: the email.send_failed rows are written after the store-work budget has
// expired, so they survive only because recordSendFailure detaches with
// context.WithoutCancel. database/sql rejects an expired context before
// reaching the driver. Mutation-verified: replacing auditSendFailure with
// s.audit.Log(ctx, ...) at either doSelfServiceRecovery site must turn this red.
func TestRequestSelfServiceRecovery_UserSendOutlivingTheBudgetStillNotifiesAdmins(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	mailer := &fakeMailer{
		enabled:   true,
		sendErr:   errors.New("peer stalled"),
		sendDelay: selfServiceTestStall, // every send outlasts the store-work budget
		sendCh:    make(chan sentEmail, 4),
	}
	grants := newTestGrantService(t, st, passkeys, mailer, NewAuditWriter(st))
	grants.selfServiceTimeout = selfServiceTestTimeout

	u := seedUser(t, st, "alice@example.test", "user")
	admin := seedUser(t, st, "admin@example.test", "admin")
	registerPasskey(t, passkeys, u.ID, "Existing Key", testRP())

	if err := grants.RequestSelfServiceRecovery(t.Context(), u.Email, "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}

	if sent := waitForSend(t, mailer.sendCh, selfServiceRecoveryWaitTimeout); sent.to != u.Email {
		t.Fatalf("first send went to %q, want the user %q", sent.to, u.Email)
	}
	if err := mailer.LastCtxErr(); err != nil {
		t.Fatalf("the user's send saw ctx.Err() = %v, want nil -- it must run on its own deliveryTimeout, not the %v store-work budget (#83)", err, selfServiceTestTimeout)
	}
	// Bounded, and by its own deliveryTimeout: a send with no deadline could
	// hang on a stalled peer, and one on the shared budget has less than
	// selfServiceTestTimeout left. (The admin send may already have started and
	// overwritten this; it is held to the same rule, so the check is sound.)
	if left := mailer.LastDeadlineLeft(); left <= selfServiceTestTimeout {
		t.Fatalf("send context had %v left on entry, want a deadline of its own, longer than the %v store-work budget (#83)", left, selfServiceTestTimeout)
	}
	if sent := waitForSend(t, mailer.sendCh, selfServiceRecoveryWaitTimeout); sent.to != admin.Email {
		t.Fatalf("second send went to %q, want the admin %q -- a slow user send must not starve the admin notice (#83)", sent.to, admin.Email)
	}

	// One row per failed send, both written after the budget expired (#81).
	pollForAuditRows(t, st, EventEmailSendFailed, 2, 5*time.Second)
}

// TestRequestSelfServiceRecovery_AdminSendOutlivingTheBudgetRunsOnItsOwnContext
// pins the admin-notify send site. The user's send is instant, and each of two
// admin sends outlasts the store-work budget.
//
//   - #83, per send: deliveryTimeout is 500ms, above one stall (350ms) and
//     below two. A context shared across the admin loop would be dead by the
//     second admin's send; one context per send is still live.
//   - #81: the failure rows are written after the store-work budget expired,
//     and must survive.
func TestRequestSelfServiceRecovery_AdminSendOutlivingTheBudgetRunsOnItsOwnContext(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	mailer := &fakeMailer{
		enabled:       true,
		sendErr:       errors.New("peer stalled"),
		sendDelay:     selfServiceTestStall,
		delayFromCall: 2, // send 1 (the user) is instant; every admin send stalls
		sendCh:        make(chan sentEmail, 4),
	}
	grants := newTestGrantService(t, st, passkeys, mailer, NewAuditWriter(st))
	grants.selfServiceTimeout = selfServiceTestTimeout
	grants.deliveryTimeout = 500 * time.Millisecond // > one selfServiceTestStall, < two

	u := seedUser(t, st, "alice@example.test", "user")
	admin1 := seedUser(t, st, "admin1@example.test", "admin")
	admin2 := seedUser(t, st, "admin2@example.test", "admin")
	registerPasskey(t, passkeys, u.ID, "Existing Key", testRP())

	if err := grants.RequestSelfServiceRecovery(t.Context(), u.Email, "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}
	waitForSend(t, mailer.sendCh, selfServiceRecoveryWaitTimeout) // the user send
	got := map[string]bool{}
	for range 2 {
		got[waitForSend(t, mailer.sendCh, selfServiceRecoveryWaitTimeout).to] = true
	}
	if !got[admin1.Email] || !got[admin2.Email] {
		t.Fatalf("admin sends went to %v, want both %s and %s", got, admin1.Email, admin2.Email)
	}
	// The SECOND admin's send: live only if it had a context of its own.
	if err := mailer.LastCtxErr(); err != nil {
		t.Fatalf("the second admin's send saw ctx.Err() = %v, want nil -- each send must run on its own deliveryTimeout (#83)", err)
	}
	if left := mailer.LastDeadlineLeft(); left <= selfServiceTestTimeout {
		t.Fatalf("the second admin's send had %v left on entry, want a deadline of its own, longer than the %v store-work budget", left, selfServiceTestTimeout)
	}

	// Three rows: the instant user send also returns sendErr. With the admin
	// site reverted to s.audit.Log(ctx, ...) only the first survives.
	pollForAuditRows(t, st, EventEmailSendFailed, 3, 5*time.Second)
}

// syncBuffer is a bytes.Buffer safe for a slog handler on the detached
// goroutine to write while the test reads it. The race detector flags an
// unsynchronised bytes.Buffer here.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestEnabledAdmins_ExhaustedBudgetIsNotBlamedOnTheDatabase is #83a, moved with
// the List call (design D12, D13). The admin list is now read before any send,
// so an exhausted budget there means the store work itself was slow. It still
// must not be reported as a store failure.
//
// Driven directly with an already-expired context: database/sql rejects it
// before reaching the driver (see TestDeliver_SurvivesCanceledRequestContext),
// so List fails deterministically, without relying on a mailer that ignores its
// context.
func TestEnabledAdmins_ExhaustedBudgetIsNotBlamedOnTheDatabase(t *testing.T) {
	st := openTestStore(t)
	var buf syncBuffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	grants := NewGrantService(st, nil, &fakeMailer{enabled: true}, "https://ddns.example.com", NewAuditWriter(st), log, testLinkTTL)
	seedUser(t, st, "admin@example.test", "admin")

	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if got := grants.enabledAdmins(ctx); got != nil {
		t.Fatalf("enabledAdmins on an expired context = %v, want nil", got)
	}
	out := buf.String()
	if !strings.Contains(out, "budget exhausted before listing admins") {
		t.Errorf("log does not name the exhausted budget; got:\n%s", out)
	}
	if strings.Contains(out, "list admins failed") {
		t.Errorf("an exhausted budget must not be reported as a store failure; got:\n%s", out)
	}
}

// TestEnabledAdmins_ReturnsOnlyEnabledAdmins: the filter moved out of the send
// loop with the List call, so it is pinned here, both halves of IsEnabledAdmin.
func TestEnabledAdmins_ReturnsOnlyEnabledAdmins(t *testing.T) {
	st := openTestStore(t)
	grants := newTestGrantService(t, st, nil, &fakeMailer{enabled: true}, NewAuditWriter(st))
	admin := seedUser(t, st, "admin@example.test", "admin")
	seedUser(t, st, "user@example.test", "user")
	disabled := seedUser(t, st, "disabled-admin@example.test", "admin")
	if err := st.Users().SetDisabled(t.Context(), disabled.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}

	got := grants.enabledAdmins(t.Context())
	if len(got) != 1 || got[0].ID != admin.ID {
		t.Fatalf("enabledAdmins = %+v, want exactly the enabled admin %s", got, admin.ID)
	}
}

// TestIssueInvite_NonASCIIBaseURLFailsTheSendLoudly closes route 5 end to end.
// GrantService.baseURL comes from cfg.Server.BaseURL and is prefixed onto every
// minted link, which is then interpolated into the body — so a non-ASCII
// base_url puts raw UTF-8 in the BODY while from and to are both ASCII. That is
// the vector a from/to-only check passes.
//
// The #52 invariant is unchanged and is asserted here: err == nil, so the link
// is valid and MUST still be shown. Only the delivery fails.
func TestIssueInvite_NonASCIIBaseURLFailsTheSendLoudly(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	// A REAL mailer, so the send path's own checkSendable runs. No fake listener
	// is needed and none exists in this package: checkSendable fires BEFORE dial,
	// so the deliberately unreachable 127.0.0.1:1 is never touched.
	mailer := email.New(config.EmailSection{
		Enabled: true, Host: "127.0.0.1", Port: 1, From: "noreply@example.test", TLS: "none",
	}, discardLogger())
	grants := NewGrantService(st, passkeys, mailer, "https://exämple.test", NewAuditWriter(st), discardLogger(), testLinkTTL)
	u := seedUser(t, st, "invitee@example.test", "user")

	link, delivery, err := grants.IssueInvite(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueInvite: %v, want nil — a delivery failure must never cost the admin the link", err)
	}
	if link == "" {
		t.Fatal("link is empty; the #52 invariant is that err == nil means the link is valid and must be shown")
	}
	if delivery.Err == nil {
		t.Fatal("Delivery.Err = nil; a non-ASCII base_url must fail the send, not be reported as delivered")
	}
	if !errors.Is(delivery.Err, email.ErrNotASCII) {
		t.Errorf("Delivery.Err = %v, want it to wrap ErrNotASCII", delivery.Err)
	}
}

// TestSendAdvisory_MailsTheRecipientItIsGiven pins the one thing the #131
// extraction adds over deliver: the recipient is a parameter, not u.Email.
// An email change mails an address that is NOT (yet, or any more) on the row.
func TestSendAdvisory_MailsTheRecipientItIsGiven(t *testing.T) {
	st := openTestStore(t)
	mailer := &fakeMailer{enabled: true}
	m := mailDeps{mailer: mailer, audit: NewAuditWriter(st), log: discardLogger(), timeout: time.Second}

	d := sendAdvisory(t.Context(), m, "actor-1", "target-1", "elsewhere@example.com", "subj", "body")
	if !d.Sent() || d.To != "elsewhere@example.com" {
		t.Fatalf("Delivery = %+v, want Sent to elsewhere@example.com", d)
	}
	sent := mailer.Sent()
	if len(sent) != 1 || sent[0].to != "elsewhere@example.com" {
		t.Fatalf("sent = %+v, want exactly one mail to elsewhere@example.com", sent)
	}

	// Nil mailer is a supported state: nothing attempted, nothing audited.
	if d := sendAdvisory(t.Context(), mailDeps{log: discardLogger(), timeout: time.Second}, "a", "t", "x@example.com", "s", "b"); d.Attempted {
		t.Fatalf("nil mailer: Delivery = %+v, want Attempted false", d)
	}

	// A failed send audits email.send_failed against targetUserID.
	failing := &fakeMailer{enabled: true, sendErr: errors.New("boom")}
	m.mailer = failing
	if d := sendAdvisory(t.Context(), m, "actor-1", "target-1", "x@example.com", "s", "b"); d.Err == nil {
		t.Fatal("Delivery.Err = nil, want the send failure")
	}
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: EventEmailSendFailed}, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0].TargetID != "target-1" || page.Rows[0].ActorUserID != "actor-1" {
		t.Fatalf("audit rows = %+v, want one email.send_failed for target-1 by actor-1", page.Rows)
	}
}

// TestRequestSelfServiceRecovery_UnmailableStoredAddressStillNotifiesEveryAdmin
// is #90. A row stored before #80's boundary validations can hold a non-ASCII
// address. The admin notice is ONE body sent to every admin, so before the fold
// that address made the transport refuse the notice for every admin, on a
// pre-auth path. Now only the user's own send fails (its To is unmailable), and
// every admin gets a notice naming the account by id.
func TestRequestSelfServiceRecovery_UnmailableStoredAddressStillNotifiesEveryAdmin(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	mailer := &fakeMailer{enabled: true, refuseNonASCII: true, sendCh: make(chan sentEmail, 4)}
	grants := newTestGrantService(t, st, passkeys, mailer, NewAuditWriter(st))

	u := seedUser(t, st, "josé@example.test", "user") // a legacy row: seedUser bypasses the service's validation
	admin1 := seedUser(t, st, "admin1@example.test", "admin")
	admin2 := seedUser(t, st, "admin2@example.test", "admin")
	registerPasskey(t, passkeys, u.ID, "Existing Key", testRP())

	if err := grants.RequestSelfServiceRecovery(t.Context(), u.Email, "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}
	byRecipient := map[string]sentEmail{}
	for range 3 { // the user, then each admin
		e := waitForSend(t, mailer.sendCh, selfServiceRecoveryWaitTimeout)
		byRecipient[e.to] = e
	}
	for _, a := range []store.User{admin1, admin2} {
		e, ok := byRecipient[a.Email]
		if !ok {
			t.Fatalf("admin %s was never sent the notice; sends: %v", a.Email, mailer.Sent())
		}
		if !email.IsASCII(e.body) {
			t.Errorf("admin notice body is not ASCII, so the transport would refuse it: %q", e.body)
		}
		if !strings.Contains(e.body, u.ID) {
			t.Errorf("admin notice body %q does not name the account id %q", e.body, u.ID)
		}
	}

	// Exactly one failure row, for the user's own unmailable address. Before
	// the fold there were three: the user plus one per admin.
	pollForAuditRows(t, st, EventEmailSendFailed, 1, 5*time.Second)
	time.Sleep(100 * time.Millisecond) // let any further (wrong) rows land before counting
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: EventEmailSendFailed}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 || page.Rows[0].TargetID != u.ID {
		t.Fatalf("email.send_failed rows = %+v, want exactly one, for the user %s", page.Rows, u.ID)
	}
}

// seedGrant plants a grant row for userID with the given reason, expiry and
// consumption time (0 means unconsumed) and returns the raw token that
// hashes to it.
func seedGrant(t *testing.T, st *store.Store, userID, reason string, expiresAt, usedAt int64) string {
	t.Helper()
	token, err := auth.RandToken(32)
	if err != nil {
		t.Fatalf("RandToken: %v", err)
	}
	if err := st.AccountRecovery().Create(t.Context(), store.RecoveryToken{
		TokenHash: auth.HashToken(token), UserID: userID, Reason: reason, ExpiresAt: expiresAt, UsedAt: usedAt,
	}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	return token
}

// beginRedeem runs RedeemBegin for token and returns the sealed challenge
// cookie plus the authenticator's attestation response for it, so a test can
// call RedeemFinish later, after changing the world in between.
func beginRedeem(t *testing.T, grants *GrantService, token string) (sealed, attResp string) {
	t.Helper()
	_, optsJSON, sealed, err := grants.RedeemBegin(t.Context(), token)
	if err != nil {
		t.Fatalf("RedeemBegin: %v", err)
	}
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(optsJSON))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v", err)
	}
	authr := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(attOpts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)
	return sealed, virtualwebauthn.CreateAttestationResponse(testRP(), authr, cred, *attOpts)
}

// newClassifyGrants builds a GrantService with passkeys over a fresh store.
func newClassifyGrants(t *testing.T) (*store.Store, *GrantService) {
	t.Helper()
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	return st, newTestGrantService(t, st, passkeys, &fakeMailer{}, NewAuditWriter(st))
}

func TestGrantService_ClassifyRegistration(t *testing.T) {
	now := store.NowUnix()
	tests := []struct {
		name string
		// token plants the grant (if any) for user and returns the token to classify.
		token func(t *testing.T, st *store.Store, user store.User) string
		// wantGrant is the expected state when an admin exists; without one a
		// non-grant token is first-run instead of dead.
		wantGrant  bool
		wantReason string
		// wantLog is the reason logged when the token ends up dead (an admin
		// exists), or "" when nothing is logged. Nothing else ever logs.
		wantLog rejectReason
	}{
		{"invite", func(t *testing.T, st *store.Store, u store.User) string {
			return seedGrant(t, st, u.ID, "invite", now+3600, 0)
		}, true, "invite", ""},
		{"recovery", func(t *testing.T, st *store.Store, u store.User) string {
			return seedGrant(t, st, u.ID, "recovery", now+3600, 0)
		}, true, "recovery", ""},
		{"expired", func(t *testing.T, st *store.Store, u store.User) string {
			return seedGrant(t, st, u.ID, "invite", now-10, 0)
		}, false, "", rejectExpired},
		{"used", func(t *testing.T, st *store.Store, u store.User) string {
			return seedGrant(t, st, u.ID, "invite", now+3600, now-5)
		}, false, "", rejectUsed},
		{"unknown", func(*testing.T, *store.Store, store.User) string { return "no-such-token" }, false, "", rejectUnknown},
		{"empty", func(*testing.T, *store.Store, store.User) string { return "" }, false, "", ""},
		// D9: a live grant whose user row is gone is not live. The foreign key
		// makes this unreachable through the API, so enforcement is switched off
		// for the delete.
		{"live grant whose user is gone", func(t *testing.T, st *store.Store, u store.User) string {
			token := seedGrant(t, st, u.ID, "invite", now+3600, 0)
			for _, q := range []string{`PRAGMA foreign_keys = OFF`, `DELETE FROM users WHERE id = '` + u.ID + `'`, `PRAGMA foreign_keys = ON`} {
				if _, err := st.DB().ExecContext(t.Context(), q); err != nil {
					t.Fatalf("%s: %v", q, err)
				}
			}
			return token
		}, false, "", rejectUserMissing},
	}
	for _, tt := range tests {
		for _, withAdmin := range []bool{true, false} {
			name := tt.name + "/no admin"
			if withAdmin {
				name = tt.name + "/admin exists"
			}
			t.Run(name, func(t *testing.T) {
				st, grants, buf := newLoggedGrants(t)
				if withAdmin {
					seedUser(t, st, "admin@example.com", "admin")
				}
				user := seedUser(t, st, "alice@example.com", "user")
				token := tt.token(t, st, user)

				got, err := grants.ClassifyRegistration(t.Context(), token)
				if err != nil {
					t.Fatalf("ClassifyRegistration: %v", err)
				}

				want := RegisterTarget{State: RegisterFirstRun}
				switch {
				case tt.wantGrant:
					want = RegisterTarget{State: RegisterGrant, Reason: tt.wantReason, Email: user.Email}
				case withAdmin:
					want = RegisterTarget{State: RegisterDead}
				}
				if got != want {
					t.Errorf("ClassifyRegistration = %+v, want %+v", got, want)
				}
				switch {
				case !withAdmin || tt.wantLog == "":
					if logged := buf.String(); logged != "" {
						t.Errorf("logged for a state that must log nothing:\n%s", logged)
					}
				case tt.wantLog == rejectUnknown:
					wantRejection(t, buf, msgGrantRejected, tt.wantLog, "")
				default:
					wantRejection(t, buf, msgGrantRejected, tt.wantLog, user.ID)
				}
				assertNoSecrets(t, buf, token, auth.HashToken(token))
			})
		}
	}
}

// TestGrantService_ClassifyRegistration_StoreFailureIsAnError pins D9 for a
// real store failure: the answer is an error, never a state. A closed store
// is the only way to fail a read, because a SQLite trigger cannot abort a
// SELECT.
func TestGrantService_ClassifyRegistration_StoreFailureIsAnError(t *testing.T) {
	for _, tt := range []struct {
		name  string
		token bool
	}{
		{"with a token (the grant read fails)", true},
		{"without a token (the admin scan fails)", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st, grants := newClassifyGrants(t)
			user := seedUser(t, st, "alice@example.com", "user")
			token := ""
			if tt.token {
				token = seedGrant(t, st, user.ID, "invite", store.NowUnix()+3600, 0)
			}
			if err := st.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			got, err := grants.ClassifyRegistration(t.Context(), token)
			if err == nil {
				t.Fatalf("ClassifyRegistration on a closed store = %+v, want an error", got)
			}
			if store.Cancelled(t.Context(), err) {
				t.Errorf("a closed store reads as cancelled: %v", err)
			}
		})
	}
}

// TestGrantService_ClassifyRegistration_CancelledContext checks the error the
// handlers' store.Cancelled test relies on: it must wrap context.Canceled.
// (store.Cancelled alone would be vacuous here, because it is true for any
// error once the context is done.)
func TestGrantService_ClassifyRegistration_CancelledContext(t *testing.T) {
	st, grants := newClassifyGrants(t)
	user := seedUser(t, st, "alice@example.com", "user")
	token := seedGrant(t, st, user.ID, "invite", store.NowUnix()+3600, 0)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	for _, tok := range []string{token, ""} {
		_, err := grants.ClassifyRegistration(ctx, tok)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("ClassifyRegistration(token %q) on a cancelled context: err = %v, want context.Canceled", tok, err)
		}
	}
}

// TestGrantService_RedeemBegin_StoreFailureIsNotGrantInvalid pins D9 for
// validGrant: a store failure behind a live link is reported as a failure,
// not as "link invalid".
func TestGrantService_RedeemBegin_StoreFailureIsNotGrantInvalid(t *testing.T) {
	st, grants := newClassifyGrants(t)
	user := seedUser(t, st, "alice@example.com", "user")
	token := seedGrant(t, st, user.ID, "invite", store.NowUnix()+3600, 0)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, _, _, err := grants.RedeemBegin(t.Context(), token)
	if err == nil {
		t.Fatal("RedeemBegin on a closed store: err = nil, want an error")
	}
	if errors.Is(err, ErrGrantInvalid) {
		t.Errorf("RedeemBegin on a closed store: err = %v, must not be ErrGrantInvalid", err)
	}
}

// TestGrantService_RedeemFinish_ConsumeFailureIsNotGrantInvalid pins D9 for
// the atomic Consume: a failure other than "no row matched" is returned, the
// grant stays unconsumed, and no credential is stored.
func TestGrantService_RedeemFinish_ConsumeFailureIsNotGrantInvalid(t *testing.T) {
	st, grants := newClassifyGrants(t)
	user := seedUser(t, st, "alice@example.com", "user")
	token := seedGrant(t, st, user.ID, "invite", store.NowUnix()+3600, 0)
	sealed, attResp := beginRedeem(t, grants, token)
	if _, err := st.DB().ExecContext(t.Context(),
		`CREATE TRIGGER block_grant_update BEFORE UPDATE ON account_recovery_tokens
		 BEGIN SELECT RAISE(ABORT, 'injected consume failure'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	_, err := grants.RedeemFinish(t.Context(), token, sealed, jsonRequest(attResp), "key")
	if err == nil {
		t.Fatal("RedeemFinish with a failing Consume: err = nil, want an error")
	}
	if errors.Is(err, ErrGrantInvalid) {
		t.Errorf("RedeemFinish: err = %v, must not be ErrGrantInvalid", err)
	}

	grant, err := st.AccountRecovery().Get(t.Context(), auth.HashToken(token))
	if err != nil {
		t.Fatalf("AccountRecovery.Get: %v", err)
	}
	if grant.UsedAt != 0 {
		t.Errorf("grant.UsedAt = %d, want 0 (unconsumed)", grant.UsedAt)
	}
	creds, err := st.WebAuthnCredentials().ListByUser(t.Context(), user.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("credentials = %d, want 0", len(creds))
	}
}
