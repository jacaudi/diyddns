package service

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/jacaudi/diyddns/internal/auth"
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
	// (1-based), so a test can let an EARLY send complete inside the budget and a
	// LATER one exhaust it. That is the only way to reach the admin-notify
	// auditSendFailure site: an exhausted budget kills Users().List first.
	// Zero and one both mean "every call", so existing literals are unaffected.
	delayFromCall int
	// calls counts Send invocations, guarded by mu, for delayFromCall.
	calls int
	// sendCh, when non-nil, additionally receives every sentEmail so a test
	// can block on the goroutine actually calling Send instead of racing it.
	sendCh chan sentEmail

	mu   sync.Mutex
	sent []sentEmail
	// lastCtxErr records ctx.Err() as observed INSIDE Send, so a test can prove
	// the send context is not the caller's canceled request context.
	lastCtxErr error
}

type sentEmail struct{ to, subject, body string }

func (m *fakeMailer) Enabled() bool { return m.enabled }

func (m *fakeMailer) Send(ctx context.Context, to, subject, body string) error {
	m.mu.Lock()
	m.calls++
	n := m.calls
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
	return m.sendErr
}

// LastCtxErr reports ctx.Err() as seen inside the most recent Send.
func (m *fakeMailer) LastCtxErr() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastCtxErr
}

// Sent returns a snapshot of every email recorded so far, safe to call
// concurrently with Send.
func (m *fakeMailer) Sent() []sentEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sentEmail(nil), m.sent...)
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

// newTestGrantService builds a GrantService bound to st, using the fixed
// base URL "https://ddns.example.com" so extractToken can round-trip a
// minted link back to its raw token.
func newTestGrantService(t *testing.T, st *store.Store, passkeys *PasskeyService, mailer email.Mailer, audit AuditSink) *GrantService {
	t.Helper()
	return NewGrantService(st, passkeys, mailer, "https://ddns.example.com", audit, discardLogger())
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
	i := strings.Index(body, "https://")
	if i < 0 {
		t.Fatalf("email body has no https:// link: %q", body)
	}
	link := body[i:]
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
	grants := NewGrantService(st, nil, nil, "https://ddns.example.com", discardAudit{}, discardLogger())

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
// MEASUREMENT, not a guess: on this branch, the pre-send work (GetByEmail,
// CountWebAuthnCredentials, mintRecoveryGrant) was measured at 0.888-1.155ms
// under -race on go1.25.13 (see the #81 commit body), so this is ~216x the
// worst observation. Too small a value makes the flow stop BEFORE the send,
// which would pass for the wrong reason and pin nothing.
const selfServiceTestTimeout = 250 * time.Millisecond

// selfServiceTestStall is how long fakeMailer sleeps in the #81/#83a tests
// that need Send to outlast selfServiceTestTimeout. The margin (100ms) is the
// shared knowledge across all three call sites: too small and a slow CI
// runner could let Send return before the budget actually expires, which
// would pass for the wrong reason and pin nothing.
const selfServiceTestStall = selfServiceTestTimeout + 100*time.Millisecond

// TestRequestSelfServiceRecovery_AuditsWhenTheBudgetExpiresDuringTheUserSend
// pins grants.go's FIRST doSelfServiceRecovery auditSendFailure call -- the one
// for the user's own recovery link.
//
// It must run on a context.WithoutCancel-derived context, so the
// email.send_failed row survives the very failure it exists to record:
// internal/email derives the CONNECTION deadline from that context, so a stalled
// peer returns at exactly the moment it expires, and database/sql rejects an
// expired context before reaching the driver.
//
// Mutation-verified at ac4d56c: replacing BOTH doSelfServiceRecovery sites with
// s.audit.Log(ctx, ...) left the whole suite GREEN. deliver's third site is
// already pinned by TestDeliver_SurvivesCanceledRequestContext.
//
// The send must actually be REACHED. Asserting only that the flow ended would
// let a test that stopped early pass for the wrong reason.
func TestRequestSelfServiceRecovery_AuditsWhenTheBudgetExpiresDuringTheUserSend(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	mailer := &fakeMailer{
		enabled: true,
		sendErr: errors.New("peer stalled"),
		// Longer than the shrunk budget, so the send exhausts it and the
		// auditSendFailure call runs on an already-dead context.
		sendDelay: selfServiceTestStall,
		sendCh:    make(chan sentEmail, 4),
	}
	grants := newTestGrantService(t, st, passkeys, mailer, NewAuditWriter(st))
	grants.selfServiceTimeout = selfServiceTestTimeout

	u := seedUser(t, st, "alice@example.test", "user")
	registerPasskey(t, passkeys, u.ID, "Existing Key", testRP())

	if err := grants.RequestSelfServiceRecovery(t.Context(), u.Email, "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}

	// The send was reached -- without this the test could pass by stopping early.
	if sent := waitForSend(t, mailer.sendCh, selfServiceRecoveryWaitTimeout); sent.to != u.Email {
		t.Fatalf("sent to %q, want %q", sent.to, u.Email)
	}

	// Pin the invariant directly: the same ctx Send just saw is the ctx
	// auditSendFailure is about to be handed, so it must already be dead here
	// -- not merely inferred from the row surviving downstream.
	if err := mailer.LastCtxErr(); err == nil {
		t.Fatal("Send saw ctx.Err() = nil, want a deadline error -- the budget must already be exhausted at the audit site")
	}

	pollForAuditRows(t, st, EventEmailSendFailed, 1, 5*time.Second)
}

// TestRequestSelfServiceRecovery_AuditsWhenTheBudgetExpiresDuringTheAdminNotify
// pins the SECOND site -- the admin-notify loop -- which the test above can
// never reach.
//
// Why a second test is unavoidable: when the budget is exhausted at the user
// send, Users().List(ctx) at grants.go:332 fails on the dead context and the
// function returns at :335, so the admin loop never executes. Here the user send
// is INSTANT (delayFromCall: 2) and succeeds inside the budget, List runs on a
// live context, and only the admin send stalls past the deadline.
func TestRequestSelfServiceRecovery_AuditsWhenTheBudgetExpiresDuringTheAdminNotify(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	mailer := &fakeMailer{
		enabled:       true,
		sendErr:       errors.New("peer stalled"),
		sendDelay:     selfServiceTestStall,
		delayFromCall: 2, // send 1 (the user) is instant; send 2 (the admin) stalls
		sendCh:        make(chan sentEmail, 4),
	}
	grants := newTestGrantService(t, st, passkeys, mailer, NewAuditWriter(st))
	grants.selfServiceTimeout = selfServiceTestTimeout

	u := seedUser(t, st, "alice@example.test", "user")
	admin := seedUser(t, st, "admin@example.test", "admin")
	registerPasskey(t, passkeys, u.ID, "Existing Key", testRP())

	if err := grants.RequestSelfServiceRecovery(t.Context(), u.Email, "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}
	waitForSend(t, mailer.sendCh, selfServiceRecoveryWaitTimeout) // the user send
	// The admin send -- proves the loop was REACHED and actually reached an
	// admin, not merely that a second send of any kind occurred (a mutant that
	// re-mails the user here would pass without this assertion).
	if sent := waitForSend(t, mailer.sendCh, selfServiceRecoveryWaitTimeout); sent.to != admin.Email {
		t.Fatalf("admin send went to %q, want %q", sent.to, admin.Email)
	}

	// Pin the invariant directly: the same ctx Send just saw is the ctx
	// auditSendFailure is about to be handed, so it must already be dead here
	// -- not merely inferred from two rows surviving downstream.
	if err := mailer.LastCtxErr(); err == nil {
		t.Fatal("Send saw ctx.Err() = nil, want a deadline error -- the budget must already be exhausted at the audit site")
	}

	// Two rows: one per failed send. With the admin site reverted to
	// s.audit.Log(ctx, ...) only the first survives.
	pollForAuditRows(t, st, EventEmailSendFailed, 2, 5*time.Second)
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

// pollForLog waits until buf contains want, or fails. The line is written by
// the detached goroutine after the send returns, so polling is what makes this
// deterministic.
func pollForLog(t *testing.T, buf *syncBuffer, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("log never contained %q within %v; got:\n%s", want, timeout, buf.String())
}

// TestDoSelfServiceRecovery_ExhaustedBudgetIsNotBlamedOnTheDatabase is #83a.
// A stalled peer consumes the whole budget at the user's send, so
// Users().List(ctx) then fails on an already-dead context and the old line
// pointed a future debugger at a database that is perfectly healthy.
func TestDoSelfServiceRecovery_ExhaustedBudgetIsNotBlamedOnTheDatabase(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	var buf syncBuffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	mailer := &fakeMailer{
		enabled:   true,
		sendErr:   errors.New("peer stalled"),
		sendDelay: selfServiceTestStall,
		sendCh:    make(chan sentEmail, 4),
	}
	grants := NewGrantService(st, passkeys, mailer, "https://ddns.example.com", NewAuditWriter(st), log)
	grants.selfServiceTimeout = selfServiceTestTimeout

	u := seedUser(t, st, "alice@example.test", "user")
	registerPasskey(t, passkeys, u.ID, "Existing Key", testRP())

	if err := grants.RequestSelfServiceRecovery(t.Context(), u.Email, "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}
	waitForSend(t, mailer.sendCh, selfServiceRecoveryWaitTimeout)

	pollForLog(t, &buf, "delivery budget exhausted before notifying admins", 5*time.Second)
	if got := buf.String(); strings.Contains(got, "list admins failed") {
		t.Errorf("an exhausted budget must not be reported as a store failure; got:\n%s", got)
	}
}
