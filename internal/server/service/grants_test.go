package service

import (
	"context"
	"errors"
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
	// sendCh, when non-nil, additionally receives every sentEmail so a test
	// can block on the goroutine actually calling Send instead of racing it.
	sendCh chan sentEmail

	mu   sync.Mutex
	sent []sentEmail
}

type sentEmail struct{ to, subject, body string }

func (m *fakeMailer) Enabled() bool { return m.enabled }

func (m *fakeMailer) Send(_ context.Context, to, subject, body string) error {
	e := sentEmail{to: to, subject: subject, body: body}
	m.mu.Lock()
	m.sent = append(m.sent, e)
	m.mu.Unlock()
	if m.sendCh != nil {
		m.sendCh <- e
	}
	return nil
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
// token via virtualwebauthn, returning whatever RedeemFinish returns.
func driveRedeem(t *testing.T, grants *GrantService, token, name string, rp virtualwebauthn.RelyingParty) error {
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

	link, err := grants.IssueInvite(t.Context(), "admin-id", u.ID)
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

	if _, err := grants.IssueRecovery(t.Context(), "admin-id", u.ID); !errors.Is(err, ErrWebAuthnUnavailable) {
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

	link, err := grants.IssueRecovery(t.Context(), "admin-id", u.ID)
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

	link, err := grants.IssueInvite(t.Context(), "admin-id", u.ID)
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
