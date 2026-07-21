package service

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/descope/virtualwebauthn"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/email"
	"github.com/jacaudi/diyddns/internal/store"
)

// fakeMailer is a test double for email.Mailer: Send records every call
// instead of contacting a server, and Enabled is set by the test.
type fakeMailer struct {
	enabled bool
	sent    []sentEmail
}

type sentEmail struct{ to, subject, body string }

func (m *fakeMailer) Enabled() bool { return m.enabled }

func (m *fakeMailer) Send(_ context.Context, to, subject, body string) error {
	m.sent = append(m.sent, sentEmail{to: to, subject: subject, body: body})
	return nil
}

var _ email.Mailer = (*fakeMailer)(nil)

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
	mailer := &fakeMailer{enabled: true}
	grants := newTestGrantService(t, st, nil, mailer, discardAudit{})

	if err := grants.RequestSelfServiceRecovery(t.Context(), "nobody@example.com", "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}
	if len(mailer.sent) != 0 {
		t.Errorf("emails sent = %d, want 0 (unknown account, no enumeration)", len(mailer.sent))
	}
}

func TestGrantService_RequestSelfServiceRecovery_OIDCOnlyNoPasskey_NoEmailNoGrant(t *testing.T) {
	st := openTestStore(t)
	mailer := &fakeMailer{enabled: true}
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
	if len(mailer.sent) != 0 {
		t.Errorf("emails sent = %d, want 0 (I2 guard: no existing passkey)", len(mailer.sent))
	}

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
	mailer := &fakeMailer{enabled: true}
	grants := newTestGrantService(t, st, passkeys, mailer, discardAudit{})

	u := seedUser(t, st, "alice@example.com", "user")
	admin := seedUser(t, st, "admin@example.com", "admin")
	rp := testRP()
	registerPasskey(t, passkeys, u.ID, "Existing Key", rp)

	if err := grants.RequestSelfServiceRecovery(t.Context(), u.Email, "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}

	if len(mailer.sent) != 2 {
		t.Fatalf("emails sent = %d, want 2 (user + admin): %+v", len(mailer.sent), mailer.sent)
	}
	var gotUser, gotAdmin bool
	for _, m := range mailer.sent {
		switch m.to {
		case u.Email:
			gotUser = true
		case admin.Email:
			gotAdmin = true
		}
	}
	if !gotUser || !gotAdmin {
		t.Errorf("expected emails to %q and %q, got %+v", u.Email, admin.Email, mailer.sent)
	}
}

func TestGrantService_RequestSelfServiceRecovery_MailerDisabled_NoEmailNoGrant(t *testing.T) {
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	mailer := &fakeMailer{enabled: false}
	grants := newTestGrantService(t, st, passkeys, mailer, NewAuditWriter(st))

	u := seedUser(t, st, "alice@example.com", "user")
	rp := testRP()
	registerPasskey(t, passkeys, u.ID, "Existing Key", rp)

	if err := grants.RequestSelfServiceRecovery(t.Context(), u.Email, "1.2.3.4"); err != nil {
		t.Fatalf("RequestSelfServiceRecovery: %v", err)
	}
	if len(mailer.sent) != 0 {
		t.Errorf("emails sent = %d, want 0 (mailer disabled)", len(mailer.sent))
	}
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "passkey.recovery_issued"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 0 {
		t.Errorf("passkey.recovery_issued entries = %d, want 0 (mailer disabled, D11)", len(page.Rows))
	}
}
