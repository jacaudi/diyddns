package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

func newReinviteGrants(t *testing.T, mailer *fakeMailer) (*store.Store, *GrantService, *PasskeyService) {
	t.Helper()
	st := openTestStore(t)
	passkeys := newTestPasskeyService(t, st, discardAudit{})
	return st, newTestGrantService(t, st, passkeys, mailer, NewAuditWriter(st)), passkeys
}

func TestReissueInvite_RefusesRegisteredAccounts(t *testing.T) {
	st, grants, _ := newReinviteGrants(t, &fakeMailer{})
	withPasskey := seedUser(t, st, "passkey@example.com", "user")
	if _, err := st.WebAuthnCredentials().Create(t.Context(), store.WebAuthnCredential{
		CredentialID: []byte("cred-pk"), UserID: withPasskey.ID, CredentialJSON: []byte("{}"), Name: "k", CreatedAt: store.NowUnix(),
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	oidcOnly, err := st.Users().Create(t.Context(), store.User{
		Email: "oidc@example.com", Role: "user", OIDCProvider: "p", OIDCSubject: "sub",
	})
	if err != nil {
		t.Fatalf("seed oidc user: %v", err)
	}
	for _, u := range []store.User{withPasskey, oidcOnly} {
		if _, _, _, err := grants.ReissueInvite(t.Context(), "admin-id", u); !errors.Is(err, ErrAlreadyRegistered) {
			t.Errorf("%s: err = %v, want ErrAlreadyRegistered", u.Email, err)
		}
	}
}

func TestReissueInvite_NilPasskeysIsUnavailable(t *testing.T) {
	st := openTestStore(t)
	grants := newTestGrantService(t, st, nil, &fakeMailer{}, discardAudit{})
	u := seedUser(t, st, "nopk@example.com", "user")
	if _, _, _, err := grants.ReissueInvite(t.Context(), "admin-id", u); !errors.Is(err, ErrWebAuthnUnavailable) {
		t.Fatalf("err = %v, want ErrWebAuthnUnavailable", err)
	}
}

// TestReissueInvite_InvalidatesEarlierLinks covers D6: once a new link is
// sent, the old one fails redeem.
func TestReissueInvite_InvalidatesEarlierLinks(t *testing.T) {
	st, grants, _ := newReinviteGrants(t, &fakeMailer{})
	u := seedUser(t, st, "lost@example.com", "user")

	first, _, err := grants.IssueInvite(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	second, _, _, err := grants.ReissueInvite(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("ReissueInvite: %v", err)
	}
	if _, _, _, err := grants.RedeemBegin(t.Context(), extractToken(t, first)); !errors.Is(err, ErrGrantInvalid) {
		t.Errorf("old link RedeemBegin: err = %v, want ErrGrantInvalid", err)
	}
	if _, _, _, err := grants.RedeemBegin(t.Context(), extractToken(t, second)); err != nil {
		t.Errorf("new link RedeemBegin: %v", err)
	}
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "passkey.invite_issued"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Errorf("passkey.invite_issued entries = %d, want 2", len(page.Rows))
	}
}

func TestReissueInvite_ExpiresAtMatchesTTL(t *testing.T) {
	st, grants, _ := newReinviteGrants(t, &fakeMailer{})
	u := seedUser(t, st, "ttl@example.com", "user")

	before := store.NowUnix()
	link, expiresAt, _, err := grants.ReissueInvite(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("ReissueInvite: %v", err)
	}
	after := store.NowUnix()
	ttl := int64(testLinkTTL.Seconds())
	if expiresAt < before+ttl || expiresAt > after+ttl {
		t.Errorf("expiresAt = %d, want within [%d, %d]", expiresAt, before+ttl, after+ttl)
	}
	grant, err := st.AccountRecovery().Get(t.Context(), auth.HashToken(extractToken(t, link)))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if grant.ExpiresAt != expiresAt || grant.Reason != "invite" {
		t.Errorf("stored grant = %+v, want reason invite expiring at %d", grant, expiresAt)
	}
}

func TestReissueInvite_DisabledAccountSuppressesMail(t *testing.T) {
	mailer := &fakeMailer{enabled: true}
	st, grants, _ := newReinviteGrants(t, mailer)
	u := seedUser(t, st, "off@example.com", "user")
	u.Disabled = true
	if err := st.Users().Update(t.Context(), u); err != nil {
		t.Fatalf("Update: %v", err)
	}

	link, _, d, err := grants.ReissueInvite(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("ReissueInvite: %v", err)
	}
	if link == "" {
		t.Error("no link returned for a disabled account")
	}
	if d.Attempted || d.Suppressed != SuppressUserDisabled {
		t.Errorf("Delivery = %+v, want Suppressed=user_disabled, not attempted", d)
	}
	if n := len(mailer.Sent()); n != 0 {
		t.Errorf("mailer received %d messages, want 0", n)
	}
}

// TestReissueInvite_EmailWordingFollowsHistory covers D12: an account that
// never registered gets the invite wording; one that had passkeys (and so a
// WebAuthn handle) gets the "new registration link" wording.
func TestReissueInvite_EmailWordingFollowsHistory(t *testing.T) {
	mailer := &fakeMailer{enabled: true}
	st, grants, passkeys := newReinviteGrants(t, mailer)

	fresh := seedUser(t, st, "fresh@example.com", "user")
	if _, _, _, err := grants.ReissueInvite(t.Context(), "admin-id", fresh); err != nil {
		t.Fatalf("ReissueInvite fresh: %v", err)
	}

	returning := seedUser(t, st, "returning@example.com", "user")
	registerPasskey(t, passkeys, returning.ID, "Old Key", testRP())
	if _, err := st.WebAuthnCredentials().DeleteAllByUser(t.Context(), returning.ID); err != nil {
		t.Fatalf("DeleteAllByUser: %v", err)
	}
	if _, _, _, err := grants.ReissueInvite(t.Context(), "admin-id", returning); err != nil {
		t.Fatalf("ReissueInvite returning: %v", err)
	}

	sent := mailer.Sent()
	if len(sent) != 2 {
		t.Fatalf("mailer received %d messages, want 2", len(sent))
	}
	if sent[0].subject != "You have been invited to DIYDDNS" {
		t.Errorf("never-registered subject = %q, want the invite subject", sent[0].subject)
	}
	if sent[1].subject != "A new DIYDDNS registration link from your administrator" {
		t.Errorf("previously-registered subject = %q, want the re-registration subject", sent[1].subject)
	}
	if !strings.Contains(sent[1].body, "expires in 15 minutes") {
		t.Errorf("re-registration body does not state the window:\n%s", sent[1].body)
	}
}

// TestIssueRecovery_InvalidatesEarlierLinks covers D13: admin recovery also
// leaves exactly one live link.
func TestIssueRecovery_InvalidatesEarlierLinks(t *testing.T) {
	st, grants, _ := newReinviteGrants(t, &fakeMailer{})
	u := seedUser(t, st, "both@example.com", "user")

	invite, _, err := grants.IssueInvite(t.Context(), "admin-id", u)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	if _, _, err := grants.IssueRecovery(t.Context(), "admin-id", u); err != nil {
		t.Fatalf("IssueRecovery: %v", err)
	}
	if _, _, _, err := grants.RedeemBegin(t.Context(), extractToken(t, invite)); !errors.Is(err, ErrGrantInvalid) {
		t.Errorf("invite link after recovery: err = %v, want ErrGrantInvalid", err)
	}
}
