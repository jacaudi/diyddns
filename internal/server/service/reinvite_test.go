package service

import (
	"errors"
	"strings"
	"sync"
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

// TestReissueInvite_ConcurrentCallsLeaveOneLiveLink covers design D6/D13: two
// concurrent calls for one account (a double-click on the re-invite button,
// an API retry) must never leave two live links, because
// DeleteUnusedByUser-then-issue is two separate statements that can interleave
// across goroutines.
func TestReissueInvite_ConcurrentCallsLeaveOneLiveLink(t *testing.T) {
	st, grants, _ := newReinviteGrants(t, &fakeMailer{})
	u := seedUser(t, st, "concurrent@example.com", "user")

	const callers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	links := make([]string, 0, callers)
	for range callers {
		wg.Go(func() {
			link, _, _, err := grants.ReissueInvite(t.Context(), "admin-id", u)
			if err != nil {
				t.Errorf("ReissueInvite: %v", err)
				return
			}
			mu.Lock()
			links = append(links, link)
			mu.Unlock()
		})
	}
	wg.Wait()

	live := 0
	for _, link := range links {
		if _, _, _, err := grants.RedeemBegin(t.Context(), extractToken(t, link)); err == nil {
			live++
		}
	}
	if live != 1 {
		t.Errorf("live redeemable links = %d, want exactly 1", live)
	}
}

// TestReissueInvite_RefusalKeepsExistingGrants covers design D7: an account
// ReissueInvite refuses (already registered) must be left completely
// untouched — a refusal is checked before any delete, so it must not cost the
// account its existing credential or its existing live grant.
func TestReissueInvite_RefusalKeepsExistingGrants(t *testing.T) {
	st, grants, _ := newReinviteGrants(t, &fakeMailer{})
	u := seedUser(t, st, "keep@example.com", "user")
	if _, err := st.WebAuthnCredentials().Create(t.Context(), store.WebAuthnCredential{
		CredentialID: []byte("cred-keep"), UserID: u.ID, CredentialJSON: []byte("{}"), Name: "k", CreatedAt: store.NowUnix(),
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	if err := st.AccountRecovery().Create(t.Context(), store.RecoveryToken{
		TokenHash: "h-keep", UserID: u.ID, Reason: "recovery", ExpiresAt: store.NowUnix() + 600,
	}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	if _, _, _, err := grants.ReissueInvite(t.Context(), "admin-id", u); !errors.Is(err, ErrAlreadyRegistered) {
		t.Fatalf("err = %v, want ErrAlreadyRegistered", err)
	}
	if _, err := st.AccountRecovery().Get(t.Context(), "h-keep"); err != nil {
		t.Errorf("Get(h-keep): %v, want the existing grant still live", err)
	}
}

// TestGrantMail_GoesToTheAddressCurrentAfterTheMint pins the #131 D8 invariant
// against a caller holding a stale user: an admin email change can land
// between the caller's user read and the mint. ReissueInvite and IssueRecovery
// must mail the address current AFTER the mint, never the stale one — a live
// link must not reach an address that has stopped speaking for the account.
func TestGrantMail_GoesToTheAddressCurrentAfterTheMint(t *testing.T) {
	issue := map[string]func(*GrantService, store.User) error{
		"ReissueInvite": func(g *GrantService, u store.User) error {
			_, _, _, err := g.ReissueInvite(t.Context(), "admin-id", u)
			return err
		},
		"IssueRecovery": func(g *GrantService, u store.User) error {
			_, _, err := g.IssueRecovery(t.Context(), "admin-id", u)
			return err
		},
	}
	for name, call := range issue {
		t.Run(name, func(t *testing.T) {
			mailer := &fakeMailer{enabled: true}
			st, grants, _ := newReinviteGrants(t, mailer)
			stale := seedUser(t, st, "old@example.com", "user")
			if err := st.Users().SetEmail(t.Context(), stale.ID, "new@example.com", store.NowUnix()); err != nil {
				t.Fatalf("SetEmail: %v", err)
			}

			if err := call(grants, stale); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			sent := mailer.Sent()
			if len(sent) != 1 {
				t.Fatalf("mailer received %d messages, want 1", len(sent))
			}
			if sent[0].to != "new@example.com" {
				t.Errorf("mailed %q, want the current address new@example.com (the caller's copy said old@example.com)", sent[0].to)
			}
		})
	}
}

// TestGrantMail_DisabledFlagIsReadAfterTheMint pins that the #82 suppression
// uses the account as it is after the mint, not the caller's copy: an account
// disabled after the caller read it gets its link minted and returned but not
// mailed.
func TestGrantMail_DisabledFlagIsReadAfterTheMint(t *testing.T) {
	mailer := &fakeMailer{enabled: true}
	st, grants, _ := newReinviteGrants(t, mailer)
	stale := seedUser(t, st, "late-disable@example.com", "user")
	if err := st.Users().SetDisabled(t.Context(), stale.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}

	link, _, d, err := grants.ReissueInvite(t.Context(), "admin-id", stale)
	if err != nil {
		t.Fatalf("ReissueInvite: %v", err)
	}
	if link == "" {
		t.Error("no link returned")
	}
	if d.Attempted || d.Suppressed != SuppressUserDisabled {
		t.Errorf("Delivery = %+v, want Suppressed=user_disabled (the account was disabled after the caller read it)", d)
	}
	if n := len(mailer.Sent()); n != 0 {
		t.Errorf("mailer received %d messages, want 0", n)
	}
}
