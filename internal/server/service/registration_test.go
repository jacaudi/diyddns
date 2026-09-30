package service

import (
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

func TestDeriveRegistration(t *testing.T) {
	plain := store.User{ID: "u"}
	oidc := store.User{ID: "u", OIDCProvider: "p", OIDCSubject: "sub"}
	disabled := store.User{ID: "u", Disabled: true}
	invite := store.LiveGrant{Reason: "invite", ExpiresAt: 1000}
	recovery := store.LiveGrant{Reason: "recovery", ExpiresAt: 2000}

	cases := []struct {
		name    string
		u       store.User
		creds   int
		live    store.LiveGrant
		hasLive bool
		want    Registration
	}{
		{"passkey", plain, 1, store.LiveGrant{}, false, Registration{Status: RegistrationRegistered}},
		{"oidc only", oidc, 0, store.LiveGrant{}, false, Registration{Status: RegistrationRegistered}},
		{"disabled but registered", disabled, 2, store.LiveGrant{}, false, Registration{Status: RegistrationRegistered}},
		{"registered with a live grant hides its expiry (D14)", plain, 1, recovery, true, Registration{Status: RegistrationRegistered}},
		{"invited", plain, 0, invite, true, Registration{Status: RegistrationInvited, LinkExpiresAt: 1000}},
		{"recovery pending", plain, 0, recovery, true, Registration{Status: RegistrationRecoveryPending, LinkExpiresAt: 2000}},
		{"no live link", plain, 0, store.LiveGrant{}, false, Registration{Status: RegistrationLinkExpired}},
	}
	for _, c := range cases {
		if got := deriveRegistration(c.u, c.creds, c.live, c.hasLive); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestIsRegistered(t *testing.T) {
	if IsRegistered(store.User{}, 0) {
		t.Error("no credential and no OIDC link must not be registered")
	}
	if !IsRegistered(store.User{}, 1) {
		t.Error("a passkey must count as registered")
	}
	if !IsRegistered(store.User{OIDCSubject: "sub"}, 0) {
		t.Error("an OIDC link must count as registered")
	}
}

// TestAdminService_RegistrationStatuses proves the aggregate path returns an
// entry for EVERY user passed in (design D5) and derives each correctly.
func TestAdminService_RegistrationStatuses(t *testing.T) {
	st, svc := newAdminSvc(t)
	ctx := t.Context()
	now := store.NowUnix()

	registered := seedUser(t, st, "reg@example.com", "user")
	if _, err := st.WebAuthnCredentials().Create(ctx, store.WebAuthnCredential{
		CredentialID: []byte("cred-reg"), UserID: registered.ID, CredentialJSON: []byte("{}"), Name: "k", CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	invited := seedUser(t, st, "inv@example.com", "user")
	if err := st.AccountRecovery().Create(ctx, store.RecoveryToken{
		TokenHash: "h-inv", UserID: invited.ID, Reason: "invite", ExpiresAt: now + 600,
	}); err != nil {
		t.Fatalf("seed invite: %v", err)
	}
	pending := seedUser(t, st, "rec@example.com", "user")
	if err := st.AccountRecovery().Create(ctx, store.RecoveryToken{
		TokenHash: "h-rec", UserID: pending.ID, Reason: "recovery", ExpiresAt: now + 900,
	}); err != nil {
		t.Fatalf("seed recovery: %v", err)
	}
	lapsed := seedUser(t, st, "lapsed@example.com", "user")

	users := []store.User{registered, invited, pending, lapsed}
	got, err := svc.RegistrationStatuses(ctx, users, now)
	if err != nil {
		t.Fatalf("RegistrationStatuses: %v", err)
	}
	if len(got) != len(users) {
		t.Fatalf("got %d entries, want %d (one per user passed in)", len(got), len(users))
	}
	want := map[string]Registration{
		registered.ID: {Status: RegistrationRegistered},
		invited.ID:    {Status: RegistrationInvited, LinkExpiresAt: now + 600},
		pending.ID:    {Status: RegistrationRecoveryPending, LinkExpiresAt: now + 900},
		lapsed.ID:     {Status: RegistrationLinkExpired},
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("user %s: got %+v, want %+v", id, got[id], w)
		}
	}
}
