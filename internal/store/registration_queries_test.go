package store

import "testing"

func TestWebAuthnCredentials_CountAllByUser(t *testing.T) {
	s, ctx := newTestStore(t)
	mk := func(email string) User {
		t.Helper()
		u, err := s.Users().Create(ctx, User{Email: email, Role: "user"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		return u
	}
	a, b, none := mk("count-a@example.com"), mk("count-b@example.com"), mk("count-none@example.com")
	for _, c := range []struct{ id, user string }{{"cred-a1", a.ID}, {"cred-a2", a.ID}, {"cred-b1", b.ID}} {
		if _, err := s.WebAuthnCredentials().Create(ctx, WebAuthnCredential{
			CredentialID: []byte(c.id), UserID: c.user, CredentialJSON: []byte("{}"), Name: "k", CreatedAt: NowUnix(),
		}); err != nil {
			t.Fatalf("create credential %s: %v", c.id, err)
		}
	}

	got, err := s.WebAuthnCredentials().CountAllByUser(ctx)
	if err != nil {
		t.Fatalf("CountAllByUser: %v", err)
	}
	if got[a.ID] != 2 || got[b.ID] != 1 {
		t.Errorf("counts = %v, want %s:2 %s:1", got, a.ID, b.ID)
	}
	if _, ok := got[none.ID]; ok {
		t.Errorf("a user with no credentials appears in the map: %v", got)
	}
}

func TestAccountRecovery_LiveByUser(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	mk := func(email string) User {
		t.Helper()
		u, err := s.Users().Create(ctx, User{Email: email, Role: "user"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		return u
	}
	grant := func(hash, userID, reason string, expiresAt, usedAt int64) {
		t.Helper()
		if err := s.AccountRecovery().Create(ctx, RecoveryToken{
			TokenHash: hash, UserID: userID, Reason: reason, ExpiresAt: expiresAt, UsedAt: usedAt,
		}); err != nil {
			t.Fatalf("create grant %s: %v", hash, err)
		}
	}

	live := mk("live@example.com")
	grant("h-live", live.ID, "invite", now+600, 0)

	used := mk("used@example.com")
	grant("h-used", used.ID, "invite", now+600, now-5)

	expired := mk("expired@example.com")
	grant("h-expired", expired.ID, "invite", now-1, 0)
	grant("h-expires-now", expired.ID, "invite", now, 0)

	latest := mk("latest@example.com")
	grant("h-latest-invite", latest.ID, "invite", now+300, 0)
	grant("h-latest-recovery", latest.ID, "recovery", now+900, 0)

	tie := mk("tie@example.com")
	grant("h-tie-invite", tie.ID, "invite", now+600, 0)
	grant("h-tie-recovery", tie.ID, "recovery", now+600, 0)

	got, err := s.AccountRecovery().LiveByUser(ctx, now)
	if err != nil {
		t.Fatalf("LiveByUser: %v", err)
	}
	if g := got[live.ID]; g.Reason != "invite" || g.ExpiresAt != now+600 {
		t.Errorf("live = %+v, want invite expiring at %d", g, now+600)
	}
	for _, absent := range []User{used, expired} {
		if g, ok := got[absent.ID]; ok {
			t.Errorf("%s has no live grant but LiveByUser returned %+v", absent.Email, g)
		}
	}
	if g := got[latest.ID]; g.Reason != "recovery" || g.ExpiresAt != now+900 {
		t.Errorf("latest = %+v, want the later-expiring recovery grant", g)
	}
	if g := got[tie.ID]; g.Reason != "recovery" {
		t.Errorf("tie = %+v, want recovery to win an expires_at tie", g)
	}
}
