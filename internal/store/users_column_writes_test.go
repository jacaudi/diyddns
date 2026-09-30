package store

import (
	"errors"
	"testing"
)

// #182: column-specific writes must never revert a concurrent write to
// another column, which UserRepo.Update does when handed a row read earlier.

func mustGetUser(t *testing.T, s *Store, id string) User {
	t.Helper()
	u, err := s.Users().GetByID(t.Context(), id)
	if err != nil {
		t.Fatalf("GetByID(%s): %v", id, err)
	}
	return u
}

func TestUsers_SetRoleWritesOnlyRole(t *testing.T) {
	s, ctx := newTestStore(t)
	u, err := s.Users().Create(ctx, User{Email: "old@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	// Concurrent writes that land between a caller's read and its role change.
	if err := s.Users().SetEmail(ctx, u.ID, "new@example.com", NowUnix()); err != nil {
		t.Fatalf("SetEmail: %v", err)
	}
	if err := s.Users().SetDisabled(ctx, u.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}

	if err := s.Users().SetRole(ctx, u.ID, "admin"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	got := mustGetUser(t, s, u.ID)
	if got.Role != "admin" || got.Email != "new@example.com" || !got.Disabled {
		t.Errorf("after SetRole: role=%q email=%q disabled=%v, want admin/new@example.com/true", got.Role, got.Email, got.Disabled)
	}
}

func TestUsers_SetRoleUnknownUserIsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	if err := s.Users().SetRole(ctx, "no-such-user", "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestUsers_LinkOIDC(t *testing.T) {
	s, ctx := newTestStore(t)
	mk := func(email string) User {
		t.Helper()
		u, err := s.Users().Create(ctx, User{Email: email, Role: "user"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		return u
	}

	t.Run("links, canonicalizes, and leaves other columns alone", func(t *testing.T) {
		matched := mk("Link@Example.com")
		if err := s.Users().SetDisabled(ctx, matched.ID, true); err != nil {
			t.Fatalf("SetDisabled: %v", err)
		}
		if err := s.Users().LinkOIDC(ctx, matched, "link@example.com", "iss", "sub-link"); err != nil {
			t.Fatalf("LinkOIDC: %v", err)
		}
		got := mustGetUser(t, s, matched.ID)
		if got.Email != "link@example.com" || got.OIDCProvider != "iss" || got.OIDCSubject != "sub-link" || !got.Disabled || got.Role != "user" {
			t.Errorf("after LinkOIDC: %+v", got)
		}
	})

	t.Run("refuses when the address moved after the match", func(t *testing.T) {
		matched := mk("moved-old@example.com")
		if err := s.Users().SetEmail(ctx, matched.ID, "moved-new@example.com", NowUnix()); err != nil {
			t.Fatalf("SetEmail: %v", err)
		}
		if err := s.Users().LinkOIDC(ctx, matched, "moved-old@example.com", "iss", "sub-moved"); !errors.Is(err, ErrConflict) {
			t.Fatalf("err = %v, want ErrConflict", err)
		}
		got := mustGetUser(t, s, matched.ID)
		if got.Email != "moved-new@example.com" || got.OIDCSubject != "" {
			t.Errorf("refused link still wrote: %+v", got)
		}
	})

	t.Run("refuses when the role changed after the match", func(t *testing.T) {
		matched := mk("promoted@example.com")
		if err := s.Users().SetRole(ctx, matched.ID, "admin"); err != nil {
			t.Fatalf("SetRole: %v", err)
		}
		if err := s.Users().LinkOIDC(ctx, matched, "promoted@example.com", "iss", "sub-promoted"); !errors.Is(err, ErrConflict) {
			t.Fatalf("err = %v, want ErrConflict (a promotion raced the link)", err)
		}
		if got := mustGetUser(t, s, matched.ID); got.OIDCSubject != "" {
			t.Errorf("refused link still wrote: %+v", got)
		}
	})

	t.Run("refuses an already-linked row", func(t *testing.T) {
		matched := mk("linked@example.com")
		if err := s.Users().LinkOIDC(ctx, matched, "linked@example.com", "iss", "sub-first"); err != nil {
			t.Fatalf("first LinkOIDC: %v", err)
		}
		if err := s.Users().LinkOIDC(ctx, matched, "linked@example.com", "iss", "sub-second"); !errors.Is(err, ErrConflict) {
			t.Fatalf("second LinkOIDC err = %v, want ErrConflict", err)
		}
		if got := mustGetUser(t, s, matched.ID); got.OIDCSubject != "sub-first" {
			t.Errorf("OIDCSubject = %q, want sub-first (the second link must not overwrite)", got.OIDCSubject)
		}
	})

	t.Run("a canonical address held by another account is a conflict", func(t *testing.T) {
		mk("taken@example.com")
		matched := mk("Taken <taken@example.com>")
		if err := s.Users().LinkOIDC(ctx, matched, "taken@example.com", "iss", "sub-taken"); !errors.Is(err, ErrConflict) {
			t.Fatalf("err = %v, want ErrConflict (UNIQUE on email)", err)
		}
		if got := mustGetUser(t, s, matched.ID); got.OIDCSubject != "" {
			t.Errorf("colliding link still wrote: %+v", got)
		}
	})
}
