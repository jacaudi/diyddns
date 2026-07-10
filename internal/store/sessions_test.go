package store

import (
	"errors"
	"testing"
)

func TestSessionCreateAndGetByIDRoundTrip(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "session-user@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Sessions()

	created, err := repo.Create(ctx, Session{
		UserID:    user.ID,
		CSRFToken: "csrf-token-1",
		IP:        "203.0.113.1",
		UserAgent: "test-agent/1.0",
		ExpiresAt: NowUnix() + 3600,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Create did not assign an ID")
	}
	if created.CreatedAt == 0 || created.LastSeenAt == 0 {
		t.Fatalf("Create did not set timestamps: %+v", created)
	}

	got, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got != created {
		t.Fatalf("GetByID() = %+v, want %+v", got, created)
	}
}

func TestSessionGetByIDMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Sessions()

	_, err := repo.GetByID(ctx, "missing-id")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByID missing: err = %v, want ErrNotFound", err)
	}
}

func TestSessionTouchUpdatesLastSeenAtAndExpiresAt(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "touch@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Sessions()

	created, err := repo.Create(ctx, Session{
		UserID:    user.ID,
		CSRFToken: "csrf-token",
		ExpiresAt: NowUnix() + 60,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	newExpiresAt := NowUnix() + 7200
	if err := repo.Touch(ctx, created.ID, newExpiresAt); err != nil {
		t.Fatalf("Touch: %v", err)
	}

	got, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.LastSeenAt < created.LastSeenAt {
		t.Fatalf("Touch did not bump last_seen_at: got %d, want >= %d", got.LastSeenAt, created.LastSeenAt)
	}
	if got.ExpiresAt != newExpiresAt {
		t.Fatalf("Touch did not update expires_at: got %d, want %d", got.ExpiresAt, newExpiresAt)
	}
}

func TestSessionTouchMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Sessions()

	err := repo.Touch(ctx, "missing-id", NowUnix()+60)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Touch missing: err = %v, want ErrNotFound", err)
	}
}

func TestSessionDeleteRemovesSession(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "delete@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Sessions()

	created, err := repo.Create(ctx, Session{
		UserID:    user.ID,
		CSRFToken: "csrf-token",
		ExpiresAt: NowUnix() + 60,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := repo.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = repo.GetByID(ctx, created.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByID after delete: err = %v, want ErrNotFound", err)
	}
}

func TestSessionDeleteMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Sessions()

	err := repo.Delete(ctx, "missing-id")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete missing: err = %v, want ErrNotFound", err)
	}
}

func TestSessionDeleteByUserPurgesOnlyThatUsersSessions(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Sessions()

	userA, err := s.Users().Create(ctx, User{Email: "user-a@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user A: %v", err)
	}
	userB, err := s.Users().Create(ctx, User{Email: "user-b@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user B: %v", err)
	}

	for range 2 {
		if _, err := repo.Create(ctx, Session{UserID: userA.ID, CSRFToken: "csrf", ExpiresAt: NowUnix() + 60}); err != nil {
			t.Fatalf("create session for user A: %v", err)
		}
	}
	sessionB, err := repo.Create(ctx, Session{UserID: userB.ID, CSRFToken: "csrf", ExpiresAt: NowUnix() + 60})
	if err != nil {
		t.Fatalf("create session for user B: %v", err)
	}

	n, err := repo.DeleteByUser(ctx, userA.ID)
	if err != nil {
		t.Fatalf("DeleteByUser: %v", err)
	}
	if n != 2 {
		t.Fatalf("DeleteByUser returned %d rows affected, want 2", n)
	}

	got, err := repo.GetByID(ctx, sessionB.ID)
	if err != nil {
		t.Fatalf("GetByID for user B's session: %v", err)
	}
	if got.ID != sessionB.ID {
		t.Fatalf("user B's session was unexpectedly affected: %+v", got)
	}
}

func TestSessionPruneExpiredRemovesExpiredLeavesFresh(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Sessions()

	user, err := s.Users().Create(ctx, User{Email: "prune@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := NowUnix()
	expired, err := repo.Create(ctx, Session{UserID: user.ID, CSRFToken: "csrf", ExpiresAt: now - 10})
	if err != nil {
		t.Fatalf("create expired session: %v", err)
	}
	fresh, err := repo.Create(ctx, Session{UserID: user.ID, CSRFToken: "csrf", ExpiresAt: now + 3600})
	if err != nil {
		t.Fatalf("create fresh session: %v", err)
	}

	n, err := repo.PruneExpired(ctx, now)
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("PruneExpired returned %d rows affected, want 1", n)
	}

	if _, err := repo.GetByID(ctx, expired.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session GetByID: err = %v, want ErrNotFound", err)
	}
	if _, err := repo.GetByID(ctx, fresh.ID); err != nil {
		t.Fatalf("fresh session GetByID: %v", err)
	}
}

// TestSessionUserDeleteCascadesToSessions proves the ON DELETE CASCADE the
// schema declares on sessions.user_id actually fires: deleting the parent
// user via the public Users().Delete API must remove that user's sessions
// too, without the sessions repo doing anything itself.
func TestSessionUserDeleteCascadesToSessions(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "cascade@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Sessions()

	created, err := repo.Create(ctx, Session{UserID: user.ID, CSRFToken: "csrf", ExpiresAt: NowUnix() + 60})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Users().Delete(ctx, user.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	_, err = repo.GetByID(ctx, created.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByID after cascading user delete: err = %v, want ErrNotFound", err)
	}
}
