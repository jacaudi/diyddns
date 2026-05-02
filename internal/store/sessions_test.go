package store

import (
	"errors"
	"testing"
	"time"
)

func TestSessionCreateAndGetByID(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "sess-alice@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users.Create: %v", err)
	}

	sess := Session{
		UserID:    u.ID,
		CSRFToken: "tok-abc",
		IP:        "127.0.0.1",
		UserAgent: "go-test/1.0",
		ExpiresAt: NowUnix() + 3600,
	}
	created, err := s.Sessions().Create(ctx, sess)
	if err != nil {
		t.Fatalf("Sessions.Create: %v", err)
	}
	if created.ID == "" {
		t.Error("Create: expected non-empty ID")
	}
	if created.CreatedAt == 0 {
		t.Error("Create: expected non-zero CreatedAt")
	}
	if created.LastSeenAt == 0 {
		t.Error("Create: expected non-zero LastSeenAt")
	}
	if created.UserID != u.ID {
		t.Errorf("Create: UserID = %q, want %q", created.UserID, u.ID)
	}
	if created.CSRFToken != sess.CSRFToken {
		t.Errorf("Create: CSRFToken = %q, want %q", created.CSRFToken, sess.CSRFToken)
	}
	if created.IP != sess.IP {
		t.Errorf("Create: IP = %q, want %q", created.IP, sess.IP)
	}
	if created.UserAgent != sess.UserAgent {
		t.Errorf("Create: UserAgent = %q, want %q", created.UserAgent, sess.UserAgent)
	}

	got, err := s.Sessions().GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("GetByID: ID = %q, want %q", got.ID, created.ID)
	}
	if got.UserID != created.UserID {
		t.Errorf("GetByID: UserID = %q, want %q", got.UserID, created.UserID)
	}
	if got.CSRFToken != created.CSRFToken {
		t.Errorf("GetByID: CSRFToken = %q, want %q", got.CSRFToken, created.CSRFToken)
	}
	if got.IP != created.IP {
		t.Errorf("GetByID: IP = %q, want %q", got.IP, created.IP)
	}
	if got.UserAgent != created.UserAgent {
		t.Errorf("GetByID: UserAgent = %q, want %q", got.UserAgent, created.UserAgent)
	}
	if got.CreatedAt != created.CreatedAt {
		t.Errorf("GetByID: CreatedAt = %d, want %d", got.CreatedAt, created.CreatedAt)
	}
	if got.ExpiresAt != created.ExpiresAt {
		t.Errorf("GetByID: ExpiresAt = %d, want %d", got.ExpiresAt, created.ExpiresAt)
	}
}

func TestSessionGetByIDNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	_, err := s.Sessions().GetByID(ctx, "nonexistent-session-id")
	if err == nil {
		t.Fatal("GetByID: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID: got %v, want errors.Is(err, ErrNotFound)", err)
	}
}

func TestSessionTouchUpdatesLastSeenAndExpires(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "sess-touch@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users.Create: %v", err)
	}

	created, err := s.Sessions().Create(ctx, Session{
		UserID:    u.ID,
		CSRFToken: "tok-touch",
		ExpiresAt: NowUnix() + 3600,
	})
	if err != nil {
		t.Fatalf("Sessions.Create: %v", err)
	}
	originalLastSeen := created.LastSeenAt

	// Unix-second precision requires at least 1s to observe a change.
	time.Sleep(time.Second)

	newExpires := NowUnix() + 7200
	if err := s.Sessions().Touch(ctx, created.ID, newExpires); err != nil {
		t.Fatalf("Touch: %v", err)
	}

	got, err := s.Sessions().GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID after Touch: %v", err)
	}
	if got.LastSeenAt <= originalLastSeen {
		t.Errorf("Touch: LastSeenAt (%d) should be > original (%d)", got.LastSeenAt, originalLastSeen)
	}
	if got.ExpiresAt != newExpires {
		t.Errorf("Touch: ExpiresAt = %d, want %d", got.ExpiresAt, newExpires)
	}
}

func TestSessionTouchNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	err := s.Sessions().Touch(ctx, "nonexistent-id", NowUnix()+3600)
	if err == nil {
		t.Fatal("Touch: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Touch: got %v, want errors.Is(err, ErrNotFound)", err)
	}
}

func TestSessionDeleteHardRemoves(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "sess-del@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users.Create: %v", err)
	}

	created, err := s.Sessions().Create(ctx, Session{
		UserID:    u.ID,
		CSRFToken: "tok-del",
		ExpiresAt: NowUnix() + 3600,
	})
	if err != nil {
		t.Fatalf("Sessions.Create: %v", err)
	}

	if err := s.Sessions().Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = s.Sessions().GetByID(ctx, created.ID)
	if err == nil {
		t.Fatal("GetByID after Delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID after Delete: got %v, want errors.Is(err, ErrNotFound)", err)
	}
}

func TestSessionDeleteNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	err := s.Sessions().Delete(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("Delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete: got %v, want errors.Is(err, ErrNotFound)", err)
	}
}

func TestSessionDeleteByUserPurgesOnlyThatUser(t *testing.T) {
	s, ctx := newTestStore(t)

	userA, err := s.Users().Create(ctx, User{Email: "sess-userA@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users.Create userA: %v", err)
	}
	userB, err := s.Users().Create(ctx, User{Email: "sess-userB@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users.Create userB: %v", err)
	}

	// Create 2 sessions for user A.
	sessA1, err := s.Sessions().Create(ctx, Session{
		UserID:    userA.ID,
		CSRFToken: "tok-a1",
		ExpiresAt: NowUnix() + 3600,
	})
	if err != nil {
		t.Fatalf("Sessions.Create A1: %v", err)
	}
	sessA2, err := s.Sessions().Create(ctx, Session{
		UserID:    userA.ID,
		CSRFToken: "tok-a2",
		ExpiresAt: NowUnix() + 3600,
	})
	if err != nil {
		t.Fatalf("Sessions.Create A2: %v", err)
	}

	// Create 1 session for user B.
	sessB1, err := s.Sessions().Create(ctx, Session{
		UserID:    userB.ID,
		CSRFToken: "tok-b1",
		ExpiresAt: NowUnix() + 3600,
	})
	if err != nil {
		t.Fatalf("Sessions.Create B1: %v", err)
	}

	n, err := s.Sessions().DeleteByUser(ctx, userA.ID)
	if err != nil {
		t.Fatalf("DeleteByUser: %v", err)
	}
	if n != 2 {
		t.Errorf("DeleteByUser: got %d rows, want 2", n)
	}

	// A's sessions must be gone.
	if _, err := s.Sessions().GetByID(ctx, sessA1.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("sessA1 still retrievable after DeleteByUser: %v", err)
	}
	if _, err := s.Sessions().GetByID(ctx, sessA2.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("sessA2 still retrievable after DeleteByUser: %v", err)
	}

	// B's session must still exist.
	got, err := s.Sessions().GetByID(ctx, sessB1.ID)
	if err != nil {
		t.Fatalf("sessB1 should still exist: %v", err)
	}
	if got.UserID != userB.ID {
		t.Errorf("sessB1 UserID = %q, want %q", got.UserID, userB.ID)
	}
}

func TestSessionPruneExpiredRemovesExpiredAndKeepsFresh(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "sess-prune@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users.Create: %v", err)
	}

	now := NowUnix()

	// Session that expired in the past.
	expired, err := s.Sessions().Create(ctx, Session{
		UserID:    u.ID,
		CSRFToken: "tok-expired",
		ExpiresAt: now - 100,
	})
	if err != nil {
		t.Fatalf("Sessions.Create expired: %v", err)
	}

	// Session that expires in the future.
	fresh, err := s.Sessions().Create(ctx, Session{
		UserID:    u.ID,
		CSRFToken: "tok-fresh",
		ExpiresAt: now + 3600,
	})
	if err != nil {
		t.Fatalf("Sessions.Create fresh: %v", err)
	}

	n, err := s.Sessions().PruneExpired(ctx, now)
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if n != 1 {
		t.Errorf("PruneExpired: got %d rows deleted, want 1", n)
	}

	// Expired session must be gone.
	if _, err := s.Sessions().GetByID(ctx, expired.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired session still retrievable after PruneExpired: %v", err)
	}

	// Fresh session must still exist.
	if _, err := s.Sessions().GetByID(ctx, fresh.ID); err != nil {
		t.Fatalf("fresh session should still exist: %v", err)
	}
}

func TestSessionFKCascadeOnUserDelete(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "sess-cascade@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users.Create: %v", err)
	}

	sess, err := s.Sessions().Create(ctx, Session{
		UserID:    u.ID,
		CSRFToken: "tok-cascade",
		ExpiresAt: NowUnix() + 3600,
	})
	if err != nil {
		t.Fatalf("Sessions.Create: %v", err)
	}

	// Delete the user — cascade should remove the session.
	if err := s.Users().Delete(ctx, u.ID); err != nil {
		t.Fatalf("Users.Delete: %v", err)
	}

	_, err = s.Sessions().GetByID(ctx, sess.ID)
	if err == nil {
		t.Fatal("GetByID after cascade delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID after cascade delete: got %v, want errors.Is(err, ErrNotFound)", err)
	}
}
