package store

import (
	"errors"
	"testing"
)

// TestMigration010_Shape asserts the schema after Open: api_keys exists with
// the right columns, foreign keys are still enforced, and a dangling
// user_id is rejected — mirrors TestMigration007_Shape's style.
func TestMigration010_Shape(t *testing.T) {
	s, ctx := newTestStore(t)

	if !dbTableExists(t, ctx, s.DB(), "api_keys") {
		t.Fatal("table api_keys missing after 00010")
	}
	for _, col := range []string{"id", "user_id", "label", "key_hash", "admin_scope", "created_at", "last_used_at"} {
		if !dbColumnExists(t, ctx, s.DB(), "api_keys", col) {
			t.Errorf("api_keys.%s missing after 00010", col)
		}
	}

	var fk int
	if err := s.DB().QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("PRAGMA foreign_keys = %d, want 1", fk)
	}

	_, err := s.DB().ExecContext(ctx,
		`INSERT INTO api_keys (id, user_id, label, key_hash, created_at) VALUES ('k1', 'no-such-user', 'x', 'h', 1)`)
	if err == nil {
		t.Error("insert with a dangling user_id succeeded; the FK to users was not created")
	}
}

func TestAPIKeys_CRUD(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	usr, err := s.Users().Create(ctx, User{Email: "keyowner@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	key := APIKey{ID: NewID(), UserID: usr.ID, Label: "laptop", KeyHash: "hash-1", CreatedAt: now}
	if err := s.APIKeys().Create(ctx, key); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.APIKeys().GetByHash(ctx, "hash-1")
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.ID != key.ID || got.UserID != usr.ID || got.Label != "laptop" || got.AdminScope || got.LastUsedAt != 0 {
		t.Errorf("GetByHash = %+v, want id %s user %s label laptop admin_scope false last_used 0", got, key.ID, usr.ID)
	}

	if _, err := s.APIKeys().GetByHash(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByHash(unknown) err = %v, want ErrNotFound", err)
	}

	// Same user, same label -> ErrConflict (UNIQUE(user_id, label)).
	dup := APIKey{ID: NewID(), UserID: usr.ID, Label: "laptop", KeyHash: "hash-2", CreatedAt: now}
	if err := s.APIKeys().Create(ctx, dup); !errors.Is(err, ErrConflict) {
		t.Errorf("Create(duplicate user+label) err = %v, want ErrConflict", err)
	}

	// Different user, same label -> succeeds (label is scoped per-user, not global).
	other, err := s.Users().Create(ctx, User{Email: "otherowner@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed other user: %v", err)
	}
	sameLabelOtherUser := APIKey{ID: NewID(), UserID: other.ID, Label: "laptop", KeyHash: "hash-3", CreatedAt: now}
	if err := s.APIKeys().Create(ctx, sameLabelOtherUser); err != nil {
		t.Errorf("Create(same label, different user) err = %v, want nil", err)
	}

	if err := s.APIKeys().TouchLastUsed(ctx, key.ID, now+5); err != nil {
		t.Fatalf("TouchLastUsed: %v", err)
	}
	list, err := s.APIKeys().List(ctx, usr.ID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].LastUsedAt != now+5 {
		t.Errorf("List(usr) = %+v, want exactly one row (not the other user's) with last_used_at %d", list, now+5)
	}

	if err := s.APIKeys().Delete(ctx, key.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.APIKeys().Delete(ctx, key.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete(again) err = %v, want ErrNotFound", err)
	}
	if _, err := s.APIKeys().GetByHash(ctx, "hash-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByHash after delete err = %v, want ErrNotFound", err)
	}
}

func TestAPIKeys_GetByID(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	usr, err := s.Users().Create(ctx, User{Email: "getbyid@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	key := APIKey{ID: NewID(), UserID: usr.ID, Label: "k", KeyHash: "h", CreatedAt: now}
	if err := s.APIKeys().Create(ctx, key); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.APIKeys().GetByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != key.ID || got.UserID != usr.ID {
		t.Errorf("GetByID = %+v, want id %s user %s", got, key.ID, usr.ID)
	}

	if err := s.APIKeys().Delete(ctx, key.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.APIKeys().GetByID(ctx, key.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID after delete err = %v, want ErrNotFound", err)
	}
}

// TestAPIKeys_CascadeOnUserDeletion: user_id is ON DELETE CASCADE (design D2)
// — the opposite of feed_tokens' ON DELETE SET NULL, deliberately: an API
// key IS the deleted user's own authority, so it must vanish with them.
func TestAPIKeys_CascadeOnUserDeletion(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	usr, err := s.Users().Create(ctx, User{Email: "cascade@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	key := APIKey{ID: NewID(), UserID: usr.ID, Label: "k", KeyHash: "h-cascade", CreatedAt: now}
	if err := s.APIKeys().Create(ctx, key); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Users().Delete(ctx, usr.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	if _, err := s.APIKeys().GetByHash(ctx, "h-cascade"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByHash after owner deleted err = %v, want ErrNotFound (row must be gone, not orphaned)", err)
	}
}

// TestAPIKeys_AdminScopeDefaultsFalse proves the column reads back false
// when Create's caller leaves AdminScope at its Go zero value — the write
// path guarantee design D2/S6 states in prose, pinned as a real test.
func TestAPIKeys_AdminScopeDefaultsFalse(t *testing.T) {
	s, ctx := newTestStore(t)
	usr, err := s.Users().Create(ctx, User{Email: "defaultscope@example.com", Role: "admin"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	key := APIKey{ID: NewID(), UserID: usr.ID, Label: "k", KeyHash: "h-default", CreatedAt: NowUnix()}
	if err := s.APIKeys().Create(ctx, key); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.APIKeys().GetByHash(ctx, "h-default")
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.AdminScope {
		t.Error("AdminScope = true, want false when the caller never set it")
	}
}

// TestAPIKeys_KeyHashUniqueAcrossUsers pins design B5's UNIQUE constraint on
// key_hash directly (added by the plan-gate review, M-4 — the CRUD test
// above only exercises the (user_id, label) half of Create's ErrConflict
// contract). Two different users' keys can never collide on key_hash in
// practice (auth.RandToken(32) has 256 bits of entropy), but the schema-
// level constraint is real and must be pinned as a real test, not left
// inferred from the CRUD test's separate assertion.
func TestAPIKeys_KeyHashUniqueAcrossUsers(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	alice, err := s.Users().Create(ctx, User{Email: "hash-alice@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	bob, err := s.Users().Create(ctx, User{Email: "hash-bob@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed bob: %v", err)
	}

	if err := s.APIKeys().Create(ctx, APIKey{ID: NewID(), UserID: alice.ID, Label: "a", KeyHash: "shared-hash", CreatedAt: now}); err != nil {
		t.Fatalf("Create(alice): %v", err)
	}
	// Different user, different label, but the SAME key_hash -- must conflict
	// even though (user_id, label) is unique.
	dup := APIKey{ID: NewID(), UserID: bob.ID, Label: "b", KeyHash: "shared-hash", CreatedAt: now}
	if err := s.APIKeys().Create(ctx, dup); !errors.Is(err, ErrConflict) {
		t.Errorf("Create(same key_hash, different user+label) err = %v, want ErrConflict", err)
	}
}
