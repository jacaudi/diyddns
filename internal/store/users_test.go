package store

import (
	"errors"
	"testing"
)

func TestUserCreateAndGetByIDRoundTrip(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Users()

	created, err := repo.Create(ctx, User{Email: "alice@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Create did not assign an ID")
	}
	if created.CreatedAt == 0 || created.UpdatedAt == 0 {
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

func TestUserCreateDuplicateEmailReturnsConflict(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Users()

	if _, err := repo.Create(ctx, User{Email: "bob@example.com", Role: "user"}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err := repo.Create(ctx, User{Email: "bob@example.com", Role: "user"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Create duplicate email: err = %v, want ErrConflict", err)
	}
}

func TestUserGetByIDMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Users()

	_, err := repo.GetByID(ctx, "missing-id")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByID missing: err = %v, want ErrNotFound", err)
	}
}

func TestUserGetByEmailMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Users()

	_, err := repo.GetByEmail(ctx, "nobody@example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByEmail missing: err = %v, want ErrNotFound", err)
	}
}

// TestUserTwoWithoutOIDCBothSucceed proves empty OIDCProvider/OIDCSubject are
// stored as SQL NULL rather than "": SQLite treats NULL as distinct from
// every other NULL in a UNIQUE index, so two OIDC-less users must not
// collide on UNIQUE(oidc_provider, oidc_subject). Storing "" would collide.
func TestUserTwoWithoutOIDCBothSucceed(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Users()

	if _, err := repo.Create(ctx, User{Email: "local-1@example.com", Role: "user"}); err != nil {
		t.Fatalf("Create user 1: %v", err)
	}
	if _, err := repo.Create(ctx, User{Email: "local-2@example.com", Role: "user"}); err != nil {
		t.Fatalf("Create user 2: %v", err)
	}
}

func TestUserOIDCLinkageRoundTrip(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Users()

	created, err := repo.Create(ctx, User{
		Email:        "oidc@example.com",
		Role:         "user",
		OIDCProvider: "google",
		OIDCSubject:  "subject-123",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByOIDC(ctx, "google", "subject-123")
	if err != nil {
		t.Fatalf("GetByOIDC: %v", err)
	}
	if got != created {
		t.Fatalf("GetByOIDC() = %+v, want %+v", got, created)
	}
}

func TestUserGetByOIDCMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Users()

	_, err := repo.GetByOIDC(ctx, "google", "does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByOIDC missing: err = %v, want ErrNotFound", err)
	}
}

func TestUserUpdateMutatesFieldsAndBumpsUpdatedAt(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Users()

	created, err := repo.Create(ctx, User{Email: "update@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated := created
	updated.Email = "updated@example.com"
	updated.Role = "admin"
	updated.OIDCProvider = "github"
	updated.OIDCSubject = "gh-456"

	if err := repo.Update(ctx, updated); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Email != "updated@example.com" || got.Role != "admin" {
		t.Fatalf("Update did not persist changes: %+v", got)
	}
	if got.OIDCProvider != "github" || got.OIDCSubject != "gh-456" {
		t.Fatalf("Update did not persist OIDC linkage: %+v", got)
	}
	if got.UpdatedAt < created.UpdatedAt {
		t.Fatalf("Update did not bump updated_at: got %d, want >= %d", got.UpdatedAt, created.UpdatedAt)
	}
}

func TestUserUpdateMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Users()

	err := repo.Update(ctx, User{ID: "missing-id", Email: "x@example.com", Role: "user"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Update missing: err = %v, want ErrNotFound", err)
	}
}

func TestUserSetDisabledToggles(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Users()

	created, err := repo.Create(ctx, User{Email: "disable@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Disabled {
		t.Fatal("newly created user should not start disabled")
	}

	if err := repo.SetDisabled(ctx, created.ID, true); err != nil {
		t.Fatalf("SetDisabled(true): %v", err)
	}
	got, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.Disabled {
		t.Fatal("SetDisabled(true) did not disable the user")
	}

	if err := repo.SetDisabled(ctx, created.ID, false); err != nil {
		t.Fatalf("SetDisabled(false): %v", err)
	}
	got, err = repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Disabled {
		t.Fatal("SetDisabled(false) did not re-enable the user")
	}
}

func TestUserDeleteRemovesUser(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Users()

	created, err := repo.Create(ctx, User{Email: "delete@example.com", Role: "user"})
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

func TestUserDeleteMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Users()

	err := repo.Delete(ctx, "missing-id")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete missing: err = %v, want ErrNotFound", err)
	}
}

func TestUserListOrdersByEmailAscending(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Users()

	for _, email := range []string{"charlie@example.com", "alice@example.com", "bob@example.com"} {
		if _, err := repo.Create(ctx, User{Email: email, Role: "user"}); err != nil {
			t.Fatalf("Create %q: %v", email, err)
		}
	}

	got, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	want := []string{"alice@example.com", "bob@example.com", "charlie@example.com"}
	if len(got) != len(want) {
		t.Fatalf("List returned %d users, want %d", len(got), len(want))
	}
	for i, u := range got {
		if u.Email != want[i] {
			t.Fatalf("List()[%d].Email = %q, want %q", i, u.Email, want[i])
		}
	}
}
