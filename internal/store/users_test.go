package store

import (
	"errors"
	"testing"
	"time"
)

const (
	roleAdmin = "admin"
	roleUser  = "user"
)

func TestUserCreateAndGetByID(t *testing.T) {
	s, ctx := newTestStore(t)

	u := User{
		Email:        "alice@example.com",
		PasswordHash: "hash1",
		Role:         roleAdmin,
	}
	created, err := s.Users().Create(ctx, u)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" {
		t.Error("Create: expected non-empty ID")
	}
	if created.CreatedAt == 0 {
		t.Error("Create: expected non-zero CreatedAt")
	}
	if created.UpdatedAt == 0 {
		t.Error("Create: expected non-zero UpdatedAt")
	}
	if created.Email != u.Email {
		t.Errorf("Create: Email = %q, want %q", created.Email, u.Email)
	}
	if created.Role != u.Role {
		t.Errorf("Create: Role = %q, want %q", created.Role, u.Role)
	}

	got, err := s.Users().GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("GetByID: ID = %q, want %q", got.ID, created.ID)
	}
	if got.Email != created.Email {
		t.Errorf("GetByID: Email = %q, want %q", got.Email, created.Email)
	}
	if got.PasswordHash != created.PasswordHash {
		t.Errorf("GetByID: PasswordHash = %q, want %q", got.PasswordHash, created.PasswordHash)
	}
	if got.CreatedAt != created.CreatedAt {
		t.Errorf("GetByID: CreatedAt = %d, want %d", got.CreatedAt, created.CreatedAt)
	}
}

func TestUserCreateDuplicateEmailReturnsErrConflict(t *testing.T) {
	s, ctx := newTestStore(t)

	u := User{
		Email: "bob@example.com",
		Role:  roleUser,
	}
	if _, err := s.Users().Create(ctx, u); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	_, err := s.Users().Create(ctx, u)
	if err == nil {
		t.Fatal("second Create: expected error, got nil")
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("second Create: got %v, want errors.Is(err, ErrConflict)", err)
	}
}

func TestUserGetByIDNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	_, err := s.Users().GetByID(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("GetByID: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID: got %v, want errors.Is(err, ErrNotFound)", err)
	}
}

func TestUserGetByEmail(t *testing.T) {
	s, ctx := newTestStore(t)

	u := User{
		Email: "carol@example.com",
		Role:  roleUser,
	}
	created, err := s.Users().Create(ctx, u)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Users().GetByEmail(ctx, u.Email)
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("GetByEmail: ID = %q, want %q", got.ID, created.ID)
	}
	if got.Email != created.Email {
		t.Errorf("GetByEmail: Email = %q, want %q", got.Email, created.Email)
	}
}

func TestUserOIDCRoundTrip(t *testing.T) {
	s, ctx := newTestStore(t)

	u := User{
		Email:        "dan@example.com",
		Role:         roleUser,
		OIDCProvider: "google",
		OIDCSubject:  "sub-123",
	}
	created, err := s.Users().Create(ctx, u)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Users().GetByOIDC(ctx, "google", "sub-123")
	if err != nil {
		t.Fatalf("GetByOIDC: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("GetByOIDC: ID = %q, want %q", got.ID, created.ID)
	}
	if got.OIDCProvider != "google" {
		t.Errorf("GetByOIDC: OIDCProvider = %q, want %q", got.OIDCProvider, "google")
	}
	if got.OIDCSubject != "sub-123" {
		t.Errorf("GetByOIDC: OIDCSubject = %q, want %q", got.OIDCSubject, "sub-123")
	}
}

func TestUserUpdate(t *testing.T) {
	s, ctx := newTestStore(t)

	u := User{
		Email:        "eve@example.com",
		PasswordHash: "oldhash",
		Role:         roleUser,
	}
	created, err := s.Users().Create(ctx, u)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Sleep 1 second so UpdatedAt can advance (unix-second precision).
	time.Sleep(time.Second)

	created.Email = "eve-updated@example.com"
	created.PasswordHash = "newhash"
	created.Role = roleAdmin
	if err := s.Users().Update(ctx, created); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.Users().GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID after Update: %v", err)
	}
	if got.Email != "eve-updated@example.com" {
		t.Errorf("Update: Email = %q, want %q", got.Email, "eve-updated@example.com")
	}
	if got.PasswordHash != "newhash" {
		t.Errorf("Update: PasswordHash = %q, want %q", got.PasswordHash, "newhash")
	}
	if got.Role != roleAdmin {
		t.Errorf("Update: Role = %q, want %q", got.Role, roleAdmin)
	}
	if got.UpdatedAt <= created.CreatedAt {
		t.Errorf("Update: UpdatedAt (%d) should be > CreatedAt (%d)", got.UpdatedAt, created.CreatedAt)
	}
}

func TestUserUpdateNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	u := User{
		ID:    "nonexistent-id",
		Email: "ghost@example.com",
		Role:  roleUser,
	}
	err := s.Users().Update(ctx, u)
	if err == nil {
		t.Fatal("Update: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Update: got %v, want errors.Is(err, ErrNotFound)", err)
	}
}

func TestUserSetDisabled(t *testing.T) {
	s, ctx := newTestStore(t)

	u := User{
		Email: "frank@example.com",
		Role:  roleUser,
	}
	created, err := s.Users().Create(ctx, u)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Users().SetDisabled(ctx, created.ID, true); err != nil {
		t.Fatalf("SetDisabled(true): %v", err)
	}

	got, err := s.Users().GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID after SetDisabled: %v", err)
	}
	if !got.Disabled {
		t.Error("SetDisabled(true): Disabled should be true")
	}

	if err := s.Users().SetDisabled(ctx, created.ID, false); err != nil {
		t.Fatalf("SetDisabled(false): %v", err)
	}

	got2, err := s.Users().GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID after SetDisabled(false): %v", err)
	}
	if got2.Disabled {
		t.Error("SetDisabled(false): Disabled should be false")
	}
}

func TestUserDelete(t *testing.T) {
	s, ctx := newTestStore(t)

	u := User{
		Email: "grace@example.com",
		Role:  roleUser,
	}
	created, err := s.Users().Create(ctx, u)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Users().Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = s.Users().GetByID(ctx, created.ID)
	if err == nil {
		t.Fatal("GetByID after Delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID after Delete: got %v, want errors.Is(err, ErrNotFound)", err)
	}
}

func TestUserDeleteNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	err := s.Users().Delete(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("Delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete: got %v, want errors.Is(err, ErrNotFound)", err)
	}
}

func TestUserListOrdersByEmail(t *testing.T) {
	s, ctx := newTestStore(t)

	emails := []string{"zara@example.com", "alice@example.com", "mike@example.com"}
	for _, email := range emails {
		if _, err := s.Users().Create(ctx, User{Email: email, Role: roleUser}); err != nil {
			t.Fatalf("Create %q: %v", email, err)
		}
	}

	list, err := s.Users().List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("List: got %d rows, want 3", len(list))
	}

	want := []string{"alice@example.com", "mike@example.com", "zara@example.com"}
	for i, u := range list {
		if u.Email != want[i] {
			t.Errorf("List[%d].Email = %q, want %q", i, u.Email, want[i])
		}
	}
}
