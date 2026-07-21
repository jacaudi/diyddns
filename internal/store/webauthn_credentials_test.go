package store

import (
	"errors"
	"testing"
)

// ---------- 1. Create + GetByID round-trip (bytes preserved) ----------

func TestWebAuthnCredentialCreateAndGetByID(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "wc-alice@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := NowUnix()
	c := WebAuthnCredential{
		CredentialID:   []byte{0x01, 0x02, 0x03, 0x04},
		UserID:         u.ID,
		CredentialJSON: []byte(`{"id":"AQIDBA","publicKey":"..."}`),
		Name:           "YubiKey 5C",
		AAGUID:         []byte{0xde, 0xad, 0xbe, 0xef},
		CreatedAt:      now,
	}
	created, err := s.WebAuthnCredentials().Create(ctx, c)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if string(created.CredentialID) != string(c.CredentialID) {
		t.Errorf("Create: CredentialID = %x, want %x", created.CredentialID, c.CredentialID)
	}
	if created.UserID != u.ID {
		t.Errorf("Create: UserID = %q, want %q", created.UserID, u.ID)
	}

	got, err := s.WebAuthnCredentials().GetByID(ctx, c.CredentialID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if string(got.CredentialID) != string(c.CredentialID) {
		t.Errorf("GetByID: CredentialID = %x, want %x", got.CredentialID, c.CredentialID)
	}
	if string(got.CredentialJSON) != string(c.CredentialJSON) {
		t.Errorf("GetByID: CredentialJSON = %q, want %q", got.CredentialJSON, c.CredentialJSON)
	}
	if got.Name != c.Name {
		t.Errorf("GetByID: Name = %q, want %q", got.Name, c.Name)
	}
	if string(got.AAGUID) != string(c.AAGUID) {
		t.Errorf("GetByID: AAGUID = %x, want %x", got.AAGUID, c.AAGUID)
	}
	if got.CreatedAt != c.CreatedAt {
		t.Errorf("GetByID: CreatedAt = %d, want %d", got.CreatedAt, c.CreatedAt)
	}
	if got.LastUsedAt != 0 {
		t.Errorf("GetByID: LastUsedAt = %d, want 0", got.LastUsedAt)
	}
}

// ---------- 2. Create duplicate credential_id -> ErrConflict ----------

func TestWebAuthnCredentialCreateDuplicateReturnsErrConflict(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "wc-bob@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	c := WebAuthnCredential{
		CredentialID:   []byte{0xaa, 0xbb},
		UserID:         u.ID,
		CredentialJSON: []byte(`{}`),
		Name:           "dup",
		CreatedAt:      NowUnix(),
	}
	if _, err := s.WebAuthnCredentials().Create(ctx, c); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	_, err = s.WebAuthnCredentials().Create(ctx, c)
	if err == nil {
		t.Fatal("second Create: expected error, got nil")
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("second Create: got %v, want ErrConflict", err)
	}
}

// ---------- 3. GetByID unknown -> ErrNotFound ----------

func TestWebAuthnCredentialGetByIDNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	_, err := s.WebAuthnCredentials().GetByID(ctx, []byte{0xff, 0xff})
	if err == nil {
		t.Fatal("GetByID: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID: got %v, want ErrNotFound", err)
	}
}

// ---------- 4. ListByUser ordering by created_at ----------

func TestWebAuthnCredentialListByUserOrdersByCreatedAt(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "wc-carol@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	base := NowUnix()
	creds := []WebAuthnCredential{
		{CredentialID: []byte{0x03}, UserID: u.ID, CredentialJSON: []byte(`{}`), Name: "third", CreatedAt: base + 20},
		{CredentialID: []byte{0x01}, UserID: u.ID, CredentialJSON: []byte(`{}`), Name: "first", CreatedAt: base},
		{CredentialID: []byte{0x02}, UserID: u.ID, CredentialJSON: []byte(`{}`), Name: "second", CreatedAt: base + 10},
	}
	for _, c := range creds {
		if _, err := s.WebAuthnCredentials().Create(ctx, c); err != nil {
			t.Fatalf("Create %q: %v", c.Name, err)
		}
	}

	list, err := s.WebAuthnCredentials().ListByUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("ListByUser: got %d rows, want 3", len(list))
	}
	want := []string{"first", "second", "third"}
	for i, c := range list {
		if c.Name != want[i] {
			t.Errorf("ListByUser[%d].Name = %q, want %q", i, c.Name, want[i])
		}
	}
}

// ---------- 5. Rename ----------

func TestWebAuthnCredentialRename(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "wc-dan@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	c := WebAuthnCredential{
		CredentialID:   []byte{0x10},
		UserID:         u.ID,
		CredentialJSON: []byte(`{}`),
		Name:           "old-name",
		CreatedAt:      NowUnix(),
	}
	if _, err := s.WebAuthnCredentials().Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.WebAuthnCredentials().Rename(ctx, c.CredentialID, "new-name"); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	got, err := s.WebAuthnCredentials().GetByID(ctx, c.CredentialID)
	if err != nil {
		t.Fatalf("GetByID after Rename: %v", err)
	}
	if got.Name != "new-name" {
		t.Errorf("Rename: Name = %q, want %q", got.Name, "new-name")
	}
}

func TestWebAuthnCredentialRenameNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	err := s.WebAuthnCredentials().Rename(ctx, []byte{0x99}, "whatever")
	if err == nil {
		t.Fatal("Rename: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Rename: got %v, want ErrNotFound", err)
	}
}

// ---------- 6. Delete (ErrNotFound on missing) ----------

func TestWebAuthnCredentialDelete(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "wc-eve@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	c := WebAuthnCredential{
		CredentialID:   []byte{0x20},
		UserID:         u.ID,
		CredentialJSON: []byte(`{}`),
		Name:           "to-delete",
		CreatedAt:      NowUnix(),
	}
	if _, err := s.WebAuthnCredentials().Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.WebAuthnCredentials().Delete(ctx, c.CredentialID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = s.WebAuthnCredentials().GetByID(ctx, c.CredentialID)
	if err == nil {
		t.Fatal("GetByID after Delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID after Delete: got %v, want ErrNotFound", err)
	}
}

func TestWebAuthnCredentialDeleteNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	err := s.WebAuthnCredentials().Delete(ctx, []byte{0x77})
	if err == nil {
		t.Fatal("Delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete: got %v, want ErrNotFound", err)
	}
}

// ---------- 7. DeleteAllByUser returns count ----------

func TestWebAuthnCredentialDeleteAllByUserReturnsCount(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "wc-frank@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	other, err := s.Users().Create(ctx, User{Email: "wc-frank-other@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create other user: %v", err)
	}

	for i, id := range [][]byte{{0x30}, {0x31}} {
		c := WebAuthnCredential{
			CredentialID:   id,
			UserID:         u.ID,
			CredentialJSON: []byte(`{}`),
			Name:           "cred",
			CreatedAt:      NowUnix() + int64(i),
		}
		if _, err := s.WebAuthnCredentials().Create(ctx, c); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}
	otherCred := WebAuthnCredential{
		CredentialID:   []byte{0x32},
		UserID:         other.ID,
		CredentialJSON: []byte(`{}`),
		Name:           "other-cred",
		CreatedAt:      NowUnix(),
	}
	if _, err := s.WebAuthnCredentials().Create(ctx, otherCred); err != nil {
		t.Fatalf("Create other: %v", err)
	}

	n, err := s.WebAuthnCredentials().DeleteAllByUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("DeleteAllByUser: %v", err)
	}
	if n != 2 {
		t.Errorf("DeleteAllByUser: n = %d, want 2", n)
	}

	list, err := s.WebAuthnCredentials().ListByUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListByUser after DeleteAllByUser: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("ListByUser after DeleteAllByUser: got %d rows, want 0", len(list))
	}

	// Other user's credential must survive.
	if _, err := s.WebAuthnCredentials().GetByID(ctx, otherCred.CredentialID); err != nil {
		t.Errorf("other user's credential should survive DeleteAllByUser: %v", err)
	}
}

// ---------- 8. User-delete cascade ----------

func TestWebAuthnCredentialFKCascadeOnUserDelete(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "wc-grace@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	c := WebAuthnCredential{
		CredentialID:   []byte{0x40},
		UserID:         u.ID,
		CredentialJSON: []byte(`{}`),
		Name:           "cascade-me",
		CreatedAt:      NowUnix(),
	}
	if _, err := s.WebAuthnCredentials().Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Users().Delete(ctx, u.ID); err != nil {
		t.Fatalf("Users().Delete: %v", err)
	}

	_, err = s.WebAuthnCredentials().GetByID(ctx, c.CredentialID)
	if err == nil {
		t.Fatal("GetByID after user delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID after user delete: got %v, want ErrNotFound", err)
	}
}

// ---------- 9. Update re-persists credential_json + last_used_at ----------

func TestWebAuthnCredentialUpdateRepersists(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "wc-henry@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	c := WebAuthnCredential{
		CredentialID:   []byte{0x50},
		UserID:         u.ID,
		CredentialJSON: []byte(`{"signCount":1}`),
		Name:           "login-cred",
		CreatedAt:      NowUnix(),
	}
	created, err := s.WebAuthnCredentials().Create(ctx, c)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	created.CredentialJSON = []byte(`{"signCount":2}`)
	created.LastUsedAt = NowUnix() + 100
	if err := s.WebAuthnCredentials().Update(ctx, created); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.WebAuthnCredentials().GetByID(ctx, c.CredentialID)
	if err != nil {
		t.Fatalf("GetByID after Update: %v", err)
	}
	if string(got.CredentialJSON) != string(created.CredentialJSON) {
		t.Errorf("Update: CredentialJSON = %q, want %q", got.CredentialJSON, created.CredentialJSON)
	}
	if got.LastUsedAt != created.LastUsedAt {
		t.Errorf("Update: LastUsedAt = %d, want %d", got.LastUsedAt, created.LastUsedAt)
	}
	// Name must be unaffected by Update (only Rename changes it).
	if got.Name != c.Name {
		t.Errorf("Update: Name = %q, want unchanged %q", got.Name, c.Name)
	}
}

func TestWebAuthnCredentialUpdateNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	c := WebAuthnCredential{
		CredentialID:   []byte{0x60},
		UserID:         "nonexistent-user",
		CredentialJSON: []byte(`{}`),
		Name:           "ghost",
	}
	err := s.WebAuthnCredentials().Update(ctx, c)
	if err == nil {
		t.Fatal("Update: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Update: got %v, want ErrNotFound", err)
	}
}

// ---------- 10. CountWebAuthnCredentials ----------

func TestWebAuthnCredentialCount(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "wc-ivan@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	n, err := s.WebAuthnCredentials().CountWebAuthnCredentials(ctx, u.ID)
	if err != nil {
		t.Fatalf("CountWebAuthnCredentials (empty): %v", err)
	}
	if n != 0 {
		t.Errorf("CountWebAuthnCredentials (empty): n = %d, want 0", n)
	}

	c := WebAuthnCredential{
		CredentialID:   []byte{0x70},
		UserID:         u.ID,
		CredentialJSON: []byte(`{}`),
		Name:           "counted",
		CreatedAt:      NowUnix(),
	}
	if _, err := s.WebAuthnCredentials().Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	n, err = s.WebAuthnCredentials().CountWebAuthnCredentials(ctx, u.ID)
	if err != nil {
		t.Fatalf("CountWebAuthnCredentials: %v", err)
	}
	if n != 1 {
		t.Errorf("CountWebAuthnCredentials: n = %d, want 1", n)
	}
}
