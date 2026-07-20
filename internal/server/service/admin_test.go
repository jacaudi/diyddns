package service

import (
	"errors"
	"testing"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// newAdminSvc returns a fresh in-memory store and an AdminService bound to
// it, using cheap argon2id params and a real audit writer (so guard paths
// that write audit entries exercise the real sink, not a discard).
func newAdminSvc(t *testing.T) (*store.Store, *AdminService) {
	t.Helper()
	st := openTestStore(t)
	pw := config.PasswordCfg{Argon2Time: 1, Argon2MemoryKiB: 8 * 1024, Argon2Parallelism: 1, MinLength: 8}
	return st, NewAdminService(st, pw, NewAuditWriter(st))
}

func TestAdminService_CreateUser_HashesPassword(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")

	u, err := svc.CreateUser(t.Context(), admin.ID, CreateUserParams{Email: "new@x", Password: "correcthorse12", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash == "" || u.PasswordHash == "correcthorse12" {
		t.Fatal("password not hashed")
	}
	ok, err := auth.VerifyPassword(u.PasswordHash, "correcthorse12")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("hash does not verify")
	}
}

func TestAdminService_CreateUser_RejectsBadRole(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")

	if _, err := svc.CreateUser(t.Context(), admin.ID, CreateUserParams{Email: "n@x", Password: "correcthorse12", Role: "superuser"}); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("err = %v, want ErrInvalidRole", err)
	}
}

func TestAdminService_CreateUser_RejectsWeakPassword(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")

	if _, err := svc.CreateUser(t.Context(), admin.ID, CreateUserParams{Email: "n@x", Password: "short", Role: "user"}); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("err = %v, want ErrWeakPassword", err)
	}
}

func TestAdminService_CreateUser_RejectsInvalidEmail(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")

	if _, err := svc.CreateUser(t.Context(), admin.ID, CreateUserParams{Email: "not-an-email", Password: "correcthorse12", Role: "user"}); !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("err = %v, want ErrInvalidEmail", err)
	}
}

func TestAdminService_UpdateUser_LastAdminDemote_Rejected(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")
	other := seedUser(t, st, "b@x", "user")

	role := "user"
	if _, err := svc.UpdateUser(t.Context(), other.ID, admin.ID, UpdateUserParams{Role: &role}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin err = %v, want ErrLastAdmin", err)
	}
}

func TestAdminService_UpdateUser_RoleChange_Success(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")
	second := seedUser(t, st, "second@x", "admin") // second admin, demoted by the first — not a self-demote

	role := "user"
	u, err := svc.UpdateUser(t.Context(), admin.ID, second.ID, UpdateUserParams{Role: &role})
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != "user" {
		t.Fatalf("Role = %q, want %q", u.Role, "user")
	}
}

func TestAdminService_UpdateUser_SelfDemote_Rejected(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")
	seedUser(t, st, "b@x", "admin") // a second admin so last-admin guard is not what fires

	role := "user"
	if _, err := svc.UpdateUser(t.Context(), admin.ID, admin.ID, UpdateUserParams{Role: &role}); !errors.Is(err, ErrSelfLockout) {
		t.Fatalf("self-demote err = %v, want ErrSelfLockout", err)
	}
}

func TestAdminService_UpdateUser_RejectsBadRole(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")
	other := seedUser(t, st, "b@x", "user")

	role := "superuser"
	if _, err := svc.UpdateUser(t.Context(), admin.ID, other.ID, UpdateUserParams{Role: &role}); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("err = %v, want ErrInvalidRole", err)
	}
}

func TestAdminService_UpdateUser_SelfDisable_Rejected(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")
	seedUser(t, st, "b@x", "admin") // a second admin so last-admin guard is not what fires

	dis := true
	if _, err := svc.UpdateUser(t.Context(), admin.ID, admin.ID, UpdateUserParams{Disabled: &dis}); !errors.Is(err, ErrSelfLockout) {
		t.Fatalf("self-disable err = %v, want ErrSelfLockout", err)
	}
}

func TestAdminService_UpdateUser_DisableRevokesSessions(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")
	target := seedUser(t, st, "b@x", "user")
	if _, err := st.Sessions().Create(t.Context(), store.Session{UserID: target.ID, CSRFToken: "c", ExpiresAt: store.NowUnix() + 3600}); err != nil {
		t.Fatal(err)
	}

	dis := true
	if _, err := svc.UpdateUser(t.Context(), admin.ID, target.ID, UpdateUserParams{Disabled: &dis}); err != nil {
		t.Fatal(err)
	}

	// The target's sessions must already be gone: a second DeleteByUser finds
	// nothing left to remove.
	n, err := st.Sessions().DeleteByUser(t.Context(), target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0 remaining sessions, DeleteByUser removed %d more", n)
	}
}

func TestAdminService_UpdateUser_PasswordOnOIDCOnly_Rejected(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")
	// OIDC-only user: no password hash.
	oidcUser, err := st.Users().Create(t.Context(), store.User{Email: "o@x", Role: "user", OIDCProvider: "https://idp", OIDCSubject: "sub1"})
	if err != nil {
		t.Fatal(err)
	}

	pwNew := "correcthorse12"
	if _, err := svc.UpdateUser(t.Context(), admin.ID, oidcUser.ID, UpdateUserParams{Password: &pwNew}); !errors.Is(err, ErrOIDCNoPassword) {
		t.Fatalf("err = %v, want ErrOIDCNoPassword", err)
	}
}

func TestAdminService_UpdateUser_RejectsWeakPassword(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")
	// other must already have a local password so the OIDC-only guard does
	// not fire before the length check under test.
	other := seedUserWithPassword(t, st, "b@x", "user", "correcthorse12")

	pwNew := "short"
	if _, err := svc.UpdateUser(t.Context(), admin.ID, other.ID, UpdateUserParams{Password: &pwNew}); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("err = %v, want ErrWeakPassword", err)
	}
}

func TestAdminService_DeleteUser_LastAdmin_Rejected(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")
	other := seedUser(t, st, "b@x", "user")

	if err := svc.DeleteUser(t.Context(), other.ID, admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin err = %v, want ErrLastAdmin", err)
	}
}

func TestAdminService_DeleteUser_Self_Rejected(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")
	seedUser(t, st, "b@x", "admin")

	if err := svc.DeleteUser(t.Context(), admin.ID, admin.ID); !errors.Is(err, ErrSelfLockout) {
		t.Fatalf("self-delete err = %v, want ErrSelfLockout", err)
	}
}

func TestAdminService_DeleteUser_Success(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")
	other := seedUser(t, st, "b@x", "user")

	if err := svc.DeleteUser(t.Context(), admin.ID, other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Users().GetByID(t.Context(), other.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetByID after delete err = %v, want ErrNotFound", err)
	}
}

func TestAdminService_ListUsers_ReturnsAll(t *testing.T) {
	st, svc := newAdminSvc(t)
	seedUser(t, st, "a@x", "admin")
	seedUser(t, st, "b@x", "user")

	users, err := svc.ListUsers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("len(users) = %d, want 2", len(users))
	}
}

func TestAdminService_ListAllDevices_ReturnsAll(t *testing.T) {
	st, svc := newAdminSvc(t)
	usr := seedUser(t, st, "a@x", "user")
	seedDevice(t, st, usr.ID, "laptop")

	devices, err := svc.ListAllDevices(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1", len(devices))
	}
}

func TestAdminService_ListAudit_ReturnsPage(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")
	other := seedUser(t, st, "b@x", "user")

	// DeleteUser writes a "user.deleted" audit entry.
	if err := svc.DeleteUser(t.Context(), admin.ID, other.ID); err != nil {
		t.Fatal(err)
	}

	page, err := svc.ListAudit(t.Context(), store.AuditFilter{}, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("len(page.Rows) = %d, want 1", len(page.Rows))
	}
	if page.Rows[0].EventType != "user.deleted" {
		t.Fatalf("EventType = %q, want %q", page.Rows[0].EventType, "user.deleted")
	}
}
