package service

import (
	"errors"
	"testing"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// newAdminSvc returns a fresh in-memory store and an AdminService bound to
// it, using a real audit writer (so guard paths that write audit entries
// exercise the real sink, not a discard). grants has a nil PasskeyService:
// UpdateUser/DeleteUser never touch it, and the role/email validation guards
// CreateUserInvite runs before its own passkeys check fire first for the
// "rejects bad input" tests below — but CreateUserInvite now also refuses to
// mint a link when passkeys are nil (see ErrWebAuthnUnavailable, a dead link
// would 404 at redeem), so tests exercising an actual successful invite need
// newAdminSvcWithPasskeys instead.
func newAdminSvc(t *testing.T) (*store.Store, *AdminService) {
	t.Helper()
	st := openTestStore(t)
	audit := NewAuditWriter(st)
	grants := NewGrantService(st, nil, &fakeMailer{}, "https://ddns.example.com", audit, discardLogger())
	return st, NewAdminService(st, audit, grants)
}

// newAdminSvcWithPasskeys is newAdminSvc but with a real PasskeyService
// wired into grants, for tests that need CreateUserInvite to actually mint a
// redeemable link.
func newAdminSvcWithPasskeys(t *testing.T) (*store.Store, *AdminService) {
	t.Helper()
	st := openTestStore(t)
	audit := NewAuditWriter(st)
	passkeys := newTestPasskeyService(t, st, audit)
	grants := NewGrantService(st, passkeys, &fakeMailer{}, "https://ddns.example.com", audit, discardLogger())
	return st, NewAdminService(st, audit, grants)
}

func TestAdminService_CreateUserInvite_RejectsBadRole(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")

	if _, _, _, err := svc.CreateUserInvite(t.Context(), admin.ID, "n@x.com", "superuser"); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("err = %v, want ErrInvalidRole", err)
	}
}

func TestAdminService_CreateUserInvite_RejectsInvalidEmail(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "a@x", "admin")

	if _, _, _, err := svc.CreateUserInvite(t.Context(), admin.ID, "not-an-email", "user"); !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("err = %v, want ErrInvalidEmail", err)
	}
}

func TestAdminService_CreateUserInvite_CredentiallessUserAndRedeemableLink(t *testing.T) {
	st, svc := newAdminSvcWithPasskeys(t)
	admin := seedUser(t, st, "admin@x.com", "admin")

	u, link, _, err := svc.CreateUserInvite(t.Context(), admin.ID, "invitee@x.com", "user")
	if err != nil {
		t.Fatalf("CreateUserInvite: %v", err)
	}
	if u.Email != "invitee@x.com" || u.Role != "user" {
		t.Errorf("CreateUserInvite: user = %+v, want Email=invitee@x.com Role=user", u)
	}
	// Credential-less: the invited user has no passkey until they redeem the
	// invite (and there is no local password to have; that concept is gone).
	count, err := st.WebAuthnCredentials().CountWebAuthnCredentials(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("CountWebAuthnCredentials: %v", err)
	}
	if count != 0 {
		t.Errorf("new invited user passkey count = %d, want 0 (credential-less)", count)
	}

	token := extractToken(t, link)
	grant, err := st.AccountRecovery().Get(t.Context(), auth.HashToken(token))
	if err != nil {
		t.Fatalf("AccountRecovery.Get: %v", err)
	}
	if grant.UserID != u.ID || grant.Reason != "invite" || grant.UsedAt != 0 {
		t.Errorf("grant = %+v, want UserID=%q Reason=invite UsedAt=0", grant, u.ID)
	}
}

// TestAdminService_CreateUserInvite_NilPasskeys_ReturnsErrWebAuthnUnavailable
// proves CreateUserInvite refuses to mint an invite link when WebAuthn isn't
// configured — such a link would 404 at redeem (register routes are gated
// off deps.Passkey != nil, server.go). newAdminSvc's grants has a nil
// PasskeyService.
func TestAdminService_CreateUserInvite_NilPasskeys_ReturnsErrWebAuthnUnavailable(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "admin@x.com", "admin")

	if _, _, _, err := svc.CreateUserInvite(t.Context(), admin.ID, "invitee@x.com", "user"); !errors.Is(err, ErrWebAuthnUnavailable) {
		t.Fatalf("CreateUserInvite with nil passkeys: err = %v, want ErrWebAuthnUnavailable", err)
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
