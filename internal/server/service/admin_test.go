package service

import (
	"encoding/json"
	"errors"
	"strings"
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
	st, svc, _ := newAdminSvcWithNotifier(t)
	return st, svc
}

// newAdminSvcWithNotifier is newAdminSvc plus the recording membership
// notifier, for the tests that assert device.added/device.removed emission
// on user disable/enable/delete.
func newAdminSvcWithNotifier(t *testing.T) (*store.Store, *AdminService, *recordingDeviceNotifier) {
	t.Helper()
	st, svc, n, _ := newAdminSvcWithMailer(t, false)
	return st, svc, n
}

// newAdminSvcWithMailer is newAdminSvcWithNotifier plus a handle on the fake
// mailer, enabled or not, for the #132 owner-notification tests. One mailer
// value is wired into both GrantService and AdminService, as server.go does.
func newAdminSvcWithMailer(t *testing.T, mailEnabled bool) (*store.Store, *AdminService, *recordingDeviceNotifier, *fakeMailer) {
	t.Helper()
	st := openTestStore(t)
	audit := NewAuditWriter(st)
	m := &fakeMailer{enabled: mailEnabled}
	grants := NewGrantService(st, nil, m, "https://ddns.example.com", audit, discardLogger())
	n := &recordingDeviceNotifier{}
	return st, NewAdminService(st, audit, grants, n, m, discardLogger()), n, m
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
	return st, NewAdminService(st, audit, grants, NopDeviceNotifier{}, &fakeMailer{}, discardLogger())
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

func TestAdminService_CreateUserInvite_RejectsNonASCIIEmail(t *testing.T) {
	for _, addr := range []string{"josé@example.test", "user@exämple.test", "日本@example.test"} {
		t.Run(addr, func(t *testing.T) {
			st, svc := newAdminSvcWithPasskeys(t)
			admin := seedUser(t, st, "admin@example.test", "admin")
			if _, _, _, err := svc.CreateUserInvite(t.Context(), admin.ID, addr, "user"); !errors.Is(err, ErrInvalidEmail) {
				t.Fatalf("err = %v, want ErrInvalidEmail", err)
			}
			users, err := st.Users().List(t.Context())
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(users) != 1 {
				t.Errorf("users = %d, want 1 (only the seeded admin) — a rejected invite must create nothing", len(users))
			}
		})
	}
}

// TestAdminService_CreateUserInvite_NormalizesTheAddress pins design §5.6: the previous code
// wrote `if _, err := mail.ParseAddress(email)` and stored the RAW string, so
// "Bob <bob@example.test>" went out as RCPT TO:<Bob <bob@example.test>> with
// Send returning nil. It is pure ASCII, so the charset guard does not catch it.
func TestAdminService_CreateUserInvite_NormalizesTheAddress(t *testing.T) {
	st, svc := newAdminSvcWithPasskeys(t)
	admin := seedUser(t, st, "admin@example.test", "admin")

	u, _, _, err := svc.CreateUserInvite(t.Context(), admin.ID, "Bob <bob@example.test>", "user")
	if err != nil {
		t.Fatalf("CreateUserInvite: %v", err)
	}
	if u.Email != "bob@example.test" {
		t.Errorf("stored email = %q, want %q", u.Email, "bob@example.test")
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

// TestAdminService_ListAllDevicesWithExpiry_ReturnsLatestAddress pins that the
// admin list's counterpart to ListAllDevices reports a device's last-recorded
// address even after the sweep has cleared current_ipv4 -- the whole point of
// #127's user-facing half is that clearing an address does not erase where
// the operator can go find it.
func TestAdminService_ListAllDevicesWithExpiry_ReturnsLatestAddress(t *testing.T) {
	st, svc := newAdminSvc(t)
	usr := seedUser(t, st, "a@x", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")

	if _, err := st.IPHistory().Append(t.Context(), store.IPHistory{
		DeviceID: dev.ID, IPv4: "203.0.113.9", ObservedAt: 1000,
	}); err != nil {
		t.Fatalf("seed history: %v", err)
	}

	devices, latest, err := svc.ListAllDevicesWithExpiry(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1", len(devices))
	}
	if got := latest[dev.ID].IPv4; got != "203.0.113.9" {
		t.Errorf("latest[dev.ID].IPv4 = %q, want 203.0.113.9", got)
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

// TestAdminService_DisableUser_EmitsRemovedPerMemberDevice is the case pass 1
// B5 showed a naive implementation gets wrong: the "before" membership must be
// computed against the PRE-WRITE user row. Three devices, one already
// disabled, one with no address: exactly one removed on disable, one added on
// re-enable.
func TestAdminService_DisableUser_EmitsRemovedPerMemberDevice(t *testing.T) {
	st, svc, n := newAdminSvcWithNotifier(t)
	admin := seedUser(t, st, "a@x", "admin")
	target := seedUser(t, st, "b@x", "user")
	member := seedDevice(t, st, target.ID, "member")
	giveIP(t, st, member.ID, "203.0.113.9")
	off := seedDevice(t, st, target.ID, "off")
	giveIP(t, st, off.ID, "203.0.113.10")
	if err := st.Devices().SetDisabled(t.Context(), off.ID, true); err != nil {
		t.Fatal(err)
	}
	seedDevice(t, st, target.ID, "noaddr")

	dis := true
	if _, err := svc.UpdateUser(t.Context(), admin.ID, target.ID, UpdateUserParams{Disabled: &dis}); err != nil {
		t.Fatal(err)
	}
	if len(n.removed) != 1 || n.removed[0].ID != member.ID {
		t.Fatalf("removed = %+v, want exactly [%s]", n.removed, member.ID)
	}

	en := false
	if _, err := svc.UpdateUser(t.Context(), admin.ID, target.ID, UpdateUserParams{Disabled: &en}); err != nil {
		t.Fatal(err)
	}
	if len(n.added) != 1 || n.added[0].ID != member.ID {
		t.Fatalf("added = %+v, want exactly [%s]", n.added, member.ID)
	}
	if len(n.removed) != 1 {
		t.Errorf("removed = %+v, want still just the one disable-time event", n.removed)
	}
}

// TestAdminService_DeleteUser_EmitsRemovedBeforeCascade: devices.user_id is
// ON DELETE CASCADE, so the member list must be read before the delete.
func TestAdminService_DeleteUser_EmitsRemovedBeforeCascade(t *testing.T) {
	st, svc, n := newAdminSvcWithNotifier(t)
	admin := seedUser(t, st, "a@x", "admin")
	target := seedUser(t, st, "b@x", "user")
	member := seedDevice(t, st, target.ID, "member")
	giveIP(t, st, member.ID, "203.0.113.9")
	seedDevice(t, st, target.ID, "noaddr")

	if err := svc.DeleteUser(t.Context(), admin.ID, target.ID); err != nil {
		t.Fatal(err)
	}
	if len(n.removed) != 1 || n.removed[0].ID != member.ID || n.removed[0].CurrentIPv4 != "203.0.113.9" {
		t.Errorf("removed = %+v, want exactly the member with its last address", n.removed)
	}
}

// TestAdminService_CreateUserInvite_RejectsCaseVariantOfHeldAddress pins
// design D20 at the invite site: the collision check compares canonical
// forms case-insensitively, over stored AND pending addresses, and exempts
// NO row -- including the acting admin's own.
func TestAdminService_CreateUserInvite_RejectsCaseVariantOfHeldAddress(t *testing.T) {
	st, svc := newAdminSvcWithPasskeys(t)
	admin := seedUser(t, st, "admin@example.test", "admin")
	seedUser(t, st, "bob@example.test", "user")
	if err := st.Users().SetPendingEmail(t.Context(), admin.ID, "pending@example.test", "h", store.NowUnix()+3600); err != nil {
		t.Fatal(err)
	}

	for _, held := range []string{"Bob@Example.TEST", "ADMIN@example.test", "Pending@example.test"} {
		if _, _, _, err := svc.CreateUserInvite(t.Context(), admin.ID, held, "user"); !errors.Is(err, store.ErrConflict) {
			t.Errorf("%q: err = %v, want store.ErrConflict", held, err)
		}
	}
	users, err := st.Users().List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("users = %d after rejected invites, want 2", len(users))
	}
}

// adminAuditRows returns every audit row of one event type, newest first.
func adminAuditRows(t *testing.T, st *store.Store, eventType string) []store.AuditEntry {
	t.Helper()
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: eventType}, "", 100)
	if err != nil {
		t.Fatalf("ListPaginated(%s): %v", eventType, err)
	}
	return page.Rows
}

// adminAuditCount returns the total number of audit rows.
func adminAuditCount(t *testing.T, st *store.Store) int {
	t.Helper()
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{}, "", 1000)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	return len(page.Rows)
}

func TestAdminService_GetDevice_ReturnsAnyDeviceWithOwner(t *testing.T) {
	st, svc := newAdminSvc(t)
	owner := seedUser(t, st, "owner@x", "user")
	dev := seedDevice(t, st, owner.ID, "theirs")

	gotDev, gotOwner, err := svc.GetDevice(t.Context(), dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotDev.ID != dev.ID || gotOwner.ID != owner.ID || gotOwner.Email != "owner@x" {
		t.Fatalf("GetDevice = (%+v, %+v), want device %s of owner %s", gotDev, gotOwner, dev.ID, owner.ID)
	}
}

func TestAdminService_GetDevice_UnknownIsErrNotFound(t *testing.T) {
	_, svc := newAdminSvc(t)
	if _, _, err := svc.GetDevice(t.Context(), "no-such-device"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// TestAdminService_GetDevice_MissingOwnerIsAFaultNotA404: the users→devices
// FK cascades, so a device without an owner row is impossible through the
// store's API and is produced here with the FK check off. It must surface as
// ErrOwnerMissing and must NOT satisfy errors.Is(err, store.ErrNotFound) —
// the web handler maps ErrNotFound to "that device does not exist", which
// would be a lie (#132 D18).
func TestAdminService_GetDevice_MissingOwnerIsAFaultNotA404(t *testing.T) {
	st, svc := newAdminSvc(t)
	owner := seedUser(t, st, "gone@x", "user")
	dev := seedDevice(t, st, owner.ID, "orphan")
	// The pool is one connection (store.Open: SetMaxOpenConns(1)), so a
	// PRAGMA issued through DB() applies to the connection every later
	// statement runs on; foreign_keys is re-enabled before the test reads.
	for _, stmt := range []string{"PRAGMA foreign_keys = OFF", "DELETE FROM users WHERE id = '" + owner.ID + "'", "PRAGMA foreign_keys = ON"} {
		if _, err := st.DB().ExecContext(t.Context(), stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}

	_, _, err := svc.GetDevice(t.Context(), dev.ID)
	if !errors.Is(err, ErrOwnerMissing) {
		t.Fatalf("err = %v, want ErrOwnerMissing", err)
	}
	if errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v must not satisfy ErrNotFound: the device exists", err)
	}
	if !strings.Contains(err.Error(), dev.ID) || !strings.Contains(err.Error(), owner.ID) {
		t.Fatalf("err = %q should name both ids for the log", err)
	}
}

func TestAdminService_SetDeviceEnabled_AuditsTheAdminAndNamesTheOwner(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "admin@x", "admin")
	owner := seedUser(t, st, "owner@x", "user")
	dev := seedDevice(t, st, owner.ID, "theirs")
	actor := store.Session{UserID: admin.ID, IP: "198.51.100.7"}

	got, err := svc.SetDeviceEnabled(t.Context(), actor, dev.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Disabled {
		t.Fatal("device not disabled")
	}
	rows := adminAuditRows(t, st, "device.disabled_by_admin")
	if len(rows) != 1 {
		t.Fatalf("device.disabled_by_admin rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.ActorUserID != admin.ID || row.IP != "198.51.100.7" || row.TargetType != "device" || row.TargetID != dev.ID {
		t.Fatalf("row = %+v, want actor=admin ip=198.51.100.7 target=device/%s", row, dev.ID)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(row.DetailsJSON), &details); err != nil {
		t.Fatalf("DetailsJSON %q: %v", row.DetailsJSON, err)
	}
	if details["owner_user_id"] != owner.ID {
		t.Fatalf("details = %v, want owner_user_id=%s", details, owner.ID)
	}
	if n := len(adminAuditRows(t, st, "device.disabled")); n != 0 {
		t.Fatalf("an owner-style device.disabled row was written (%d); the admin path must use its own event", n)
	}

	got, err = svc.SetDeviceEnabled(t.Context(), actor, dev.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Disabled {
		t.Fatal("device not re-enabled")
	}
	if rows := adminAuditRows(t, st, "device.enabled_by_admin"); len(rows) != 1 || rows[0].ActorUserID != admin.ID {
		t.Fatalf("device.enabled_by_admin rows = %+v, want one by the admin", rows)
	}
}

func TestAdminService_SetDeviceEnabled_EmitsMembershipFromPreWriteSnapshot(t *testing.T) {
	st, svc, n := newAdminSvcWithNotifier(t)
	admin := seedUser(t, st, "admin@x", "admin")
	owner := seedUser(t, st, "owner@x", "user")
	dev := seedDevice(t, st, owner.ID, "theirs")
	giveIP(t, st, dev.ID, "203.0.113.9")
	actor := store.Session{UserID: admin.ID}

	if _, err := svc.SetDeviceEnabled(t.Context(), actor, dev.ID, true); err != nil {
		t.Fatal(err)
	}
	if len(n.removed) != 1 || n.removed[0].ID != dev.ID || len(n.added) != 0 {
		t.Fatalf("removed=%+v added=%+v, want one removed", n.removed, n.added)
	}
	if _, err := svc.SetDeviceEnabled(t.Context(), actor, dev.ID, false); err != nil {
		t.Fatal(err)
	}
	if len(n.added) != 1 || n.added[0].ID != dev.ID {
		t.Fatalf("added=%+v, want the re-enabled device", n.added)
	}

	// A disabled owner is out of the feed regardless of the device: no event.
	if err := st.Users().SetDisabled(t.Context(), owner.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetDeviceEnabled(t.Context(), actor, dev.ID, true); err != nil {
		t.Fatal(err)
	}
	if len(n.removed) != 1 {
		t.Fatalf("removed=%+v, want no new event while the owner is disabled", n.removed)
	}
}

// TestAdminService_SetDeviceEnabled_IsIdempotent: a double-submit must not
// write a second audit row or send a second unsolicited email (#132 D11).
func TestAdminService_SetDeviceEnabled_IsIdempotent(t *testing.T) {
	st, svc, _, m := newAdminSvcWithMailer(t, true)
	admin := seedUser(t, st, "admin@x", "admin")
	owner := seedUser(t, st, "owner@x", "user")
	dev := seedDevice(t, st, owner.ID, "theirs")
	actor := store.Session{UserID: admin.ID}

	if _, err := svc.SetDeviceEnabled(t.Context(), actor, dev.ID, true); err != nil {
		t.Fatal(err)
	}
	before := adminAuditCount(t, st)
	if _, err := svc.SetDeviceEnabled(t.Context(), actor, dev.ID, true); err != nil {
		t.Fatal(err)
	}
	if after := adminAuditCount(t, st); after != before {
		t.Fatalf("audit rows %d → %d on a no-op disable, want unchanged", before, after)
	}
	m.mu.Lock()
	sent := len(m.sent)
	m.mu.Unlock()
	if sent != 1 {
		t.Fatalf("mails sent = %d, want exactly 1 (the first disable)", sent)
	}
}

func TestAdminService_SetDeviceEnabled_MailsTheOwner(t *testing.T) {
	st, svc, _, m := newAdminSvcWithMailer(t, true)
	admin := seedUser(t, st, "admin@x", "admin")
	owner := seedUser(t, st, "owner@x", "user")
	dev := seedDevice(t, st, owner.ID, "Büro-Pi")
	actor := store.Session{UserID: admin.ID}

	if _, err := svc.SetDeviceEnabled(t.Context(), actor, dev.ID, true); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) != 1 {
		t.Fatalf("sent = %+v, want one mail", m.sent)
	}
	e := m.sent[0]
	if e.to != "owner@x" {
		t.Errorf("to = %q, want the owner", e.to)
	}
	if e.subject != "An administrator disabled one of your DIYDDNS devices" {
		t.Errorf("subject = %q", e.subject)
	}
	if !strings.Contains(e.body, dev.ID) || !strings.Contains(e.body, "B?ro-Pi") {
		t.Errorf("body should name the device by id and folded label:\n%s", e.body)
	}
	if m.lastCtxErr != nil {
		t.Errorf("Send saw a dead context: %v (cancellation must be stripped)", m.lastCtxErr)
	}
}

func TestAdminService_SetDeviceEnabled_NoMailWhenMailerDisabledOrNil(t *testing.T) {
	st, svc, _, m := newAdminSvcWithMailer(t, false)
	admin := seedUser(t, st, "admin@x", "admin")
	owner := seedUser(t, st, "owner@x", "user")
	dev := seedDevice(t, st, owner.ID, "theirs")
	if _, err := svc.SetDeviceEnabled(t.Context(), store.Session{UserID: admin.ID}, dev.ID, true); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	sent := len(m.sent)
	m.mu.Unlock()
	if sent != 0 {
		t.Fatalf("disabled mailer sent %d mails", sent)
	}

	// A nil mailer is the state testDeps in webui wires; it must not panic.
	nilSvc := NewAdminService(st, NewAuditWriter(st), nil, NopDeviceNotifier{}, nil, discardLogger())
	if _, err := nilSvc.SetDeviceEnabled(t.Context(), store.Session{UserID: admin.ID}, dev.ID, false); err != nil {
		t.Fatal(err)
	}
}

// TestAdminService_SetDeviceEnabled_MailFailureIsAuditedNotReturned: the
// disable is the durable record; the mail is a courtesy. A failed send leaves
// the device disabled, returns nil, and writes an email.send_failed row that
// names the device so it can be told from an invite or recovery failure
// (#132 design §6).
func TestAdminService_SetDeviceEnabled_MailFailureIsAuditedNotReturned(t *testing.T) {
	st, svc, _, m := newAdminSvcWithMailer(t, true)
	m.sendErr = errors.New("smtp: boom")
	admin := seedUser(t, st, "admin@x", "admin")
	owner := seedUser(t, st, "owner@x", "user")
	dev := seedDevice(t, st, owner.ID, "theirs")
	actor := store.Session{UserID: admin.ID, IP: "198.51.100.7"}

	got, err := svc.SetDeviceEnabled(t.Context(), actor, dev.ID, true)
	if err != nil {
		t.Fatalf("a mail failure must not fail the request: %v", err)
	}
	if !got.Disabled {
		t.Fatal("device not disabled")
	}
	rows := adminAuditRows(t, st, EventEmailSendFailed)
	if len(rows) != 1 {
		t.Fatalf("email.send_failed rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.ActorUserID != admin.ID || row.IP != "198.51.100.7" || row.TargetType != "user" || row.TargetID != owner.ID {
		t.Fatalf("row = %+v, want actor=admin target=user/%s", row, owner.ID)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(row.DetailsJSON), &details); err != nil || details["device_id"] != dev.ID {
		t.Fatalf("DetailsJSON = %q (%v), want device_id=%s", row.DetailsJSON, err, dev.ID)
	}
}

func TestAdminService_SetDeviceEnabled_UnknownDeviceWritesNothing(t *testing.T) {
	st, svc := newAdminSvc(t)
	admin := seedUser(t, st, "admin@x", "admin")
	before := adminAuditCount(t, st)
	if _, err := svc.SetDeviceEnabled(t.Context(), store.Session{UserID: admin.ID}, "no-such-device", true); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if after := adminAuditCount(t, st); after != before {
		t.Fatalf("audit rows %d → %d, want unchanged", before, after)
	}
}
