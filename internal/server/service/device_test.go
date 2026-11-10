package service

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

// newDeviceServiceTest opens a fresh in-memory store, seeds one user, and
// builds a DeviceService wired to a discard audit sink and a recording
// membership notifier. Reused by every DeviceService test in this file.
func newDeviceServiceTest(t *testing.T) (*store.Store, string, *DeviceService) {
	t.Helper()
	st, userID, svc, _ := newDeviceServiceTestWithNotifier(t)
	return st, userID, svc
}

func newDeviceServiceTestWithNotifier(t *testing.T) (*store.Store, string, *DeviceService, *recordingDeviceNotifier) {
	t.Helper()
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	n := &recordingDeviceNotifier{}
	svc := NewDeviceService(st, testKey32(), discardAudit{}, n)
	return st, usr.ID, svc, n
}

// giveIP records an address for dev so it becomes a feed member.
func giveIP(t *testing.T, st *store.Store, deviceID, v4 string) {
	t.Helper()
	if err := st.Devices().UpdateIP(t.Context(), deviceID, v4, "", "", "", "", store.NowUnix()); err != nil {
		t.Fatalf("UpdateIP: %v", err)
	}
}

func TestDeviceService_Get_ReturnsOwnedDevice(t *testing.T) {
	st, userID, svc := newDeviceServiceTest(t)
	dev := seedDevice(t, st, userID, "laptop")

	got, err := svc.Get(t.Context(), userID, dev.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != dev.ID {
		t.Fatalf("Get: ID = %q, want %q", got.ID, dev.ID)
	}
}

func TestDeviceService_Get_OtherUsersDeviceErrNotFound(t *testing.T) {
	st, userID, svc := newDeviceServiceTest(t)
	other := seedUser(t, st, "other@b.co", "user")
	dev := seedDevice(t, st, userID, "laptop")

	_, err := svc.Get(t.Context(), other.ID, dev.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get: err = %v, want store.ErrNotFound", err)
	}
}

func TestDeviceService_List_ReturnsOnlyCallersDevices(t *testing.T) {
	st, userID, svc := newDeviceServiceTest(t)
	other := seedUser(t, st, "other@b.co", "user")
	seedDevice(t, st, userID, "laptop")
	seedDevice(t, st, userID, "phone")
	seedDevice(t, st, other.ID, "tablet")

	got, err := svc.List(t.Context(), userID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List: len = %d, want 2", len(got))
	}
	for _, d := range got {
		if d.UserID != userID {
			t.Fatalf("List: returned device %+v belongs to another user", d)
		}
	}
}

// TestDeviceService_ListWithExpiry_ReturnsLatestAddress pins that the owner
// list's counterpart to List reports a device's last-recorded address even
// after the sweep has cleared current_ipv4.
func TestDeviceService_ListWithExpiry_ReturnsLatestAddress(t *testing.T) {
	st, userID, svc := newDeviceServiceTest(t)
	dev := seedDevice(t, st, userID, "laptop")

	if _, err := st.IPHistory().Append(t.Context(), store.IPHistory{
		DeviceID: dev.ID, IPv4: "203.0.113.9", ObservedAt: 1000,
	}); err != nil {
		t.Fatalf("seed history: %v", err)
	}

	devices, latest, err := svc.ListWithExpiry(t.Context(), userID)
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

// TestDeviceService_LatestAddress_OwnerScoped mirrors ownedDevice's
// scoping guarantee (Get/Rename/etc): a foreign device's history must not
// leak through the single-device fallback the detail page uses when none of
// its five preview rows carries a family's address.
func TestDeviceService_LatestAddress_OwnerScoped(t *testing.T) {
	st, userID, svc := newDeviceServiceTest(t)
	other := seedUser(t, st, "other@b.co", "user")
	dev := seedDevice(t, st, other.ID, "tablet")

	if _, err := svc.LatestAddress(t.Context(), userID, dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("LatestAddress: err = %v, want store.ErrNotFound", err)
	}
}

func TestDeviceService_LatestAddress_ReturnsRecordedValue(t *testing.T) {
	st, userID, svc := newDeviceServiceTest(t)
	dev := seedDevice(t, st, userID, "laptop")

	if _, err := st.IPHistory().Append(t.Context(), store.IPHistory{
		DeviceID: dev.ID, IPv4: "203.0.113.9", ObservedAt: 1000,
	}); err != nil {
		t.Fatalf("seed history: %v", err)
	}

	got, err := svc.LatestAddress(t.Context(), userID, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.IPv4 != "203.0.113.9" {
		t.Errorf("IPv4 = %q, want 203.0.113.9", got.IPv4)
	}
}

func TestDeviceService_Rename_OwnerScoped(t *testing.T) {
	st, userID, svc := newDeviceServiceTest(t)
	dev := seedDevice(t, st, userID, "old-label")

	got, err := svc.Rename(t.Context(), userID, dev.ID, "new-label")
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "new-label" {
		t.Fatalf("label = %q, want new-label", got.Label)
	}

	// Foreign owner → ErrNotFound.
	if _, err := svc.Rename(t.Context(), "someone-else", dev.ID, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign rename err = %v, want ErrNotFound", err)
	}
}

func TestDeviceService_Rename_ConflictSurfaces(t *testing.T) {
	st, userID, svc := newDeviceServiceTest(t)
	seedDevice(t, st, userID, "taken")
	dev := seedDevice(t, st, userID, "other")
	if _, err := svc.Rename(t.Context(), userID, dev.ID, "taken"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestDeviceService_SetEnabled_TogglesDisabled(t *testing.T) {
	st, userID, svc := newDeviceServiceTest(t)
	dev := seedDevice(t, st, userID, "d")
	got, err := svc.SetEnabled(t.Context(), userID, dev.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Disabled {
		t.Fatal("expected Disabled=true")
	}
}

func TestDeviceService_Delete_OwnerScoped(t *testing.T) {
	st, userID, svc := newDeviceServiceTest(t)
	dev := seedDevice(t, st, userID, "d")
	if err := svc.Delete(t.Context(), "not-owner", dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign delete err = %v, want ErrNotFound", err)
	}
	if err := svc.Delete(t.Context(), userID, dev.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Devices().GetByID(t.Context(), dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("device still present after delete: %v", err)
	}
}

// TestDeviceService_RotateSecret_NextRequestSeesNewSecret pins that there is no
// secret cache to evict: a Verifier over the real store rejects the old secret
// right after RotateSecret and accepts the new one.
func TestDeviceService_RotateSecret_NextRequestSeesNewSecret(t *testing.T) {
	st, userID, svc := newDeviceServiceTest(t)
	key := testKey32()
	old := bytes.Repeat([]byte{0x07}, 32)
	sealed, err := auth.SealSecret(key, old)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := st.Devices().Create(t.Context(), store.Device{UserID: userID, Label: "laptop", SecretHash: sealed})
	if err != nil {
		t.Fatal(err)
	}
	v := auth.NewVerifier(st.Devices(), st.Users(), st.ReplayNonces(),
		NewRotationService(st, key, discardAudit{}, false), key, 120*time.Second, 120*time.Second)
	const now int64 = 1720000000
	signed := func(secret []byte, nonce string) auth.RequestParts {
		ts := strconv.FormatInt(now, 10)
		sig := shared.Sign(secret, shared.CanonicalRequest("POST", "/agent/v1/checkin", ts, nonce, shared.BodyHashHex(nil)))
		return auth.RequestParts{Device: dev.ID, Timestamp: ts, Nonce: nonce, Signature: sig, Method: "POST", Path: "/agent/v1/checkin"}
	}
	if _, err := v.Verify(t.Context(), signed(old, "n1"), now); err != nil {
		t.Fatalf("old secret before rotate: %v", err)
	}

	secret, err := svc.RotateSecret(t.Context(), userID, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) == 0 {
		t.Fatal("expected a plaintext secret")
	}
	if _, err := v.Verify(t.Context(), signed(old, "n2"), now); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("old secret after rotate: err = %v, want ErrUnauthorized", err)
	}
	if _, err := v.Verify(t.Context(), signed(secret, "n3"), now); err != nil {
		t.Fatalf("new secret after rotate: %v", err)
	}
	// Foreign owner cannot rotate.
	if _, err := svc.RotateSecret(t.Context(), "nope", dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign rotate err = %v, want ErrNotFound", err)
	}
}

func TestDeviceService_History_Paginates(t *testing.T) {
	st, userID, svc := newDeviceServiceTest(t)
	dev := seedDevice(t, st, userID, "d")
	for i := range 3 {
		if _, err := st.IPHistory().Append(t.Context(), store.IPHistory{DeviceID: dev.ID, IPv4: "203.0.113.1", ObservedAt: int64(1000 + i)}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := svc.History(t.Context(), userID, dev.ID, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 2 || page.NextCursor == "" {
		t.Fatalf("page = %d rows, cursor %q; want 2 rows + cursor", len(page.Rows), page.NextCursor)
	}
	// Foreign owner → ErrNotFound (never leaks another user's history).
	if _, err := svc.History(t.Context(), "intruder", dev.ID, "", 2); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign history err = %v, want ErrNotFound", err)
	}
}

// TestDeviceService_SetEnabled_EmitsMembershipEvents pins design §6.2: a
// flip out of the feed emits removed, a flip back in emits added, and a
// device with no address emits nothing either way. The "before" snapshot is
// the pre-write row and the "after" is that row with the flag set to its
// intended value — never a re-read.
func TestDeviceService_SetEnabled_EmitsMembershipEvents(t *testing.T) {
	st, userID, svc, n := newDeviceServiceTestWithNotifier(t)
	dev := seedDevice(t, st, userID, "d")
	giveIP(t, st, dev.ID, "203.0.113.9")

	if _, err := svc.SetEnabled(t.Context(), userID, dev.ID, true); err != nil {
		t.Fatal(err)
	}
	if len(n.removed) != 1 || n.removed[0].ID != dev.ID || n.removed[0].CurrentIPv4 != "203.0.113.9" {
		t.Fatalf("removed = %+v, want the device with its last address", n.removed)
	}
	if len(n.added) != 0 {
		t.Fatalf("added = %+v, want none on disable", n.added)
	}

	if _, err := svc.SetEnabled(t.Context(), userID, dev.ID, false); err != nil {
		t.Fatal(err)
	}
	if len(n.added) != 1 || n.added[0].ID != dev.ID || n.added[0].Disabled {
		t.Fatalf("added = %+v, want the re-enabled device", n.added)
	}

	// Disabling a device that never checked in: not a member, no event.
	quiet := seedDevice(t, st, userID, "quiet")
	if _, err := svc.SetEnabled(t.Context(), userID, quiet.ID, true); err != nil {
		t.Fatal(err)
	}
	if len(n.removed) != 1 {
		t.Errorf("removed = %+v, want no event for a device with no address", n.removed)
	}
	if len(n.added) != 1 {
		t.Errorf("added = %+v, want still just the one re-enable event", n.added)
	}
}

// TestDeviceService_SetEnabled_OwnerDisabledEmitsNothing: the owner check
// applies to removed as much as to added (pass 2 S1).
func TestDeviceService_SetEnabled_OwnerDisabledEmitsNothing(t *testing.T) {
	st, userID, svc, n := newDeviceServiceTestWithNotifier(t)
	dev := seedDevice(t, st, userID, "d")
	giveIP(t, st, dev.ID, "203.0.113.9")
	if err := st.Users().SetDisabled(t.Context(), userID, true); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.SetEnabled(t.Context(), userID, dev.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetEnabled(t.Context(), userID, dev.ID, false); err != nil {
		t.Fatal(err)
	}
	if len(n.added)+len(n.removed) != 0 {
		t.Errorf("added=%+v removed=%+v, want nothing while the owner is disabled", n.added, n.removed)
	}
}

func TestDeviceService_Delete_EmitsRemovedForMember(t *testing.T) {
	st, userID, svc, n := newDeviceServiceTestWithNotifier(t)
	member := seedDevice(t, st, userID, "m")
	giveIP(t, st, member.ID, "203.0.113.9")
	quiet := seedDevice(t, st, userID, "q")

	if err := svc.Delete(t.Context(), userID, member.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(t.Context(), userID, quiet.ID); err != nil {
		t.Fatal(err)
	}
	if len(n.removed) != 1 || n.removed[0].ID != member.ID {
		t.Errorf("removed = %+v, want exactly the member", n.removed)
	}
}

// TestDeviceService_NotifierPanicDoesNotFailTheRequest mirrors the check-in
// path's guarantee: a broken hook must not turn an admin action into a 500.
func TestDeviceService_NotifierPanicDoesNotFailTheRequest(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	svc := NewDeviceService(st, testKey32(), discardAudit{}, panickingDeviceNotifier{})
	dev := seedDevice(t, st, usr.ID, "d")
	giveIP(t, st, dev.ID, "203.0.113.9")

	if _, err := svc.SetEnabled(t.Context(), usr.ID, dev.ID, true); err != nil {
		t.Fatalf("SetEnabled: %v (a panicking notifier must be contained)", err)
	}
}

type panickingDeviceNotifier struct{}

func (panickingDeviceNotifier) DeviceAdded(context.Context, store.Device)   { panic("boom") }
func (panickingDeviceNotifier) DeviceRemoved(context.Context, store.Device) { panic("boom") }

// TestDeviceMutator_FlipDisabled_EmitsFromPreWriteSnapshot pins the one
// piece of knowledge flipDisabled exists to hold (#132 D8): membership is
// computed from the rows as read BEFORE the write (design #106 §7.2), the
// audit entry is written exactly as handed in, and the returned row is the
// re-read post-write state. Both DeviceService.SetEnabled and
// AdminService.SetDeviceEnabled build on this; neither re-derives it.
func TestDeviceMutator_FlipDisabled_EmitsFromPreWriteSnapshot(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "d")
	giveIP(t, st, dev.ID, "203.0.113.9")
	// giveIP wrote to the database; the local dev is still the address-less
	// row. flipDisabled computes membership from the value it is HANDED, so
	// re-read the row -- that is the pre-write snapshot a caller holds.
	dev, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	n := &recordingDeviceNotifier{}
	m := deviceMutator{st: st, audit: NewAuditWriter(st), notify: n}

	entry := store.AuditEntry{ActorUserID: usr.ID, EventType: "device.disabled", TargetType: "device", TargetID: dev.ID, IP: "198.51.100.7"}
	got, err := m.flipDisabled(t.Context(), dev, usr, true, entry)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Disabled {
		t.Fatal("returned row is not the post-write state")
	}
	if len(n.removed) != 1 || n.removed[0].ID != dev.ID || len(n.added) != 0 {
		t.Fatalf("removed=%+v added=%+v, want exactly one removed", n.removed, n.added)
	}
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "device.disabled"}, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0].ActorUserID != usr.ID || page.Rows[0].TargetID != dev.ID || page.Rows[0].IP != "198.51.100.7" {
		t.Fatalf("audit rows = %+v, want the entry as handed in", page.Rows)
	}

	// Flip back from the post-write row: before=not a member, after=member.
	entry.EventType = "device.enabled"
	if _, err := m.flipDisabled(t.Context(), got, usr, false, entry); err != nil {
		t.Fatal(err)
	}
	if len(n.added) != 1 || n.added[0].ID != dev.ID || n.added[0].Disabled {
		t.Fatalf("added = %+v, want the re-enabled device", n.added)
	}

	// An unknown device is the store's ErrNotFound, unwrapped: the caller
	// adds its own "service.X:" prefix.
	if _, err := m.flipDisabled(t.Context(), store.Device{ID: "nope", UserID: usr.ID}, usr, true, entry); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown device err = %v, want ErrNotFound", err)
	}
}

// An owner rotate-secret clears rotate_secret_at, which completes a requested
// secret rotation with no promote step: it must be audited like a promotion is.
func TestDeviceService_RotateSecret_AuditsCompletedRotation(t *testing.T) {
	tests := []struct {
		name      string
		requested bool
		want      int
	}{
		{"rotation requested", true, 1},
		{"routine rotate", false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := openTestStore(t)
			usr := seedUser(t, st, "a@b.co", "user")
			dev := seedDevice(t, st, usr.ID, "laptop")
			svc := NewDeviceService(st, testKey32(), NewAuditWriter(st), &recordingDeviceNotifier{})
			if tt.requested {
				if err := st.Devices().MarkRotation(t.Context(), dev.ID, true, false, 1_700_000_000); err != nil {
					t.Fatalf("MarkRotation: %v", err)
				}
			}

			if _, err := svc.RotateSecret(t.Context(), usr.ID, dev.ID); err != nil {
				t.Fatalf("RotateSecret: %v", err)
			}

			rows := auditRows(t, st, "device.rotation.completed")
			if len(rows) != tt.want {
				t.Fatalf("completed rows = %d, want %d", len(rows), tt.want)
			}
			if tt.want == 0 {
				return
			}
			if d := decodeDetails(t, rows[0]); rows[0].ActorUserID != "" || rows[0].TargetID != dev.ID || d["track"] != "secret" || len(d) != 1 {
				t.Errorf("row = %+v details %v, want a system row for %s with track secret", rows[0], d, dev.ID)
			}
		})
	}
}
