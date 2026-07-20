package service

import (
	"errors"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// fakeInvalidator is a mutation-checked SecretCacheInvalidator: it records
// every device ID passed to Invalidate so tests can assert eviction happened
// exactly once, for exactly the right device.
type fakeInvalidator struct{ called []string }

func (f *fakeInvalidator) Invalidate(id string) { f.called = append(f.called, id) }

// newDeviceServiceTest opens a fresh in-memory store, seeds one user, and
// builds a DeviceService wired to a fakeInvalidator and a discard audit
// sink. Reused by every DeviceService test in this file.
func newDeviceServiceTest(t *testing.T) (*store.Store, string, *DeviceService, *fakeInvalidator) {
	t.Helper()
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	inv := &fakeInvalidator{}
	svc := NewDeviceService(st, testKey32(), inv, discardAudit{})
	return st, usr.ID, svc, inv
}

func TestDeviceService_Get_ReturnsOwnedDevice(t *testing.T) {
	st, userID, svc, _ := newDeviceServiceTest(t)
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
	st, userID, svc, _ := newDeviceServiceTest(t)
	other := seedUser(t, st, "other@b.co", "user")
	dev := seedDevice(t, st, userID, "laptop")

	_, err := svc.Get(t.Context(), other.ID, dev.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get: err = %v, want store.ErrNotFound", err)
	}
}

func TestDeviceService_List_ReturnsOnlyCallersDevices(t *testing.T) {
	st, userID, svc, _ := newDeviceServiceTest(t)
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

func TestDeviceService_Rename_OwnerScoped(t *testing.T) {
	st, userID, svc, _ := newDeviceServiceTest(t)
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
	st, userID, svc, _ := newDeviceServiceTest(t)
	seedDevice(t, st, userID, "taken")
	dev := seedDevice(t, st, userID, "other")
	if _, err := svc.Rename(t.Context(), userID, dev.ID, "taken"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestDeviceService_SetEnabled_TogglesDisabled(t *testing.T) {
	st, userID, svc, _ := newDeviceServiceTest(t)
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
	st, userID, svc, _ := newDeviceServiceTest(t)
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

func TestDeviceService_RotateSecret_ReSealsAndEvicts(t *testing.T) {
	st, userID, svc, inv := newDeviceServiceTest(t)
	dev := seedDevice(t, st, userID, "d")
	before, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatal(err)
	}

	secret, err := svc.RotateSecret(t.Context(), userID, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) == 0 {
		t.Fatal("expected a plaintext secret")
	}
	after, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.SecretHash == before.SecretHash {
		t.Fatal("expected SecretHash to change after rotate")
	}
	if len(inv.called) != 1 || inv.called[0] != dev.ID {
		t.Fatalf("Invalidate calls = %v, want [%s]", inv.called, dev.ID)
	}
	// Foreign owner cannot rotate.
	if _, err := svc.RotateSecret(t.Context(), "nope", dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign rotate err = %v, want ErrNotFound", err)
	}
}

func TestDeviceService_History_Paginates(t *testing.T) {
	st, userID, svc, _ := newDeviceServiceTest(t)
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
