package store

import (
	"errors"
	"testing"
	"time"
)

func TestDeviceCreateAndGetByIDRoundTrip(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "device-user@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Devices()

	created, err := repo.Create(ctx, Device{
		UserID:     user.ID,
		Label:      "laptop",
		SecretHash: "hash-1",
	})
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

func TestDeviceCreateDuplicateUserLabelReturnsConflict(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "dup-device@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Devices()

	if _, err := repo.Create(ctx, Device{UserID: user.ID, Label: "laptop", SecretHash: "hash-1"}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = repo.Create(ctx, Device{UserID: user.ID, Label: "laptop", SecretHash: "hash-2"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Create duplicate (user_id,label): err = %v, want ErrConflict", err)
	}
}

func TestDeviceGetByIDMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Devices()

	_, err := repo.GetByID(ctx, "missing-id")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByID missing: err = %v, want ErrNotFound", err)
	}
}

func TestDeviceGetByUserAndLabelRoundTrip(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "label-lookup@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Devices()

	created, err := repo.Create(ctx, Device{UserID: user.ID, Label: "phone", SecretHash: "hash-1"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByUserAndLabel(ctx, user.ID, "phone")
	if err != nil {
		t.Fatalf("GetByUserAndLabel: %v", err)
	}
	if got != created {
		t.Fatalf("GetByUserAndLabel() = %+v, want %+v", got, created)
	}
}

func TestDeviceGetByUserAndLabelMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "label-missing@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Devices()

	_, err = repo.GetByUserAndLabel(ctx, user.ID, "does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByUserAndLabel missing: err = %v, want ErrNotFound", err)
	}
}

func TestDeviceListByUserOrdersByLabelAscending(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "list-by-user@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	otherUser, err := s.Users().Create(ctx, User{Email: "list-by-user-other@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create other user: %v", err)
	}
	repo := s.Devices()

	for _, label := range []string{"phone", "desktop", "laptop"} {
		if _, err := repo.Create(ctx, Device{UserID: user.ID, Label: label, SecretHash: "hash"}); err != nil {
			t.Fatalf("Create %q: %v", label, err)
		}
	}
	if _, err := repo.Create(ctx, Device{UserID: otherUser.ID, Label: "aardvark", SecretHash: "hash"}); err != nil {
		t.Fatalf("Create other user's device: %v", err)
	}

	got, err := repo.ListByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}

	want := []string{"desktop", "laptop", "phone"}
	if len(got) != len(want) {
		t.Fatalf("ListByUser returned %d devices, want %d", len(got), len(want))
	}
	for i, d := range got {
		if d.Label != want[i] {
			t.Fatalf("ListByUser()[%d].Label = %q, want %q", i, d.Label, want[i])
		}
	}
}

// TestDeviceListAllOrdersByCreatedAtDescending proves ListAll (the admin
// view) orders across all users by created_at descending. NowUnix() has
// 1-second resolution, so the test sleeps past a full second between
// creates to guarantee distinct created_at values instead of relying on
// coincidental ordering.
func TestDeviceListAllOrdersByCreatedAtDescending(t *testing.T) {
	s, ctx := newTestStore(t)
	userA, err := s.Users().Create(ctx, User{Email: "list-all-a@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user A: %v", err)
	}
	userB, err := s.Users().Create(ctx, User{Email: "list-all-b@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user B: %v", err)
	}
	repo := s.Devices()

	first, err := repo.Create(ctx, Device{UserID: userA.ID, Label: "first", SecretHash: "hash"})
	if err != nil {
		t.Fatalf("Create first: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	second, err := repo.Create(ctx, Device{UserID: userB.ID, Label: "second", SecretHash: "hash"})
	if err != nil {
		t.Fatalf("Create second: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	third, err := repo.Create(ctx, Device{UserID: userA.ID, Label: "third", SecretHash: "hash"})
	if err != nil {
		t.Fatalf("Create third: %v", err)
	}

	got, err := repo.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}

	want := []string{third.ID, second.ID, first.ID}
	if len(got) != len(want) {
		t.Fatalf("ListAll returned %d devices, want %d", len(got), len(want))
	}
	for i, d := range got {
		if d.ID != want[i] {
			t.Fatalf("ListAll()[%d].ID = %q, want %q", i, d.ID, want[i])
		}
	}
}

func TestDeviceUpdateIPSetsFieldsAndBumpsUpdatedAt(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "update-ip@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Devices()

	created, err := repo.Create(ctx, Device{UserID: user.ID, Label: "laptop", SecretHash: "hash"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.LastSeenAt != 0 {
		t.Fatalf("newly created device should have LastSeenAt=0, got %d", created.LastSeenAt)
	}

	lastSeenAt := NowUnix()
	err = repo.UpdateIP(ctx, created.ID, "203.0.113.5", "2001:db8::1", "1.2.3", "my-host", "linux", lastSeenAt)
	if err != nil {
		t.Fatalf("UpdateIP: %v", err)
	}

	got, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.CurrentIPv4 != "203.0.113.5" {
		t.Fatalf("UpdateIP did not set CurrentIPv4: got %q", got.CurrentIPv4)
	}
	if got.CurrentIPv6 != "2001:db8::1" {
		t.Fatalf("UpdateIP did not set CurrentIPv6: got %q", got.CurrentIPv6)
	}
	if got.ClientVersion != "1.2.3" {
		t.Fatalf("UpdateIP did not set ClientVersion: got %q", got.ClientVersion)
	}
	if got.Hostname != "my-host" {
		t.Fatalf("UpdateIP did not set Hostname: got %q", got.Hostname)
	}
	if got.OS != "linux" {
		t.Fatalf("UpdateIP did not set OS: got %q", got.OS)
	}
	if got.LastSeenAt != lastSeenAt {
		t.Fatalf("UpdateIP did not set LastSeenAt: got %d, want %d", got.LastSeenAt, lastSeenAt)
	}
	if got.UpdatedAt < created.UpdatedAt {
		t.Fatalf("UpdateIP did not bump updated_at: got %d, want >= %d", got.UpdatedAt, created.UpdatedAt)
	}
}

func TestDeviceUpdateIPMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Devices()

	err := repo.UpdateIP(ctx, "missing-id", "203.0.113.5", "", "1.2.3", "host", "linux", NowUnix())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateIP missing: err = %v, want ErrNotFound", err)
	}
}

func TestDeviceRenameToTakenLabelReturnsConflict(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "rename-conflict@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Devices()

	if _, err := repo.Create(ctx, Device{UserID: user.ID, Label: "laptop", SecretHash: "hash"}); err != nil {
		t.Fatalf("Create laptop: %v", err)
	}
	phone, err := repo.Create(ctx, Device{UserID: user.ID, Label: "phone", SecretHash: "hash"})
	if err != nil {
		t.Fatalf("Create phone: %v", err)
	}

	err = repo.Rename(ctx, phone.ID, "laptop")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Rename to taken label: err = %v, want ErrConflict", err)
	}
}

func TestDeviceRenameSucceeds(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "rename-ok@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Devices()

	created, err := repo.Create(ctx, Device{UserID: user.ID, Label: "old-name", SecretHash: "hash"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := repo.Rename(ctx, created.ID, "new-name"); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	got, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Label != "new-name" {
		t.Fatalf("Rename did not persist: got Label=%q, want %q", got.Label, "new-name")
	}
}

func TestDeviceRenameMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Devices()

	err := repo.Rename(ctx, "missing-id", "new-name")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Rename missing: err = %v, want ErrNotFound", err)
	}
}

func TestDeviceRotateSecretChangesHashAndBumpsUpdatedAt(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "rotate-secret@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Devices()

	created, err := repo.Create(ctx, Device{UserID: user.ID, Label: "laptop", SecretHash: "old-hash"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := repo.RotateSecret(ctx, created.ID, "new-hash"); err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}

	got, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.SecretHash != "new-hash" {
		t.Fatalf("RotateSecret did not persist: got SecretHash=%q, want %q", got.SecretHash, "new-hash")
	}
	if got.UpdatedAt < created.UpdatedAt {
		t.Fatalf("RotateSecret did not bump updated_at: got %d, want >= %d", got.UpdatedAt, created.UpdatedAt)
	}
}

func TestDeviceRotateSecretMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Devices()

	err := repo.RotateSecret(ctx, "missing-id", "new-hash")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("RotateSecret missing: err = %v, want ErrNotFound", err)
	}
}

func TestDeviceSetDisabledToggles(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "set-disabled@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Devices()

	created, err := repo.Create(ctx, Device{UserID: user.ID, Label: "laptop", SecretHash: "hash"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Disabled {
		t.Fatal("newly created device should not start disabled")
	}

	if err := repo.SetDisabled(ctx, created.ID, true); err != nil {
		t.Fatalf("SetDisabled(true): %v", err)
	}
	got, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.Disabled {
		t.Fatal("SetDisabled(true) did not disable the device")
	}

	if err := repo.SetDisabled(ctx, created.ID, false); err != nil {
		t.Fatalf("SetDisabled(false): %v", err)
	}
	got, err = repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Disabled {
		t.Fatal("SetDisabled(false) did not re-enable the device")
	}
}

func TestDeviceSetDisabledMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Devices()

	err := repo.SetDisabled(ctx, "missing-id", true)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetDisabled missing: err = %v, want ErrNotFound", err)
	}
}

func TestDeviceDeleteRemovesDevice(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "delete-device@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Devices()

	created, err := repo.Create(ctx, Device{UserID: user.ID, Label: "laptop", SecretHash: "hash"})
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

func TestDeviceDeleteMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Devices()

	err := repo.Delete(ctx, "missing-id")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete missing: err = %v, want ErrNotFound", err)
	}
}

// TestDeviceUserDeleteCascadesToDevices proves the ON DELETE CASCADE the
// schema declares on devices.user_id actually fires: deleting the parent
// user via the public Users().Delete API must remove that user's devices
// too, without the devices repo doing anything itself.
func TestDeviceUserDeleteCascadesToDevices(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "cascade-device@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.Devices()

	created, err := repo.Create(ctx, Device{UserID: user.ID, Label: "laptop", SecretHash: "hash"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Users().Delete(ctx, user.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	_, err = repo.GetByID(ctx, created.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByID after cascading user delete: err = %v, want ErrNotFound", err)
	}
}
