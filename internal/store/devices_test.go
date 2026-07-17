package store

import (
	"errors"
	"testing"
	"time"
)

// ---------- 1. Create + GetByID round-trip ----------

func TestDeviceCreateAndGetByID(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "alice@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	d := Device{
		UserID:     u.ID,
		Label:      "home",
		SecretHash: "hash1",
	}
	created, err := s.Devices().Create(ctx, d)
	if err != nil {
		t.Fatalf("Create device: %v", err)
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
	if created.UserID != u.ID {
		t.Errorf("Create: UserID = %q, want %q", created.UserID, u.ID)
	}
	if created.Label != "home" {
		t.Errorf("Create: Label = %q, want %q", created.Label, "home")
	}
	if created.SecretHash != "hash1" {
		t.Errorf("Create: SecretHash = %q, want %q", created.SecretHash, "hash1")
	}

	got, err := s.Devices().GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("GetByID: ID = %q, want %q", got.ID, created.ID)
	}
	if got.UserID != created.UserID {
		t.Errorf("GetByID: UserID = %q, want %q", got.UserID, created.UserID)
	}
	if got.Label != created.Label {
		t.Errorf("GetByID: Label = %q, want %q", got.Label, created.Label)
	}
	if got.SecretHash != created.SecretHash {
		t.Errorf("GetByID: SecretHash = %q, want %q", got.SecretHash, created.SecretHash)
	}
	if got.CreatedAt != created.CreatedAt {
		t.Errorf("GetByID: CreatedAt = %d, want %d", got.CreatedAt, created.CreatedAt)
	}
	// LastSeenAt should be 0 (NULL stored as NULL, scanned as 0)
	if got.LastSeenAt != 0 {
		t.Errorf("GetByID: LastSeenAt = %d, want 0", got.LastSeenAt)
	}
	if got.Disabled {
		t.Error("GetByID: Disabled should be false by default")
	}
}

// ---------- 2. Duplicate (user_id, label) → ErrConflict ----------

func TestDeviceCreateDuplicateLabelReturnsErrConflict(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "bob@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	d := Device{UserID: u.ID, Label: "office", SecretHash: "h1"}
	if _, err := s.Devices().Create(ctx, d); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	_, err = s.Devices().Create(ctx, d)
	if err == nil {
		t.Fatal("second Create: expected error, got nil")
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("second Create: got %v, want ErrConflict", err)
	}
}

// ---------- 3. Same label, different users → both succeed ----------

func TestDeviceCreateSameLabelDifferentUsersOK(t *testing.T) {
	s, ctx := newTestStore(t)

	uA, err := s.Users().Create(ctx, User{Email: "userA@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create userA: %v", err)
	}
	uB, err := s.Users().Create(ctx, User{Email: "userB@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create userB: %v", err)
	}

	dA := Device{UserID: uA.ID, Label: "home", SecretHash: "hA"}
	if _, err := s.Devices().Create(ctx, dA); err != nil {
		t.Fatalf("Create for userA: %v", err)
	}

	dB := Device{UserID: uB.ID, Label: "home", SecretHash: "hB"}
	if _, err := s.Devices().Create(ctx, dB); err != nil {
		t.Fatalf("Create for userB: %v", err)
	}
}

// ---------- 4. GetByUserAndLabel round-trip; missing → ErrNotFound ----------

func TestDeviceGetByUserAndLabel(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "carol@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	d := Device{UserID: u.ID, Label: "laptop", SecretHash: "hC"}
	created, err := s.Devices().Create(ctx, d)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Devices().GetByUserAndLabel(ctx, u.ID, "laptop")
	if err != nil {
		t.Fatalf("GetByUserAndLabel: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("GetByUserAndLabel: ID = %q, want %q", got.ID, created.ID)
	}

	// Missing label
	_, err = s.Devices().GetByUserAndLabel(ctx, u.ID, "nonexistent")
	if err == nil {
		t.Fatal("GetByUserAndLabel missing: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByUserAndLabel missing: got %v, want ErrNotFound", err)
	}
}

// ---------- 5. ListByUser ordered by label ASC ----------

func TestDeviceListByUserOrdersByLabel(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "dan@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	labels := []string{"zebra", "alpha", "mango"}
	for _, label := range labels {
		if _, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: label, SecretHash: "h"}); err != nil {
			t.Fatalf("Create %q: %v", label, err)
		}
	}

	list, err := s.Devices().ListByUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("ListByUser: got %d, want 3", len(list))
	}

	want := []string{"alpha", "mango", "zebra"}
	for i, dev := range list {
		if dev.Label != want[i] {
			t.Errorf("ListByUser[%d].Label = %q, want %q", i, dev.Label, want[i])
		}
	}
}

// ---------- 6. ListAll ordered by created_at DESC ----------

func TestDeviceListAllOrdersByCreatedAtDesc(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "eve@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	labels := []string{"first", "second", "third"}
	for _, label := range labels {
		if _, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: label, SecretHash: "h"}); err != nil {
			t.Fatalf("Create %q: %v", label, err)
		}
		// Sleep so created_at differs by at least 1 second between rows.
		time.Sleep(time.Second)
	}

	list, err := s.Devices().ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("ListAll: got %d, want 3", len(list))
	}

	// Expect reverse insertion order: third, second, first
	want := []string{"third", "second", "first"}
	for i, dev := range list {
		if dev.Label != want[i] {
			t.Errorf("ListAll[%d].Label = %q, want %q", i, dev.Label, want[i])
		}
	}
}

// ---------- 7. UpdateIP ----------

func TestDeviceUpdateIP(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "frank@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "router", SecretHash: "h"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	originalUpdatedAt := d.UpdatedAt
	time.Sleep(time.Second)

	lastSeen := NowUnix()
	err = s.Devices().UpdateIP(ctx, d.ID, "1.2.3.4", "::1", "v1.2.3", "myhost", "linux", lastSeen)
	if err != nil {
		t.Fatalf("UpdateIP: %v", err)
	}

	got, err := s.Devices().GetByID(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetByID after UpdateIP: %v", err)
	}
	if got.CurrentIPv4 != "1.2.3.4" {
		t.Errorf("UpdateIP: CurrentIPv4 = %q, want %q", got.CurrentIPv4, "1.2.3.4")
	}
	if got.CurrentIPv6 != "::1" {
		t.Errorf("UpdateIP: CurrentIPv6 = %q, want %q", got.CurrentIPv6, "::1")
	}
	if got.ClientVersion != "v1.2.3" {
		t.Errorf("UpdateIP: ClientVersion = %q, want %q", got.ClientVersion, "v1.2.3")
	}
	if got.Hostname != "myhost" {
		t.Errorf("UpdateIP: Hostname = %q, want %q", got.Hostname, "myhost")
	}
	if got.OS != "linux" {
		t.Errorf("UpdateIP: OS = %q, want %q", got.OS, "linux")
	}
	if got.LastSeenAt != lastSeen {
		t.Errorf("UpdateIP: LastSeenAt = %d, want %d", got.LastSeenAt, lastSeen)
	}
	if got.UpdatedAt <= originalUpdatedAt {
		t.Errorf("UpdateIP: UpdatedAt (%d) should be > original (%d)", got.UpdatedAt, originalUpdatedAt)
	}
}

// ---------- 8. UpdateIP not found ----------

func TestDeviceUpdateIPNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	err := s.Devices().UpdateIP(ctx, "nonexistent-id", "1.2.3.4", "", "v1", "h", "linux", NowUnix())
	if err == nil {
		t.Fatal("UpdateIP: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateIP: got %v, want ErrNotFound", err)
	}
}

// ---------- 9. Rename success ----------

func TestDeviceRenameSuccess(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "grace@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "old", SecretHash: "h"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Devices().Rename(ctx, d.ID, "new"); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	got, err := s.Devices().GetByID(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetByID after Rename: %v", err)
	}
	if got.Label != "new" {
		t.Errorf("Rename: Label = %q, want %q", got.Label, "new")
	}
}

// ---------- 10. Rename conflict ----------

func TestDeviceRenameConflict(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "henry@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	if _, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "a", SecretHash: "h"}); err != nil {
		t.Fatalf("Create a: %v", err)
	}
	dB, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "b", SecretHash: "h"})
	if err != nil {
		t.Fatalf("Create b: %v", err)
	}

	err = s.Devices().Rename(ctx, dB.ID, "a")
	if err == nil {
		t.Fatal("Rename conflict: expected error, got nil")
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("Rename conflict: got %v, want ErrConflict", err)
	}
}

// ---------- 11. Rename not found ----------

func TestDeviceRenameNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	err := s.Devices().Rename(ctx, "nonexistent-id", "anylabel")
	if err == nil {
		t.Fatal("Rename not found: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Rename not found: got %v, want ErrNotFound", err)
	}
}

// ---------- 12. RotateSecret ----------

func TestDeviceRotateSecret(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "irene@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "phone", SecretHash: "oldhash"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Devices().RotateSecret(ctx, d.ID, "newhash"); err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}

	got, err := s.Devices().GetByID(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetByID after RotateSecret: %v", err)
	}
	if got.SecretHash != "newhash" {
		t.Errorf("RotateSecret: SecretHash = %q, want %q", got.SecretHash, "newhash")
	}
}

// ---------- 13. SetDisabled toggle ----------

func TestDeviceSetDisabled(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "jack@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "tablet", SecretHash: "h"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Disable
	if err := s.Devices().SetDisabled(ctx, d.ID, true); err != nil {
		t.Fatalf("SetDisabled(true): %v", err)
	}
	got, err := s.Devices().GetByID(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetByID after SetDisabled(true): %v", err)
	}
	if !got.Disabled {
		t.Error("SetDisabled(true): Disabled should be true")
	}

	// Re-enable
	if err := s.Devices().SetDisabled(ctx, d.ID, false); err != nil {
		t.Fatalf("SetDisabled(false): %v", err)
	}
	got2, err := s.Devices().GetByID(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetByID after SetDisabled(false): %v", err)
	}
	if got2.Disabled {
		t.Error("SetDisabled(false): Disabled should be false")
	}
}

// ---------- 14. Delete cascades to ip_history ----------

func TestDeviceDeleteAndCascadesToIPHistory(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "kate@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "watch", SecretHash: "h"})
	if err != nil {
		t.Fatalf("Create device: %v", err)
	}

	// Insert an ip_history row directly via raw SQL — the IPHistory repo does
	// not exist yet (Task 14); raw SQL is explicitly allowed here to verify the
	// FK cascade before that repo is implemented.
	_, err = s.DB().ExecContext(ctx,
		`INSERT INTO ip_history (device_id, ipv4, ipv6, observed_at) VALUES (?, ?, ?, ?)`,
		d.ID, "10.0.0.1", nil, NowUnix(),
	)
	if err != nil {
		t.Fatalf("insert ip_history: %v", err)
	}

	if err := s.Devices().Delete(ctx, d.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Verify cascade: no ip_history rows should remain for this device.
	var count int
	if err := s.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM ip_history WHERE device_id = ?`, d.ID,
	).Scan(&count); err != nil {
		t.Fatalf("count ip_history: %v", err)
	}
	if count != 0 {
		t.Errorf("cascade: ip_history count = %d, want 0", count)
	}

	// Device itself should be gone.
	_, err = s.Devices().GetByID(ctx, d.ID)
	if err == nil {
		t.Fatal("GetByID after Delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID after Delete: got %v, want ErrNotFound", err)
	}
}

// ---------- 15. Touch advances last_seen_at without an IP change ----------

func TestDeviceRepo_Touch(t *testing.T) {
	s, ctx := newTestStore(t)
	u, err := s.Users().Create(ctx, User{Email: "touch@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "box"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	if err := s.Devices().Touch(ctx, dev.ID, 1_700_000_000); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, err := s.Devices().GetByID(ctx, dev.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.LastSeenAt != 1_700_000_000 {
		t.Errorf("LastSeenAt = %d, want 1700000000", got.LastSeenAt)
	}
	if got.UpdatedAt == 0 {
		t.Errorf("UpdatedAt not set")
	}

	if err := s.Devices().Touch(ctx, "nonexistent", 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("Touch(missing) err = %v, want ErrNotFound", err)
	}
}

// ---------- 16. FK cascade on user delete ----------

func TestDeviceFKCascadeOnUserDelete(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "liam@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "desktop", SecretHash: "h"})
	if err != nil {
		t.Fatalf("Create device: %v", err)
	}

	if err := s.Users().Delete(ctx, u.ID); err != nil {
		t.Fatalf("Users().Delete: %v", err)
	}

	_, err = s.Devices().GetByID(ctx, d.ID)
	if err == nil {
		t.Fatal("GetByID after user delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID after user delete: got %v, want ErrNotFound", err)
	}
}
