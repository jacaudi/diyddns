package store

import (
	"errors"
	"testing"
)

// TestDeviceDeleteWithConsumedEnrollmentCode guards a foreign-key gap: the
// enrollment flow's Consume sets enrollment_codes.device_id to the new
// device, so every code-enrolled device is referenced by a surviving
// consumed code. Deleting that device must succeed (the code survives the
// cascade with its device link cleared), not fail on the FK.
func TestDeviceDeleteWithConsumedEnrollmentCode(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "fk@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "phone", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if _, err := s.EnrollmentCodes().Create(ctx, EnrollmentCode{
		Code: "fk-code", UserID: u.ID, Label: "phone", ExpiresAt: NowUnix() + 3600,
	}); err != nil {
		t.Fatalf("create code: %v", err)
	}
	if _, err := s.EnrollmentCodes().Consume(ctx, "fk-code", d.ID, NowUnix()); err != nil {
		t.Fatalf("consume code: %v", err)
	}

	// The device is now referenced by the consumed code via device_id.
	if err := s.Devices().Delete(ctx, d.ID); err != nil {
		t.Fatalf("Delete of a code-enrolled device: %v (want nil)", err)
	}

	// Device is gone.
	if _, err := s.Devices().GetByID(ctx, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByID after delete: %v, want ErrNotFound", err)
	}

	// The consumed code survives the cascade, with its device link cleared.
	code, err := s.EnrollmentCodes().Get(ctx, "fk-code")
	if err != nil {
		t.Fatalf("Get code after device delete: %v (code should survive the cascade)", err)
	}
	if code.DeviceID != "" {
		t.Fatalf("code.DeviceID = %q after device delete, want empty (link cleared by ON DELETE SET NULL)", code.DeviceID)
	}
	if code.UsedAt == 0 {
		t.Fatalf("code.UsedAt = 0 after device delete, want the original consumption time preserved")
	}
}

// TestUserDeleteCascadesWithConsumedEnrollmentCode pins that deleting a user
// still cascades cleanly when a device has a consumed enrollment code
// referencing it (users -> devices and users -> enrollment_codes both
// cascade via user_id; this must not deadlock on the device_id FK).
func TestUserDeleteCascadesWithConsumedEnrollmentCode(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "fk2@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "phone", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if _, err := s.EnrollmentCodes().Create(ctx, EnrollmentCode{
		Code: "fk2-code", UserID: u.ID, Label: "phone", ExpiresAt: NowUnix() + 3600,
	}); err != nil {
		t.Fatalf("create code: %v", err)
	}
	if _, err := s.EnrollmentCodes().Consume(ctx, "fk2-code", d.ID, NowUnix()); err != nil {
		t.Fatalf("consume code: %v", err)
	}

	if err := s.Users().Delete(ctx, u.ID); err != nil {
		t.Fatalf("Delete user (cascade): %v (want nil)", err)
	}
	if _, err := s.Devices().GetByID(ctx, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("device after user delete: %v, want ErrNotFound", err)
	}
	if _, err := s.EnrollmentCodes().Get(ctx, "fk2-code"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("code after user delete: %v, want ErrNotFound", err)
	}
}
