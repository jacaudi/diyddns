package store

import (
	"errors"
	"testing"
)

func TestEnrollmentCodeCreateAndGetRoundTrip(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "enroll-user@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.EnrollmentCodes()

	created, err := repo.Create(ctx, EnrollmentCode{
		Code:      "code-1",
		UserID:    user.ID,
		Label:     "phone",
		ExpiresAt: NowUnix() + 3600,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.UsedAt != 0 {
		t.Fatalf("newly created code should have UsedAt=0, got %d", created.UsedAt)
	}
	if created.DeviceID != "" {
		t.Fatalf("newly created code should have DeviceID=%q, got %q", "", created.DeviceID)
	}

	got, err := repo.Get(ctx, "code-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != created {
		t.Fatalf("Get() = %+v, want %+v", got, created)
	}
}

func TestEnrollmentCodeCreateDuplicateReturnsConflict(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "enroll-dup@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	repo := s.EnrollmentCodes()

	if _, err := repo.Create(ctx, EnrollmentCode{Code: "dup-code", UserID: user.ID, Label: "phone", ExpiresAt: NowUnix() + 3600}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = repo.Create(ctx, EnrollmentCode{Code: "dup-code", UserID: user.ID, Label: "laptop", ExpiresAt: NowUnix() + 3600})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Create duplicate code: err = %v, want ErrConflict", err)
	}
}

func TestEnrollmentCodeGetMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.EnrollmentCodes()

	_, err := repo.Get(ctx, "missing-code")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing: err = %v, want ErrNotFound", err)
	}
}

// TestEnrollmentCodeConsumeSucceedsOnceThenFailsOnSecondAttempt is the
// load-bearing test: it proves Consume is single-use. The guarded UPDATE
// (WHERE used_at IS NULL) is the atomicity mechanism, so a second Consume of
// the same code must be indistinguishable from an unknown/expired code:
// ErrNotFound.
func TestEnrollmentCodeConsumeSucceedsOnceThenFailsOnSecondAttempt(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "enroll-consume@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	device, err := s.Devices().Create(ctx, Device{UserID: user.ID, Label: "phone", SecretHash: "hash"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	repo := s.EnrollmentCodes()

	if _, err := repo.Create(ctx, EnrollmentCode{Code: "consume-once", UserID: user.ID, Label: "phone", ExpiresAt: NowUnix() + 3600}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	now := NowUnix()
	consumed, err := repo.Consume(ctx, "consume-once", device.ID, now)
	if err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if consumed.DeviceID != device.ID {
		t.Fatalf("Consume did not set DeviceID: got %q, want %q", consumed.DeviceID, device.ID)
	}
	if consumed.UsedAt != now {
		t.Fatalf("Consume did not set UsedAt: got %d, want %d", consumed.UsedAt, now)
	}

	otherDevice, err := s.Devices().Create(ctx, Device{UserID: user.ID, Label: "laptop", SecretHash: "hash"})
	if err != nil {
		t.Fatalf("create other device: %v", err)
	}
	_, err = repo.Consume(ctx, "consume-once", otherDevice.ID, NowUnix())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Consume of already-used code: err = %v, want ErrNotFound", err)
	}

	// The row itself must retain the FIRST consumption, proving the second
	// attempt did not overwrite it.
	got, err := repo.Get(ctx, "consume-once")
	if err != nil {
		t.Fatalf("Get after double-consume: %v", err)
	}
	if got.DeviceID != device.ID {
		t.Fatalf("row after double-consume: DeviceID = %q, want first device %q (must not be overwritten)", got.DeviceID, device.ID)
	}
}

func TestEnrollmentCodeConsumeExpiredReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "enroll-expired@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	device, err := s.Devices().Create(ctx, Device{UserID: user.ID, Label: "phone", SecretHash: "hash"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	repo := s.EnrollmentCodes()

	now := NowUnix()
	if _, err := repo.Create(ctx, EnrollmentCode{Code: "expired-code", UserID: user.ID, Label: "phone", ExpiresAt: now - 10}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = repo.Consume(ctx, "expired-code", device.ID, now)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Consume expired code: err = %v, want ErrNotFound", err)
	}
}

func TestEnrollmentCodeConsumeMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.EnrollmentCodes()

	_, err := repo.Consume(ctx, "missing-code", "some-device", NowUnix())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Consume missing: err = %v, want ErrNotFound", err)
	}
}

// TestEnrollmentCodePruneExpiredRemovesOnlyUnusedExpired proves the DELETE
// guard: an expired-but-unused code is pruned, a fresh (non-expired) unused
// code is left alone, and an expired code that was already consumed is kept
// for audit (per the design's "consumed codes stay for audit" rule).
func TestEnrollmentCodePruneExpiredRemovesOnlyUnusedExpired(t *testing.T) {
	s, ctx := newTestStore(t)
	user, err := s.Users().Create(ctx, User{Email: "enroll-prune@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	device, err := s.Devices().Create(ctx, Device{UserID: user.ID, Label: "phone", SecretHash: "hash"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	repo := s.EnrollmentCodes()

	now := NowUnix()
	if _, err := repo.Create(ctx, EnrollmentCode{Code: "fresh-unused", UserID: user.ID, Label: "a", ExpiresAt: now + 3600}); err != nil {
		t.Fatalf("Create fresh-unused: %v", err)
	}
	if _, err := repo.Create(ctx, EnrollmentCode{Code: "expired-unused", UserID: user.ID, Label: "b", ExpiresAt: now - 10}); err != nil {
		t.Fatalf("Create expired-unused: %v", err)
	}
	if _, err := repo.Create(ctx, EnrollmentCode{
		Code: "expired-consumed", UserID: user.ID, Label: "c", ExpiresAt: now - 10,
		UsedAt: now - 20, DeviceID: device.ID,
	}); err != nil {
		t.Fatalf("Create expired-consumed: %v", err)
	}

	n, err := repo.PruneExpired(ctx, now)
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("PruneExpired() = %d, want 1", n)
	}

	if _, err := repo.Get(ctx, "fresh-unused"); err != nil {
		t.Fatalf("Get fresh-unused after prune: %v, want nil (should survive)", err)
	}
	if _, err := repo.Get(ctx, "expired-consumed"); err != nil {
		t.Fatalf("Get expired-consumed after prune: %v, want nil (audit record should survive)", err)
	}
	if _, err := repo.Get(ctx, "expired-unused"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get expired-unused after prune: err = %v, want ErrNotFound (should have been pruned)", err)
	}
}
