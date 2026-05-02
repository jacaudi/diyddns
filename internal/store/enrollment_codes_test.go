package store

import (
	"errors"
	"testing"
)

// ---------- 1. Create + Get round-trip ----------

func TestEnrollmentCodeCreateAndGet(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ec-alice@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := NowUnix()
	c := EnrollmentCode{
		Code:      "CODE-ROUNDTRIP",
		UserID:    u.ID,
		Label:     "my-device",
		ExpiresAt: now + 3600,
	}
	created, err := s.EnrollmentCodes().Create(ctx, c)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Code != c.Code {
		t.Errorf("Create: Code = %q, want %q", created.Code, c.Code)
	}
	if created.UserID != u.ID {
		t.Errorf("Create: UserID = %q, want %q", created.UserID, u.ID)
	}
	if created.Label != c.Label {
		t.Errorf("Create: Label = %q, want %q", created.Label, c.Label)
	}
	if created.ExpiresAt != c.ExpiresAt {
		t.Errorf("Create: ExpiresAt = %d, want %d", created.ExpiresAt, c.ExpiresAt)
	}
	if created.UsedAt != 0 {
		t.Errorf("Create: UsedAt = %d, want 0", created.UsedAt)
	}
	if created.DeviceID != "" {
		t.Errorf("Create: DeviceID = %q, want empty", created.DeviceID)
	}

	got, err := s.EnrollmentCodes().Get(ctx, c.Code)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Code != c.Code {
		t.Errorf("Get: Code = %q, want %q", got.Code, c.Code)
	}
	if got.UserID != u.ID {
		t.Errorf("Get: UserID = %q, want %q", got.UserID, u.ID)
	}
	if got.ExpiresAt != c.ExpiresAt {
		t.Errorf("Get: ExpiresAt = %d, want %d", got.ExpiresAt, c.ExpiresAt)
	}
	if got.UsedAt != 0 {
		t.Errorf("Get: UsedAt = %d, want 0", got.UsedAt)
	}
	if got.DeviceID != "" {
		t.Errorf("Get: DeviceID = %q, want empty", got.DeviceID)
	}
}

// ---------- 2. Duplicate code → ErrConflict ----------

func TestEnrollmentCodeCreateDuplicateReturnsErrConflict(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ec-bob@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	c := EnrollmentCode{
		Code:      "CODE-DUP",
		UserID:    u.ID,
		Label:     "lbl",
		ExpiresAt: NowUnix() + 3600,
	}
	if _, err := s.EnrollmentCodes().Create(ctx, c); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	_, err = s.EnrollmentCodes().Create(ctx, c)
	if err == nil {
		t.Fatal("second Create: expected error, got nil")
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("second Create: got %v, want ErrConflict", err)
	}
}

// ---------- 3. Get unknown code → ErrNotFound ----------

func TestEnrollmentCodeGetNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	_, err := s.EnrollmentCodes().Get(ctx, "NONEXISTENT-CODE")
	if err == nil {
		t.Fatal("Get: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get: got %v, want ErrNotFound", err)
	}
}

// ---------- 4. Consume success returns consumed row ----------

func TestEnrollmentCodeConsumeSuccessReturnsConsumedRow(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ec-carol@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "laptop", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	now := NowUnix()
	c := EnrollmentCode{
		Code:      "CODE-CONSUME",
		UserID:    u.ID,
		Label:     "new-device",
		ExpiresAt: now + 3600,
	}
	if _, err := s.EnrollmentCodes().Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	consumed, err := s.EnrollmentCodes().Consume(ctx, c.Code, dev.ID, now)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if consumed.UsedAt != now {
		t.Errorf("Consume: UsedAt = %d, want %d", consumed.UsedAt, now)
	}
	if consumed.DeviceID != dev.ID {
		t.Errorf("Consume: DeviceID = %q, want %q", consumed.DeviceID, dev.ID)
	}
	if consumed.Code != c.Code {
		t.Errorf("Consume: Code = %q, want %q", consumed.Code, c.Code)
	}
}

// ---------- 5. Consume already-used code → ErrNotFound ----------

func TestEnrollmentCodeConsumeSecondCallReturnsErrNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ec-dan@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "phone", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	now := NowUnix()
	c := EnrollmentCode{
		Code:      "CODE-DOUBLE-CONSUME",
		UserID:    u.ID,
		Label:     "lbl",
		ExpiresAt: now + 3600,
	}
	if _, err := s.EnrollmentCodes().Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.EnrollmentCodes().Consume(ctx, c.Code, dev.ID, now); err != nil {
		t.Fatalf("first Consume: %v", err)
	}

	_, err = s.EnrollmentCodes().Consume(ctx, c.Code, dev.ID, now)
	if err == nil {
		t.Fatal("second Consume: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("second Consume: got %v, want ErrNotFound", err)
	}
}

// ---------- 6. Consume expired code → ErrNotFound ----------

func TestEnrollmentCodeConsumeExpiredReturnsErrNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ec-eve@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "tablet", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	now := NowUnix()
	c := EnrollmentCode{
		Code:      "CODE-EXPIRED",
		UserID:    u.ID,
		Label:     "lbl",
		ExpiresAt: now - 3600, // in the past
	}
	if _, err := s.EnrollmentCodes().Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = s.EnrollmentCodes().Consume(ctx, c.Code, dev.ID, now)
	if err == nil {
		t.Fatal("Consume expired: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Consume expired: got %v, want ErrNotFound", err)
	}
}

// ---------- 7. Consume unknown code → ErrNotFound ----------

func TestEnrollmentCodeConsumeUnknownCodeReturnsErrNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ec-frank@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "watch", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	_, err = s.EnrollmentCodes().Consume(ctx, "CODE-UNKNOWN", dev.ID, NowUnix())
	if err == nil {
		t.Fatal("Consume unknown: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Consume unknown: got %v, want ErrNotFound", err)
	}
}

// ---------- 8. PruneExpired removes only unused expired codes ----------

func TestEnrollmentCodePruneExpiredRemovesOnlyUnusedExpired(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ec-grace@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "desktop", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	now := NowUnix()

	// Code A: unused, expired
	codeA := EnrollmentCode{
		Code:      "CODE-A-UNUSED-EXPIRED",
		UserID:    u.ID,
		Label:     "a",
		ExpiresAt: now - 3600,
	}
	if _, err := s.EnrollmentCodes().Create(ctx, codeA); err != nil {
		t.Fatalf("Create A: %v", err)
	}

	// Code B: unused, fresh (not expired)
	codeB := EnrollmentCode{
		Code:      "CODE-B-UNUSED-FRESH",
		UserID:    u.ID,
		Label:     "b",
		ExpiresAt: now + 3600,
	}
	if _, err := s.EnrollmentCodes().Create(ctx, codeB); err != nil {
		t.Fatalf("Create B: %v", err)
	}

	// Code C: consumed, expired — must be retained for audit
	codeC := EnrollmentCode{
		Code:      "CODE-C-CONSUMED-EXPIRED",
		UserID:    u.ID,
		Label:     "c",
		ExpiresAt: now + 60, // not yet expired so Consume can succeed
	}
	if _, err := s.EnrollmentCodes().Create(ctx, codeC); err != nil {
		t.Fatalf("Create C: %v", err)
	}
	if _, err := s.EnrollmentCodes().Consume(ctx, codeC.Code, dev.ID, now); err != nil {
		t.Fatalf("Consume C: %v", err)
	}
	// Manually set expires_at into the past so PruneExpired would want to prune it
	// if it weren't consumed — we verify consumed codes are exempt.
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE enrollment_codes SET expires_at = ? WHERE code = ?`,
		now-3600, codeC.Code,
	); err != nil {
		t.Fatalf("backdate C: %v", err)
	}

	n, err := s.EnrollmentCodes().PruneExpired(ctx, now)
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if n != 1 {
		t.Errorf("PruneExpired: rows affected = %d, want 1", n)
	}

	// A should be gone
	_, err = s.EnrollmentCodes().Get(ctx, codeA.Code)
	if err == nil {
		t.Fatal("After prune: code A should be gone, but Get succeeded")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("After prune: code A Get returned %v, want ErrNotFound", err)
	}

	// B should still exist
	if _, err := s.EnrollmentCodes().Get(ctx, codeB.Code); err != nil {
		t.Errorf("After prune: code B should still exist, got %v", err)
	}

	// C should still exist (consumed, audit retention)
	if _, err := s.EnrollmentCodes().Get(ctx, codeC.Code); err != nil {
		t.Errorf("After prune: code C should still exist (consumed), got %v", err)
	}
}

// ---------- 9. FK cascade on user delete ----------

func TestEnrollmentCodeFKCascadeOnUserDelete(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ec-henry@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	c := EnrollmentCode{
		Code:      "CODE-FK-CASCADE",
		UserID:    u.ID,
		Label:     "lbl",
		ExpiresAt: NowUnix() + 3600,
	}
	if _, err := s.EnrollmentCodes().Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Users().Delete(ctx, u.ID); err != nil {
		t.Fatalf("Users().Delete: %v", err)
	}

	_, err = s.EnrollmentCodes().Get(ctx, c.Code)
	if err == nil {
		t.Fatal("Get after user delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after user delete: got %v, want ErrNotFound", err)
	}
}
