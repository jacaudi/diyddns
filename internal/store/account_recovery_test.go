package store

import (
	"database/sql"
	"errors"
	"testing"
)

// ---------- 1. Create + Consume happy path returns the row with reason ----------

func TestAccountRecoveryCreateAndConsumeHappyPath(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ar-alice@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := NowUnix()
	tok := RecoveryToken{
		TokenHash: "HASH-ROUNDTRIP",
		UserID:    u.ID,
		Reason:    "admin_invite",
		ExpiresAt: now + 3600,
	}
	if err := s.AccountRecovery().Create(ctx, tok); err != nil {
		t.Fatalf("Create: %v", err)
	}

	consumed, err := s.AccountRecovery().Consume(ctx, tok.TokenHash, now)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if consumed.TokenHash != tok.TokenHash {
		t.Errorf("Consume: TokenHash = %q, want %q", consumed.TokenHash, tok.TokenHash)
	}
	if consumed.UserID != u.ID {
		t.Errorf("Consume: UserID = %q, want %q", consumed.UserID, u.ID)
	}
	if consumed.Reason != tok.Reason {
		t.Errorf("Consume: Reason = %q, want %q", consumed.Reason, tok.Reason)
	}
	if consumed.ExpiresAt != tok.ExpiresAt {
		t.Errorf("Consume: ExpiresAt = %d, want %d", consumed.ExpiresAt, tok.ExpiresAt)
	}
	if consumed.UsedAt != now {
		t.Errorf("Consume: UsedAt = %d, want %d", consumed.UsedAt, now)
	}
}

// ---------- 2. Duplicate token_hash → ErrConflict ----------

func TestAccountRecoveryCreateDuplicateReturnsErrConflict(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ar-bob@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	tok := RecoveryToken{
		TokenHash: "HASH-DUP",
		UserID:    u.ID,
		Reason:    "account_recovery",
		ExpiresAt: NowUnix() + 3600,
	}
	if err := s.AccountRecovery().Create(ctx, tok); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	err = s.AccountRecovery().Create(ctx, tok)
	if err == nil {
		t.Fatal("second Create: expected error, got nil")
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("second Create: got %v, want ErrConflict", err)
	}
}

// ---------- 3. Consume unknown token_hash → ErrNotFound ----------

func TestAccountRecoveryConsumeUnknownReturnsErrNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	_, err := s.AccountRecovery().Consume(ctx, "HASH-UNKNOWN", NowUnix())
	if err == nil {
		t.Fatal("Consume unknown: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Consume unknown: got %v, want ErrNotFound", err)
	}
}

// ---------- 4. Consume expired token → ErrNotFound ----------

func TestAccountRecoveryConsumeExpiredReturnsErrNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ar-eve@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := NowUnix()
	tok := RecoveryToken{
		TokenHash: "HASH-EXPIRED",
		UserID:    u.ID,
		Reason:    "admin_invite",
		ExpiresAt: now - 3600, // in the past
	}
	if err := s.AccountRecovery().Create(ctx, tok); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = s.AccountRecovery().Consume(ctx, tok.TokenHash, now)
	if err == nil {
		t.Fatal("Consume expired: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Consume expired: got %v, want ErrNotFound", err)
	}
}

// ---------- 5. Double-Consume: first succeeds, second → ErrNotFound (atomic gate) ----------

func TestAccountRecoveryConsumeSecondCallReturnsErrNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ar-dan@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := NowUnix()
	tok := RecoveryToken{
		TokenHash: "HASH-DOUBLE-CONSUME",
		UserID:    u.ID,
		Reason:    "account_recovery",
		ExpiresAt: now + 3600,
	}
	if err := s.AccountRecovery().Create(ctx, tok); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.AccountRecovery().Consume(ctx, tok.TokenHash, now); err != nil {
		t.Fatalf("first Consume: %v", err)
	}

	_, err = s.AccountRecovery().Consume(ctx, tok.TokenHash, now)
	if err == nil {
		t.Fatal("second Consume: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("second Consume: got %v, want ErrNotFound", err)
	}
}

// ---------- 6. PruneExpired removes ALL expired tokens ----------

func TestAccountRecoveryPruneExpiredRemovesAllExpired(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ar-grace@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := NowUnix()

	// Token A: unused, expired
	tokA := RecoveryToken{
		TokenHash: "HASH-A-UNUSED-EXPIRED",
		UserID:    u.ID,
		Reason:    "admin_invite",
		ExpiresAt: now - 3600,
	}
	if err := s.AccountRecovery().Create(ctx, tokA); err != nil {
		t.Fatalf("Create A: %v", err)
	}

	// Token B: unused, fresh (not expired)
	tokB := RecoveryToken{
		TokenHash: "HASH-B-UNUSED-FRESH",
		UserID:    u.ID,
		Reason:    "admin_invite",
		ExpiresAt: now + 3600,
	}
	if err := s.AccountRecovery().Create(ctx, tokB); err != nil {
		t.Fatalf("Create B: %v", err)
	}

	// Token C: consumed, expired — must be retained for audit
	tokC := RecoveryToken{
		TokenHash: "HASH-C-CONSUMED-EXPIRED",
		UserID:    u.ID,
		Reason:    "account_recovery",
		ExpiresAt: now + 60, // not yet expired so Consume can succeed
	}
	if err := s.AccountRecovery().Create(ctx, tokC); err != nil {
		t.Fatalf("Create C: %v", err)
	}
	if _, err := s.AccountRecovery().Consume(ctx, tokC.TokenHash, now); err != nil {
		t.Fatalf("Consume C: %v", err)
	}
	// Manually set expires_at into the past so PruneExpired would want to
	// prune it if it weren't consumed — we verify consumed tokens are exempt.
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE account_recovery_tokens SET expires_at = ? WHERE token_hash = ?`,
		now-3600, tokC.TokenHash,
	); err != nil {
		t.Fatalf("backdate C: %v", err)
	}

	n, err := s.AccountRecovery().PruneExpired(ctx, now)
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if n != 2 {
		t.Errorf("PruneExpired: rows affected = %d, want 2 (A unused-expired, C consumed-expired)", n)
	}

	// A should be gone
	_, err = s.AccountRecovery().Consume(ctx, tokA.TokenHash, now)
	if err == nil {
		t.Fatal("After prune: token A should be gone, but Consume succeeded")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("After prune: token A Consume returned %v, want ErrNotFound", err)
	}

	// B should still exist (consumable)
	if _, err := s.AccountRecovery().Consume(ctx, tokB.TokenHash, now); err != nil {
		t.Errorf("After prune: token B should still exist, got %v", err)
	}

	// C is consumed AND expired, so it is gone too: expiry is the only gate.
	// Verified via raw query since Consume would fail either way.
	var got string
	err = s.DB().QueryRowContext(ctx,
		`SELECT token_hash FROM account_recovery_tokens WHERE token_hash = ?`, tokC.TokenHash,
	).Scan(&got)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("After prune: consumed-expired token C should be gone, Scan err = %v", err)
	}
}

// TestAccountRecoveryPruneExpiredKeepsConsumedUnexpired pins the new clause as
// expiry-keyed rather than use-keyed: a consumed token that has NOT yet expired
// survives the sweep.
func TestAccountRecoveryPruneExpiredKeepsConsumedUnexpired(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ar-unexpired@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	now := NowUnix()
	// NOTE: AccountRecoveryRepo.Create returns only an error, not the token.
	tok := RecoveryToken{UserID: u.ID, TokenHash: "consumed-unexpired", ExpiresAt: now + 3600}
	if err := s.AccountRecovery().Create(ctx, tok); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.AccountRecovery().Consume(ctx, tok.TokenHash, now); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	if _, err := s.AccountRecovery().PruneExpired(ctx, now); err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}

	var got string
	if err := s.DB().QueryRowContext(ctx,
		`SELECT token_hash FROM account_recovery_tokens WHERE token_hash = ?`, tok.TokenHash,
	).Scan(&got); err != nil {
		t.Errorf("consumed but unexpired token should survive, got %v", err)
	}
}

// ---------- 6b. Get reads a row without consuming it ----------

func TestAccountRecoveryGet_ReadsWithoutConsuming(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ar-frank@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := NowUnix()
	tok := RecoveryToken{
		TokenHash: "HASH-GET",
		UserID:    u.ID,
		Reason:    "invite",
		ExpiresAt: now + 3600,
	}
	if err := s.AccountRecovery().Create(ctx, tok); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.AccountRecovery().Get(ctx, tok.TokenHash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.UserID != u.ID || got.Reason != "invite" || got.UsedAt != 0 {
		t.Errorf("Get: got %+v, want UserID=%q Reason=invite UsedAt=0", got, u.ID)
	}

	// Get must not consume: Consume must still succeed afterward.
	if _, err := s.AccountRecovery().Consume(ctx, tok.TokenHash, now); err != nil {
		t.Fatalf("Consume after Get: %v, want success (Get must be read-only)", err)
	}
}

func TestAccountRecoveryGet_UnknownReturnsErrNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	_, err := s.AccountRecovery().Get(ctx, "HASH-NEVER-ISSUED")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get unknown: got %v, want ErrNotFound", err)
	}
}

// ---------- 7. FK cascade on user delete ----------

func TestAccountRecoveryFKCascadeOnUserDelete(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "ar-henry@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	tok := RecoveryToken{
		TokenHash: "HASH-FK-CASCADE",
		UserID:    u.ID,
		Reason:    "admin_invite",
		ExpiresAt: NowUnix() + 3600,
	}
	if err := s.AccountRecovery().Create(ctx, tok); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Users().Delete(ctx, u.ID); err != nil {
		t.Fatalf("Users().Delete: %v", err)
	}

	var count int
	if err := s.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM account_recovery_tokens WHERE token_hash = ?`, tok.TokenHash,
	).Scan(&count); err != nil {
		t.Fatalf("count after user delete: %v", err)
	}
	if count != 0 {
		t.Errorf("after user delete: count = %d, want 0", count)
	}
}
