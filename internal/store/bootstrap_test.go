package store

import (
	"errors"
	"testing"
)

func TestBootstrapGetOnEmptyReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Bootstrap()

	_, err := repo.Get(ctx)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on empty: err = %v, want ErrNotFound", err)
	}
}

func TestBootstrapSetTokenHashAndGetRoundTrip(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Bootstrap()

	if err := repo.SetTokenHash(ctx, "hash-1"); err != nil {
		t.Fatalf("SetTokenHash: %v", err)
	}

	got, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.TokenHash != "hash-1" {
		t.Fatalf("Get().TokenHash = %q, want %q", got.TokenHash, "hash-1")
	}
	if got.CreatedAt == 0 {
		t.Fatalf("Get().CreatedAt = 0, want nonzero")
	}
	if got.ConsumedAt != 0 {
		t.Fatalf("Get().ConsumedAt = %d, want 0 (not consumed)", got.ConsumedAt)
	}
}

// TestBootstrapConsumeSucceedsOnceThenFailsOnSecondAttempt is the
// load-bearing test: it proves Consume is single-use. The guarded UPDATE
// (WHERE consumed_at IS NULL) is the atomicity mechanism, so a second
// Consume must return ErrNotFound rather than silently succeeding again.
func TestBootstrapConsumeSucceedsOnceThenFailsOnSecondAttempt(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Bootstrap()

	if err := repo.SetTokenHash(ctx, "hash-1"); err != nil {
		t.Fatalf("SetTokenHash: %v", err)
	}

	if err := repo.Consume(ctx); err != nil {
		t.Fatalf("first Consume: %v", err)
	}

	got, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("Get after Consume: %v", err)
	}
	if got.TokenHash != "" {
		t.Fatalf("Get().TokenHash after Consume = %q, want empty", got.TokenHash)
	}
	if got.ConsumedAt == 0 {
		t.Fatalf("Get().ConsumedAt after Consume = 0, want nonzero")
	}

	err = repo.Consume(ctx)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Consume: err = %v, want ErrNotFound", err)
	}
}

func TestBootstrapConsumeNeverSetReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.Bootstrap()

	err := repo.Consume(ctx)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Consume never-set: err = %v, want ErrNotFound", err)
	}
}
