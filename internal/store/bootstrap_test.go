package store

import (
	"errors"
	"testing"
)

func TestBootstrapGetWhenEmptyReturnsErrNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	_, err := s.Bootstrap().Get(ctx)
	if err == nil {
		t.Fatal("Get on empty bootstrap: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get on empty bootstrap: got %v, want errors.Is(err, ErrNotFound)", err)
	}
}

func TestBootstrapSetTokenHashThenGetRoundTrips(t *testing.T) {
	s, ctx := newTestStore(t)

	before := NowUnix()

	if err := s.Bootstrap().SetTokenHash(ctx, "hash1"); err != nil {
		t.Fatalf("SetTokenHash: %v", err)
	}

	got, err := s.Bootstrap().Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.TokenHash != "hash1" {
		t.Errorf("TokenHash: got %q, want %q", got.TokenHash, "hash1")
	}
	if got.ConsumedAt != 0 {
		t.Errorf("ConsumedAt: got %d, want 0", got.ConsumedAt)
	}
	after := NowUnix()
	if got.CreatedAt < before-2 || got.CreatedAt > after+2 {
		t.Errorf("CreatedAt: got %d, want in [%d, %d]", got.CreatedAt, before-2, after+2)
	}
}

func TestBootstrapSetTokenHashReplacesExisting(t *testing.T) {
	s, ctx := newTestStore(t)

	if err := s.Bootstrap().SetTokenHash(ctx, "a"); err != nil {
		t.Fatalf("SetTokenHash a: %v", err)
	}

	first, err := s.Bootstrap().Get(ctx)
	if err != nil {
		t.Fatalf("Get after first set: %v", err)
	}

	if err := s.Bootstrap().SetTokenHash(ctx, "b"); err != nil {
		t.Fatalf("SetTokenHash b: %v", err)
	}

	second, err := s.Bootstrap().Get(ctx)
	if err != nil {
		t.Fatalf("Get after second set: %v", err)
	}

	if second.TokenHash != "b" {
		t.Errorf("TokenHash after replace: got %q, want %q", second.TokenHash, "b")
	}
	if second.CreatedAt < first.CreatedAt {
		t.Errorf("CreatedAt after replace: got %d, want >= %d", second.CreatedAt, first.CreatedAt)
	}
}

func TestBootstrapConsumeFirstCallSucceeds(t *testing.T) {
	s, ctx := newTestStore(t)

	if err := s.Bootstrap().SetTokenHash(ctx, "h"); err != nil {
		t.Fatalf("SetTokenHash: %v", err)
	}

	before := NowUnix()
	if err := s.Bootstrap().Consume(ctx); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	got, err := s.Bootstrap().Get(ctx)
	if err != nil {
		t.Fatalf("Get after consume: %v", err)
	}

	if got.TokenHash != "" {
		t.Errorf("TokenHash after consume: got %q, want empty", got.TokenHash)
	}
	after := NowUnix()
	if got.ConsumedAt <= 0 {
		t.Errorf("ConsumedAt after consume: got %d, want > 0", got.ConsumedAt)
	}
	if got.ConsumedAt < before-2 || got.ConsumedAt > after+2 {
		t.Errorf("ConsumedAt: got %d, want in [%d, %d]", got.ConsumedAt, before-2, after+2)
	}
}

func TestBootstrapConsumeSecondCallReturnsErrNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	if err := s.Bootstrap().SetTokenHash(ctx, "h"); err != nil {
		t.Fatalf("SetTokenHash: %v", err)
	}
	if err := s.Bootstrap().Consume(ctx); err != nil {
		t.Fatalf("first Consume: %v", err)
	}

	err := s.Bootstrap().Consume(ctx)
	if err == nil {
		t.Fatal("second Consume: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("second Consume: got %v, want errors.Is(err, ErrNotFound)", err)
	}
}

func TestBootstrapConsumeWhenEmptyReturnsErrNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	err := s.Bootstrap().Consume(ctx)
	if err == nil {
		t.Fatal("Consume on empty bootstrap: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Consume on empty bootstrap: got %v, want errors.Is(err, ErrNotFound)", err)
	}
}
