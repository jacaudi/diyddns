package store

import (
	"errors"
	"testing"
)

func TestReplayNonceInsertAndExists(t *testing.T) {
	s, ctx := newTestStore(t)

	futureExpiry := int64(9_999_999_999)

	if err := s.ReplayNonces().Insert(ctx, "sig1", futureExpiry); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	found, err := s.ReplayNonces().Exists(ctx, "sig1")
	if err != nil {
		t.Fatalf("Exists(sig1): %v", err)
	}
	if !found {
		t.Error("Exists(sig1): got false, want true")
	}

	found, err = s.ReplayNonces().Exists(ctx, "nope")
	if err != nil {
		t.Fatalf("Exists(nope): %v", err)
	}
	if found {
		t.Error("Exists(nope): got true, want false")
	}
}

func TestReplayNonceInsertDuplicateReturnsErrConflict(t *testing.T) {
	s, ctx := newTestStore(t)

	futureExpiry := int64(9_999_999_999)

	if err := s.ReplayNonces().Insert(ctx, "dup-sig", futureExpiry); err != nil {
		t.Fatalf("Insert first: %v", err)
	}

	err := s.ReplayNonces().Insert(ctx, "dup-sig", futureExpiry)
	if err == nil {
		t.Fatal("Insert duplicate: expected error, got nil")
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("Insert duplicate: got %v, want errors.Is(err, ErrConflict)", err)
	}
}

func TestReplayNoncePruneExpiredRemovesExpired(t *testing.T) {
	s, ctx := newTestStore(t)

	// Expiring at 100 — will be pruned when now=500.
	if err := s.ReplayNonces().Insert(ctx, "sig-expired", 100); err != nil {
		t.Fatalf("Insert expired: %v", err)
	}

	// Expiring far in the future — must survive.
	if err := s.ReplayNonces().Insert(ctx, "sig-future", 9_999_999_999); err != nil {
		t.Fatalf("Insert future: %v", err)
	}

	n, err := s.ReplayNonces().PruneExpired(ctx, 500)
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if n != 1 {
		t.Errorf("PruneExpired: got %d rows deleted, want 1", n)
	}

	// Expired nonce must be gone.
	found, err := s.ReplayNonces().Exists(ctx, "sig-expired")
	if err != nil {
		t.Fatalf("Exists(sig-expired): %v", err)
	}
	if found {
		t.Error("Exists(sig-expired): got true after prune, want false")
	}

	// Future nonce must still be present.
	found, err = s.ReplayNonces().Exists(ctx, "sig-future")
	if err != nil {
		t.Fatalf("Exists(sig-future): %v", err)
	}
	if !found {
		t.Error("Exists(sig-future): got false, want true")
	}
}

func TestReplayNoncePruneZeroWhenAllFresh(t *testing.T) {
	s, ctx := newTestStore(t)

	if err := s.ReplayNonces().Insert(ctx, "fresh-a", 9_999_999_998); err != nil {
		t.Fatalf("Insert fresh-a: %v", err)
	}
	if err := s.ReplayNonces().Insert(ctx, "fresh-b", 9_999_999_999); err != nil {
		t.Fatalf("Insert fresh-b: %v", err)
	}

	n, err := s.ReplayNonces().PruneExpired(ctx, 0)
	if err != nil {
		t.Fatalf("PruneExpired(0): %v", err)
	}
	if n != 0 {
		t.Errorf("PruneExpired(0): got %d rows deleted, want 0", n)
	}

	// Both nonces must still be present.
	for _, sig := range []string{"fresh-a", "fresh-b"} {
		found, err := s.ReplayNonces().Exists(ctx, sig)
		if err != nil {
			t.Fatalf("Exists(%s): %v", sig, err)
		}
		if !found {
			t.Errorf("Exists(%s): got false, want true", sig)
		}
	}
}
