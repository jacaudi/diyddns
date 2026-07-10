package store

import (
	"errors"
	"testing"
)

func TestReplayNonceInsertAndExistsRoundTrip(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.ReplayNonces()

	if err := repo.Insert(ctx, "sig-1", NowUnix()+3600); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	ok, err := repo.Exists(ctx, "sig-1")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !ok {
		t.Fatalf("Exists(%q) = false, want true after Insert", "sig-1")
	}
}

// TestReplayNonceInsertDuplicateReturnsConflict is the load-bearing test:
// a repeated signature is the replay signal, and Insert must surface it as
// ErrConflict so callers can reject the replayed request.
func TestReplayNonceInsertDuplicateReturnsConflict(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.ReplayNonces()

	if err := repo.Insert(ctx, "dup-sig", NowUnix()+3600); err != nil {
		t.Fatalf("first Insert: %v", err)
	}

	err := repo.Insert(ctx, "dup-sig", NowUnix()+3600)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("second Insert of same signature: err = %v, want ErrConflict", err)
	}
}

func TestReplayNonceExistsMissingReturnsFalse(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.ReplayNonces()

	ok, err := repo.Exists(ctx, "unknown-sig")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if ok {
		t.Fatalf("Exists(%q) = true, want false for unknown signature", "unknown-sig")
	}
}

// TestReplayNoncePruneExpiredRemovesOnlyExpired proves the DELETE guard: a
// nonce whose expires_at is before now is pruned, and a nonce whose
// expires_at is still in the future is left alone.
func TestReplayNoncePruneExpiredRemovesOnlyExpired(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.ReplayNonces()

	now := NowUnix()
	if err := repo.Insert(ctx, "expired-sig", now-10); err != nil {
		t.Fatalf("Insert expired-sig: %v", err)
	}
	if err := repo.Insert(ctx, "fresh-sig", now+3600); err != nil {
		t.Fatalf("Insert fresh-sig: %v", err)
	}

	n, err := repo.PruneExpired(ctx, now)
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("PruneExpired() = %d, want 1", n)
	}

	ok, err := repo.Exists(ctx, "expired-sig")
	if err != nil {
		t.Fatalf("Exists(expired-sig) after prune: %v", err)
	}
	if ok {
		t.Fatalf("Exists(expired-sig) after prune = true, want false (should have been pruned)")
	}

	ok, err = repo.Exists(ctx, "fresh-sig")
	if err != nil {
		t.Fatalf("Exists(fresh-sig) after prune: %v", err)
	}
	if !ok {
		t.Fatalf("Exists(fresh-sig) after prune = false, want true (should survive)")
	}
}

// TestReplayNoncePruneExpiredKeepsExactlyAtNow proves the strict-inequality
// boundary: a nonce whose expires_at equals now is NOT expired yet (the
// query is expires_at < now, not <=), so it must survive the prune.
func TestReplayNoncePruneExpiredKeepsExactlyAtNow(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.ReplayNonces()

	now := NowUnix()
	if err := repo.Insert(ctx, "boundary-sig", now); err != nil {
		t.Fatalf("Insert boundary-sig: %v", err)
	}

	n, err := repo.PruneExpired(ctx, now)
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if n != 0 {
		t.Fatalf("PruneExpired() = %d, want 0 (expires_at == now must not be pruned)", n)
	}

	ok, err := repo.Exists(ctx, "boundary-sig")
	if err != nil {
		t.Fatalf("Exists(boundary-sig) after prune: %v", err)
	}
	if !ok {
		t.Fatalf("Exists(boundary-sig) after prune = false, want true (exactly-now must survive)")
	}
}
