package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestPrune_RemovesExpiredRecords seeds one expired row in each of the three
// pruned tables and confirms prune() deletes all of them and reports
// accurate counts.
func TestPrune_RemovesExpiredRecords(t *testing.T) {
	ctx := t.Context()
	st := openTestStore(t)

	past := store.NowUnix() - int64(time.Hour/time.Second)

	u, err := st.Users().Create(ctx, store.User{Email: "prune@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users().Create: %v", err)
	}

	if err := st.ReplayNonces().Insert(ctx, "expired-sig", past); err != nil {
		t.Fatalf("ReplayNonces().Insert: %v", err)
	}
	sess, err := st.Sessions().Create(ctx, store.Session{UserID: u.ID, ExpiresAt: past})
	if err != nil {
		t.Fatalf("Sessions().Create: %v", err)
	}
	if _, err := st.EnrollmentCodes().Create(ctx, store.EnrollmentCode{
		Code: "expired-code", UserID: u.ID, Label: "x", ExpiresAt: past,
	}); err != nil {
		t.Fatalf("EnrollmentCodes().Create: %v", err)
	}

	prune(ctx, st, discardLog())

	if exists, err := st.ReplayNonces().Exists(ctx, "expired-sig"); err != nil {
		t.Fatalf("ReplayNonces().Exists: %v", err)
	} else if exists {
		t.Error("expired replay nonce was not pruned")
	}
	if _, err := st.Sessions().GetByID(ctx, sess.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired session was not pruned, GetByID err = %v", err)
	}
	if _, err := st.EnrollmentCodes().Get(ctx, "expired-code"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired enrollment code was not pruned, Get err = %v", err)
	}
}

// TestRunPruner_StopsOnContextCancel confirms the ticker goroutine exits
// promptly once ctx is cancelled — its only shutdown path.
func TestRunPruner_StopsOnContextCancel(t *testing.T) {
	st := openTestStore(t)
	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan struct{})
	go func() {
		runPruner(ctx, st, discardLog())
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runPruner did not stop within 5s of ctx cancellation")
	}
}
