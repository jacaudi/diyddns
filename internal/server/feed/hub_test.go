package feed

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestHub_SubscribeCapAndShutdownGate: the 33rd subscriber is refused, and
// after Shutdown every subscribe is refused so no Add can race the Wait.
func TestHub_SubscribeCapAndShutdownGate(t *testing.T) {
	h := New()
	var subs []*subscriber
	for i := range maxStreamConns {
		s, err := h.subscribe("tok")
		if err != nil {
			t.Fatalf("subscribe %d: %v", i, err)
		}
		subs = append(subs, s)
	}
	if _, err := h.subscribe("tok"); !errors.Is(err, ErrTooManyConnections) {
		t.Fatalf("33rd subscribe err = %v, want ErrTooManyConnections", err)
	}
	for _, s := range subs {
		h.unsubscribe(s)
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown with nothing live: %v", err)
	}
	if _, err := h.subscribe("tok"); !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("subscribe after Shutdown err = %v, want ErrShuttingDown", err)
	}
}

// TestHub_UnsubscribeIsIdempotent: the overflow path and the handler's defer
// may both call it; the WaitGroup must be decremented exactly once, so
// Shutdown returns promptly rather than panicking or hanging (pass 4 BL-1).
func TestHub_UnsubscribeIsIdempotent(t *testing.T) {
	h := New()
	s, err := h.subscribe("tok")
	if err != nil {
		t.Fatal(err)
	}
	h.unsubscribe(s)
	h.unsubscribe(s)
	h.unsubscribe(s)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v (the WaitGroup count is wrong)", err)
	}
}

// TestHub_BroadcastOverflowRemovesSubscriberOutsideTheLock: filling a
// subscriber's buffer cancels it with causeSlowConsumer, frees its slot at
// once, and never deadlocks Broadcast (pass 5 B1 reproduced the deadlock of
// calling unsubscribe under hub.mu).
//
// Broadcast is non-blocking by design (§5.3): the broadcaster can complete
// every send before a separate "drain continuously" goroutine is ever
// scheduled, so that goroutine is only fast if the scheduler happens to run
// it. Under GOMAXPROCS=1 on Linux CI it wasn't, the fast subscriber's buffer
// overflowed exactly like the slow one, and — because sub.ch is never closed
// — the stranded drainer then broke goleak.VerifyNone for every later
// TestStream_* test in the package. Draining the fast subscriber in lockstep
// on the test goroutine, right after each Broadcast call returns, keeps its
// buffer at zero or one message regardless of scheduling, and leaves no
// goroutine behind.
func TestHub_BroadcastOverflowRemovesSubscriberOutsideTheLock(t *testing.T) {
	h := New()
	slow, err := h.subscribe("slow")
	if err != nil {
		t.Fatal(err)
	}
	fast, err := h.subscribe("fast")
	if err != nil {
		t.Fatal(err)
	}

	// broadcast runs Broadcast on its own goroutine and waits for it to
	// return, preserving the deadlock guard this test exists for (pass 5
	// B1): every such goroutine terminates because Broadcast always returns.
	broadcast := func(payload []byte) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			defer close(done)
			h.Broadcast(payload)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("Broadcast did not return: overflow handling deadlocked")
		}
	}

	fastGot := 0
	for range streamBuffer + 1 { // one more than the buffer holds
		broadcast([]byte("x"))
		select {
		case <-fast.ch:
			fastGot++
		case <-time.After(3 * time.Second):
			t.Fatal("fast subscriber did not receive the broadcast")
		}
	}

	select {
	case <-slow.ctx.Done():
	default:
		t.Fatal("slow subscriber was not cancelled after overflowing")
	}
	if c := causeOf(slow.ctx); c.Code != causeSlowConsumer.Code {
		t.Errorf("slow cause = %+v, want 1013", c)
	}
	if h.Live() != 1 {
		t.Errorf("live = %d after the overflow, want 1 (the slot is freed at once)", h.Live())
	}
	select {
	case <-fast.ctx.Done():
		t.Fatal("the fast subscriber was cancelled too")
	default:
	}
	// The fast subscriber received every broadcast; the hub kept serving it.
	if fastGot != streamBuffer+1 {
		t.Errorf("fast received %d, want %d", fastGot, streamBuffer+1)
	}
	// The slow one's later unsubscribe is a no-op, and Shutdown still returns.
	h.unsubscribe(slow)
	h.unsubscribe(fast)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestHub_CloseTokenCancelsOnlyThatToken(t *testing.T) {
	h := New()
	a, _ := h.subscribe("a")
	b, _ := h.subscribe("b")
	h.CloseToken("a")
	if c := causeOf(a.ctx); a.ctx.Err() == nil || c.Code != 4001 || c.Reason != "token revoked" {
		t.Errorf("a: err=%v cause=%+v, want cancelled with 4001 token revoked", a.ctx.Err(), c)
	}
	if b.ctx.Err() != nil {
		t.Error("b was cancelled by another token's revoke")
	}
	h.unsubscribe(a)
	h.unsubscribe(b)
}

// TestHub_ShutdownPropagatesCauseAndWaits: every live subscriber inherits
// causeShutdown; Shutdown returns ctx.Err() if a pump never unsubscribes.
func TestHub_ShutdownPropagatesCauseAndWaits(t *testing.T) {
	h := New()
	s, _ := h.subscribe("tok")

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	err := h.Shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown with a pump still live: err = %v, want DeadlineExceeded", err)
	}
	if c := causeOf(s.ctx); s.ctx.Err() == nil || c.Code != 1001 || c.Reason != "server shutting down" {
		t.Errorf("subscriber cause = %+v, want 1001 server shutting down", c)
	}
	h.unsubscribe(s)
	if err := h.Shutdown(t.Context()); err != nil {
		t.Errorf("second Shutdown after the pump left: %v", err)
	}
}

// TestHub_SubscribeRacesShutdownCleanly runs subscribe concurrently with
// Shutdown at a zero counter; under -race (which task test enables) an Add
// racing a Wait is reported, and this must stay silent (pass 4 S-E).
func TestHub_SubscribeRacesShutdownCleanly(t *testing.T) {
	for range 200 {
		h := New()
		var wg sync.WaitGroup
		wg.Go(func() {
			if s, err := h.subscribe("tok"); err == nil {
				h.unsubscribe(s)
			}
		})
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			_ = h.Shutdown(ctx)
		})
		wg.Wait()
	}
}
