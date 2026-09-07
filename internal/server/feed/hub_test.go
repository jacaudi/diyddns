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
	// The fast subscriber drains continuously, like a live pump; only the
	// slow one lets its buffer fill.
	fastGot := make(chan int, 1)
	go func() {
		n := 0
		for range fast.ch {
			n++
			if n == streamBuffer+1 {
				fastGot <- n
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i <= streamBuffer; i++ { // one more than the buffer holds
			h.Broadcast([]byte("x"))
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Broadcast did not return: overflow handling deadlocked")
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
	select {
	case n := <-fastGot:
		if n != streamBuffer+1 {
			t.Errorf("fast received %d, want %d", n, streamBuffer+1)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fast subscriber did not receive every broadcast")
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
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = h.Shutdown(ctx)
		})
		wg.Wait()
	}
}
