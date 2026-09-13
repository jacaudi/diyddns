package telemetry

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestShutdown_RunsProvidersConcurrently proves the fan-out is genuinely
// concurrent, not merely correct-looking while actually running the funcs one
// at a time. Each of three stub shutdown funcs signals it has started, then
// blocks until ALL THREE have signalled -- a barrier only a concurrent
// Shutdown can pass. A sequential implementation calls the funcs one at a
// time: the first call blocks waiting for the second and third to start,
// which can never happen until the first one returns -- deadlock. Bounded by
// a short ctx so a sequential mutant fails FAST via ctx.Err() rather than
// hanging the suite.
//
// Fix round 1, C1: this is the "barrier" stub test the critic measured at
// 0.00s with no network. It replaces wall-clock timing (SURVIVED against the
// black-hole test in the original round, because only one of three real
// providers does network I/O when nothing was recorded) with a mechanism that
// cannot pass without genuine concurrency.
func TestShutdown_RunsProvidersConcurrently(t *testing.T) {
	const n = 3
	var wg sync.WaitGroup
	wg.Add(n)
	allStarted := make(chan struct{})
	go func() {
		wg.Wait()
		close(allStarted)
	}()

	p := &Providers{}
	for range n {
		p.shutdown = append(p.shutdown, func(ctx context.Context) error {
			wg.Done()
			select {
			case <-allStarted:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v (a sequential fan-out cannot clear this barrier)", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("Shutdown took %s to clear a 3-way barrier with no I/O; want near-instant", elapsed)
	}
	// A do-nothing Shutdown (the pre-Task-7 stub) also returns nil
	// near-instantly, which would pass both checks above vacuously without
	// ever calling a single shutdown func. allStarted can only be closed if
	// all three funcs actually ran and called wg.Done().
	select {
	case <-allStarted:
	default:
		t.Error("Shutdown returned without ever invoking its shutdown funcs")
	}
}

// errStubA and errStubB are distinct sentinels so TestShutdown_JoinsEveryProvidersError
// can prove BOTH survive into the returned error, not just one.
var (
	errStubA = errors.New("stub provider A failed")
	errStubB = errors.New("stub provider B failed")
)

// TestShutdown_JoinsEveryProvidersError proves Shutdown collects every
// provider's error rather than returning on the first. "Return on first
// error instead of errors.Join" SURVIVED the original round's mutation table
// because no test inspected the returned error's content; this closes that
// gap.
func TestShutdown_JoinsEveryProvidersError(t *testing.T) {
	p := &Providers{shutdown: []func(context.Context) error{
		func(context.Context) error { return errStubA },
		func(context.Context) error { return nil },
		func(context.Context) error { return errStubB },
	}}
	err := p.Shutdown(t.Context())
	if !errors.Is(err, errStubA) {
		t.Errorf("Shutdown's error does not wrap errStubA: %v", err)
	}
	if !errors.Is(err, errStubB) {
		t.Errorf("Shutdown's error does not wrap errStubB: %v", err)
	}
}

// TestShutdown_ClearsFuncsSoASecondCallDoesNotRerunThem proves the funcs
// captured by the first Shutdown call are not invoked again by a second one,
// on an *enabled*-shaped Providers (a real, non-empty shutdown slice) --
// TestShutdown_IsIdempotent (telemetry_test.go) only exercises a *disabled*
// Providers, whose shutdown slice is already empty.
//
// "Drop p.shutdown = nil" originally SURVIVED the mutation table for exactly
// this reason. It was re-tested after adding shutdownOnce (S1, Fix round 1)
// and now ALSO SURVIVES, for a different, benign reason: shutdownOnce.Do
// already guarantees the closure that would re-invoke the funcs runs at most
// once, so whether p.shutdown is cleared afterward no longer changes this
// test's observable outcome. p.shutdown = nil is kept anyway, for GC hygiene
// (see its comment in telemetry.go), not for this correctness property. This
// test still pins the property that matters -- a second call does not
// re-invoke the funcs -- it is just shutdownOnce, not the clear, that now
// makes it true.
func TestShutdown_ClearsFuncsSoASecondCallDoesNotRerunThem(t *testing.T) {
	var calls int
	p := &Providers{shutdown: []func(context.Context) error{
		func(context.Context) error { calls++; return nil },
	}}
	if err := p.Shutdown(t.Context()); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	if err := p.Shutdown(t.Context()); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
	if calls != 1 {
		t.Errorf("shutdown func called %d times across two Shutdown calls, want 1", calls)
	}
}

// TestShutdown_SafeForConcurrentSelfCalls pins S1 (Fix round 1): two
// goroutines calling Shutdown on the SAME *Providers concurrently must not
// race reading and clearing p.shutdown. Caught under -race before sync.Once
// was added (read at telemetry.go's `len(p.shutdown) == 0` check vs the write
// at `p.shutdown = nil`); see task-7-report.md's Fix round 1 section for the
// transcript. No caller does this today, but Shutdown's entire subject is
// concurrency, so it must tolerate being called that way itself.
func TestShutdown_SafeForConcurrentSelfCalls(t *testing.T) {
	p := &Providers{shutdown: []func(context.Context) error{
		func(context.Context) error { return nil },
	}}
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			_ = p.Shutdown(t.Context())
		})
	}
	wg.Wait()
}
