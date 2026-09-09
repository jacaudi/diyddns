package poller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/client/checkin"
	"github.com/jacaudi/diyddns/internal/client/ipdiscovery"
)

type fakeDisc struct{ v4, v6 ipdiscovery.Result }

func (f fakeDisc) Discover(context.Context) (ipdiscovery.Result, ipdiscovery.Result) {
	return f.v4, f.v6
}

type fakeChk struct {
	last checkin.Report
	res  checkin.Result
	err  error
	n    int
}

func (f *fakeChk) Checkin(_ context.Context, r checkin.Report) (checkin.Result, error) {
	f.last = r
	f.n++
	return f.res, f.err
}

// seqChk answers each Checkin call with the next error in errs (nil = success),
// then repeats the last one. It pins ORDER-dependent behaviour, which fakeChk's
// single fixed error cannot.
type seqChk struct {
	errs []error
	n    int
}

func (s *seqChk) Checkin(context.Context, checkin.Report) (checkin.Result, error) {
	i := min(s.n, len(s.errs)-1)
	s.n++
	return checkin.Result{}, s.errs[i]
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRunOnce_ReportsQuorumFamiliesOnly(t *testing.T) {
	d := fakeDisc{v4: ipdiscovery.Result{Addr: netip.MustParseAddr("203.0.113.7"), OK: true}}
	c := &fakeChk{res: checkin.Result{Stored: true}}
	p := New(d, c, Options{Logger: testLogger()})
	if err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if c.last.IPv4 != "203.0.113.7" || c.last.IPv6 != "" {
		t.Errorf("report = %+v, want IPv4 only (v6 omitted)", c.last)
	}
}

func TestRunOnce_NoQuorum(t *testing.T) {
	p := New(fakeDisc{}, &fakeChk{}, Options{Logger: testLogger()})
	if err := p.RunOnce(context.Background()); !errors.Is(err, ErrNoQuorum) {
		t.Errorf("err = %v, want ErrNoQuorum", err)
	}
}

func TestRunOnce_AlwaysChecksInWhenQuorum(t *testing.T) {
	d := fakeDisc{v4: ipdiscovery.Result{Addr: netip.MustParseAddr("203.0.113.7"), OK: true}}
	c := &fakeChk{res: checkin.Result{Stored: false}} // unchanged
	p := New(d, c, Options{Logger: testLogger()})
	if err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if c.n != 1 {
		t.Errorf("checkin calls = %d, want 1 even when unchanged", c.n)
	}
}

// fakeClock records sleep durations and cancels after N sleeps.
type fakeClock struct {
	sleeps []time.Duration
	cancel context.CancelFunc
	stopAt int
}

func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.sleeps = append(c.sleeps, d)
	if len(c.sleeps) >= c.stopAt {
		c.cancel()
		return context.Canceled
	}
	return nil
}

func TestRun_BackoffThenReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clk := &fakeClock{cancel: cancel, stopAt: 3}
	d := fakeDisc{v4: ipdiscovery.Result{Addr: netip.MustParseAddr("203.0.113.7"), OK: true}}
	c := &fakeChk{err: fmt.Errorf("%w: status 500", checkin.ErrServer)} // a 5xx backs off, forever
	p := New(d, c, Options{Interval: 5 * time.Minute, Clock: clk, RandFloat: func() float64 { return 0.5 }, Logger: testLogger()})
	_ = p.Run(ctx)
	// First two failures back off: min(30s,interval)=30s, then 60s.
	if len(clk.sleeps) < 2 || clk.sleeps[0] != 30*time.Second || clk.sleeps[1] != 60*time.Second {
		t.Errorf("backoff sequence = %v, want [30s 60s ...]", clk.sleeps)
	}
}

func TestRun_SuccessJitterWithinBound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clk := &fakeClock{cancel: cancel, stopAt: 1}
	d := fakeDisc{v4: ipdiscovery.Result{Addr: netip.MustParseAddr("203.0.113.7"), OK: true}}
	c := &fakeChk{res: checkin.Result{Stored: true}}
	p := New(d, c, Options{Interval: 100 * time.Second, Clock: clk, RandFloat: func() float64 { return 1.0 }, Logger: testLogger()})
	_ = p.Run(ctx)
	// rand=1.0 → interval*(1 + 0.1*(2*1-1)) = 110s (upper bound).
	if clk.sleeps[0] != 110*time.Second {
		t.Errorf("jittered sleep = %v, want 110s", clk.sleeps[0])
	}
}

func TestRun_ThreeConsecutiveUnauthorized_Terminates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clk := &fakeClock{cancel: cancel, stopAt: 10} // never reached: Run must stop on its own
	d := fakeDisc{v4: ipdiscovery.Result{Addr: netip.MustParseAddr("203.0.113.7"), OK: true}}
	c := &seqChk{errs: []error{checkin.ErrUnauthorized}}
	p := New(d, c, Options{Interval: 5 * time.Minute, Clock: clk, RandFloat: func() float64 { return 0.5 }, Logger: testLogger()})

	err := p.Run(ctx)

	// #102: the server answers 401 for every rejection kind, so the first two
	// are treated as possibly transient (backoff), and the third in a row is
	// the signal that the credential is gone — rotated or disabled — and no
	// amount of retrying will fix it. Exit so the operator sees it.
	if !errors.Is(err, checkin.ErrUnauthorized) {
		t.Fatalf("Run returned %v, want an error matching checkin.ErrUnauthorized", err)
	}
	if c.n != 3 {
		t.Errorf("check-ins = %d, want 3 (terminate on the third consecutive 401)", c.n)
	}
	if len(clk.sleeps) != 2 {
		t.Errorf("sleeps = %v, want exactly 2 (backoff after the first two, none after the third)", clk.sleeps)
	}
}

func TestRun_UnauthorizedStreakResetsOnSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clk := &fakeClock{cancel: cancel, stopAt: 5}
	d := fakeDisc{v4: ipdiscovery.Result{Addr: netip.MustParseAddr("203.0.113.7"), OK: true}}
	// 401, 401, ok, 401, ok — never three in a row, so Run keeps going until
	// the clock cancels the context after the fifth sleep.
	c := &seqChk{errs: []error{checkin.ErrUnauthorized, checkin.ErrUnauthorized, nil, checkin.ErrUnauthorized, nil}}
	p := New(d, c, Options{Interval: 5 * time.Minute, Clock: clk, RandFloat: func() float64 { return 0.5 }, Logger: testLogger()})

	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run returned %v, want nil (clean stop on cancel; the streak was broken)", err)
	}
	if c.n != 5 {
		t.Errorf("check-ins = %d, want 5", c.n)
	}
}
