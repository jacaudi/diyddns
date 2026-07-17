package poller

import (
	"context"
	"errors"
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
	c := &fakeChk{err: errors.New("boom")} // every cycle fails → backoff
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
