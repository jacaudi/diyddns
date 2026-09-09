// Package poller runs the diyddns-client reporting loop: each cycle discovers
// the host's public IP(s) and posts a signed check-in. It always checks in
// (every contact is a liveness signal); scheduling uses a fixed interval with
// exponential backoff on failure and small jitter on success.
package poller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/jacaudi/diyddns/internal/client/checkin"
	"github.com/jacaudi/diyddns/internal/client/ipdiscovery"
)

// ErrNoQuorum means no address family reached quorum this cycle.
var ErrNoQuorum = errors.New("poller: no address family reached quorum")

// ErrCredentialRejected is returned by Run once the server has answered 401
// on unauthorizedLimit consecutive check-ins: the device secret was rotated
// or the device was disabled, and no amount of retrying will change that.
// It wraps checkin.ErrUnauthorized so callers can match either.
var ErrCredentialRejected = fmt.Errorf("poller: credential rejected by the server: %w", checkin.ErrUnauthorized)

// unauthorizedLimit is how many consecutive 401s Run tolerates before it
// stops. The server answers 401 for every rejection kind — clock skew and a
// replayed nonce included — with a deliberately uniform body, so a single
// one may be transient; three in a row across two backoff sleeps is not.
const unauthorizedLimit = 3

// Discoverer runs public-IP discovery for both families.
type Discoverer interface {
	Discover(ctx context.Context) (v4, v6 ipdiscovery.Result)
}

// Checkiner posts a signed check-in.
type Checkiner interface {
	Checkin(ctx context.Context, r checkin.Report) (checkin.Result, error)
}

// Clock abstracts time for deterministic scheduling tests.
type Clock interface {
	Sleep(ctx context.Context, d time.Duration) error
}

type systemClock struct{}

// NewSystemClock returns a real-time Clock.
func NewSystemClock() Clock { return systemClock{} }

func (systemClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Options configures a Poller. Interval defaults to 5m; Clock to real time;
// RandFloat to a real [0,1) source; Logger to slog.Default().
type Options struct {
	Interval      time.Duration
	Clock         Clock
	RandFloat     func() float64
	Logger        *slog.Logger
	Hostname      string
	OS            string
	ClientVersion string
}

// Poller owns one device's reporting loop.
type Poller struct {
	disc      Discoverer
	chk       Checkiner
	interval  time.Duration
	clock     Clock
	randFloat func() float64
	log       *slog.Logger
	hostname  string
	os        string
	clientVer string
}

// New builds a Poller, applying defaults for unset Options.
func New(d Discoverer, c Checkiner, opts Options) *Poller {
	if opts.Interval <= 0 {
		opts.Interval = 5 * time.Minute
	}
	if opts.Clock == nil {
		opts.Clock = NewSystemClock()
	}
	if opts.RandFloat == nil {
		opts.RandFloat = defaultRandFloat
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Poller{
		disc: d, chk: c, interval: opts.Interval, clock: opts.Clock,
		randFloat: opts.RandFloat, log: opts.Logger,
		hostname: opts.Hostname, os: opts.OS, clientVer: opts.ClientVersion,
	}
}

// RunOnce performs one discover→check-in cycle. It reports every family that
// reached quorum (omitting the rest) and always posts if at least one did.
func (p *Poller) RunOnce(ctx context.Context) error {
	v4, v6 := p.disc.Discover(ctx)
	if !v4.OK && !v6.OK {
		return ErrNoQuorum
	}
	rep := checkin.Report{Hostname: p.hostname, OS: p.os, ClientVersion: p.clientVer}
	if v4.OK {
		rep.IPv4 = v4.Addr.String()
	}
	if v6.OK {
		rep.IPv6 = v6.Addr.String()
	}
	res, err := p.chk.Checkin(ctx, rep)
	if err != nil {
		return err
	}
	p.log.LogAttrs(ctx, slog.LevelInfo, "check-in",
		slog.Bool("stored", res.Stored),
		slog.String("ipv4", res.CurrentIPv4),
		slog.String("ipv6", res.CurrentIPv6))
	return nil
}

// Run loops until ctx is cancelled: cycle now, then sleep the jittered interval
// on success or an exponential backoff (capped at interval) on failure.
func (p *Poller) Run(ctx context.Context) error {
	var backoff time.Duration
	var unauthorized int // consecutive checkin.ErrUnauthorized results
	for {
		err := p.RunOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		var d time.Duration
		if err != nil {
			if errors.Is(err, checkin.ErrUnauthorized) {
				unauthorized++
				if unauthorized >= unauthorizedLimit {
					p.log.LogAttrs(ctx, slog.LevelError, "credential rejected by the server; stopping",
						slog.Int("consecutive", unauthorized), slog.Any("error", err))
					return ErrCredentialRejected
				}
			} else {
				unauthorized = 0
			}
			p.log.LogAttrs(ctx, slog.LevelWarn, "cycle failed", slog.Any("error", err))
			backoff = nextBackoff(backoff, p.interval)
			d = backoff
		} else {
			backoff, unauthorized = 0, 0
			d = p.jittered()
		}
		if err := p.clock.Sleep(ctx, d); err != nil {
			return nil // ctx cancelled → clean stop
		}
	}
}

// nextBackoff returns min(30s,interval) on the first failure, then doubles up
// to interval (M4: first step is clamped so a short interval never backs off
// longer than its own cap).
func nextBackoff(cur, interval time.Duration) time.Duration {
	if cur == 0 {
		return min(30*time.Second, interval)
	}
	return min(cur*2, interval)
}

// jittered returns interval scaled by (1 ± 0.10).
func (p *Poller) jittered() time.Duration {
	factor := 1 + 0.10*(2*p.randFloat()-1)
	return time.Duration(float64(p.interval) * factor)
}

// defaultRandFloat uses math/rand/v2, which needs no seeding. Kept behind the
// RandFloat seam so scheduling tests are deterministic.
func defaultRandFloat() float64 {
	return rand.Float64() //nolint:gosec // G404: jitter timing is not security-sensitive; math/rand/v2 needs no seeding
}
