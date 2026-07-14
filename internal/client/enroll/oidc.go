package enroll

import (
	"context"
	"errors"
	"time"
)

// Clock abstracts time so the poll loop is testable without real sleeps. Sleep
// returns the context error if ctx is cancelled while waiting.
type Clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

// Prompter renders the user_code / verification_uri to the operator.
type Prompter interface {
	ShowUserCode(DeviceStart)
	Waiting()
}

// Result is the outcome of a completed device-code enrollment. Secret is the
// device HMAC key as wire base64 (verbatim).
type Result struct {
	DeviceID string
	Secret   string
}

const (
	minIntervalSeconds       = 5
	slowDownBumpSeconds      = 5
	maxConsecutiveBadGateway = 3
)

// DeviceCodeEnroll drives the RFC 8628 flow: start → display → poll loop →
// minted credentials. It writes no files. The first poll happens immediately
// (the server allows it); subsequent polls wait min(interval, time-to-deadline).
func DeviceCodeEnroll(ctx context.Context, c *Client, p Prompter, clk Clock) (Result, error) {
	ds, err := c.OIDCDeviceStart(ctx)
	if err != nil {
		return Result{}, err
	}
	if ds.ExpiresIn <= 0 {
		return Result{}, ErrExpired
	}
	p.ShowUserCode(ds)
	p.Waiting()

	deadline := clk.Now().Add(time.Duration(ds.ExpiresIn) * time.Second)
	intervalSecs := ds.Interval
	if intervalSecs < minIntervalSeconds {
		intervalSecs = minIntervalSeconds
	}
	interval := time.Duration(intervalSecs) * time.Second

	consecutive502 := 0
	for {
		res, err := c.OIDCDevicePoll(ctx, ds.FlowID)
		switch {
		case err == nil:
			consecutive502 = 0
			switch res.Kind {
			case pollComplete:
				return Result{DeviceID: res.DeviceID, Secret: res.Secret}, nil
			case pollSlowDown:
				interval += slowDownBumpSeconds * time.Second
			case pollPending:
			}
		case isBadGateway(err):
			consecutive502++
			if consecutive502 >= maxConsecutiveBadGateway {
				return Result{}, ErrBadGateway
			}
			interval += slowDownBumpSeconds * time.Second
		default:
			return Result{}, err // 410/401/500/protocol → terminal
		}

		now := clk.Now()
		if !now.Before(deadline) {
			return Result{}, ErrExpired
		}
		wait := interval
		if remaining := deadline.Sub(now); remaining < wait {
			wait = remaining
		}
		if err := clk.Sleep(ctx, wait); err != nil {
			return Result{}, err
		}
	}
}

func isBadGateway(err error) bool {
	return errors.Is(err, ErrBadGateway)
}

// NewSystemClock returns a Clock backed by the real wall clock. Sleep unblocks
// early (returning ctx.Err()) if ctx is cancelled — e.g. on SIGINT/SIGTERM.
func NewSystemClock() Clock { return systemClock{} }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }
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
