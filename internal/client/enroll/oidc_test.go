package enroll

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock advances virtual time on each Sleep so deadline logic terminates
// without real waiting.
type fakeClock struct {
	now   time.Time
	slept []time.Duration
}

func (f *fakeClock) Now() time.Time { return f.now }
func (f *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	f.slept = append(f.slept, d)
	f.now = f.now.Add(d)
	return nil
}

type capturePrompter struct {
	shown  bool
	waited bool
}

func (c *capturePrompter) ShowUserCode(DeviceStart) { c.shown = true }
func (c *capturePrompter) Waiting()                 { c.waited = true }

// scriptServer serves a fixed start response, then returns poll responses from
// pollBodies in order (last one repeats).
func scriptServer(t *testing.T, start string, pollBodies []struct {
	status int
	body   string
}) *Client {
	t.Helper()
	var n int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/v1/enroll/oidc/start":
			_, _ = w.Write([]byte(start))
		case "/agent/v1/enroll/oidc/poll":
			i := int(atomic.AddInt64(&n, 1)) - 1
			if i >= len(pollBodies) {
				i = len(pollBodies) - 1
			}
			w.WriteHeader(pollBodies[i].status)
			_, _ = w.Write([]byte(pollBodies[i].body))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(ts.Close)
	c, err := NewClient(ts.URL, ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type pb = struct {
	status int
	body   string
}

const startOK = `{"flow_id":"f","user_code":"UC","verification_uri":"https://v","expires_in":300,"interval":5}`

func TestDeviceCodeEnrollSuccessAfterPending(t *testing.T) {
	c := scriptServer(t, startOK, []pb{
		{200, `{"status":"pending"}`},
		{200, `{"status":"pending"}`},
		{200, `{"device_id":"dev_9","secret":"c2VjcmV0"}`},
	})
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	p := &capturePrompter{}
	res, err := DeviceCodeEnroll(context.Background(), c, p, clk)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if res.DeviceID != "dev_9" || res.Secret != "c2VjcmV0" {
		t.Errorf("result = %+v", res)
	}
	if !p.shown || !p.waited {
		t.Errorf("prompter not called: %+v", p)
	}
	if len(clk.slept) != 2 { // slept between the 3 polls, not before the 1st, not after success
		t.Errorf("slept %d times, want 2", len(clk.slept))
	}
}

func TestDeviceCodeEnrollSlowDownBumpsInterval(t *testing.T) {
	c := scriptServer(t, startOK, []pb{
		{200, `{"status":"slow_down"}`},
		{200, `{"device_id":"d","secret":"c2VjcmV0"}`},
	})
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk); err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(clk.slept) != 1 || clk.slept[0] != 10*time.Second { // 5s base + 5s bump
		t.Errorf("slept = %v, want [10s]", clk.slept)
	}
}

func TestDeviceCodeEnrollTerminalStatuses(t *testing.T) {
	tests := []struct {
		name string
		poll pb
		want error
	}{
		{"gone", pb{410, `{}`}, ErrFlowGone},
		{"rejected", pb{401, `{}`}, ErrRejected},
		{"server", pb{500, `{}`}, ErrServer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := scriptServer(t, startOK, []pb{tt.poll})
			clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
			_, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk)
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDeviceCodeEnrollBadGatewayToleratedThenExhausted(t *testing.T) {
	// Two 502s then success → tolerated.
	c := scriptServer(t, startOK, []pb{
		{502, `{}`}, {502, `{}`}, {200, `{"device_id":"d","secret":"c2VjcmV0"}`},
	})
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk); err != nil {
		t.Fatalf("tolerated 502 failed: %v", err)
	}
	// Three consecutive 502s → ErrBadGateway.
	c = scriptServer(t, startOK, []pb{{502, `{}`}})
	clk = &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk); !errors.Is(err, ErrBadGateway) {
		t.Errorf("err = %v, want ErrBadGateway", err)
	}
}

func TestDeviceCodeEnrollExpires(t *testing.T) {
	// expires_in small, always pending → deadline reached → ErrExpired.
	start := `{"flow_id":"f","user_code":"UC","verification_uri":"https://v","expires_in":7,"interval":5}`
	c := scriptServer(t, start, []pb{{200, `{"status":"pending"}`}})
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestDeviceCodeEnrollExpiresInNonPositive(t *testing.T) {
	start := `{"flow_id":"f","user_code":"UC","verification_uri":"https://v","expires_in":0,"interval":5}`
	c := scriptServer(t, start, []pb{{200, `{"status":"pending"}`}})
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestDeviceCodeEnrollContextCancel(t *testing.T) {
	c := scriptServer(t, startOK, []pb{{200, `{"status":"pending"}`}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(ctx, c, &capturePrompter{}, clk); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestDeviceCodeEnrollIntervalFloor(t *testing.T) {
	// interval=1 is below the 5s floor → the first sleep must be 5s, not 1s.
	start := `{"flow_id":"f","user_code":"UC","verification_uri":"https://v","expires_in":300,"interval":1}`
	c := scriptServer(t, start, []pb{
		{200, `{"status":"pending"}`},
		{200, `{"device_id":"d","secret":"c2VjcmV0"}`},
	})
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk); err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(clk.slept) != 1 || clk.slept[0] != 5*time.Second { // floored up from 1s
		t.Errorf("slept = %v, want [5s]", clk.slept)
	}
}

func TestDeviceCodeEnrollBadGatewayBumpsInterval(t *testing.T) {
	// A single 502 bumps the interval by 5s → first sleep is 5s base + 5s = 10s.
	c := scriptServer(t, startOK, []pb{
		{502, `{}`},
		{200, `{"device_id":"d","secret":"c2VjcmV0"}`},
	})
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk); err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(clk.slept) != 1 || clk.slept[0] != 10*time.Second { // 5s base + 5s bump
		t.Errorf("slept = %v, want [10s]", clk.slept)
	}
}

func TestDeviceCodeEnrollConsecutive502ResetsOnNon502(t *testing.T) {
	// Four 502s total, but interleaved by a pending so they never reach three in
	// a row → the consecutive counter resets and enrollment completes.
	c := scriptServer(t, startOK, []pb{
		{502, `{}`}, {502, `{}`},
		{200, `{"status":"pending"}`}, // resets consecutive502 to 0
		{502, `{}`}, {502, `{}`},
		{200, `{"device_id":"d","secret":"c2VjcmV0"}`},
	})
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	if _, err := DeviceCodeEnroll(context.Background(), c, &capturePrompter{}, clk); err != nil {
		t.Fatalf("interleaved 502s must not trip ErrBadGateway: %v", err)
	}
}
