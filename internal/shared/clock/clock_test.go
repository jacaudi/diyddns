package clock

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSleep_ReturnsNilAfterTheDuration(t *testing.T) {
	start := time.Now()
	if err := Sleep(t.Context(), 10*time.Millisecond); err != nil {
		t.Fatalf("Sleep = %v, want nil", err)
	}
	if got := time.Since(start); got < 10*time.Millisecond {
		t.Errorf("Sleep returned after %v, want at least 10ms", got)
	}
}

// A cancelled context ends the wait at once with ctx.Err(), e.g. on SIGTERM.
func TestSleep_ReturnsContextErrorWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	start := time.Now()
	if err := Sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sleep = %v, want context.Canceled", err)
	}
	if got := time.Since(start); got > time.Second {
		t.Errorf("cancelled Sleep took %v, want it to return immediately", got)
	}
}
