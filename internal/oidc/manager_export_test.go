package oidc

import (
	"context"
	"time"
)

// SetSleepForTest overrides the Manager's backoff sleep with a test-controlled
// function, so RetryLoop tests avoid real timers.
func SetSleepForTest(m *Manager, f func(context.Context, time.Duration) bool) { m.sleep = f }
