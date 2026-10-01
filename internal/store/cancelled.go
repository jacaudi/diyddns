package store

import (
	"context"
	"errors"
)

// Cancelled reports whether err, returned by a store call made with ctx, means
// the caller's context ended (the request went away or timed out) rather than
// the store failing.
func Cancelled(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
