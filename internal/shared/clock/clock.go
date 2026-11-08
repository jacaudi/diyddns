// Package clock holds the context-aware sleep the client's poll loops and the
// server's OIDC retry loop share. Stdlib-only, so the client may import it.
package clock

import (
	"context"
	"time"
)

// Sleep waits for d, or until ctx is done, whichever comes first. It returns
// ctx.Err() when ctx ended the wait and nil otherwise.
func Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
