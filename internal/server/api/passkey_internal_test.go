package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/logtest"
	"github.com/jacaudi/diyddns/internal/store"
)

// TestPasskeyErr_CancelledRequest drives the mapper directly, so the status
// literal and the sentinel-before-cancelled order are pinned without a server.
// The HTTP path is TestRegister_BeginForACancelledRequest. A cancelled request
// is the client's doing, not an infrastructure failure: 499, one Info line, no
// Error line. The sentinel cases still win, so a wrapped store.ErrNotFound
// stays a 404.
func TestPasskeyErr_CancelledRequest(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		cancelled  bool
		wantStatus int
		wantInfo   int
	}{
		{"wrapped context.Canceled", fmt.Errorf("account_recovery.Get: %w", context.Canceled), true, 499, 1}, // the literal: a changed constant must fail this
		{"error alone, live context", fmt.Errorf("account_recovery.Get: %w", context.Canceled), false, 499, 1},
		{"sentinel wins over cancellation", fmt.Errorf("get: %w", store.ErrNotFound), true, 404, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, buf := captureLogger()
			ctx, cancel := context.WithCancel(t.Context())
			if tt.cancelled {
				cancel()
			}
			defer cancel()

			err := passkeyErr(ctx, ServerDeps{Log: log}, "begin registration", tt.err)

			se, ok := errors.AsType[huma.StatusError](err)
			if !ok {
				t.Fatalf("passkeyErr returned %v (%T), want a huma.StatusError", err, err)
			}
			if se.GetStatus() != tt.wantStatus {
				t.Errorf("status = %d, want %d", se.GetStatus(), tt.wantStatus)
			}
			if n := strings.Count(buf.String(), "\n"); n != tt.wantInfo {
				t.Fatalf("log lines = %d, want %d; log:\n%s", n, tt.wantInfo, buf)
			}
			if tt.wantInfo == 0 {
				return
			}
			if rec := logtest.Find(t, buf.String(), "begin registration cancelled"); rec["level"] != "INFO" {
				t.Errorf("level = %v, want INFO", rec["level"])
			}
			if se.Error() != "client closed request" {
				t.Errorf("message = %q, want %q", se.Error(), "client closed request")
			}
		})
	}
}
