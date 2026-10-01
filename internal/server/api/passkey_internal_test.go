package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/store"
)

// recordsAt returns the JSON records in buf logged at level ("INFO", "ERROR").
func recordsAt(t *testing.T, buf *bytes.Buffer, level string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line not JSON: %v (%s)", err, line)
		}
		if rec["level"] == level {
			out = append(out, rec)
		}
	}
	return out
}

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
			info := recordsAt(t, buf, "INFO")
			if len(info) != tt.wantInfo {
				t.Fatalf("Info lines = %d, want %d; log:\n%s", len(info), tt.wantInfo, buf)
			}
			if tt.wantInfo == 1 && info[0]["msg"] != "begin registration cancelled" {
				t.Errorf("Info msg = %v, want %q", info[0]["msg"], "begin registration cancelled")
			}
			if tt.wantInfo == 1 && se.Error() != "client closed request" {
				t.Errorf("message = %q, want %q", se.Error(), "client closed request")
			}
			if errs := recordsAt(t, buf, "ERROR"); len(errs) != 0 {
				t.Errorf("Error lines = %v, want none", errs)
			}
		})
	}
}
