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

// TestEnrollErr is a white-box test of the ConsumeCode error mapper (#9): an
// unusable code stays the uniform 401; a taken label is a 409 (a state the user
// created, not a bad code); a request that went away is 499, logged at Info;
// anything else is a logged 500. The order is part of the contract: a cancelled
// context must not turn a 401 or a 409 into a 499. The statuses are literals, so
// a changed constant fails here; enroll_errors_test.go covers the HTTP path.
func TestEnrollErr(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		cancelled  bool
		wantStatus int
		wantMsg    string
		wantLog    string // "" for no line
		wantLevel  string
	}{
		{"unknown, expired or used code", fmt.Errorf("service.ConsumeCode: %w", store.ErrNotFound), false, 401, errEnrollUnauthorized, "", ""},
		{"label already taken", fmt.Errorf("service.ConsumeCode: %w", store.ErrConflict), false, 409, "a device with that label already exists", "", ""},
		{"request went away", fmt.Errorf("enrollment_codes.Get: %w", context.Canceled), true, 499, "client closed request", "enroll device cancelled", "INFO"},
		{"unusable code stays 401 on a cancelled request", fmt.Errorf("service.ConsumeCode: %w", store.ErrNotFound), true, 401, errEnrollUnauthorized, "", ""},
		{"taken label stays 409 on a cancelled request", fmt.Errorf("service.ConsumeCode: %w", store.ErrConflict), true, 409, "a device with that label already exists", "", ""},
		{"store failure", errors.New("sql: database is closed"), false, 500, "failed to enroll device", "enroll device failed", "ERROR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, buf := captureLogger()
			ctx, cancel := context.WithCancel(t.Context())
			if tt.cancelled {
				cancel()
			}
			defer cancel()

			err := enrollErr(ctx, ServerDeps{Log: log}, tt.err)

			se, ok := errors.AsType[huma.StatusError](err)
			if !ok {
				t.Fatalf("enrollErr returned %v (%T), want a huma.StatusError", err, err)
			}
			if se.GetStatus() != tt.wantStatus || se.Error() != tt.wantMsg {
				t.Errorf("response = %d %q, want %d %q", se.GetStatus(), se.Error(), tt.wantStatus, tt.wantMsg)
			}
			if tt.wantLog == "" {
				if buf.Len() != 0 {
					t.Fatalf("logged, want nothing:\n%s", buf)
				}
				return
			}
			if n := strings.Count(buf.String(), "\n"); n != 1 {
				t.Fatalf("log lines = %d, want 1:\n%s", n, buf)
			}
			if rec := logtest.Find(t, buf.String(), tt.wantLog); rec["level"] != tt.wantLevel {
				t.Errorf("level = %v, want %s", rec["level"], tt.wantLevel)
			}
		})
	}
}

// TestEnrollErr_ShareTheLabelConflictTextWithDeviceMgmtErr: the enrollment and
// device-management 409s say one thing, from one constant.
func TestEnrollErr_ShareTheLabelConflictTextWithDeviceMgmtErr(t *testing.T) {
	log, _ := captureLogger()
	deps := ServerDeps{Log: log}

	enroll := enrollErr(t.Context(), deps, store.ErrConflict)
	manage := deviceMgmtErr(t.Context(), deps, "rename device", "u1", "d1", store.ErrConflict)

	for name, err := range map[string]error{"enrollErr": enroll, "deviceMgmtErr": manage} {
		se, ok := errors.AsType[huma.StatusError](err)
		if !ok || se.GetStatus() != 409 || se.Error() != "a device with that label already exists" {
			t.Errorf("%s = %v, want 409 %q", name, err, "a device with that label already exists")
		}
	}
}
