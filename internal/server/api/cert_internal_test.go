package api

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/store"
)

// TestCertErr_UnknownDeviceCarriesTheChallenge: a device deleted after its HMAC
// verified is a 401, and every 401 carries a challenge (RFC 9110 §15.5.2, #191).
// The route is HMAC-signed, so the challenge is the HMAC one, written out here
// so a changed constant fails this test.
func TestCertErr_UnknownDeviceCarriesTheChallenge(t *testing.T) {
	err := certErr(context.Background(), ServerDeps{}, "dev-1", fmt.Errorf("issue: %w", store.ErrNotFound))

	se, ok := errors.AsType[huma.StatusError](err)
	if !ok || se.GetStatus() != 401 {
		t.Fatalf("certErr = %v, want a 401 status error", err)
	}
	he, ok := errors.AsType[huma.HeadersError](err)
	if !ok {
		t.Fatalf("certErr = %v, want an error carrying headers", err)
	}
	if got, want := he.GetHeaders().Get("WWW-Authenticate"), `DIYDDNS-HMAC realm="diyddns"`; got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}
