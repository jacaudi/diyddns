package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/server/service"
)

// TestAdminErr_MapsErrWebAuthnUnavailable is a white-box test (package api)
// proving adminErr maps service.ErrWebAuthnUnavailable to 503 — reachable
// via both POST /api/v1/admin/users (CreateUserInvite) and POST
// /api/v1/admin/users/{id}/recovery (IssueRecovery) when WebAuthn isn't
// configured. Before this fix the error fell through adminErr's default
// case to a generic 500, obscuring a client-actionable "not configured"
// condition behind an "unexpected error" response.
func TestAdminErr_MapsErrWebAuthnUnavailable(t *testing.T) {
	deps := ServerDeps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	err := adminErr(context.Background(), deps, "create user", service.ErrWebAuthnUnavailable)

	var se huma.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("adminErr returned %v (%T), want a huma.StatusError", err, err)
	}
	if se.GetStatus() != 503 {
		t.Errorf("status = %d, want 503", se.GetStatus())
	}
}
