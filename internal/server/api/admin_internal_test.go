package api

import (
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

	err := adminErr(t.Context(), deps, "create user", service.ErrWebAuthnUnavailable)

	se, ok := errors.AsType[huma.StatusError](err)
	if !ok {
		t.Fatalf("adminErr returned %v (%T), want a huma.StatusError", err, err)
	}
	if se.GetStatus() != 503 {
		t.Errorf("status = %d, want 503", se.GetStatus())
	}
}

// TestAdminErr_MapsErrEmailManagedByOIDC is a white-box test proving adminErr
// maps service.ErrEmailManagedByOIDC to 422 with adminGuardMessage's exact
// wording (#151). Unlike ErrEmailUnchanged, this case is not reachable via an
// HTTP round trip through PATCH /api/v1/admin/users/{id}/email today:
// EmailChangeService.AdminSet deliberately never returns it (design D3 — an
// admin's direct set intentionally bypasses the OIDC-managed guard that gates
// only the self-service path). The switch case is still added for parity
// with accountEmailErr and to keep adminErr correct if AdminSet's guards ever
// change; this test is its only coverage, mirroring
// TestAdminErr_MapsErrWebAuthnUnavailable's own white-box precedent above.
func TestAdminErr_MapsErrEmailManagedByOIDC(t *testing.T) {
	deps := ServerDeps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	err := adminErr(t.Context(), deps, "set user email", service.ErrEmailManagedByOIDC)

	se, ok := errors.AsType[huma.StatusError](err)
	if !ok {
		t.Fatalf("adminErr returned %v (%T), want a huma.StatusError", err, err)
	}
	if se.GetStatus() != 422 {
		t.Errorf("status = %d, want 422", se.GetStatus())
	}
	if se.Error() != "This account's email address is managed by its identity provider." {
		t.Errorf("message = %q, want the exact adminGuardMessage wording", se.Error())
	}
}
