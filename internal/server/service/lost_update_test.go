package service

import (
	"errors"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// #182: the two callers that used to write a whole row read earlier in the
// request must not revert concurrent writes to other columns.

func TestApplyRole_DoesNotRevertConcurrentWrites(t *testing.T) {
	st, svc := newAdminSvc(t)
	ctx := t.Context()
	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "old@example.com", "user")
	if err := st.Users().SetEmail(ctx, target.ID, "new@example.com", store.NowUnix()); err != nil {
		t.Fatalf("SetEmail: %v", err)
	}
	if err := st.Users().SetDisabled(ctx, target.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}

	role := "admin"
	if err := svc.applyRole(ctx, admin.ID, target.ID, UpdateUserParams{Role: &role}); err != nil {
		t.Fatalf("applyRole: %v", err)
	}
	got, err := st.Users().GetByID(ctx, target.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Role != "admin" || got.Email != "new@example.com" || !got.Disabled {
		t.Errorf("after applyRole: role=%q email=%q disabled=%v, want admin/new@example.com/true (a disable must never be undone)", got.Role, got.Email, got.Disabled)
	}
}

func newLinkTestOIDCService(t *testing.T, st *store.Store) *OIDCService {
	t.Helper()
	sm := auth.NewSessionManager(st.Sessions(), st.Users(), time.Hour, time.Minute)
	return NewOIDCService(st, sm, config.OIDCCfg{AutoLinkByEmail: true, AllowOIDCSignup: true}, NewAuditWriter(st), discardLogger(),
		NewEmailChangeService(st, nil, "https://ddns.example.com", NewAuditWriter(st), discardLogger()))
}

func TestLinkExisting_RefusesWhenAddressMovedUnderIt(t *testing.T) {
	st := openTestStore(t)
	svc := newLinkTestOIDCService(t, st)
	ctx := t.Context()
	stale := seedUser(t, st, "old@example.com", "user") // the row the login matched
	if err := st.Users().SetEmail(ctx, stale.ID, "new@example.com", store.NowUnix()); err != nil {
		t.Fatalf("SetEmail: %v", err)
	}

	if _, err := svc.linkExisting(ctx, stale, "iss", "sub", "old@example.com", true); !errors.Is(err, ErrOIDCRejected) {
		t.Fatalf("linkExisting err = %v, want ErrOIDCRejected", err)
	}
	got, err := st.Users().GetByID(ctx, stale.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Email != "new@example.com" || got.OIDCSubject != "" {
		t.Errorf("refused link still wrote: email=%q oidc_subject=%q", got.Email, got.OIDCSubject)
	}
}

func TestLinkExisting_DoesNotUndoConcurrentDisable(t *testing.T) {
	st := openTestStore(t)
	svc := newLinkTestOIDCService(t, st)
	ctx := t.Context()
	stale := seedUser(t, st, "link@example.com", "user")
	if err := st.Users().SetDisabled(ctx, stale.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}

	if _, err := svc.linkExisting(ctx, stale, "iss", "sub", "link@example.com", true); err != nil {
		t.Fatalf("linkExisting: %v", err)
	}
	got, err := st.Users().GetByID(ctx, stale.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.Disabled {
		t.Error("linking an OIDC identity re-enabled a disabled account")
	}
	if got.OIDCSubject != "sub" {
		t.Errorf("OIDCSubject = %q, want sub", got.OIDCSubject)
	}
}

// TestLinkExisting_RefusesWhenPromotedToAdminUnderIt pins "never auto-link
// admins" against a race: linkExisting's guard reads the role from the row the
// login matched, so a promotion landing between that match and the link must
// make the link refuse, not auto-link a fresh admin by email claim.
func TestLinkExisting_RefusesWhenPromotedToAdminUnderIt(t *testing.T) {
	st := openTestStore(t)
	svc := newLinkTestOIDCService(t, st)
	ctx := t.Context()
	stale := seedUser(t, st, "promoted@example.com", "user") // matched as a plain user
	if err := st.Users().SetRole(ctx, stale.ID, "admin"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	_, err := svc.linkExisting(ctx, stale, "iss", "sub", "promoted@example.com", true)
	if !errors.Is(err, ErrOIDCRejected) {
		t.Fatalf("linkExisting err = %v, want ErrOIDCRejected (the account became an admin)", err)
	}
	got, err := st.Users().GetByID(ctx, stale.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.OIDCSubject != "" {
		t.Errorf("an admin was auto-linked: oidc_subject=%q", got.OIDCSubject)
	}
}
