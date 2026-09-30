package webui

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// seedGrant gives userID a live registration grant.
func seedGrant(t *testing.T, st *store.Store, userID, hash, reason string, expiresAt int64) {
	t.Helper()
	if err := st.AccountRecovery().Create(t.Context(), store.RecoveryToken{
		TokenHash: hash, UserID: userID, Reason: reason, ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}

// TestAdminUsers_RegistrationColumn covers #177 on the list: one tag per
// status, and "—" rather than "Passkey" in the Auth column for an account
// that cannot sign in yet.
//
// Deliberately not t.Parallel() — see TestAdminUserRecovery_RequiresTypedConfirmation.
func TestAdminUsers_RegistrationColumn(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	seedPasskey(t, st, admin.ID, "admin key")
	invited := seedUser(t, st, "invited@example.com", "user")
	seedGrant(t, st, invited.ID, "h-inv", "invite", store.NowUnix()+600)
	pending := seedUser(t, st, "pending@example.com", "user")
	seedGrant(t, st, pending.ID, "h-rec", "recovery", store.NowUnix()+600)
	seedUser(t, st, "lapsed@example.com", "user")

	rec := getPage(t, h, signIn(t, deps, admin), "/admin/users")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"<th>Registration</th>",
		`<span class="tag ok">Registered</span>`,
		`<span class="tag neutral">Invited</span>`,
		`<span class="tag warn">Recovery pending</span>`,
		`<span class="tag danger">Link expired</span>`,
		`<span class="muted">—</span>`,
		`<span class="muted">Passkey</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("users list missing %q", want)
		}
	}
}

// TestAdminUserEdit_HeaderStatesRegistration covers #177 on the detail page.
//
// Deliberately not t.Parallel() — see TestAdminUserRecovery_RequiresTypedConfirmation.
func TestAdminUserEdit_HeaderStatesRegistration(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	cookie := signIn(t, deps, admin)

	registered := seedUser(t, st, "registered@example.com", "user")
	seedPasskey(t, st, registered.ID, "k")
	invited := seedUser(t, st, "invited@example.com", "user")
	seedGrant(t, st, invited.ID, "h-inv", "invite", store.NowUnix()+600)
	pending := seedUser(t, st, "pending@example.com", "user")
	seedGrant(t, st, pending.ID, "h-rec", "recovery", store.NowUnix()+600)
	lapsed := seedUser(t, st, "lapsed@example.com", "user")

	cases := []struct {
		id, want string
	}{
		{registered.ID, "user · active · registered</p>"},
		{invited.ID, "user · active · invited, link expires in 10 minutes</p>"},
		{pending.ID, "user · active · recovery pending, link expires in 10 minutes</p>"},
		{lapsed.ID, "user · active · no live registration link</p>"},
	}
	for _, c := range cases {
		rec := getPage(t, h, cookie, "/admin/users/"+c.id)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d for %s", rec.Code, c.id)
		}
		if body := rec.Body.String(); !strings.Contains(body, c.want) {
			t.Errorf("header for %s missing %q", c.id, c.want)
		}
	}
}
