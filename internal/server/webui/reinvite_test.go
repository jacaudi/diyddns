package webui

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// Deliberately not t.Parallel() in this file — see
// TestAdminUserRecovery_RequiresTypedConfirmation.

func TestAdminUserEdit_RegistrationCardOnlyForUnregistered(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	cookie := signIn(t, deps, admin)
	pending := seedUser(t, st, "pending@example.com", "user")
	registered := seedUser(t, st, "registered@example.com", "user")
	seedPasskey(t, st, registered.ID, "k")

	body := getPage(t, h, cookie, "/admin/users/"+pending.ID).Body.String()
	if !strings.Contains(body, `action="/admin/users/`+pending.ID+`/invite"`) {
		t.Error("unregistered account: Registration card (send a new link) missing")
	}
	if strings.Contains(body, `action="/admin/users/`+pending.ID+`/recovery"`) {
		t.Error("unregistered account: danger-zone recovery offered, want it hidden (D11)")
	}

	body = getPage(t, h, cookie, "/admin/users/"+registered.ID).Body.String()
	if strings.Contains(body, `action="/admin/users/`+registered.ID+`/invite"`) {
		t.Error("registered account: Registration card rendered, want it hidden (D7)")
	}
	if !strings.Contains(body, `action="/admin/users/`+registered.ID+`/recovery"`) {
		t.Error("registered account: danger-zone recovery missing")
	}
}

func TestAdminUserReinvite_RevealsNewLinkAndKillsOldOne(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)
	pending := seedUser(t, st, "pending@example.com", "user")
	seedGrant(t, st, pending.ID, "h-old", "invite", store.NowUnix()+600)

	rec := postForm(t, h, cookie, "/admin/users/"+pending.ID+"/invite", url.Values{"csrf": {sess.CSRFToken}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"New registration link — shown once",
		"https://ddns.test/register?token=",
		"Earlier links for this account no longer work.",
		"It expires in 15 minutes and can be used once.",
		"Sending another link cancels this one.",
		"invited, link expires in",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("reveal missing %q", want)
		}
	}
	if strings.Contains(body, "has been revoked") {
		t.Error("invite reveal shows the recovery warning")
	}
	if _, err := st.AccountRecovery().Get(t.Context(), "h-old"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("old grant: err = %v, want ErrNotFound (deleted)", err)
	}
}

func TestAdminUserReinvite_RegisteredAccountIs422(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)
	registered := seedUser(t, st, "registered@example.com", "user")
	seedPasskey(t, st, registered.ID, "k")

	rec := postForm(t, h, cookie, "/admin/users/"+registered.ID+"/invite", url.Values{"csrf": {sess.CSRFToken}})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "This account has already registered.") {
		t.Error("422 page does not explain why")
	}
}

func TestAdminUserReinvite_RequiresCSRF(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	cookie := signIn(t, deps, admin)
	pending := seedUser(t, st, "pending@example.com", "user")

	rec := postForm(t, h, cookie, "/admin/users/"+pending.ID+"/invite", url.Values{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 without a CSRF token", rec.Code)
	}
}

// TestAdminUserError_404HidesRegistrationCard covers HideActions: when the
// target vanished between page render and submit, the error page must not
// offer an action on it.
func TestAdminUserError_404HidesRegistrationCard(t *testing.T) {
	deps, st := testDeps(t)
	h := newTestHandler(t, deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	gone := store.User{ID: "vanished-id", Email: "gone@example.com", Role: "user"}
	sess := sessionFor(t, deps, signIn(t, deps, admin))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/users/vanished-id/invite", nil)
	h.renderAdminUserError(rec, req, admin, sess, gone, http.StatusNotFound, "That user no longer exists.")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `/invite"`) {
		t.Error("404 page for a vanished user still offers the Registration card")
	}
}
