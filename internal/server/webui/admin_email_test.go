package webui

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

func TestAdminUserEmail_SetsImmediatelyAndShowsNotice(t *testing.T) {
	deps, st := testDeps(t)
	mailer := &recordingMailer{}
	deps.EmailChange = service.NewEmailChangeService(st, mailer, deps.Cfg.Server.BaseURL, service.NewAuditWriter(st), deps.Log)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "old@example.com", "user")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	rec := postForm(t, h, cookie, "/admin/users/"+target.ID+"/email", url.Values{"csrf": {sess.CSRFToken}, "email": {"new@example.com"}})
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (rendered in-response so the notice can show); body=%s", rec.Code, body)
	}
	if !strings.Contains(body, "Address changed. The previous address was notified.") || !strings.Contains(body, "issue a recovery link below") {
		t.Errorf("notice missing or wrong:\n%s", body)
	}
	if !strings.Contains(body, "<h1>new@example.com</h1>") {
		t.Errorf("page heading still shows the old address:\n%s", body)
	}
	if got, _ := st.Users().GetByID(t.Context(), target.ID); got.Email != "new@example.com" {
		t.Errorf("persisted Email = %q, want new@example.com", got.Email)
	}
	if len(mailer.bodies) != 1 || !strings.Contains(mailer.bodies[0], "administrator") {
		t.Errorf("mails = %q, want one admin changed notice", mailer.bodies)
	}
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "user.email_changed_by_admin"}, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0].ActorUserID != admin.ID {
		t.Errorf("audit rows = %+v, want one by the admin", page.Rows)
	}
}

func TestAdminUserEmail_NoMailerNoticeIsHonest(t *testing.T) {
	deps, st := testDeps(t)
	deps.EmailChange = service.NewEmailChangeService(st, nil, deps.Cfg.Server.BaseURL, service.NewAuditWriter(st), deps.Log)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "old@example.com", "user")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	rec := postForm(t, h, cookie, "/admin/users/"+target.ID+"/email", url.Values{"csrf": {sess.CSRFToken}, "email": {"new@example.com"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Email is not configured, so the previous address was not notified.") {
		t.Errorf("status = %d, want 200 with the not-configured notice; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminUserEmail_SendFailureNoticeIsHonest(t *testing.T) {
	deps, st := testDeps(t)
	deps.EmailChange = service.NewEmailChangeService(st, stubMailer{enabled: true, err: errors.New("smtp exploded")}, deps.Cfg.Server.BaseURL, service.NewAuditWriter(st), deps.Log)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "old@example.com", "user")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	rec := postForm(t, h, cookie, "/admin/users/"+target.ID+"/email", url.Values{"csrf": {sess.CSRFToken}, "email": {"new@example.com"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "could not be sent") {
		t.Errorf("status = %d, want 200 with the could-not-be-sent notice; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminUserEmail_Guards(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "old@example.com", "user")
	seedUser(t, st, "taken@example.com", "user")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	for _, tc := range []struct{ in, want string }{
		{"nope", "plain 7-bit ASCII"},
		{"OLD@example.com", "already the account"},
		{"Taken@example.com", "already exists"},
	} {
		rec := postForm(t, h, cookie, "/admin/users/"+target.ID+"/email", url.Values{"csrf": {sess.CSRFToken}, "email": {tc.in}})
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%q: status = %d, want 422 containing %q; body=%s", tc.in, rec.Code, tc.want, rec.Body.String())
		}
	}
	if got, _ := st.Users().GetByID(t.Context(), target.ID); got.Email != "old@example.com" {
		t.Errorf("a rejected set changed the address to %q", got.Email)
	}
	if rec := postForm(t, h, cookie, "/admin/users/"+target.ID+"/email", url.Values{"email": {"x@example.com"}}); rec.Code != http.StatusForbidden {
		t.Errorf("without csrf: status = %d, want 403", rec.Code)
	}
	if rec := postForm(t, h, cookie, "/admin/users/no-such-id/email", url.Values{"csrf": {sess.CSRFToken}, "email": {"x@example.com"}}); rec.Code != http.StatusNotFound {
		t.Errorf("unknown target: status = %d, want 404", rec.Code)
	}
}

func TestAdminUserEmail_PageShowsCardAndOIDCWarning(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	local := seedUser(t, st, "local@example.com", "user")
	linked, err := st.Users().Create(t.Context(), store.User{Email: "linked@example.com", Role: "user", OIDCProvider: "https://idp.example.com", OIDCSubject: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	cookie := signIn(t, deps, admin)

	body := getPage(t, h, cookie, "/admin/users/"+local.ID).Body.String()
	if !strings.Contains(body, `action="/admin/users/`+local.ID+`/email"`) || !strings.Contains(body, `value="local@example.com"`) {
		t.Errorf("local user page lacks the email form:\n%s", body)
	}
	if strings.Contains(body, "identity provider") {
		t.Errorf("local user page carries the OIDC warning:\n%s", body)
	}
	body = getPage(t, h, cookie, "/admin/users/"+linked.ID).Body.String()
	if !strings.Contains(body, "identity provider") || !strings.Contains(body, `action="/admin/users/`+linked.ID+`/email"`) {
		t.Errorf("linked user page: want the form AND the OIDC warning:\n%s", body)
	}
}

func TestNoticeNote(t *testing.T) {
	for name, tc := range map[string]struct {
		d    service.Delivery
		want string
	}{
		"sent":       {service.Delivery{Attempted: true, To: "old@example.com"}, "The previous address was notified."},
		"no mailer":  {service.Delivery{}, "Email is not configured, so the previous address was not notified."},
		"failed":     {service.Delivery{Attempted: true, To: "old@example.com", Err: errors.New("x")}, "could not be sent"},
		"suppressed": {service.Delivery{Suppressed: service.SuppressUserDisabled}, "No notice was sent"},
	} {
		if got := noticeNote(tc.d); !strings.Contains(got, tc.want) {
			t.Errorf("%s: noticeNote = %q, want to contain %q", name, got, tc.want)
		}
	}
}
