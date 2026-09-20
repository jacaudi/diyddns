package webui

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// postForm and getPage are NOT defined here: endpoints_test.go:89 and :99 in
// this package already define them with these exact signatures --
//   postForm(t, h http.Handler, cookie *http.Cookie, path string, form url.Values) *httptest.ResponseRecorder
//   getPage(t, h http.Handler, cookie *http.Cookie, path string) *httptest.ResponseRecorder
// -- and this file reuses them. Redeclaring either fails the build.

// recordingMailer is an enabled email.Mailer that keeps every body, so a test
// can pull the confirmation token out of the mail the way a user would.
type recordingMailer struct {
	mu     sync.Mutex
	bodies []string
}

func (m *recordingMailer) Enabled() bool { return true }
func (m *recordingMailer) Send(_ context.Context, _, _, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bodies = append(m.bodies, body)
	return nil
}

var tokenRE = regexp.MustCompile(`token=([A-Za-z0-9_-]+)`)

// accountHarness is testDeps with email enabled and a recording mailer wired
// into a fresh EmailChangeService, plus a signed-in user and the handler.
func accountHarness(t *testing.T, email, role string) (http.Handler, *store.Store, Deps, store.User, *http.Cookie, *recordingMailer) {
	t.Helper()
	deps, st := testDeps(t)
	deps.Cfg.Email.Enabled = true
	mailer := &recordingMailer{}
	deps.EmailChange = service.NewEmailChangeService(st, mailer, deps.Cfg.Server.BaseURL, service.NewAuditWriter(st), deps.Log)
	h, _ := New(deps)
	usr := seedUser(t, st, email, role)
	cookie := signIn(t, deps, usr)
	return h, st, deps, usr, cookie, mailer
}

func TestAccount_EmailCard_States(t *testing.T) {
	t.Run("form when email is enabled", func(t *testing.T) {
		h, _, _, _, cookie, _ := accountHarness(t, "u@example.com", "user")
		body := getPage(t, h, cookie, "/account").Body.String()
		if !strings.Contains(body, `action="/account/email"`) || !strings.Contains(body, `name="email"`) {
			t.Errorf("account page missing the change form:\n%s", body)
		}
	})
	t.Run("no form when email is disabled", func(t *testing.T) {
		deps, st := testDeps(t)
		h, _ := New(deps)
		usr := seedUser(t, st, "u@example.com", "user")
		body := getPage(t, h, signIn(t, deps, usr), "/account").Body.String()
		if strings.Contains(body, `action="/account/email"`) || !strings.Contains(body, "Ask an administrator") {
			t.Errorf("email disabled: want the ask-an-administrator copy and no form:\n%s", body)
		}
	})
	t.Run("managed copy for an OIDC-linked account", func(t *testing.T) {
		deps, st := testDeps(t)
		deps.Cfg.Email.Enabled = true
		h, _ := New(deps)
		usr, err := st.Users().Create(t.Context(), store.User{Email: "o@example.com", Role: "user", OIDCProvider: "https://idp.example.com", OIDCSubject: "s1"})
		if err != nil {
			t.Fatal(err)
		}
		body := getPage(t, h, signIn(t, deps, usr), "/account").Body.String()
		if strings.Contains(body, `action="/account/email"`) || !strings.Contains(body, "identity provider") {
			t.Errorf("OIDC-linked: want the managed copy and no form:\n%s", body)
		}
	})
	t.Run("pending card with cancel", func(t *testing.T) {
		h, st, _, usr, cookie, _ := accountHarness(t, "u@example.com", "user")
		if err := st.Users().SetPendingEmail(t.Context(), usr.ID, "next@example.com", "h", store.NowUnix()+3600); err != nil {
			t.Fatal(err)
		}
		body := getPage(t, h, cookie, "/account").Body.String()
		if !strings.Contains(body, "next@example.com") || !strings.Contains(body, "waiting for confirmation") || !strings.Contains(body, `action="/account/email/cancel"`) {
			t.Errorf("pending: want the notice naming next@example.com and a cancel form:\n%s", body)
		}
		if strings.Contains(body, `action="/account/email">`) {
			t.Errorf("pending: the request form must be hidden:\n%s", body)
		}
	})
}

// TestAccount_RoleIndicator: #146. The role information the userchip used to
// carry (as an inline badge on every page) now lives on /account instead,
// which previously showed no role information at all.
func TestAccount_RoleIndicator(t *testing.T) {
	// "Role: " is the new indicator's own label text -- distinct from the
	// bare role-badge <span> app.html's userchip used to carry before #146
	// moved it here, so this can't pass by accidentally matching a leftover
	// badge the account page still shares the app shell with.
	t.Run("admin sees the admin role", func(t *testing.T) {
		h, _, _, _, cookie, _ := accountHarness(t, "a@example.com", "admin")
		body := getPage(t, h, cookie, "/account").Body.String()
		if !strings.Contains(body, `Role: <span class="tag accent role-badge">admin</span>`) {
			t.Errorf("account page missing the admin role indicator:\n%s", body)
		}
	})
	t.Run("a regular user sees the user role, not admin", func(t *testing.T) {
		h, _, _, _, cookie, _ := accountHarness(t, "u@example.com", "user")
		body := getPage(t, h, cookie, "/account").Body.String()
		if !strings.Contains(body, `Role: <span class="tag neutral role-badge">user</span>`) {
			t.Errorf("account page missing the user role indicator:\n%s", body)
		}
		if strings.Contains(body, `role-badge">admin<`) {
			t.Errorf("a non-admin was shown the admin role indicator:\n%s", body)
		}
	})
}

func TestAccountEmail_Request(t *testing.T) {
	t.Run("redirects and the page shows the pending change", func(t *testing.T) {
		h, st, deps, usr, cookie, mailer := accountHarness(t, "u@example.com", "user")
		sess := sessionFor(t, deps, cookie)
		rec := postForm(t, h, cookie, "/account/email", url.Values{"csrf": {sess.CSRFToken}, "email": {"  next@example.com "}})
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account" {
			t.Fatalf("status = %d, Location = %q; want 303 to /account; body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
		}
		if got, _ := st.Users().GetByID(t.Context(), usr.ID); got.PendingEmail != "next@example.com" {
			t.Errorf("PendingEmail = %q, want next@example.com", got.PendingEmail)
		}
		if len(mailer.bodies) != 2 {
			t.Errorf("sent %d mails, want 2", len(mailer.bodies))
		}
		body := getPage(t, h, cookie, "/account").Body.String()
		if !strings.Contains(body, "waiting for confirmation") {
			t.Errorf("account page after request lacks the pending notice:\n%s", body)
		}
	})
	t.Run("invalid address re-renders the account page at 422", func(t *testing.T) {
		h, _, deps, _, cookie, _ := accountHarness(t, "u@example.com", "user")
		sess := sessionFor(t, deps, cookie)
		rec := postForm(t, h, cookie, "/account/email", url.Values{"csrf": {sess.CSRFToken}, "email": {"nope"}})
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "plain 7-bit ASCII") {
			t.Errorf("status = %d, want 422 with the invalid-email copy; body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("same address is 422", func(t *testing.T) {
		h, _, deps, _, cookie, _ := accountHarness(t, "u@example.com", "user")
		sess := sessionFor(t, deps, cookie)
		rec := postForm(t, h, cookie, "/account/email", url.Values{"csrf": {sess.CSRFToken}, "email": {"U@example.com"}})
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "already the account") {
			t.Errorf("status = %d, want 422 with the unchanged copy; body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("email disabled is 503", func(t *testing.T) {
		deps, st := testDeps(t)
		deps.EmailChange = service.NewEmailChangeService(st, nil, deps.Cfg.Server.BaseURL, service.NewAuditWriter(st), deps.Log)
		h, _ := New(deps)
		usr := seedUser(t, st, "u@example.com", "user")
		cookie := signIn(t, deps, usr)
		sess := sessionFor(t, deps, cookie)
		rec := postForm(t, h, cookie, "/account/email", url.Values{"csrf": {sess.CSRFToken}, "email": {"next@example.com"}})
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestAccountEmail_EveryPostNeedsCSRF(t *testing.T) {
	h, _, _, _, cookie, _ := accountHarness(t, "u@example.com", "user")
	for _, path := range []string{"/account/email", "/account/email/cancel", "/account/email/confirm"} {
		if rec := postForm(t, h, cookie, path, url.Values{"email": {"x@example.com"}, "token": {"t"}}); rec.Code != http.StatusForbidden {
			t.Errorf("%s without csrf: status = %d, want 403", path, rec.Code)
		}
	}
}

func TestAccountEmail_Cancel(t *testing.T) {
	h, st, deps, usr, cookie, _ := accountHarness(t, "u@example.com", "user")
	sess := sessionFor(t, deps, cookie)
	if err := st.Users().SetPendingEmail(t.Context(), usr.ID, "next@example.com", "h", store.NowUnix()+3600); err != nil {
		t.Fatal(err)
	}
	rec := postForm(t, h, cookie, "/account/email/cancel", url.Values{"csrf": {sess.CSRFToken}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if got, _ := st.Users().GetByID(t.Context(), usr.ID); got.PendingEmail != "" {
		t.Errorf("PendingEmail = %q after cancel", got.PendingEmail)
	}
	if body := getPage(t, h, cookie, "/account").Body.String(); !strings.Contains(body, `action="/account/email"`) {
		t.Errorf("form did not come back after cancel:\n%s", body)
	}
}

func TestAccountEmail_ConfirmGET(t *testing.T) {
	h, st, _, usr, cookie, _ := accountHarness(t, "u@example.com", "user")
	if rec := getPage(t, h, cookie, "/account/email/confirm?token=abc"); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("nothing pending: status = %d, want 422", rec.Code)
	}
	if err := st.Users().SetPendingEmail(t.Context(), usr.ID, "next@example.com", "h", store.NowUnix()+3600); err != nil {
		t.Fatal(err)
	}
	if rec := getPage(t, h, cookie, "/account/email/confirm"); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("missing token: status = %d, want 422", rec.Code)
	}
	rec := getPage(t, h, cookie, "/account/email/confirm?token=abc")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `name="token" value="abc"`) || !strings.Contains(body, "next@example.com") || !strings.Contains(body, `action="/account/email/confirm"`) {
		t.Errorf("pending + token: status = %d, want 200 with the hidden token and a confirm form:\n%s", rec.Code, body)
	}
	if got, _ := st.Users().GetByID(t.Context(), usr.ID); got.Email != "u@example.com" || got.PendingEmail != "next@example.com" {
		t.Errorf("GET changed state: %+v", got)
	}
}

func TestAccountEmail_ConfirmPOST(t *testing.T) {
	h, st, deps, usr, cookie, mailer := accountHarness(t, "u@example.com", "user")
	sess := sessionFor(t, deps, cookie)
	if rec := postForm(t, h, cookie, "/account/email", url.Values{"csrf": {sess.CSRFToken}, "email": {"next@example.com"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("request: status = %d", rec.Code)
	}
	m := tokenRE.FindStringSubmatch(mailer.bodies[0])
	if m == nil {
		t.Fatalf("no token in the confirmation mail: %q", mailer.bodies[0])
	}
	token := m[1]

	rec := postForm(t, h, cookie, "/account/email/confirm", url.Values{"csrf": {sess.CSRFToken}, "token": {"wrong"}})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "invalid or has expired") {
		t.Errorf("wrong token: status = %d, want 422 on the account page; body=%s", rec.Code, rec.Body.String())
	}
	if got, _ := st.Users().GetByID(t.Context(), usr.ID); got.Email != "u@example.com" {
		t.Fatalf("wrong token changed the address to %q", got.Email)
	}

	rec = postForm(t, h, cookie, "/account/email/confirm", url.Values{"csrf": {sess.CSRFToken}, "token": {token}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account" {
		t.Fatalf("right token: status = %d, Location = %q; want 303 to /account; body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	body := getPage(t, h, cookie, "/account").Body.String()
	if !strings.Contains(body, "next@example.com") || strings.Contains(body, "waiting for confirmation") {
		t.Errorf("after confirm: want the new address in the page and no pending notice:\n%s", body)
	}
}
