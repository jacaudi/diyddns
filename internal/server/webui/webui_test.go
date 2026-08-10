package webui

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

// fakeInvalidator satisfies service.SecretCacheInvalidator. The real
// implementation is *auth.Verifier, whose cache these tests never exercise.
type fakeInvalidator struct{ invalidated []string }

func (f *fakeInvalidator) Invalidate(deviceID string) {
	f.invalidated = append(f.invalidated, deviceID)
}

// testDeps builds a fully-wired Deps over an in-memory store, and returns the
// store so tests can seed users and devices directly.
//
// PasskeyService is REAL, not nil. That matters: AdminService.CreateUserInvite
// and GrantService.IssueRecovery both return ErrWebAuthnUnavailable when it is
// nil (service/admin.go:96, service/grants.go:122), so a nil fixture would make
// the invite reveal, the recovery reveal, and grantLink's base-URL handling
// permanently untestable — including the revoke-then-mint path the typed
// confirmation exists to protect.
func testDeps(t *testing.T) (Deps, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	sessions := auth.NewSessionManager(st.Sessions(), st.Users(), time.Hour, time.Hour)
	log := slog.New(slog.DiscardHandler)

	cfg := config.Server{}
	cfg.Auth.Session.CookieName = "diyddns_session"
	cfg.Server.BaseURL = "https://ddns.test"

	// A 32-byte AEAD key. auth.SealSecret requires exactly 32 bytes; the value
	// is arbitrary and is not a secret.
	key := bytes.Repeat([]byte{0x24}, 32)

	audit := service.NewAuditWriter(st)
	passkeys, err := service.NewPasskeyService(st, sessions, key, cfg.Auth.WebAuthn, "localhost", "http://localhost", audit)
	if err != nil {
		t.Fatalf("NewPasskeyService: %v", err)
	}
	grants := service.NewGrantService(st, passkeys, nil, cfg.Server.BaseURL, audit, log)

	return Deps{
		Sessions:  sessions,
		Cfg:       cfg,
		Log:       log,
		Devices:   service.NewDeviceService(st, key, &fakeInvalidator{}, audit),
		Enroll:    service.NewEnrollmentService(st, key, 15*time.Minute, audit),
		Admin:     service.NewAdminService(st, audit, grants),
		Grants:    grants,
		Info:      version.Info{Version: "test", Commit: "abc1234", Date: "2026-08-07"},
		StartedAt: time.Now().Add(-2 * time.Hour),
	}, st
}

// TestTestDeps_GrantsAndAdminAreFunctional proves testDeps wires a REAL
// PasskeyService into Grants and Admin, not a nil one. CreateUserInvite and
// IssueRecovery both return ErrWebAuthnUnavailable when PasskeyService is
// nil (service/admin.go:96-97, service/grants.go:122-123) — a nil fixture
// would make the invite and recovery flows, the two most destructive paths
// in the product, permanently untestable while every other test stayed
// green. This is a behavioral test, not a compile check: it fails today
// because testDeps has no Admin/Grants fields at all.
func TestTestDeps_GrantsAndAdminAreFunctional(t *testing.T) {
	deps, _ := testDeps(t)

	usr, link, err := deps.Admin.CreateUserInvite(context.Background(), "actor-id", "invitee@example.com", "user")
	if err != nil {
		t.Fatalf("CreateUserInvite: %v (a nil PasskeyService fails here with ErrWebAuthnUnavailable)", err)
	}
	if link == "" {
		t.Error("CreateUserInvite: empty invite link")
	}

	if link, err := deps.Grants.IssueRecovery(context.Background(), "actor-id", usr.ID); err != nil {
		t.Fatalf("IssueRecovery: %v (a nil PasskeyService fails here with ErrWebAuthnUnavailable)", err)
	} else if link == "" {
		t.Error("IssueRecovery: empty recovery link")
	}
}

// seedSessionCookie creates a user and a session for it, returning an
// http.Cookie a test can attach to a request to authenticate as that user.
func seedSessionCookie(t *testing.T, st *store.Store, sm *auth.SessionManager, email string) (*http.Cookie, store.Session) {
	t.Helper()
	usr, err := st.Users().Create(context.Background(), store.User{Email: email, Role: "user"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	sess, err := sm.Create(context.Background(), usr.ID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("session create: %v", err)
	}
	return &http.Cookie{Name: "diyddns_session", Value: sess.ID}, sess
}

func TestHandleLogin_RendersPasskeyButton(t *testing.T) {
	deps, _ := testDeps(t)
	h, _ := New(deps)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `id="passkey-login"`) {
		t.Errorf("body missing passkey login button:\n%s", body)
	}
}

func TestHandleLogin_HideLocalLoginUI_OmitsPasskeyButOIDCShown(t *testing.T) {
	deps, _ := testDeps(t)
	deps.Cfg.Auth.HideLocalLoginUI = true
	deps.Cfg.Auth.OIDC.Enabled = true
	h, _ := New(deps)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, `id="passkey-login"`) {
		t.Errorf("body should omit passkey login button under hide_local_login_ui:\n%s", body)
	}
	if !strings.Contains(body, "/api/v1/auth/oidc/start") {
		t.Errorf("body missing OIDC sign-in link:\n%s", body)
	}
}

func TestHandleAccount_NoSession_RedirectsToLogin(t *testing.T) {
	deps, _ := testDeps(t)
	h, _ := New(deps)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}

func TestHandleAccount_ValidSession_Renders200(t *testing.T) {
	deps, st := testDeps(t)
	cookie, _ := seedSessionCookie(t, st, deps.Sessions, "user@example.com")
	h, _ := New(deps)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "user@example.com") {
		t.Errorf("body missing account email:\n%s", rec.Body.String())
	}
}

func TestAuthenticateBrowser_ValidCookie_ReturnsUser(t *testing.T) {
	deps, st := testDeps(t)
	cookie, wantSess := seedSessionCookie(t, st, deps.Sessions, "auth@example.com")

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.AddCookie(cookie)

	usr, sess, err := authenticateBrowser(deps.Sessions, req, deps.Cfg.Auth.Session.CookieName)
	if err != nil {
		t.Fatalf("authenticateBrowser: %v", err)
	}
	if usr.Email != "auth@example.com" {
		t.Errorf("Email = %q, want auth@example.com", usr.Email)
	}
	if sess.ID != wantSess.ID {
		t.Errorf("session ID = %q, want %q", sess.ID, wantSess.ID)
	}
}

func TestAuthenticateBrowser_MissingCookie_ReturnsError(t *testing.T) {
	deps, _ := testDeps(t)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	if _, _, err := authenticateBrowser(deps.Sessions, req, deps.Cfg.Auth.Session.CookieName); err == nil {
		t.Fatal("authenticateBrowser: want error for missing cookie, got nil")
	}
}

func TestAuthenticateBrowser_InvalidCookie_ReturnsError(t *testing.T) {
	deps, _ := testDeps(t)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.AddCookie(&http.Cookie{Name: "diyddns_session", Value: "not-a-real-session"})
	if _, _, err := authenticateBrowser(deps.Sessions, req, deps.Cfg.Auth.Session.CookieName); err == nil {
		t.Fatal("authenticateBrowser: want error for invalid cookie, got nil")
	}
}

func TestHandleLogin_RecoveryForm_HasHiddenCSRFField(t *testing.T) {
	deps, _ := testDeps(t)
	deps.Cfg.Email.Enabled = true
	h, _ := New(deps)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `id="recover-form"`) {
		t.Fatalf("body missing recovery form:\n%s", body)
	}
	if !strings.Contains(body, `type="hidden" name="csrf"`) {
		t.Errorf("recovery form missing hidden csrf field:\n%s", body)
	}
}

func TestHandleRegister_Renders200_WithTokenFromQuery(t *testing.T) {
	deps, _ := testDeps(t)
	h, _ := New(deps)

	req := httptest.NewRequest(http.MethodGet, "/register?token=abc123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "abc123") {
		t.Errorf("body missing token from query param:\n%s", rec.Body.String())
	}
}

func TestStaticAssets_ServedUnderStaticPrefix(t *testing.T) {
	deps, _ := testDeps(t)
	h, _ := New(deps)

	for _, path := range []string{"/static/app.css", "/static/passkey.js"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200", path, rec.Code)
		}
		if b, _ := io.ReadAll(rec.Body); len(b) == 0 {
			t.Errorf("GET %s: empty body", path)
		}
	}
}

// TestAppCSS_BrandRuleIsScopedToTopbar guards against the app-shell .brand
// rule leaking into the auth shell. Both layout.html (login/register) and
// app.html render an element with class="brand"; mock.css deliberately keeps
// these namespaces separate — .brand for the app shell, .auth-brand for the
// auth shell — so a second bare ".brand { ... }" rule in app.css would sit at
// equal specificity with the auth shell's and win any shared property by
// source order, silently drifting /login and /register's styling. The
// app-shell rule must read ".topbar .brand" instead.
func TestAppCSS_BrandRuleIsScopedToTopbar(t *testing.T) {
	css, err := staticFS.ReadFile("static/app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}
	bareBrand := regexp.MustCompile(`(?m)^\.brand\s*\{`)
	if matches := bareBrand.FindAll(css, -1); len(matches) != 1 {
		t.Errorf("app.css has %d unscoped \".brand {\" rules, want 1 (the auth shell's only); "+
			"the app-shell rule must be scoped as \".topbar .brand\" so it cannot leak into /login and /register",
			len(matches))
	}
}

// TestAccount_RendersInAppShell asserts /account carries the app chrome, so the
// authenticated pages share one navigation rather than the narrow auth shell.
//
// Deliberately not t.Parallel(): testDeps calls store.Open, and store.Migrate
// (internal/store/migrate.go) mutates goose's package-level globals with no
// synchronization, so concurrent store opens race under -race.
func TestAccount_RendersInAppShell(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)

	usr := seedUser(t, st, "jane@example.com", "user")
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.AddCookie(signIn(t, deps, usr))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	for _, want := range []string{`class="topbar"`, `href="/devices"`, "jane@example.com", "JA"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if strings.Contains(body, `href="/admin/users"`) {
		t.Error("a non-admin was shown the admin nav")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}

// TestAppShell_ShowsAdminNavToAdmins is the positive half of the check above.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestAppShell_ShowsAdminNavToAdmins(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)

	usr := seedUser(t, st, "admin@example.com", "admin")
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.AddCookie(signIn(t, deps, usr))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	for _, want := range []string{`href="/admin/users"`, `href="/admin/audit"`, `href="/admin/server"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("admin nav missing %q", want)
		}
	}
}

// TestRoot_RedirectsBySession replaces TestRoot_RedirectsInsteadOf404: the root
// now branches on whether a session is present.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell. Its own
// subtests stay t.Parallel(): they share the one store opened above rather
// than calling testDeps themselves, so they don't race on goose's globals.
func TestRoot_RedirectsBySession(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)

	t.Run("anonymous goes to login", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
		}
		if got := rec.Header().Get("Location"); got != "/login" {
			t.Errorf("Location = %q, want %q", got, "/login")
		}
	})

	t.Run("signed in goes to devices", func(t *testing.T) {
		t.Parallel()
		usr := seedUser(t, st, "root@example.com", "user")
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(signIn(t, deps, usr))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Location"); got != "/devices" {
			t.Errorf("Location = %q, want %q", got, "/devices")
		}
	})

	t.Run("unknown paths still 404", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/no-such-page", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET /no-such-page = %d, want 404 (root must not be a catch-all)", rec.Code)
		}
	})
}

// newTestHandler builds the unexported handler directly, so guard behaviour can
// be tested without routing a request through the mux.
func newTestHandler(t *testing.T, deps Deps) *handler {
	t.Helper()
	return &handler{pages: parsePages(), deps: deps}
}

// seedUser inserts a user with the given email and role.
func seedUser(t *testing.T, st *store.Store, email, role string) store.User {
	t.Helper()
	u, err := st.Users().Create(t.Context(), store.User{Email: email, Role: role})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

// signIn mints a real session for usr and returns the cookie a browser would
// send. It goes through the real SessionManager rather than hand-writing a
// session row, so these tests stay honest about the cookie and CSRF contract.
func signIn(t *testing.T, deps Deps, usr store.User) *http.Cookie {
	t.Helper()
	sess, err := deps.Sessions.Create(t.Context(), usr.ID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return &http.Cookie{Name: deps.Cfg.Auth.Session.CookieName, Value: sess.ID}
}

// sessionFor resolves the session behind a cookie, so a test can read the CSRF
// token it must submit with a form POST.
func sessionFor(t *testing.T, deps Deps, cookie *http.Cookie) store.Session {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	_, sess, err := deps.Sessions.AuthenticateRequest(req, deps.Cfg.Auth.Session.CookieName)
	if err != nil {
		t.Fatalf("resolve session: %v", err)
	}
	return sess
}

// TestRequireAdmin_ForbidsNonAdmin asserts a signed-in non-admin gets 403 rather
// than a redirect. Redirecting to /login would loop: they are already signed in.
func TestRequireAdmin_ForbidsNonAdmin(t *testing.T) {
	deps, st := testDeps(t)

	usr := seedUser(t, st, "user@example.com", "user")
	cookie := signIn(t, deps, usr)

	req := httptest.NewRequest(http.MethodGet, "/admin/probe", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	guarded := newTestHandler(t, deps).requireAdmin(func(http.ResponseWriter, *http.Request, store.User, store.Session) {
		t.Error("handler ran for a non-admin")
	})
	guarded(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestRequirePost_RejectsBadCSRF asserts the wrapped handler never runs without
// a valid token.
func TestRequirePost_RejectsBadCSRF(t *testing.T) {
	deps, st := testDeps(t)

	usr := seedUser(t, st, "user@example.com", "user")
	cookie := signIn(t, deps, usr)

	tests := []struct {
		name  string
		token string
	}{
		{"absent", ""},
		{"wrong", "not-the-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := url.Values{"csrf": {tt.token}}
			req := httptest.NewRequest(http.MethodPost, "/probe", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()

			ran := false
			h := newTestHandler(t, deps).requirePost(func(http.ResponseWriter, *http.Request, store.User, store.Session) {
				ran = true
			})
			h(rec, req)

			if ran {
				t.Error("handler ran despite an invalid CSRF token")
			}
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
		})
	}
}
