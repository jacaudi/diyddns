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

// TestAppCSS_BrandMarginIsNotSharedAcrossShells guards against the SAME
// two-rules-one-class collision as TestAppCSS_BrandRuleIsScopedToTopbar
// above, leaking in the opposite direction: the shared bare ".brand" rule
// used to carry "margin-bottom: 24px", needed only by the auth shell (which
// stacks the brand mark above the card in layout.html). ".topbar .brand"
// never overrode it, and because a flex row with align-items: center
// centers the MARGIN box rather than the border box, that inherited margin
// shifted the app-shell brand 12px above the nav's centre line at desktop
// width (Task 5 review round 2). This is a text-level proxy for a geometric
// property — the real assertion is "brand and nav share a centre line",
// which needs a browser (Task 14 extends the Playwright harness for that).
// This test only confirms the CSS source no longer has the shape that
// caused the bug: the shared rule stays margin-free, and the auth shell's
// spacing lives in its own scoped rule instead.
func TestAppCSS_BrandMarginIsNotSharedAcrossShells(t *testing.T) {
	css, err := staticFS.ReadFile("static/app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}
	text := string(css)

	bareBrand := regexp.MustCompile(`(?ms)^\.brand\s*\{([^}]*)\}`)
	m := bareBrand.FindStringSubmatch(text)
	if m == nil {
		t.Fatal("app.css has no bare .brand rule")
	}
	if strings.Contains(m[1], "margin-bottom") {
		t.Errorf("the shared bare .brand rule sets margin-bottom (body: %q); this leaks into "+
			".topbar .brand in the app shell and misaligns the brand with the nav — scope it to "+
			"the auth shell instead (e.g. \".wrap .brand\")", strings.TrimSpace(m[1]))
	}

	scopedBrand := regexp.MustCompile(`(?ms)^\.wrap \.brand\s*\{([^}]*)\}`)
	sm := scopedBrand.FindStringSubmatch(text)
	if sm == nil {
		t.Fatal(`app.css is missing a ".wrap .brand { ... }" rule for the auth shell's spacing`)
	}
	// Task 5 review round 3 replaced every hard-coded spacing value in
	// app.css, including this one, with a token from the spacing scale;
	// var(--space-5) resolves to the same 24px this test originally asserted
	// literally (see TestAppCSS_SpacingScaleTokensExist for the scale
	// itself).
	if !strings.Contains(sm[1], "margin-bottom: var(--space-5)") {
		t.Errorf(".wrap .brand rule = %q, want margin-bottom: var(--space-5)", strings.TrimSpace(sm[1]))
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

// seedDevice inserts a device owned by userID with a sealed dummy secret. It
// goes through the store rather than EnrollmentService because these tests care
// about rendering, not about the enrollment ceremony.
func seedDevice(t *testing.T, st *store.Store, userID, label string) store.Device {
	t.Helper()
	d, err := st.Devices().Create(t.Context(), store.Device{
		UserID: userID, Label: label, SecretHash: "sealed-test-secret",
	})
	if err != nil {
		t.Fatalf("seed device %q: %v", label, err)
	}
	return d
}

// touchDevice advances a device's last_seen_at, so status derivation can be
// exercised without a real check-in.
func touchDevice(t *testing.T, st *store.Store, id string, at int64) {
	t.Helper()
	if err := st.Devices().Touch(t.Context(), id, at); err != nil {
		t.Fatalf("touch device: %v", err)
	}
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

// TestAppCSS_SpacingScaleTokensExist guards the Task 5 review round 3 spacing
// scale: seven numeric custom properties in :root, the only source for
// margin/padding/gap values in app.css. Numeric tokens only — no semantic
// alias layer (e.g. --stack-action) was approved.
func TestAppCSS_SpacingScaleTokensExist(t *testing.T) {
	css, err := staticFS.ReadFile("static/app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}
	text := string(css)

	want := map[string]string{
		"--space-1": "4px",
		"--space-2": "8px",
		"--space-3": "12px",
		"--space-4": "16px",
		"--space-5": "24px",
		"--space-6": "32px",
		"--space-7": "48px",
	}
	for name, value := range want {
		token := regexp.MustCompile(regexp.QuoteMeta(name) + `:\s*` + regexp.QuoteMeta(value) + `;`)
		if !token.MatchString(text) {
			t.Errorf("app.css :root is missing %q: %q", name, value)
		}
	}
}

// TestAppCSS_CrampedFormSpacingIsCorrected guards the three Part 2 fixes from
// Task 5 review round 3: the maintainer measured label->input at 5px and
// input->primary-button at 14px on the real rendered page and asked for a
// deliberate step UP (not the nearest-scale-step down to 4px, which would
// have made the label complaint worse). This is a text-level proxy for a
// geometric property — the real assertion is the rendered gap in a browser,
// which the maintainer measures directly with Playwright; this test only
// confirms the CSS source carries the agreed values. Round 5 revisited two
// of them after seeing the corrected gaps rendered — the action gap came
// back down a step, and the status line moved a step away from the button
// ("the error is too close to the button"):
//
//	label -> input     var(--space-2)  (8px)
//	field -> field      var(--space-4) (16px, .field's own margin-bottom)
//	input -> button     var(--space-4) (16px, via .field + .btn; was --space-5)
//	button -> status    var(--space-4) (16px, .status's top margin; was --space-2)
//	field .hint          var(--space-2) (8px, same reasoning as the label)
func TestAppCSS_CrampedFormSpacingIsCorrected(t *testing.T) {
	css, err := staticFS.ReadFile("static/app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}
	text := string(css)

	tests := []struct {
		name    string
		pattern string
	}{
		{"label -> input (.field label margin-bottom)", `\.field label\s*\{[^}]*margin-bottom:\s*var\(--space-2\)`},
		{"field -> field (.field margin-bottom)", `^\.field\s*\{\s*margin-bottom:\s*var\(--space-4\)`},
		{"input -> button (.field + .btn margin-top)", `\.field \+ \.btn\s*\{\s*margin-top:\s*var\(--space-4\)`},
		{"button -> status (.status margin-top)", `^\.status\s*\{[^}]*margin:\s*var\(--space-4\)\s+0\s+0`},
		{"field hint (.field .hint margin-top)", `\.field \.hint\s*\{[^}]*margin-top:\s*var\(--space-2\)`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re := regexp.MustCompile(`(?m)` + tt.pattern)
			if !re.MatchString(text) {
				t.Errorf("app.css does not match %s", tt.name)
			}
		})
	}
}

// TestAppCSS_ActionGapDoesNotRelyOnMarginCollapsing guards the OTHER half of
// the input->button gap, which the assertion above cannot see. Round 3 set
// ".field + .btn { margin-top: var(--space-5) }" and reasoned that the
// field's own var(--space-4) bottom margin would collapse away against it,
// leaving 24px. It does not always: margins collapse only between
// block-level boxes in normal block flow, and the base .btn is display:
// inline-block, which does not participate. The maintainer measured
// 16 + 24 = 40px on the real /account page at 1280px.
//
// Whether a call site collapsed turned out to depend on its button
// modifier — .btn block is display: block, so /login and /register were
// already right, while /account's .btn primary summed. The fix is to stop
// depending on collapsing at all: zero the bottom margin of a field that is
// immediately followed by a button, so the button's margin-top owns the
// entire gap. max(0, n) and 0 + n are the same number, so every site lands
// on exactly that margin-top however its button is displayed. Round 5 then
// retuned the gap from --space-5 to --space-4 by editing one token, with no
// per-page arithmetic, which is the property this test exists to keep.
//
// The value itself — that .field + .btn carries the WHOLE token, rather
// than a subtracted one that only reaches the target while .field's
// margin-bottom happens to be 16px — is already asserted by the test above
// and is deliberately not repeated here.
//
// Like that test, this one is a text-level proxy: it can only prove the
// stylesheet carries the collapse-independent mechanism, never that a
// browser lays it out at 24px. The rendered geometry stays the maintainer's
// measurement to make.
func TestAppCSS_ActionGapDoesNotRelyOnMarginCollapsing(t *testing.T) {
	css, err := staticFS.ReadFile("static/app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}

	neutralized := regexp.MustCompile(`(?m)^\.field:has\(\s*\+\s*\.btn\s*\)\s*\{[^}]*margin-bottom:\s*0\s*[;}]`)
	if !neutralized.Match(css) {
		t.Error(`app.css is missing ".field:has(+ .btn) { margin-bottom: 0; }"; without it the ` +
			`field's own var(--space-4) bottom margin adds to the button's margin-top instead of ` +
			`collapsing with it, and the rendered input->button gap on /account is the sum of the ` +
			`two rather than the button's margin-top alone`)
	}
}

// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell: testDeps
// calls store.Open, and store.Migrate mutates goose's package-level globals
// with no synchronization, so concurrent store opens race under -race.
func TestDevices_ListsOwnDevicesOnly(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)

	mine := seedUser(t, st, "mine@example.com", "user")
	theirs := seedUser(t, st, "theirs@example.com", "user")
	seedDevice(t, st, mine.ID, "home-router")
	seedDevice(t, st, theirs.ID, "someone-elses-nuc")

	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	req.AddCookie(signIn(t, deps, mine))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "home-router") {
		t.Error("own device missing from the list")
	}
	if strings.Contains(body, "someone-elses-nuc") {
		t.Error("another user's device leaked into the list")
	}
}

// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDevices_EmptyStates(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "empty@example.com", "user")

	t.Run("no devices at all teaches the next step", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/devices", nil)
		req.AddCookie(signIn(t, deps, usr))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if !strings.Contains(rec.Body.String(), "No devices yet") {
			t.Error("missing the teaching empty state")
		}
	})

	t.Run("no matches is a different message", func(t *testing.T) {
		seedDevice(t, st, usr.ID, "home-router")
		req := httptest.NewRequest(http.MethodGet, "/devices?q=nothing-matches-this", nil)
		req.AddCookie(signIn(t, deps, usr))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		body := rec.Body.String()
		if !strings.Contains(body, "No devices match") {
			t.Error("missing the filtered empty state")
		}
		if strings.Contains(body, "No devices yet") {
			t.Error("showed the zero-devices state when the user has devices")
		}
	})
}

// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDevices_StatusFilter(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "filter@example.com", "user")

	online := seedDevice(t, st, usr.ID, "online-box")
	touchDevice(t, st, online.ID, time.Now().Unix())
	seedDevice(t, st, usr.ID, "never-seen-box") // LastSeenAt stays 0

	req := httptest.NewRequest(http.MethodGet, "/devices?status=never", nil)
	req.AddCookie(signIn(t, deps, usr))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "never-seen-box") {
		t.Error("never-seen device missing under ?status=never")
	}
	if strings.Contains(body, "online-box") {
		t.Error("online device leaked through ?status=never")
	}
}

// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDevices_RequiresSession(t *testing.T) {
	deps, _ := testDeps(t)
	h, _ := New(deps)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/devices", nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if got := rec.Header().Get("Location"); got != "/login" {
		t.Errorf("Location = %q, want /login", got)
	}
}

// TestDeviceNew_RevealsCodeAndCommand asserts the reveal step renders in the
// POST response itself: the code, the ready-to-paste client command, the
// shown-once warning, and no-store caching, without ever claiming a device
// was created (CreateCode mints a code; the device row appears only when a
// client redeems it).
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell: testDeps
// calls store.Open, and store.Migrate mutates goose's package-level globals
// with no synchronization, so concurrent store opens race under -race.
func TestDeviceNew_RevealsCodeAndCommand(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "new@example.com", "user")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "label": {"garage-pi"}}
	req := httptest.NewRequest(http.MethodPost, "/devices/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the reveal renders in the POST response)", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "diyddns-client enroll") {
		t.Error("the ready-to-paste command is missing")
	}
	if !strings.Contains(body, "Shown once") {
		t.Error("the shown-once warning is missing")
	}
	if !strings.Contains(body, "single use") {
		t.Error("the single-use note is missing")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	// The reveal must not claim a device exists: CreateCode mints a code, and
	// the device row appears only when a client redeems it.
	if strings.Contains(body, "Device created") {
		t.Error("the reveal claims a device was created")
	}
}

// TestDeviceNew_RejectsEmptyLabel asserts the handler owns the non-empty-label
// check CreateCode itself never performs.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceNew_RejectsEmptyLabel(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "empty-label@example.com", "user")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "label": {"   "}}
	req := httptest.NewRequest(http.MethodPost, "/devices/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "Shown once") {
		t.Error("a code was revealed for an empty label")
	}
}

// TestDeviceNew_RejectsDuplicateLabel asserts the handler's advisory
// duplicate-label pre-check against Devices.List: EnrollmentService.CreateCode
// cannot detect this itself, since UNIQUE (user_id, label) lives on the
// devices table, not enrollment_codes.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceNew_RejectsDuplicateLabel(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "dupe@example.com", "user")
	seedDevice(t, st, usr.ID, "home-router")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "label": {"home-router"}}
	req := httptest.NewRequest(http.MethodPost, "/devices/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 — a duplicate label would fail at redeem time", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "already have a device") {
		t.Error("the duplicate-label error does not name the collision")
	}
}

// TestDeviceNew_RequiresCSRF asserts the mint-a-code POST is guarded by
// requirePost like every other mutation.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceNew_RequiresCSRF(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "csrf@example.com", "user")

	form := url.Values{"csrf": {"wrong"}, "label": {"garage-pi"}}
	req := httptest.NewRequest(http.MethodPost, "/devices/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(signIn(t, deps, usr))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestDevices_QueryFilter_MatchesPositively proves matchesQuery's matching
// branch, not just its no-match branch: TestDevices_EmptyStates only ever
// exercises ?q= against a single device that fails to match. Each subtest
// seeds two devices and asserts BOTH halves — the matching device present AND
// the non-matching device absent — because presence alone would also pass
// against a filter that does nothing.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDevices_QueryFilter_MatchesPositively(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "queryfilter@example.com", "user")

	t.Run("matches the label case-insensitively", func(t *testing.T) {
		seedDevice(t, st, usr.ID, "garage-node")
		seedDevice(t, st, usr.ID, "porch-light")

		req := httptest.NewRequest(http.MethodGet, "/devices?q=GARAGE", nil)
		req.AddCookie(signIn(t, deps, usr))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		body := rec.Body.String()
		if !strings.Contains(body, "garage-node") {
			t.Error("device matching a differently-cased query missing from the filtered list")
		}
		if strings.Contains(body, "porch-light") {
			t.Error("non-matching device leaked through the query filter")
		}
	})

	t.Run("matches current IPv4, a non-label field", func(t *testing.T) {
		matching := seedDevice(t, st, usr.ID, "cellar-box")
		seedDevice(t, st, usr.ID, "attic-box")
		if err := st.Devices().UpdateIP(t.Context(), matching.ID, "10.20.30.40", "", "", "", "", 0); err != nil {
			t.Fatalf("set current IPv4: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/devices?q=10.20.30.40", nil)
		req.AddCookie(signIn(t, deps, usr))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		body := rec.Body.String()
		if !strings.Contains(body, "cellar-box") {
			t.Error("device matching by current IPv4 missing from the filtered list")
		}
		if strings.Contains(body, "attic-box") {
			t.Error("non-matching device leaked through the IPv4 filter")
		}
	})
}

// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell: testDeps
// calls store.Open, and store.Migrate mutates goose's package-level globals
// with no synchronization, so concurrent store opens race under -race.
func TestDeviceDetail_ForeignDeviceIs404(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)

	mine := seedUser(t, st, "mine@example.com", "user")
	theirs := seedUser(t, st, "theirs@example.com", "user")
	foreign := seedDevice(t, st, theirs.ID, "not-mine")

	cookie := signIn(t, deps, mine)
	sess := sessionFor(t, deps, cookie)

	// Every route scoped to {id}, not just the GETs. rotate-secret matters most:
	// it mints a credential.
	// /history is NOT listed here: Task 9 registers it, so at this task an
	// unregistered path answers 404 — the expected status — and the subtest
	// would pass for the wrong reason, giving no isolation signal. Task 9 Step 6
	// adds it.
	for _, p := range []struct{ method, path string }{
		{http.MethodGet, "/devices/" + foreign.ID},
		{http.MethodPost, "/devices/" + foreign.ID + "/rename"},
		{http.MethodPost, "/devices/" + foreign.ID + "/enabled"},
		{http.MethodPost, "/devices/" + foreign.ID + "/rotate-secret"},
		{http.MethodPost, "/devices/" + foreign.ID + "/delete"},
	} {
		t.Run(p.method+" "+p.path, func(t *testing.T) {
			form := url.Values{
				"csrf":          {sess.CSRFToken},
				"label":         {"renamed-by-attacker"},
				"disabled":      {"true"},
				"confirm_label": {"not-mine"}, // the real label, were the check to run
			}
			req := httptest.NewRequest(p.method, p.path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404 (not 403 — foreign and missing must be indistinguishable)", rec.Code)
			}
		})
	}

	// And nothing happened to the victim's device.
	after, err := st.Devices().GetByID(t.Context(), foreign.ID)
	if err != nil {
		t.Fatalf("the foreign device was deleted: %v", err)
	}
	if after.Label != "not-mine" || after.Disabled {
		t.Errorf("the foreign device was modified: %+v", after)
	}
}

// TestDeviceMutations_RequireCSRF asserts every device mutation is actually
// wrapped by requirePost. Testing the wrapper in isolation proves the wrapper
// works; it does not prove each route uses it.
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceMutations_RequireCSRF(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "csrf-routes@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "home-router")
	cookie := signIn(t, deps, usr)

	for _, path := range []string{
		"/devices/new",
		"/devices/" + dev.ID + "/rename",
		"/devices/" + dev.ID + "/enabled",
		"/devices/" + dev.ID + "/rotate-secret",
		"/devices/" + dev.ID + "/delete",
	} {
		t.Run(path, func(t *testing.T) {
			form := url.Values{"csrf": {"wrong-token"}, "label": {"x"}, "confirm_label": {"home-router"}}
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403 — this route is not CSRF-guarded", rec.Code)
			}
		})
	}
	if _, err := st.Devices().GetByID(t.Context(), dev.ID); err != nil {
		t.Fatalf("a CSRF-less request mutated the device: %v", err)
	}
}

// TestDeviceRotate_RequiresMatchingLabel is the rotate half of the typed
// confirmation set. Delete has one; rotate guards the action that silently
// breaks a running agent, so it needs one too.
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceRotate_RequiresMatchingLabel(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "rot-confirm@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "home-router")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "confirm_label": {"wrong-name"}}
	req := httptest.NewRequest(http.MethodPost, "/devices/"+dev.ID+"/rotate-secret", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	after, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if after.SecretHash != dev.SecretHash {
		t.Error("the secret was rotated despite a mismatched confirmation")
	}
}

// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceDelete_RequiresMatchingLabel(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "del@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "home-router")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	t.Run("mismatch changes nothing", func(t *testing.T) {
		form := url.Values{"csrf": {sess.CSRFToken}, "confirm_label": {"wrong-name"}}
		req := httptest.NewRequest(http.MethodPost, "/devices/"+dev.ID+"/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", rec.Code)
		}
		if _, err := st.Devices().GetByID(t.Context(), dev.ID); err != nil {
			t.Fatalf("device was deleted despite a mismatched confirmation: %v", err)
		}
	})

	t.Run("match deletes and redirects", func(t *testing.T) {
		form := url.Values{"csrf": {sess.CSRFToken}, "confirm_label": {"home-router"}}
		req := httptest.NewRequest(http.MethodPost, "/devices/"+dev.ID+"/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303", rec.Code)
		}
		if got := rec.Header().Get("Location"); got != "/devices" {
			t.Errorf("Location = %q, want /devices", got)
		}
		if _, err := st.Devices().GetByID(t.Context(), dev.ID); err == nil {
			t.Error("device still exists after a confirmed delete")
		}
	})
}

// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceRotate_RevealsSecretOnce(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "rot@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "home-router")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "confirm_label": {"home-router"}}
	req := httptest.NewRequest(http.MethodPost, "/devices/"+dev.ID+"/rotate-secret", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the reveal renders in the POST response)", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"credentials.json", "0600", "Reloading this page rotates the secret again"} {
		if !strings.Contains(body, want) {
			t.Errorf("rotate reveal missing %q", want)
		}
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store — this is the most secret-bearing response in the UI", got)
	}
	// Do NOT assert on `"secret":` — html/template escapes " to &#34; in text
	// context, so the rendered snippet reads secret&#34;: and any assertion
	// containing a raw double quote fails against a correct implementation.
	// Assert on the base64 payload instead: its alphabet (A-Za-z0-9+/=) passes
	// through escaping untouched.
	updated, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if updated.SecretHash == dev.SecretHash {
		t.Fatal("the stored sealed secret did not change — nothing was rotated")
	}
	// The plaintext is returned once and never persisted, so the test cannot
	// recompute it. Assert the reveal carries a plausible base64 secret and the
	// device's own id, in the snippet rather than anywhere on the page.
	snippet := revealSnippet(t, body)
	if !strings.Contains(snippet, dev.ID) {
		t.Error("the credentials.json snippet does not name this device")
	}
	if !base64Pattern.MatchString(snippet) {
		t.Errorf("the credentials.json snippet carries no base64 secret: %q", snippet)
	}
}

// base64Pattern matches a plausible base64-encoded 32-byte secret. Declared at
// package level so it compiles once.
//
// Deviation from the task brief: html/template's text-context escaper also
// rewrites a literal "+" to "&#43;" (confirmed against the stdlib; only "+"
// among the base64 alphabet is touched — "/" and "=" pass through
// unescaped). auth.GenerateSecret's 32 random bytes contain "+" in roughly
// half of all base64 encodings, so the brief's literal `[A-Za-z0-9+/]`
// pattern is flaky by construction — reproduced locally as ~50% failures
// across repeated runs. The alternation below accepts either form so the
// assertion is deterministic regardless of the random secret's content.
var base64Pattern = regexp.MustCompile(`(?:[A-Za-z0-9/]|&#43;){40,}={0,2}`)

// revealSnippet extracts the credentials.json block from a rendered rotate
// reveal, so assertions cannot be satisfied by the metadata card or the app
// shell. It returns "" when no reveal is present.
func revealSnippet(t *testing.T, body string) string {
	t.Helper()
	_, after, found := strings.Cut(body, "server_url")
	if !found {
		return ""
	}
	snippet, _, _ := strings.Cut(after, "</code>")
	return snippet
}

// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceRename_UpdatesAndRedirects(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "ren@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "old-name")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "label": {"new-name"}}
	req := httptest.NewRequest(http.MethodPost, "/devices/"+dev.ID+"/rename", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	got, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if got.Label != "new-name" {
		t.Errorf("label = %q, want %q", got.Label, "new-name")
	}
}
