package webui

import (
	"bytes"
	"context"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
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

// seedHistory appends an ip_history row for a device.
func seedHistory(t *testing.T, st *store.Store, deviceID, v4, v6, clientVersion string) {
	t.Helper()
	if _, err := st.IPHistory().Append(t.Context(), store.IPHistory{
		DeviceID: deviceID, IPv4: v4, IPv6: v6,
		ObservedAt: store.NowUnix(), ClientVersion: clientVersion,
	}); err != nil {
		t.Fatalf("seed history: %v", err)
	}
}

// lastHistoryCursor returns a syntactically valid cursor positioned past every
// existing row, so a request with it comes back empty.
func lastHistoryCursor(t *testing.T, st *store.Store, deviceID string) string {
	t.Helper()
	seedHistory(t, st, deviceID, "203.0.113.1", "", "seed")
	page, err := st.IPHistory().Page(t.Context(), deviceID, "", 1)
	if err != nil {
		t.Fatalf("page history: %v", err)
	}
	if page.NextCursor == "" {
		t.Fatal("expected a next cursor from a full page of 1")
	}
	return page.NextCursor
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
		// [^{]* rather than \s*: the declaration may be shared with another
		// selector in a group (.disclosure .hint reuses it). What this guards is
		// the 8px top margin, not whether the rule is written on its own.
		{"field hint (.field .hint margin-top)", `\.field \.hint[^{]*\{[^}]*margin-top:\s*var\(--space-2\)`},
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

// TestAppCSS_FlexibleGridTracksCanShrinkBelowMinContent guards the whole
// stylesheet against one defect class, not one rule.
//
// A grid track written as bare `1fr` is `minmax(auto, 1fr)`, and `auto` as a
// track MINIMUM is the item's min-content width — so such a track can grow to
// fill, but can never shrink below the widest unbreakable thing inside it. On
// /devices/{id} that unbreakable thing is the Device ID `.copy` pill, which is
// `white-space: nowrap` around a 36-char UUID: measured in Chromium at a 390px
// viewport, each `.grid.cols-2` card was pinned at 440px and the document
// scrolled to 464px. `minmax(0, 1fr)` lets the track shrink, and the pill's
// own `max-width: 100%` plus its `overflow: auto` code element then absorb the
// difference by scrolling in place — which is what they were written to do.
//
// `.danger-item` was already fixed this way once, and that fix is exactly why
// this test is file-wide rather than a list of three selectors: the 780px
// override of `.danger-item` was left as a bare `1fr` and reintroduced the
// same defect one media query down. Guarding the class instead of the instance
// is what stops the next grid from repeating it.
//
// Scope note: this asserts only that a FLEXIBLE track may shrink. Fixed tracks
// (`160px`, `200px`) are untouched — they carry a deliberate width, and their
// media-query overrides are where they get to stop being fixed.
//
// Like the spacing tests above this is a text-level proxy for a geometric
// property; the rendered 390px document width stays a browser measurement.
func TestAppCSS_FlexibleGridTracksCanShrinkBelowMinContent(t *testing.T) {
	css, err := staticFS.ReadFile("static/app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}

	decl := regexp.MustCompile(`grid-template-columns:[^;}]*`)
	found := decl.FindAllString(string(css), -1)
	if len(found) == 0 {
		t.Fatal("no grid-template-columns declarations found; this test has lost its subject")
	}

	for _, d := range found {
		// Remove the correct form, then anything still saying 1fr is bare.
		if strings.Contains(strings.ReplaceAll(d, "minmax(0, 1fr)", ""), "1fr") {
			t.Errorf("bare 1fr track in %q: a track that is minmax(auto, 1fr) cannot shrink "+
				"below its content's min-content width, so an unbreakable child (a nowrap .copy "+
				"pill) forces document overflow at narrow viewports; write minmax(0, 1fr)", d)
		}
	}
}

// TestAppCSS_DescriptionValuesWrapOperatorSuppliedStrings guards the one place
// in the UI that renders arbitrary operator-configured text.
//
// Every value on /admin/server — a database path, a listen address, a base
// URL, a build string — comes from the config file or the build, so none of
// them has a bounded length and several contain no spaces at all. With the
// default `overflow-wrap: normal` a <dd> holding one of those has no break
// opportunity, so its box stays viewport-wide while the text spills out of it
// as an anonymous inline box: measured in the browser smoke at a 390px
// viewport, a temp-directory database path pushed the document 296px wider
// than the viewport while every element box still reported as fitting.
//
// That invisibility is the reason this is asserted rather than eyeballed. The
// overflow is not attributable to any element's geometry, so it survives a
// screenshot review of a page whose boxes all look correct — and it only
// appears with real config, which is why the audit that ran against seeded
// test data never saw it.
//
// `anywhere` rather than `break-word`: only `anywhere` also lets the box's
// min-content size shrink, which is what stops the containing grid track from
// being held open in the first place.
func TestAppCSS_DescriptionValuesWrapOperatorSuppliedStrings(t *testing.T) {
	css, err := staticFS.ReadFile("static/app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}

	rule := regexp.MustCompile(`(?s)\.kv > dd\s*\{(.*?)\}`).FindStringSubmatch(string(css))
	if rule == nil {
		t.Fatal("no `.kv > dd` rule in app.css; this test has lost its subject")
	}
	if !strings.Contains(rule[1], "overflow-wrap: anywhere") {
		t.Error("`.kv > dd` is missing `overflow-wrap: anywhere`; a config value with no spaces " +
			"(a filesystem path, a URL) then has no break opportunity and spills out of the page")
	}
}

// TestAppCSS_SmallButtonsAreStillTouchTargets pins the one rule that decides
// whether the compact controls can be hit with a thumb.
//
// Measured in Chromium at a 390px viewport, .btn.sm rendered 24px tall as a
// <button> ("Copy" on /devices/{id}, "Disable" on /admin/users) and 30px as an
// <a> ("Open" on /devices, "Full history ›" on /devices/{id}) — the same class,
// two different heights, because the two element types compute different
// content box heights from identical padding. That is why the fix is a
// min-height and not more padding: padding cannot land both on one number, and
// whichever value fixed the <button> would overshoot the <a>.
//
// var(--space-6) is 32px on the project's 4px scale. WCAG 2.2 Target Size
// (Minimum) would be satisfied at 24px, so the 24px controls were arguably
// already conformant; 32px is a deliberate choice above the floor, because the
// audit measured these as uncomfortable on a real phone-width viewport rather
// than merely non-conformant.
//
// A text assertion can only prove the rule is present. That it produces 32px
// in a real layout engine is asserted by internal/smoke/browser/smoke.mjs,
// which measures the rendered boxes.
func TestAppCSS_SmallButtonsAreStillTouchTargets(t *testing.T) {
	css, err := staticFS.ReadFile("static/app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}

	rule := regexp.MustCompile(`(?s)\.btn\.sm\s*\{(.*?)\}`).FindStringSubmatch(string(css))
	if rule == nil {
		t.Fatal("no .btn.sm rule in app.css; this test has lost its subject")
	}
	body := rule[1]

	for _, want := range []struct{ name, decl string }{
		{"a floor on the target height", "min-height: var(--space-6)"},
		{"a box that can centre the label vertically", "display: inline-flex"},
		{"the label centred in that box", "align-items: center"},
	} {
		if !strings.Contains(body, want.decl) {
			t.Errorf(".btn.sm is missing %s (%q); without it the rendered control is "+
				"24px tall as a <button> and 30px as an <a>", want.name, want.decl)
		}
	}
}

// TestPages_EachRenderExactlyOneH1 guards the document outline across every
// app-shell screen at once.
//
// A page with no <h1> starts its heading hierarchy at <h2>, which leaves a
// screen reader's heading list with no entry naming the page and makes
// "jump to the top heading" land on a section instead. A page with two
// competing <h1>s is the same defect from the other side. Twelve of the
// fourteen screens already got this right by convention (.page-head > h1);
// /devices/new and /admin/users/new rendered zero, in BOTH of their states —
// the audit only caught the form step, but the reveal step was missing one
// too.
//
// Both of those screens are two pages behind one URL: a form, and the
// once-only reveal that the POST renders inline. Each state is listed here
// separately, because a fix applied to only the branch the auditor happened
// to screenshot is exactly the half-fix this test exists to prevent.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestPages_EachRenderExactlyOneH1(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "outline@example.com", "admin")
	dev := seedDevice(t, st, usr.ID, "outline-box")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	tests := []struct {
		name   string
		method string
		path   string
		form   url.Values
	}{
		{"devices list", http.MethodGet, "/devices", nil},
		{"device new (form step)", http.MethodGet, "/devices/new", nil},
		{"device new (reveal step)", http.MethodPost, "/devices/new", url.Values{"label": {"outline-pi"}}},
		{"device detail", http.MethodGet, "/devices/" + dev.ID, nil},
		{"device history", http.MethodGet, "/devices/" + dev.ID + "/history", nil},
		{"account", http.MethodGet, "/account", nil},
		{"admin users", http.MethodGet, "/admin/users", nil},
		{"admin user new (form step)", http.MethodGet, "/admin/users/new", nil},
		{"admin user new (reveal step)", http.MethodPost, "/admin/users/new", url.Values{"email": {"invitee@example.com"}, "role": {"user"}}},
		{"admin user edit", http.MethodGet, "/admin/users/" + usr.ID, nil},
		{"admin audit", http.MethodGet, "/admin/audit", nil},
		{"admin server", http.MethodGet, "/admin/server", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.method == http.MethodPost {
				tt.form.Set("csrf", sess.CSRFToken)
				req = httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(http.MethodGet, tt.path, nil)
			}
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s %s = %d, want 200", tt.method, tt.path, rec.Code)
			}
			if n := strings.Count(rec.Body.String(), "<h1"); n != 1 {
				t.Errorf("%d <h1> elements, want exactly 1: a page with none has no heading "+
					"naming it, and a page with two has no single one that does", n)
			}
		})
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
	// The shown-once callout must say the code can't be shown again, not just
	// that this page won't show it — the trimmed copy still has to carry the
	// non-recoverable fact, not merely the display policy.
	if !strings.Contains(body, "can't be shown again") {
		t.Error("the shown-once callout no longer says the code can't be shown again")
	}
	if !strings.Contains(body, "single use") {
		t.Error("the single-use note is missing")
	}
	// The container path is the recommended install route, so both steps must
	// render with the exact volume and container names the recovery copy and
	// the README also use — a mismatch hands the operator commands that do not
	// refer to the same objects.
	if !strings.Contains(body, "docker run --rm -v diyddns-client:/home/nonroot/.config") {
		t.Error("the container enroll command is missing")
	}
	if !strings.Contains(body, "--name diyddns-client-run") {
		t.Error("the container run command is missing")
	}
	if !strings.Contains(body, "--restart unless-stopped") {
		t.Error("the run command does not survive a reboot")
	}
	// testDeps pins Version:"test", which is not a published release shape, so
	// the page must advertise :latest rather than a tag that 404s.
	if !strings.Contains(body, "ghcr.io/jacaudi/diyddns/client:latest") {
		t.Error("the image reference is missing or is not the dev fallback")
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

// TestDeviceNew_DevBuildNote pins the version-dependent half of the reveal. The
// note exists to stop an operator reading ":latest" as "newest stable"; a
// release build must not show it, because there the pinned tag IS the release.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceNew_DevBuildNote(t *testing.T) {
	for _, tc := range []struct {
		name     string
		version  string
		wantTag  string
		wantNote bool
	}{
		{"dev", "v0.0.0-dev", "ghcr.io/jacaudi/diyddns/client:latest", true},
		{"release", "v0.1.0", "ghcr.io/jacaudi/diyddns/client:v0.1.0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps, st := testDeps(t)
			// Set Info on the local copy rather than a package global: Deps is
			// passed by value into New, and the goose race documented above
			// makes global mutation unsafe in this package.
			deps.Info = version.Info{Version: tc.version}
			h, _ := New(deps)
			usr := seedUser(t, st, "devnote-"+tc.name+"@example.com", "user")
			cookie := signIn(t, deps, usr)
			sess := sessionFor(t, deps, cookie)

			form := url.Values{"csrf": {sess.CSRFToken}, "label": {"note-" + tc.name}}
			req := httptest.NewRequest(http.MethodPost, "/devices/new", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			body := rec.Body.String()
			if !strings.Contains(body, tc.wantTag) {
				t.Errorf("image tag %q is missing", tc.wantTag)
			}
			if got := strings.Contains(body, "development build"); got != tc.wantNote {
				t.Errorf("dev-build note present = %v, want %v", got, tc.wantNote)
			}
		})
	}
}

// TestDeviceNew_RecoveryHints guards the copy that tells an operator what to do
// when enroll fails. Three properties, each of which has been got wrong before:
//
//  1. The branches must not over-claim. "credentials already exist" fires before
//     any server contact, so the code is intact. "permission denied" is emitted
//     by TWO states — a 0700 root-owned dir fails in credentials.Load before the
//     code is sent, while a traversable one fails after — so the message alone
//     cannot tell the operator whether the code was spent, and the copy must
//     send them to the device list instead of asserting it.
//  2. The destructive commands must be SCOPED to the branches that need them.
//     Rendered as an unconditional trailer, they are one click from destroying a
//     live device's credentials for an operator whose error said to leave it be.
//  3. Emphasis inside a callout must be <b>, never <strong>: .callout strong is
//     a descendant selector setting display:block, which shatters the sentence
//     around it. A Contains() check cannot see that, so assert the tag.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceNew_RecoveryHints(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "recovery@example.com", "user")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "label": {"recovery-pi"}}
	req := httptest.NewRequest(http.MethodPost, "/devices/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()

	// All three branches, including the default arm.
	for _, want := range []string{
		"credentials already exist",
		"permission denied",
		"Anything else, including that one",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("recovery copy is missing the %q branch", want)
		}
	}

	// Property 1: permission denied must NOT assert the code was spent, and must
	// send the operator to the device list.
	if !strings.Contains(body, "may or may not be spent") {
		t.Error("the permission-denied branch over-claims: it must not assert spent-ness")
	}
	if !strings.Contains(body, "device list") {
		t.Error("the permission-denied branch does not tell the operator how to check")
	}
	// The permission-denied paragraph's job is to discriminate the client's own
	// message from Docker's daemon-socket message, not to explain the volume's
	// ownership — the operator can't act on "wrong owner" directly, only on
	// which branch applies to them.
	if !strings.Contains(body, "is the client's own message") {
		t.Error("the permission-denied branch does not say it is the client's own message")
	}
	// The trimmed "credentials already exist" paragraph must not restate what
	// the code snippet already told the reader.
	if strings.Contains(body, "This host is already enrolled") {
		t.Error("the credentials-already-exist branch still repeats the code snippet in prose")
	}

	// Property 3: inline emphasis renders as <b>, not <strong>.
	if !strings.Contains(body, "<b>not spent</b>") {
		t.Error(`emphasis must be <b>; <strong> inside a callout renders display:block`)
	}

	// Both recovery commands sit inside copy pills. Asserting the pill markup
	// rather than the bare string is the point: bare text satisfies a naive
	// Contains check while being unusable on the page.
	for _, cmd := range []string{
		"docker rm -f diyddns-client-run",
		"docker volume rm diyddns-client",
	} {
		if !strings.Contains(body, `data-copy="`+cmd+`"`) {
			t.Errorf("%q does not render inside a copyValue pill", cmd)
		}
	}

	// Container-then-volume: a volume cannot be removed while a container holds
	// it, so the reverse order fails with "volume is in use".
	rmIdx := strings.Index(body, "docker rm -f diyddns-client-run")
	volIdx := strings.Index(body, "docker volume rm diyddns-client")
	if rmIdx == -1 || volIdx == -1 || rmIdx > volIdx {
		t.Errorf("recovery commands are out of order: rm at %d, volume rm at %d", rmIdx, volIdx)
	}

	// Property 2: the commands must appear exactly once, inside the branch that
	// needs them — not repeated as an unconditional trailer.
	if n := strings.Count(body, `data-copy="docker volume rm diyddns-client"`); n != 1 {
		t.Errorf("docker volume rm renders %d times, want exactly 1 (scoped to its branch)", n)
	}

	// The corrected Next-step callout must not tell the operator that enroll
	// alone starts reporting — that belief is what makes them skip step 2.
	if strings.Contains(body, "Run the command on the device") {
		t.Error("the stale Next-step callout still claims one command starts reporting")
	}
	// The trimmed Next-step callout must still say the device does not report
	// until the second container command is running — the fact that made the
	// stale claim above a defect in the first place.
	if !strings.Contains(body, "won't report until the second") {
		t.Error("the Next-step callout no longer says the device waits on the second command")
	}

	// B1: the default ("any other message") branch must not assert that the
	// server was left untouched — EnrollmentService.ConsumeCode commits the
	// device and consumes the code before the client persists anything, so a
	// client-side failure after that point (dropped connection, non-JSON 200
	// from a proxy, credentials.Save hitting a full disk) can leave the code
	// spent while matching neither of the other two branches.
	if strings.Contains(body, "nothing was changed on the server") {
		t.Error(`the default branch still claims "nothing was changed on the server", which is false once the client has POSTed`)
	}

	// B1 + S5: the default branch's discriminator must name the row the
	// operator just tried to enroll, not an unresolvable "the device" — the
	// devices list has no hostname column, so nothing on the page tells them
	// which row corresponds to "this host".
	if !strings.Contains(body, "the device you just named") {
		t.Error(`the default branch does not point the operator at "the device you just named" as the discriminator`)
	}

	// S3: the permission-denied branch must be scoped to the CLIENT's own
	// "credentials: ... permission denied" message, not the bare substring
	// "permission denied" — that also matches Docker's own
	// "permission denied while trying to connect to the Docker daemon socket",
	// which fires before any container runs and must not be mis-triaged into
	// this branch.
	if !strings.Contains(body, "credentials: ... permission denied") {
		t.Error(`the permission-denied branch is not scoped to the client's own "credentials: ... permission denied" message`)
	}
}

// TestDeviceNew_BaseURLWarningPlacement guards two properties of the
// cleartext-credential warning on the reveal screen: it renders once, and it
// renders ABOVE the commands it warns about rather than below all four of
// them, where "this" in its text would be ambiguous.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceNew_BaseURLWarningPlacement(t *testing.T) {
	deps, st := testDeps(t)
	deps.Cfg.Server.BaseURL = ""
	h, _ := New(deps)
	usr := seedUser(t, st, "baseurlwarn@example.com", "user")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "label": {"scheme-pi"}}
	req := httptest.NewRequest(http.MethodPost, "/devices/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// S2: "this" no longer stands in for four rendered commands.
	if !strings.Contains(body, "Check the scheme before running the commands below") {
		t.Error(`baseURLWarning no longer says "Check the scheme before running the commands below"`)
	}

	warnIdx := strings.Index(body, "server.base_url is not configured")
	containerIdx := strings.Index(body, "docker run --rm -v diyddns-client:/home/nonroot/.config")
	if warnIdx == -1 || containerIdx == -1 || warnIdx > containerIdx {
		t.Errorf("the base-URL warning does not render before the container commands: warning at %d, container command at %d",
			warnIdx, containerIdx)
	}
}

// TestDeviceNew_BinaryPathIsCollapsed pins the bare-binary command behind a
// collapsed disclosure. The container path is the recommended one and the only
// one an operator can follow from a standing start; the binary command serves
// the minority who already have it, and shown open it competes for attention
// with the path most readers must actually take.
//
// It must stay in the markup rather than being dropped: collapsed still copies,
// greps, and prints. So the assertion is about WHERE it renders, not whether —
// a Contains check alone would pass with the command sitting in the open.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceNew_BinaryPathIsCollapsed(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "collapsed@example.com", "user")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "label": {"collapsed-pi"}}
	req := httptest.NewRequest(http.MethodPost, "/devices/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()

	start := strings.Index(body, `<details class="disclosure">`)
	if start == -1 {
		t.Fatal("the binary path does not render inside a disclosure")
	}
	// An `open` attribute would defeat the point, so assert its absence on the
	// element itself rather than anywhere in the page.
	if strings.Contains(body, `<details class="disclosure" open>`) {
		t.Error("the disclosure renders open; it must start collapsed")
	}
	end := strings.Index(body[start:], "</details>")
	if end == -1 {
		t.Fatal("the disclosure is never closed")
	}
	seg := body[start : start+end]

	if !strings.Contains(seg, "<summary>") {
		t.Error("the disclosure has no summary, so there is nothing to click")
	}
	// The load-bearing assertion: the command is INSIDE the disclosure. Placed
	// outside it, the page would look collapsed while the command still showed.
	if !strings.Contains(seg, `data-copy="diyddns-client enroll`) {
		t.Error("the bare-binary command renders outside the disclosure")
	}
	// The shell-history warning travels with the command it warns about.
	if !strings.Contains(seg, "shell history") {
		t.Error("the shell-history hint did not move inside the disclosure with its command")
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
// TestTemplates_AbsentValueIsSingleSourced keeps the "this value is absent"
// representation in one place. It was hand-written at 12 call sites across five
// templates, so changing the em dash to anything else — "Never", "not
// reported" — meant twelve synchronised edits, and missing one leaves the UI
// saying two different things about the same condition.
//
// Source-level rather than render-level on purpose: rendering proves the dash
// still appears, not that it stopped being copy-pasted. Same approach as
// TestAppCSS_CrampedFormSpacingIsCorrected.
func TestTemplates_AbsentValueIsSingleSourced(t *testing.T) {
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		t.Fatalf("read templates dir: %v", err)
	}
	const dash = `<span class="muted">—</span>`
	for _, e := range entries {
		if e.Name() == "partials.html" {
			continue // the one place it is allowed to live
		}
		b, err := templateFS.ReadFile("templates/" + e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if n := strings.Count(string(b), dash); n > 0 {
			t.Errorf("%s hand-writes the absent-value dash %d time(s); call the partial instead", e.Name(), n)
		}
	}
}

// TestDeviceDetail_EmptyHistoryUsesTheEmptyComponent stops this page telling
// the operator "nothing here yet" in a shape no other page uses. Every other
// empty state on the site is .empty with a heading; this one hand-rolled a
// muted paragraph.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceDetail_EmptyHistoryUsesTheEmptyComponent(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "emptyhist@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "no-checkins")
	cookie := signIn(t, deps, usr)

	req := httptest.NewRequest(http.MethodGet, "/devices/"+dev.ID, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()

	if !strings.Contains(body, `<div class="empty">`) {
		t.Error("the no-history state does not use the .empty component")
	}
	if strings.Contains(body, `<p class="muted">No check-ins recorded yet.</p>`) {
		t.Error("the hand-rolled empty state is still rendering")
	}
}

// TestDeviceDetail_DestructiveConfirmsAreCollapsed pins the danger zone's
// confirm fields behind a disclosure, so at rest the card shows one button per
// action instead of three open forms competing for the same right edge.
//
// Only the two DESTRUCTIVE actions collapse. Disable is reversible and keeps
// its history, so it stays a single click — collapsing it would add friction
// where none is warranted, which is how friction stops being read as a signal.
//
// The assertion is about WHERE each confirm input renders, not whether it
// exists: a Contains check would pass with the field sitting in the open,
// which is the exact layout this replaces.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceDetail_DestructiveConfirmsAreCollapsed(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "danger@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "danger-pi")
	cookie := signIn(t, deps, usr)

	req := httptest.NewRequest(http.MethodGet, "/devices/"+dev.ID, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	const open = `<details class="modal">`
	if n := strings.Count(body, open); n != 2 {
		t.Errorf("%d collapsed actions, want exactly 2 (rotate and delete)", n)
	}
	if strings.Contains(body, `<details class="modal" open>`) {
		t.Error("a destructive action renders already expanded")
	}
	// Built on <details>, not <dialog>: ui.js's contract is that every action
	// still works with JavaScript blocked, and a <dialog> without an open
	// attribute is display:none, which would put the confirm field out of reach.
	if strings.Contains(body, "<dialog") {
		t.Error("a <dialog> is unreachable with JS blocked; this must stay a <details>")
	}
	if n := strings.Count(body, `class="modal-panel"`); n != 2 {
		t.Errorf("%d modal panels, want 2", n)
	}

	// Collect each disclosure's inner markup, then require every confirm input
	// to live in one of them.
	var blocks []string
	for rest := body; ; {
		_, after, found := strings.Cut(rest, open)
		if !found {
			break
		}
		inner, _, closed := strings.Cut(after, "</details>")
		if !closed {
			t.Fatal("a disclosure is never closed")
		}
		blocks = append(blocks, inner)
		rest = after
	}
	for _, id := range []string{`id="rotate-confirm"`, `id="delete-confirm"`} {
		if !strings.Contains(body, id) {
			t.Errorf("%s is missing from the page entirely", id)
			continue
		}
		found := false
		for _, b := range blocks {
			if strings.Contains(b, id) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s renders outside a disclosure, so it is visible at rest", id)
		}
	}

	// Disable is reversible; it must NOT have been swept up in the change.
	if strings.Contains(body, `<summary class="btn danger">Disable`) {
		t.Error("Disable was collapsed too; only destructive actions should be")
	}
}

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
	for _, p := range []struct{ method, path string }{
		{http.MethodGet, "/devices/" + foreign.ID},
		{http.MethodPost, "/devices/" + foreign.ID + "/rename"},
		{http.MethodPost, "/devices/" + foreign.ID + "/enabled"},
		{http.MethodPost, "/devices/" + foreign.ID + "/rotate-secret"},
		{http.MethodPost, "/devices/" + foreign.ID + "/delete"},
		{http.MethodGet, "/devices/" + foreign.ID + "/history"},
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

// TestDeviceHistory_EmptyStatesDifferByCursor asserts the two reachable empty
// states render different copy: a device that has never checked in is not the
// same situation as paging past the last row of one that has.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell: testDeps
// calls store.Open, and store.Migrate mutates goose's package-level globals
// unsynchronized. Its own subtests stay t.Parallel()-free too since they
// share this one store sequentially rather than opening their own.
func TestDeviceHistory_EmptyStatesDifferByCursor(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "hist@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "home-router")
	cookie := signIn(t, deps, usr)

	t.Run("no rows and no cursor means never reported", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/devices/"+dev.ID+"/history", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if !strings.Contains(rec.Body.String(), "No check-ins recorded yet") {
			t.Error("missing the never-reported empty state")
		}
	})

	t.Run("no rows with a cursor means end of the stream", func(t *testing.T) {
		cursor := lastHistoryCursor(t, st, dev.ID)
		req := httptest.NewRequest(http.MethodGet, "/devices/"+dev.ID+"/history?cursor="+cursor, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		body := rec.Body.String()
		if !strings.Contains(body, "No more history") {
			t.Error("missing the end-of-stream empty state")
		}
		if strings.Contains(body, "No check-ins recorded yet") {
			t.Error("claimed the device never reported while paging past the end")
		}
	})
}

// TestDeviceHistory_BadCursorIs400 asserts a malformed cursor — a pasted or
// truncated URL — answers 400, not 500, since decodeCursor has no sentinel
// error to distinguish user input from a genuine store failure.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceHistory_BadCursorIs400(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "cursor@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "home-router")

	req := httptest.NewRequest(http.MethodGet, "/devices/"+dev.ID+"/history?cursor=not-a-cursor", nil)
	req.AddCookie(signIn(t, deps, usr))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — a pasted or truncated URL must not 500", rec.Code)
	}
	// Design §4.4 mandates a "start from the first page" LINK on this page, not
	// just those words in the prose. Without it a non-admin's only escape from
	// their own device's history is "Back to devices" — the page tells them to
	// go somewhere it does not take them.
	assertErrorPageLinksTo(t, rec.Body.String(), "/devices/"+dev.ID+"/history")
}

// assertErrorPageLinksTo fails unless the rendered error page offers an anchor
// pointing at want. It compares un-escaped hrefs because html/template escapes
// & and + inside an attribute (see nextPagerURL).
func assertErrorPageLinksTo(t *testing.T, body, want string) {
	t.Helper()
	found := hrefs(body)
	if slices.Contains(found, want) {
		return
	}
	t.Errorf("error page offers no link to %q; hrefs = %v", want, found)
}

// hrefs returns every anchor target on a rendered page, un-escaped.
func hrefs(body string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`<a[^>]+href="([^"]*)"`).FindAllStringSubmatch(body, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

// TestDeviceHistory_RendersRows asserts a device with history renders its
// rows on the full history screen.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceHistory_RendersRows(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "rows@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "home-router")
	seedHistory(t, st, dev.ID, "203.0.113.42", "", "diyddns-client/1.4.0")

	req := httptest.NewRequest(http.MethodGet, "/devices/"+dev.ID+"/history", nil)
	req.AddCookie(signIn(t, deps, usr))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	for _, want := range []string{"203.0.113.42", "diyddns-client/1.4.0"} {
		if !strings.Contains(body, want) {
			t.Errorf("history row missing %q", want)
		}
	}
}

// dropTable removes one table so a single downstream query fails while every
// other one keeps working. That is what makes a PARTIAL failure reachable: the
// mutation commits and the step after it fails, which is precisely the state
// the messages below have to describe honestly.
func dropTable(t *testing.T, st *store.Store, name string) {
	t.Helper()
	if _, err := st.DB().ExecContext(t.Context(), "DROP TABLE "+name); err != nil {
		t.Fatalf("drop %s: %v", name, err)
	}
}

// TestDeviceRotate_RenderFailureSaysTheSecretIsGone asserts that when the
// rotate reveal cannot be prepared, the page says the rotation ALREADY HAPPENED
// rather than "please try again".
//
// RotateSecret returns the plaintext exactly once and never persists it in the
// clear; newDetailData then runs a fresh ip_history query purely to fill a
// cosmetic "Recent IP history" card. Dropping ip_history fails that query while
// leaving the devices and audit_log writes RotateSecret performs intact — so
// the secret is genuinely rotated, genuinely unrecoverable, and the device
// cannot authenticate. Telling the operator to "try again" there is wrong
// twice: nothing was undone, and trying again rotates it a second time.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceRotate_RenderFailureSaysTheSecretIsGone(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "rotate-fail@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "home-router")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)
	dropTable(t, st, "ip_history")

	form := url.Values{"csrf": {sess.CSRFToken}, "confirm_label": {dev.Label}}
	req := httptest.NewRequest(http.MethodPost, "/devices/"+dev.ID+"/rotate-secret",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "Please try again.") {
		t.Error("the rotate failure page says \"try again\" — but the secret is already rotated and gone")
	}
	for _, want := range []string{"rotated", "not recoverable", "Rotate it again"} {
		if !strings.Contains(body, want) {
			t.Errorf("rotate failure page missing %q:\n%s", want, body)
		}
	}
}

// TestAdminUserInvite_FailureSaysTheAccountMayExist asserts the invite failure
// page describes the partial effect instead of "try again".
//
// CreateUserInvite creates the user and THEN issues the grant, with no
// compensating delete (service/admin.go:100-109). Dropping the grant table
// fails the second step while the user row and its user.created audit entry
// survive — so a retry hits a duplicate-email conflict and the admin never
// learns why. The account is asserted to still exist, so the copy is checked
// against the real state and not just against itself.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestAdminUserInvite_FailureSaysTheAccountMayExist(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)
	dropTable(t, st, "account_recovery_tokens")

	form := url.Values{"csrf": {sess.CSRFToken}, "email": {"invitee@example.com"}, "role": {"user"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	users, err := deps.Admin.ListUsers(t.Context())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if _, ok := userIDByEmail(users, "invitee@example.com"); !ok {
		t.Fatal("expected the orphaned account to exist; the premise of this test no longer holds")
	}

	body := rec.Body.String()
	if strings.Contains(body, "Please try again.") {
		t.Error("the invite failure page says \"try again\" — a retry hits a duplicate-email conflict")
	}
	for _, want := range []string{"may already have been created", "recovery link"} {
		if !strings.Contains(body, want) {
			t.Errorf("invite failure page missing %q:\n%s", want, body)
		}
	}
}

// TestAdminUserRecovery_FailureSaysPasskeysAreRevoked asserts the recovery
// failure page says the passkeys are already gone.
//
// IssueRecovery calls DeleteAllByUser BEFORE minting (service/grants.go:125-131),
// so a mint failure leaves the target with no credential at all and no link.
// "Try again" understates it: the user is locked out right now. The credential
// count is asserted to be zero so the copy is checked against the real state.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestAdminUserRecovery_FailureSaysPasskeysAreRevoked(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "locked-out@example.com", "user")
	seedPasskey(t, st, target.ID, "laptop")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)
	dropTable(t, st, "account_recovery_tokens")

	form := url.Values{"csrf": {sess.CSRFToken}, "confirm_email": {target.Email}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+target.ID+"/recovery",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	n, err := st.WebAuthnCredentials().CountWebAuthnCredentials(t.Context(), target.ID)
	if err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if n != 0 {
		t.Fatalf("credentials = %d, want 0; the premise of this test no longer holds", n)
	}

	body := rec.Body.String()
	if strings.Contains(body, "Please try again.") {
		t.Error("the recovery failure page says \"try again\" — the passkeys are already revoked")
	}
	for _, want := range []string{"may already have been revoked", "another recovery link"} {
		if !strings.Contains(body, want) {
			t.Errorf("recovery failure page missing %q:\n%s", want, body)
		}
	}
}

// TestDeviceHistory_NextLinkPointsAtTheSameDevice is the device-history half of
// the pager-link guard (see TestAdminAudit_NextLinkPreservesFilters). This
// screen has no filters, so the property is narrower: the Next link stays on
// this device's history and carries a cursor the handler will accept.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceHistory_NextLinkPointsAtTheSameDevice(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "pager@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "home-router")
	cookie := signIn(t, deps, usr)

	// A full page, since HistoryPage.NextCursor is set only when the page is
	// full (store/ip_history.go:192-197).
	for range historyPageSize {
		seedHistory(t, st, dev.ID, "203.0.113.7", "", "diyddns-client/1.4.0")
	}

	req := httptest.NewRequest(http.MethodGet, "/devices/"+dev.ID+"/history", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	next, err := url.Parse(nextPagerURL(t, rec.Body.String()))
	if err != nil {
		t.Fatalf("parse Next URL: %v", err)
	}
	if want := "/devices/" + dev.ID + "/history"; next.Path != want {
		t.Errorf("Next path = %q, want %q", next.Path, want)
	}
	if next.Query().Get("cursor") == "" {
		t.Fatal("Next link carries no cursor")
	}

	follow := httptest.NewRequest(http.MethodGet, next.String(), nil)
	follow.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, follow)
	if rec2.Code != http.StatusOK {
		t.Fatalf("following the Next link = %d, want 200 — the cursor did not survive escaping", rec2.Code)
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

// TestDeviceRename_RejectPathsLeaveLabelUnchanged closes a gap left by
// TestDeviceRename_UpdatesAndRedirects, which only proves the happy path. A
// handler that returned 422 and renamed anyway would have passed before this
// test existed: both reject branches — empty label and a label collision —
// must leave the STORED label untouched, not merely answer 422.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceRename_RejectPathsLeaveLabelUnchanged(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "ren-reject@example.com", "user")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	t.Run("empty label", func(t *testing.T) {
		dev := seedDevice(t, st, usr.ID, "old-name")

		form := url.Values{"csrf": {sess.CSRFToken}, "label": {"   "}}
		req := httptest.NewRequest(http.MethodPost, "/devices/"+dev.ID+"/rename", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", rec.Code)
		}
		got, err := st.Devices().GetByID(t.Context(), dev.ID)
		if err != nil {
			t.Fatalf("get device: %v", err)
		}
		if got.Label != "old-name" {
			t.Errorf("label = %q, want unchanged %q (an empty label must not be stored)", got.Label, "old-name")
		}
	})

	t.Run("conflicting label", func(t *testing.T) {
		taken := seedDevice(t, st, usr.ID, "existing-name")
		dev := seedDevice(t, st, usr.ID, "old-name-2")

		form := url.Values{"csrf": {sess.CSRFToken}, "label": {taken.Label}}
		req := httptest.NewRequest(http.MethodPost, "/devices/"+dev.ID+"/rename", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", rec.Code)
		}
		got, err := st.Devices().GetByID(t.Context(), dev.ID)
		if err != nil {
			t.Fatalf("get device: %v", err)
		}
		if got.Label != "old-name-2" {
			t.Errorf("label = %q, want unchanged %q (a colliding rename must not be stored)", got.Label, "old-name-2")
		}
	})
}

// TestDeviceSetEnabled_TogglesStoredState closes a gap where the only
// coverage of POST /devices/{id}/enabled proved the CSRF and ownership
// guards, never the handler itself. Both directions are asserted — an
// inverted boolean would pass a test that only checked one — and the
// redirect is asserted too, since a broken redirect is one of the failure
// modes this gap hides. The stored Disabled flag is re-read from the store
// rather than trusted from the response.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestDeviceSetEnabled_TogglesStoredState(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	usr := seedUser(t, st, "toggle@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "toggle-box")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	postEnabled := func(t *testing.T, disabled string) *httptest.ResponseRecorder {
		t.Helper()
		form := url.Values{"csrf": {sess.CSRFToken}, "disabled": {disabled}}
		req := httptest.NewRequest(http.MethodPost, "/devices/"+dev.ID+"/enabled", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	t.Run("disable", func(t *testing.T) {
		rec := postEnabled(t, "true")
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303", rec.Code)
		}
		if got := rec.Header().Get("Location"); got != "/devices/"+dev.ID {
			t.Errorf("Location = %q, want %q", got, "/devices/"+dev.ID)
		}
		got, err := st.Devices().GetByID(t.Context(), dev.ID)
		if err != nil {
			t.Fatalf("get device: %v", err)
		}
		if !got.Disabled {
			t.Error("Disabled = false, want true after posting disabled=true")
		}
	})

	t.Run("re-enable", func(t *testing.T) {
		rec := postEnabled(t, "false")
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303", rec.Code)
		}
		if got := rec.Header().Get("Location"); got != "/devices/"+dev.ID {
			t.Errorf("Location = %q, want %q", got, "/devices/"+dev.ID)
		}
		got, err := st.Devices().GetByID(t.Context(), dev.ID)
		if err != nil {
			t.Fatalf("get device: %v", err)
		}
		if got.Disabled {
			t.Error("Disabled = true, want false after posting disabled=false")
		}
	})
}

// TestAdminRoutes_RequireAdmin covers the admin routes that exist AS OF THIS
// TASK. A role gate tested only on GETs would let a mutating route ship
// unguarded — the one that actually matters.
//
// Tasks 11, 12, and 13 each EXTEND this table as they register routes. The list
// must never name a route that is not yet registered: an unregistered path
// answers 404, not 403, so the test would fail with no correct way to make it
// pass. Task 13 Step 6 asserts the final table covers all ten.
func TestAdminRoutes_RequireAdmin(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)

	victim := seedUser(t, st, "victim@example.com", "user")
	usr := seedUser(t, st, "plain@example.com", "user")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	for _, rt := range []struct{ method, path string }{
		// Task 10 registers exactly these two.
		{http.MethodGet, "/admin/users"},
		{http.MethodPost, "/admin/users/" + victim.ID + "/enabled"},
		// Task 11 registers exactly these six.
		{http.MethodGet, "/admin/users/new"},
		{http.MethodPost, "/admin/users/new"},
		{http.MethodGet, "/admin/users/" + victim.ID},
		{http.MethodPost, "/admin/users/" + victim.ID + "/update"},
		{http.MethodPost, "/admin/users/" + victim.ID + "/delete"},
		{http.MethodPost, "/admin/users/" + victim.ID + "/recovery"},
		// Task 12 registers exactly this one.
		{http.MethodGet, "/admin/audit"},
		// Task 13 registers exactly this one — the last of the ten.
		{http.MethodGet, "/admin/server"},
	} {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			form := url.Values{
				"csrf":          {sess.CSRFToken}, // a VALID token: the role gate is what must reject
				"email":         {"someone@example.com"},
				"role":          {"admin"},
				"disabled":      {"true"},
				"confirm_email": {"victim@example.com"},
			}
			req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403 for a non-admin", rec.Code)
			}
		})
	}

	// The victim survived every attempt: still present, still a plain enabled
	// user, still holding whatever credentials they had.
	after, err := st.Users().GetByID(t.Context(), victim.ID)
	if err != nil {
		t.Fatalf("a non-admin deleted a user: %v", err)
	}
	if after.Role != "user" || after.Disabled {
		t.Errorf("a non-admin modified a user: %+v", after)
	}
}

func TestAdminUsers_ListsUsersAndCounts(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)

	admin := seedUser(t, st, "admin@example.com", "admin")
	other := seedUser(t, st, "mark@example.com", "user")
	seedDevice(t, st, other.ID, "marks-pi")

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.AddCookie(signIn(t, deps, admin))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"admin@example.com", "mark@example.com", "(you)"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	// The mock's Last login column is deliberately dropped.
	if strings.Contains(body, "Last login") {
		t.Error("Last login column rendered — no field or query backs it")
	}
}

func TestAdminUsers_ToggleDisabled(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)

	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "target@example.com", "user")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "disabled": {"true"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+target.ID+"/enabled", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	got, err := st.Users().GetByID(t.Context(), target.ID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if !got.Disabled {
		t.Error("user was not disabled")
	}
}

func TestAdminUsers_LastAdminGuardRendersBanner(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)

	admin := seedUser(t, st, "only-admin@example.com", "admin")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	// Disabling yourself is ErrSelfLockout; the service owns the guard and the
	// UI renders it rather than re-implementing it.
	form := url.Values{"csrf": {sess.CSRFToken}, "disabled": {"true"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+admin.ID+"/enabled", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	got, err := st.Users().GetByID(t.Context(), admin.ID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if got.Disabled {
		t.Fatal("the last admin disabled themselves")
	}
}

// seedPasskey inserts a WebAuthn credential for a user, so tests can assert
// whether a recovery revoked it.
func seedPasskey(t *testing.T, st *store.Store, userID, name string) {
	t.Helper()
	if _, err := st.WebAuthnCredentials().Create(t.Context(), store.WebAuthnCredential{
		CredentialID:   []byte("test-credential-" + userID),
		UserID:         userID,
		CredentialJSON: []byte("{}"),
		Name:           name,
		CreatedAt:      store.NowUnix(),
	}); err != nil {
		t.Fatalf("seed passkey: %v", err)
	}
}

// TestAdminUserRecovery_RequiresTypedConfirmation is deliberately not
// t.Parallel() — see TestAccount_RendersInAppShell: testDeps opens a store
// via goose, whose package-global state races under t.Parallel().
func TestAdminUserRecovery_RequiresTypedConfirmation(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)

	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "target@example.com", "user")
	seedPasskey(t, st, target.ID, "existing key")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "confirm_email": {"wrong@example.com"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+target.ID+"/recovery", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	// The critical assertion: a mismatched confirmation must not have revoked
	// the target's credentials. IssueRecovery deletes them BEFORE minting.
	n, err := st.WebAuthnCredentials().CountWebAuthnCredentials(t.Context(), target.ID)
	if err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if n == 0 {
		t.Fatal("passkeys were revoked despite a mismatched confirmation")
	}
}

// TestAdminUserInvite_RevealsLinkOnce is deliberately not t.Parallel() — see
// TestAdminUserRecovery_RequiresTypedConfirmation.
func TestAdminUserInvite_RevealsLinkOnce(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "email": {"newbie@example.com"}, "role": {"user"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// testDeps wires a REAL PasskeyService, so this must succeed. Accepting
	// "200 or 422" here would make the test vacuous and would leave the invite
	// reveal and grantLink with no coverage at all.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the reveal renders in the POST response); body=%s",
			rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"/register?token=", "Shown once", "one hour"} {
		if !strings.Contains(body, want) {
			t.Errorf("invite reveal missing %q", want)
		}
	}
	// The link must be absolute: GrantService builds it from cfg.Server.BaseURL,
	// which testDeps sets to https://ddns.test.
	if !strings.Contains(body, "https://ddns.test/register?token=") {
		t.Error("the invite link is not an absolute URL")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if _, err := st.Users().GetByEmail(t.Context(), "newbie@example.com"); err != nil {
		t.Errorf("the invited user was not created: %v", err)
	}
}

// TestAdminUserInvite_RelativeLinkGetsPrefixed covers grantLink's fallback: with
// server.base_url unset, GrantService returns a bare "/register?token=…", which
// is not a URL an admin can send anyone.
//
// Deliberately not t.Parallel() — see TestAdminUserRecovery_RequiresTypedConfirmation.
func TestAdminUserInvite_RelativeLinkGetsPrefixed(t *testing.T) {
	deps, st := testDeps(t)
	deps.Cfg.Server.BaseURL = ""
	// GrantService captured the base URL at construction, so rebuild the two
	// services that depend on it with an empty base.
	audit := service.NewAuditWriter(st)
	passkeys, err := service.NewPasskeyService(st, deps.Sessions, bytes.Repeat([]byte{0x24}, 32),
		deps.Cfg.Auth.WebAuthn, "localhost", "http://localhost", audit)
	if err != nil {
		t.Fatalf("NewPasskeyService: %v", err)
	}
	deps.Grants = service.NewGrantService(st, passkeys, nil, "", audit, deps.Log)
	deps.Admin = service.NewAdminService(st, audit, deps.Grants)
	h, _ := New(deps)

	admin := seedUser(t, st, "admin@example.com", "admin")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "email": {"newbie@example.com"}, "role": {"user"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "ddns.example.com"
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "http://ddns.example.com/register?token=") {
		t.Error("a relative grant link was not prefixed with the derived base URL")
	}
	if !strings.Contains(body, "server.base_url") {
		t.Error("the operator was not warned that server.base_url is unset")
	}
}

// TestAdminMutations_RequireCSRF is the admin counterpart to Task 8's device
// version, and it closes a gap the role-gate test cannot.
//
// TestAdminRoutes_RequireAdmin deliberately submits a VALID CSRF token so the
// role gate is what rejects. That means a route wired h.requireAdmin(...) where
// it should be h.requirePostAdmin(...) still answers 403 to a non-admin and
// passes every other test in this plan — while accepting a cross-site POST from
// a logged-in admin. This test is what catches that.
//
// Deliberately not t.Parallel() — see TestAdminUserRecovery_RequiresTypedConfirmation.
// Its own subtests stay non-parallel too, since they assert on shared user state
// after the loop completes.
func TestAdminMutations_RequireCSRF(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)

	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "target@example.com", "user")
	// Seed a passkey so the recovery route's assertion is meaningful: without
	// one, "credentials still exist" is trivially true and proves nothing.
	seedPasskey(t, st, target.ID, "existing key")
	cookie := signIn(t, deps, admin)

	for _, path := range []string{
		"/admin/users/new",
		"/admin/users/" + target.ID + "/enabled",
		"/admin/users/" + target.ID + "/update",
		"/admin/users/" + target.ID + "/delete",
		"/admin/users/" + target.ID + "/recovery",
	} {
		t.Run(path, func(t *testing.T) {
			form := url.Values{
				"csrf":          {"wrong-token"},
				"email":         {"someone@example.com"},
				"role":          {"admin"},
				"disabled":      {"true"},
				"confirm_email": {"target@example.com"}, // the REAL address, so only CSRF can reject
			}
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

	after, err := st.Users().GetByID(t.Context(), target.ID)
	if err != nil {
		t.Fatalf("a CSRF-less request deleted the user: %v", err)
	}
	if after.Role != "user" || after.Disabled {
		t.Errorf("a CSRF-less request modified the user: %+v", after)
	}
	n, err := st.WebAuthnCredentials().CountWebAuthnCredentials(t.Context(), target.ID)
	if err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if n == 0 {
		t.Error("a CSRF-less POST to /recovery revoked the target's passkeys")
	}
	// /admin/users/new is the one route in the loop above with no
	// side-effect-absence check of its own: the form posts email=someone@example.com,
	// so a CSRF-guard bug on that route specifically would silently create the user.
	if _, err := st.Users().GetByEmail(t.Context(), "someone@example.com"); err == nil {
		t.Error("a CSRF-less POST to /admin/users/new created the invited user")
	}
}

// TestAdminUserEdit_UnknownIDIs404 is deliberately not t.Parallel() — see
// TestAdminUserRecovery_RequiresTypedConfirmation.
func TestAdminUserEdit_UnknownIDIs404(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")

	req := httptest.NewRequest(http.MethodGet, "/admin/users/01920000-0000-7000-8000-000000000000", nil)
	req.AddCookie(signIn(t, deps, admin))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestAdminUserUpdate_NoOpSaveDoesNotAuditRoleChange is deliberately not
// t.Parallel() — see TestAdminUserRecovery_RequiresTypedConfirmation.
//
// AdminService.applyRole (internal/server/service/admin.go:172-182) audits
// user.role_change UNCONDITIONALLY whenever UpdateUserParams.Role is non-nil.
// handleAdminUserUpdate's changed-fields-only diff is the only thing standing
// between a routine "Save" click that touched nothing and a spurious audit
// entry on every single save — the exact regression an earlier revision of
// this plan shipped. This posts the target's CURRENT role/disabled values
// back unchanged and asserts no user.role_change entry was written, checking
// the event type specifically (not a total count) so an unrelated audit
// event can never mask a regression here.
func TestAdminUserUpdate_NoOpSaveDoesNotAuditRoleChange(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "target@example.com", "user")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "role": {"user"}, "disabled": {"false"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+target.ID+"/update", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}
	page, err := st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "user.role_change"}, "", 10)
	if err != nil {
		t.Fatalf("list audit log: %v", err)
	}
	if len(page.Rows) != 0 {
		t.Errorf("user.role_change audit entries = %d, want 0 — a no-op save must not audit a role change", len(page.Rows))
	}
}

// TestAdminUserUpdate_PersistsChanges is deliberately not t.Parallel() — see
// TestAdminUserRecovery_RequiresTypedConfirmation. Its subtests share the one
// store and admin session opened above, each against its own freshly-seeded
// target, so they stay non-parallel to avoid interleaving posts against a
// shared session's CSRF token.
func TestAdminUserUpdate_PersistsChanges(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	t.Run("role change persists", func(t *testing.T) {
		target := seedUser(t, st, "role-target@example.com", "user")
		form := url.Values{"csrf": {sess.CSRFToken}, "role": {"admin"}, "disabled": {"false"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/users/"+target.ID+"/update", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303; body=%s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Location"); got != "/admin/users/"+target.ID {
			t.Errorf("Location = %q, want %q", got, "/admin/users/"+target.ID)
		}
		got, err := st.Users().GetByID(t.Context(), target.ID)
		if err != nil {
			t.Fatalf("get user: %v", err)
		}
		if got.Role != "admin" {
			t.Errorf("role = %q, want %q — the change did not persist", got.Role, "admin")
		}
	})

	t.Run("disabled change persists", func(t *testing.T) {
		target := seedUser(t, st, "disable-target@example.com", "user")
		form := url.Values{"csrf": {sess.CSRFToken}, "role": {"user"}, "disabled": {"true"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/users/"+target.ID+"/update", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303; body=%s", rec.Code, rec.Body.String())
		}
		got, err := st.Users().GetByID(t.Context(), target.ID)
		if err != nil {
			t.Fatalf("get user: %v", err)
		}
		if !got.Disabled {
			t.Error("disabled = false, want true — the change did not persist")
		}
	})
}

// TestAdminUserDelete_RequiresMatchingEmail is deliberately not t.Parallel()
// — see TestAdminUserRecovery_RequiresTypedConfirmation.
func TestAdminUserDelete_RequiresMatchingEmail(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "doomed@example.com", "user")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "confirm_email": {"typo@example.com"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+target.ID+"/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	if _, err := st.Users().GetByID(t.Context(), target.ID); err != nil {
		t.Fatal("user was deleted despite a mismatched confirmation")
	}
}

// TestAdminUserDelete_Succeeds is deliberately not t.Parallel() — see
// TestAdminUserRecovery_RequiresTypedConfirmation.
func TestAdminUserDelete_Succeeds(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "doomed@example.com", "user")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "confirm_email": {"doomed@example.com"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+target.ID+"/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/admin/users" {
		t.Errorf("Location = %q, want %q", got, "/admin/users")
	}
	if _, err := st.Users().GetByID(t.Context(), target.ID); err == nil {
		t.Error("user still exists after a confirmed delete")
	}
}

// TestAdminUserRecovery_RevokesPasskeysAndRevealsLink covers the successful
// recovery path — the revoke-then-mint the confirmation gate exists to
// protect, which no other test covers.
//
// Deliberately not t.Parallel() — see TestAdminUserRecovery_RequiresTypedConfirmation.
func TestAdminUserRecovery_RevokesPasskeysAndRevealsLink(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)

	admin := seedUser(t, st, "admin@example.com", "admin")
	target := seedUser(t, st, "target@example.com", "user")
	seedPasskey(t, st, target.ID, "existing key")
	cookie := signIn(t, deps, admin)
	sess := sessionFor(t, deps, cookie)

	form := url.Values{"csrf": {sess.CSRFToken}, "confirm_email": {"target@example.com"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+target.ID+"/recovery", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"https://ddns.test/register?token=", "revoked", "one hour"} {
		if !strings.Contains(body, want) {
			t.Errorf("recovery reveal missing %q", want)
		}
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	n, err := st.WebAuthnCredentials().CountWebAuthnCredentials(t.Context(), target.ID)
	if err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if n != 0 {
		t.Errorf("credential count = %d, want 0 — IssueRecovery must revoke every passkey", n)
	}
}

// seedAudit appends an audit entry.
func seedAudit(t *testing.T, st *store.Store, actorID, eventType, targetType, targetID string) {
	t.Helper()
	if _, err := st.AuditLog().Append(t.Context(), store.AuditEntry{
		ActorUserID: actorID, EventType: eventType,
		TargetType: targetType, TargetID: targetID,
	}); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
}

// tableBody extracts the rendered <tbody>...</tbody> so assertions cannot be
// satisfied by the filter form's datalist, the echoed filter values, or the
// app shell.
//
// Matches the opening tag by prefix ("<tbody"), not the literal "<tbody>",
// because the htmx seam id lives on the tbody itself (<tbody id="audit-rows">,
// design §6.9: swapping the tbody keeps the thead's column headers across a
// filter request). A literal "<tbody>" match silently returns "" the moment
// the element carries an attribute, and every filter assertion downstream
// would then be asserting against an empty string — passing an absence check
// for the wrong reason.
// nextPagerURL returns the pager's "Next ›" target, un-escaped.
//
// It EXTRACTS the rendered href rather than reconstructing the expected one —
// reconstructing would re-derive the very code under test. Un-escaping is not
// optional: html/template escapes an attribute's & to &amp; and + to &#43;
// (url.Values.Encode writes a space as +), so a raw string comparison against
// the page fails for reasons that have nothing to do with pagination. Callers
// then assert per-parameter through url.Parse, which is also immune to
// Encode's alphabetical ordering.
func nextPagerURL(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`<a[^>]*href="([^"]*)"[^>]*>Next ›</a>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no Next link rendered; the page needs a full page of rows to produce one:\n%s", body)
	}
	return html.UnescapeString(m[1])
}

func tableBody(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, "<tbody")
	if start == -1 {
		return "" // no table rendered: an empty-state page
	}
	openTagEnd := strings.IndexByte(body[start:], '>')
	if openTagEnd == -1 {
		return ""
	}
	after := body[start+openTagEnd+1:]
	rows, _, _ := strings.Cut(after, "</tbody>")
	return rows
}

// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell: testDeps
// calls store.Open, and store.Migrate races on goose's package-global state
// when two stores open concurrently.
func TestAdminAudit_FiltersByEventType(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")

	seedAudit(t, st, admin.ID, "user.login.passkey", "user", admin.ID)
	seedAudit(t, st, admin.ID, "device.deleted", "device", "dev-1")

	req := httptest.NewRequest(http.MethodGet, "/admin/audit?event_type=device.deleted", nil)
	req.AddCookie(signIn(t, deps, admin))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// Assert against the TABLE BODY, not the whole page. Every event type also
	// appears in the filter's <datalist> of suggestions, so a whole-body
	// Contains check for "user.login.passkey" always matches and a whole-body
	// check for "device.deleted" passes even when filtering is broken.
	rows := tableBody(t, rec.Body.String())
	if !strings.Contains(rows, "device.deleted") {
		t.Error("filtered event missing from the table body")
	}
	if strings.Contains(rows, "user.login.passkey") {
		t.Error("an event outside the filter leaked into the table body")
	}
}

// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestAdminAudit_ResolvesActorEmail(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")
	seedAudit(t, st, admin.ID, "user.created", "user", "someone")
	seedAudit(t, st, "", "retention.prune", "", "") // system event: empty actor

	req := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
	req.AddCookie(signIn(t, deps, admin))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// Assert against the table body: the signed-in admin's own address appears in
	// the app shell's user chip, so a whole-page check for "admin@example.com"
	// passes even when actorLabel returns "".
	rows := tableBody(t, rec.Body.String())
	if !strings.Contains(rows, "admin@example.com") {
		t.Error("actor id was not resolved to an email in the table body")
	}
	if !strings.Contains(rows, "system") {
		t.Error("an empty actor did not render as system")
	}
}

// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestAdminAudit_UnknownActorEmailSaysSo(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")

	req := httptest.NewRequest(http.MethodGet, "/admin/audit?actor=nobody@example.com", nil)
	req.AddCookie(signIn(t, deps, admin))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "No user matches") {
		t.Error("an unmatched actor email must say so rather than silently showing everything")
	}
}

// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestAdminAudit_BadCursorIs400(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")

	req := httptest.NewRequest(http.MethodGet, "/admin/audit?event_type=device.deleted&cursor=garbage", nil)
	req.AddCookie(signIn(t, deps, admin))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	// Design §4.4: the page must offer a "start from the first page" link, and
	// it must drop only the cursor — an admin sent back to an unfiltered audit
	// log has lost the query they were reading.
	assertErrorPageLinksTo(t, rec.Body.String(), "/admin/audit?event_type=device.deleted")
}

// TestAdminAudit_NextLinkPreservesFilters asserts the rendered Next link keeps
// every filter parameter (design §6.7). A regression that dropped one would
// silently WIDEN an admin's query on page 2 — showing them events they had
// filtered out, under a heading that still says they are filtered — and no
// other test inspects a rendered pager link at all.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestAdminAudit_NextLinkPreservesFilters(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	admin := seedUser(t, st, "admin@example.com", "admin")

	// Exactly one full page of MATCHING rows: ListPaginated returns a
	// NextCursor only when len(rows) == limit (store/audit_log.go:203-207).
	for range auditPageSize {
		seedAudit(t, st, admin.ID, "device.deleted", "device", "dev-1")
	}
	seedAudit(t, st, admin.ID, "user.created", "user", "someone") // outside the filter

	const query = "event_type=device.deleted&actor=admin@example.com&from=2020-01-01&to=2099-12-31"
	req := httptest.NewRequest(http.MethodGet, "/admin/audit?"+query, nil)
	cookie := signIn(t, deps, admin)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	next, err := url.Parse(nextPagerURL(t, rec.Body.String()))
	if err != nil {
		t.Fatalf("parse Next URL: %v", err)
	}
	if next.Path != "/admin/audit" {
		t.Errorf("Next path = %q, want /admin/audit", next.Path)
	}
	q := next.Query()
	for key, want := range map[string]string{
		"event_type": "device.deleted",
		"actor":      "admin@example.com",
		"from":       "2020-01-01",
		"to":         "2099-12-31",
	} {
		if got := q.Get(key); got != want {
			t.Errorf("Next link %s = %q, want %q — page 2 would not be the query the admin was reading", key, got, want)
		}
	}
	if q.Get("cursor") == "" {
		t.Fatal("Next link carries no cursor")
	}

	// Follow it. This is what proves the cursor survived url.Values.Encode and
	// the template's attribute escaping: a mis-escaped cursor answers 400.
	follow := httptest.NewRequest(http.MethodGet, next.String(), nil)
	follow.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, follow)
	if rec2.Code != http.StatusOK {
		t.Fatalf("following the Next link = %d, want 200", rec2.Code)
	}
	// Page 2 holds only the row outside the filter, so a preserved filter shows
	// an empty table and a dropped one leaks "user.created" into it.
	if rows := tableBody(t, rec2.Body.String()); strings.Contains(rows, "user.created") {
		t.Error("an event outside the filter appeared on page 2")
	}
}

// TestAdminServer_ShowsInfoAndNoSecrets asserts the three secrets this page
// sits next to never reach the rendered body.
//
// OIDC is ENABLED here on purpose. oidcNote returns "" immediately when
// auth.oidc.enabled is false (admin.go), so with OIDC left off the
// client-secret assertion is satisfied by a short-circuit rather than by
// omission at the source: the whole formatting branch — the single most likely
// place the secret would ever be added — never executes, and the check passes
// against code that leaks. Enabling OIDC (and asserting the note actually
// rendered, below) is what makes the absence load-bearing.
//
// Deliberately not t.Parallel() — see TestAccount_RendersInAppShell.
func TestAdminServer_ShowsInfoAndNoSecrets(t *testing.T) {
	deps, st := testDeps(t)
	deps.Cfg.Auth.OIDC.Enabled = true
	deps.Cfg.Auth.OIDC.Issuer = "https://idp.example.com"
	deps.Cfg.Auth.OIDC.ClientID = "diyddns-web"
	deps.Cfg.Auth.OIDC.Scopes = []string{"openid", "email"}
	deps.Cfg.Auth.OIDC.ClientSecret = "super-secret-value"
	deps.Cfg.Auth.HMAC.SecretKey = "hmac-secret-value"
	deps.Cfg.Email.Password = "smtp-secret-value"
	h, _ := New(deps)

	admin := seedUser(t, st, "admin@example.com", "admin")
	req := httptest.NewRequest(http.MethodGet, "/admin/server", nil)
	req.AddCookie(signIn(t, deps, admin))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	for _, secret := range []string{"super-secret-value", "hmac-secret-value", "smtp-secret-value"} {
		if strings.Contains(body, secret) {
			t.Errorf("a secret leaked onto /admin/server: %q", secret)
		}
	}
	// Positive companions. An absence check alone is satisfied by a 500 or an
	// empty body, and the OIDC absence specifically is satisfied by oidcNote
	// short-circuiting — so assert the page rendered its content AND that the
	// OIDC branch the secret would live in actually ran.
	for _, want := range []string{"Uptime", "Go runtime", "15m0s", // 15m0s = staleAfter
		"https://idp.example.com", "diyddns-web", "openid email"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	// The settings form is deliberately absent.
	if strings.Contains(body, "Save settings") {
		t.Error("a settings form rendered; this page is read-only")
	}
}
