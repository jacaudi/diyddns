package webui

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// testDeps builds a webui.Deps backed by an in-memory store's SessionManager,
// mirroring internal/server/api's own white-box test harness pattern
// (openTestStore in that package's authmw_test.go).
func testDeps(t *testing.T) (Deps, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	sm := auth.NewSessionManager(st.Sessions(), st.Users(), time.Hour, time.Hour)
	cfg := config.Server{}
	cfg.Auth.Session.CookieName = "diyddns_session"
	return Deps{Sessions: sm, Cfg: cfg, Log: slog.New(slog.DiscardHandler)}, st
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

// TestRoot_RedirectsInsteadOf404 covers the bare base URL. There is no
// dashboard yet, so / used to 404 — a first-run operator visiting the address
// they were given dead-ended. It must redirect, and it must NOT become a
// catch-all: Go's ServeMux treats a bare "/" as a prefix match, which would
// turn every genuine 404 into a redirect too.
func TestRoot_RedirectsInsteadOf404(t *testing.T) {
	deps, _ := testDeps(t)
	h, _ := New(deps)

	t.Run("root redirects", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("GET / = %d, want %d", rec.Code, http.StatusSeeOther)
		}
		if loc := rec.Header().Get("Location"); loc != "/account" {
			t.Errorf("Location = %q, want /account", loc)
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
