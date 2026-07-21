package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

// authTestCookieName mirrors the default cookie name from config's
// keyDefaults, kept as a local literal so this file doesn't depend on
// config's internal default map.
const authTestCookieName = "diyddns_session"

// cheapPasswordCfg keeps argon2id fast enough for tests (mirrors
// agent_test.go's seedAgentUserWithPassword params).
func cheapPasswordCfg() config.PasswordCfg {
	return config.PasswordCfg{Argon2Time: 1, Argon2MemoryKiB: 8 * 1024, Argon2Parallelism: 1, MinLength: 8}
}

// authHarness bundles a full api.Build-assembled server with the concrete
// store, session manager, and auth/bootstrap services needed to drive the
// browser auth + bootstrap HTTP surface end to end.
type authHarness struct {
	srv       *httptest.Server
	st        *store.Store
	sessions  *auth.SessionManager
	bootstrap *service.BootstrapService
	cfg       config.Auth
}

// newAuthHarness assembles a real :memory: store and the auth/bootstrap
// services, wires them through api.Build onto a fresh mux, and captures any
// bootstrap token minted by Startup via tokenSink instead of logging it.
func newAuthHarness(t *testing.T, tokenSink func(token string)) authHarness {
	t.Helper()
	st, err := store.Open(t.Context(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := config.Auth{
		Session: config.SessionCfg{
			CookieName:   authTestCookieName,
			CookieSecure: false,
			TTL:          time.Hour,
			SlideWindow:  time.Minute,
		},
		Password: cheapPasswordCfg(),
	}

	sessions := auth.NewSessionManager(st.Sessions(), st.Users(), cfg.Session.TTL, cfg.Session.SlideWindow)

	authSvc, err := service.NewAuthService(st, sessions, cfg.Password, discardAgentAudit{})
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bootstrapSvc := service.NewBootstrapService(st, cfg.Bootstrap, cfg.Password, log, discardAgentAudit{}, tokenSink, nil, nil)

	mux := http.NewServeMux()
	api.Build(mux, api.ServerDeps{
		Log:       log,
		Store:     st,
		Sessions:  sessions,
		Auth:      authSvc,
		Bootstrap: bootstrapSvc,
		Cfg:       cfg,
		Info:      version.Info{Version: "v1.2.3"},
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return authHarness{srv: srv, st: st, sessions: sessions, bootstrap: bootstrapSvc, cfg: cfg}
}

// doJSON sends method to url with an optional JSON body, cookie, and CSRF
// header. It reads and closes the response body itself — the same
// self-contained shape as agent_test.go's postJSON — and returns the status
// code, response header (for Set-Cookie inspection via findCookie), and raw
// body bytes, so callers never hold a live response.Body to leak.
func doJSON(t *testing.T, method, url string, body any, cookie *http.Cookie, csrf string) (status int, header http.Header, respBody []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp.StatusCode, resp.Header, respBody
}

// findCookie returns the named cookie parsed from header's Set-Cookie
// entries, or nil if absent.
func findCookie(header http.Header, name string) *http.Cookie {
	resp := &http.Response{Header: header}
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// seedAuthUserWithPassword creates a user with an argon2id password hash
// for login tests.
func seedAuthUserWithPassword(t *testing.T, st *store.Store, email, password string) store.User {
	t.Helper()
	hash, err := auth.HashPassword(password, auth.Argon2Params{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1})
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	u, err := st.Users().Create(context.Background(), store.User{Email: email, Role: "user", PasswordHash: hash})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

func TestLogin_SetsSessionCookieWithHttpOnlyAndSameSiteLax(t *testing.T) {
	h := newAuthHarness(t, nil)
	seedAuthUserWithPassword(t, h.st, "login@example.com", "correct horse battery staple")

	status, header, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/login", map[string]string{
		"email": "login@example.com", "password": "correct horse battery staple",
	}, nil, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}

	cookie := findCookie(header, authTestCookieName)
	if cookie == nil {
		t.Fatalf("no %s cookie in response; headers=%v", authTestCookieName, header)
	}
	if !cookie.HttpOnly {
		t.Fatal("session cookie is not HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.Value == "" {
		t.Fatal("session cookie has empty value")
	}
}

func TestLogin_BadCredentialsReturns401(t *testing.T) {
	h := newAuthHarness(t, nil)
	seedAuthUserWithPassword(t, h.st, "login2@example.com", "correct horse battery staple")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/login", map[string]string{
		"email": "login2@example.com", "password": "wrong-password",
	}, nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
}

func TestMe_WithSessionCookieReturnsUserAndCSRF(t *testing.T) {
	h := newAuthHarness(t, nil)
	usr := seedAuthUserWithPassword(t, h.st, "me@example.com", "correct horse battery staple")

	_, loginHeader, _ := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/login", map[string]string{
		"email": "me@example.com", "password": "correct horse battery staple",
	}, nil, "")
	cookie := findCookie(loginHeader, authTestCookieName)
	if cookie == nil {
		t.Fatal("no session cookie from login")
	}

	status, _, meBody := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/auth/me", nil, cookie, "")
	if status != http.StatusOK {
		t.Fatalf("me status = %d, want 200, body=%s", status, meBody)
	}

	var got struct {
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"user"`
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(meBody, &got); err != nil {
		t.Fatalf("decode me response: %v, body=%s", err, meBody)
	}
	if got.User.ID != usr.ID || got.User.Email != usr.Email || got.User.Role != usr.Role {
		t.Fatalf("me user = %+v, want id=%q email=%q role=%q", got.User, usr.ID, usr.Email, usr.Role)
	}
	if got.CSRF == "" {
		t.Fatal("me returned empty csrf token")
	}
}

func TestPassword_RequiresCookieAndMatchingCSRFToken(t *testing.T) {
	h := newAuthHarness(t, nil)
	seedAuthUserWithPassword(t, h.st, "pw@example.com", "correct horse battery staple")

	_, loginHeader, _ := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/login", map[string]string{
		"email": "pw@example.com", "password": "correct horse battery staple",
	}, nil, "")
	cookie := findCookie(loginHeader, authTestCookieName)
	if cookie == nil {
		t.Fatal("no session cookie from login")
	}

	_, _, meBody := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/auth/me", nil, cookie, "")
	var me struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(meBody, &me); err != nil {
		t.Fatalf("decode me: %v", err)
	}

	t.Run("missing csrf token returns 403", func(t *testing.T) {
		status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/password", map[string]string{
			"old_password": "correct horse battery staple", "new_password": "new password long enough",
		}, cookie, "")
		if status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", status, body)
		}
	})

	t.Run("wrong csrf token returns 403", func(t *testing.T) {
		status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/password", map[string]string{
			"old_password": "correct horse battery staple", "new_password": "new password long enough",
		}, cookie, "wrong-token")
		if status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", status, body)
		}
	})

	t.Run("wrong old password with matching csrf returns 422 uniformly", func(t *testing.T) {
		status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/password", map[string]string{
			"old_password": "not the right old password", "new_password": "new password long enough",
		}, cookie, me.CSRF)
		if status != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body=%s", status, body)
		}
	})

	t.Run("too-short new password with matching csrf returns 422 uniformly", func(t *testing.T) {
		status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/password", map[string]string{
			"old_password": "correct horse battery staple", "new_password": "short",
		}, cookie, me.CSRF)
		if status != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body=%s", status, body)
		}
	})

	t.Run("matching cookie and csrf token succeeds and new password works", func(t *testing.T) {
		status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/password", map[string]string{
			"old_password": "correct horse battery staple", "new_password": "new password long enough",
		}, cookie, me.CSRF)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", status, body)
		}

		newLoginStatus, _, newLoginBody := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/login", map[string]string{
			"email": "pw@example.com", "password": "new password long enough",
		}, nil, "")
		if newLoginStatus != http.StatusOK {
			t.Fatalf("login with new password status = %d, want 200, body=%s", newLoginStatus, newLoginBody)
		}
	})
}

func TestLogout_ClearsSessionSoSubsequentMeReturns401(t *testing.T) {
	h := newAuthHarness(t, nil)
	seedAuthUserWithPassword(t, h.st, "logout@example.com", "correct horse battery staple")

	_, loginHeader, _ := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/login", map[string]string{
		"email": "logout@example.com", "password": "correct horse battery staple",
	}, nil, "")
	cookie := findCookie(loginHeader, authTestCookieName)
	if cookie == nil {
		t.Fatal("no session cookie from login")
	}

	logoutStatus, _, logoutBody := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/logout", nil, cookie, "")
	if logoutStatus != http.StatusOK {
		t.Fatalf("logout status = %d, want 200, body=%s", logoutStatus, logoutBody)
	}

	meStatus, _, meBody := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/auth/me", nil, cookie, "")
	if meStatus != http.StatusUnauthorized {
		t.Fatalf("me after logout status = %d, want 401, body=%s", meStatus, meBody)
	}
}

func TestBootstrap_FreshStoreCreatesAdminThenSecondAttemptReturns410(t *testing.T) {
	var token string
	h := newAuthHarness(t, func(tok string) { token = tok })

	if err := h.bootstrap.Startup(t.Context()); err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if token == "" {
		t.Fatal("Startup did not mint a bootstrap token")
	}

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/bootstrap", map[string]string{
		"token": token, "email": "admin@example.com", "password": "admin password long enough",
	}, nil, "")
	if status != http.StatusOK {
		t.Fatalf("first bootstrap status = %d, want 200, body=%s", status, body)
	}

	admin, err := h.st.Users().GetByEmail(t.Context(), "admin@example.com")
	if err != nil {
		t.Fatalf("GetByEmail(admin): %v", err)
	}
	if admin.Role != "admin" {
		t.Fatalf("created user role = %q, want admin", admin.Role)
	}

	secondStatus, _, secondBody := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/auth/bootstrap", map[string]string{
		"token": token, "email": "second-admin@example.com", "password": "admin password long enough",
	}, nil, "")
	if secondStatus != http.StatusGone {
		t.Fatalf("second bootstrap status = %d, want 410, body=%s", secondStatus, secondBody)
	}
}
