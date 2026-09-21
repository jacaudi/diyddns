package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// registerKeyOrSessionProbe wires a throwaway op behind
// sessionOrAPIKeyMiddleware (+ csrfMiddleware chained after, matching the
// required session-mutation ordering) and returns everything a test needs:
// the server, a seeded admin user + their real API key (AdminScope=false,
// as every #149 mint always produces) + session + csrf token, a seeded
// disabled user + their key, and the log buffer.
func registerKeyOrSessionProbe(t *testing.T) (srv *httptest.Server, st *store.Store, keySvc *service.APIKeyService,
	admin store.User, adminKeyPlain string, adminSess store.Session, adminCSRF string,
	disabledUser store.User, disabledKeyPlain string, buf *bytes.Buffer) {
	t.Helper()
	st = openTestStore(t)

	admin, err := st.Users().Create(t.Context(), store.User{Email: "mwadmin@example.com", Role: "admin"})
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	disabledUser, err = st.Users().Create(t.Context(), store.User{Email: "mwdisabled@example.com", Role: "user", Disabled: true})
	if err != nil {
		t.Fatalf("seed disabled user: %v", err)
	}

	keySvc = service.NewAPIKeyService(st, discardServiceAudit{})
	_, adminKeyPlain, err = keySvc.MintKey(t.Context(), admin.ID, "admin-probe-key")
	if err != nil {
		t.Fatalf("mint admin key: %v", err)
	}
	_, disabledKeyPlain, err = keySvc.MintKey(t.Context(), disabledUser.ID, "disabled-probe-key")
	if err != nil {
		t.Fatalf("mint disabled-user key: %v", err)
	}

	sm := auth.NewSessionManager(st.Sessions(), st.Users(), time.Hour, time.Minute)
	adminSess, err = sm.Create(t.Context(), admin.ID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("SessionManager.Create: %v", err)
	}
	adminCSRF = adminSess.CSRFToken

	const path = "/api/v1/probe"
	mux := http.NewServeMux()
	probeAPI := humago.New(mux, huma.DefaultConfig("key-or-session-probe", "1"))

	log, buf := captureLogger()
	mw := sessionOrAPIKeyMiddleware(probeAPI, keySvc, sm, testCookieName, log)
	csrfMw := csrfMiddleware(probeAPI, log)

	type out struct {
		Body struct {
			UserID string `json:"userId"`
			Role   string `json:"role"`
		}
	}

	huma.Register(probeAPI, huma.Operation{
		Method:      http.MethodGet,
		Path:        path,
		Middlewares: huma.Middlewares{mw},
	}, func(ctx context.Context, _ *struct{}) (*out, error) {
		u := UserFrom(ctx)
		o := &out{}
		o.Body.UserID, o.Body.Role = u.ID, u.Role
		return o, nil
	})

	huma.Register(probeAPI, huma.Operation{
		Method:      http.MethodPost,
		Path:        path,
		Middlewares: huma.Middlewares{mw, csrfMw},
	}, func(ctx context.Context, _ *struct{}) (*out, error) {
		u := UserFrom(ctx)
		o := &out{}
		o.Body.UserID, o.Body.Role = u.ID, u.Role
		return o, nil
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return
}

// discardServiceAudit is a no-op AuditSink for this file's probes.
type discardServiceAudit struct{}

func (discardServiceAudit) Log(context.Context, store.AuditEntry) {}

func doProbe(t *testing.T, method, url string, cookie *http.Cookie, bearer, csrfHeader string) (status int, body []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if csrfHeader != "" {
		req.Header.Set("X-CSRF-Token", csrfHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBytes
}

// TestSessionOrAPIKey_CookieStillWorks: with no Authorization header, the
// cookie path behaves exactly as sessionMiddleware always has.
func TestSessionOrAPIKey_CookieStillWorks(t *testing.T) {
	srv, _, _, admin, _, adminSess, _, _, _, _ := registerKeyOrSessionProbe(t)

	status, body := doProbe(t, http.MethodGet, srv.URL+"/api/v1/probe",
		&http.Cookie{Name: testCookieName, Value: adminSess.ID}, "", "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	var got struct {
		UserID string `json:"userId"`
		Role   string `json:"role"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v, body=%s", err, body)
	}
	if got.UserID != admin.ID || got.Role != "admin" {
		t.Errorf("got = %+v, want userId %s role admin (session path: real role, uncapped)", got, admin.ID)
	}
}

// TestSessionOrAPIKey_KeyCapsRoleToUser is design D5's core property: an
// admin's own key (AdminScope=false, as every #149 mint produces) reaches
// the handler with role "user", not "admin" -- proven directly against the
// live middleware, not inferred from adminMW's separate behavior.
func TestSessionOrAPIKey_KeyCapsRoleToUser(t *testing.T) {
	srv, _, _, admin, adminKeyPlain, _, _, _, _, _ := registerKeyOrSessionProbe(t)

	status, body := doProbe(t, http.MethodGet, srv.URL+"/api/v1/probe", nil, adminKeyPlain, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	var got struct {
		UserID string `json:"userId"`
		Role   string `json:"role"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v, body=%s", err, body)
	}
	if got.UserID != admin.ID {
		t.Errorf("UserID = %q, want %q", got.UserID, admin.ID)
	}
	if got.Role != "user" {
		t.Errorf("Role = %q, want %q -- an admin's non-admin-scoped key must NOT report the real role", got.Role, "user")
	}
}

// TestSessionOrAPIKey_DisabledUsersKeyRejected pins design B3 (design-gate
// review): a disabled user's key must be rejected 401 on every request,
// live, not just at mint time.
func TestSessionOrAPIKey_DisabledUsersKeyRejected(t *testing.T) {
	srv, _, _, _, _, _, _, _, disabledKeyPlain, _ := registerKeyOrSessionProbe(t)

	status, body := doProbe(t, http.MethodGet, srv.URL+"/api/v1/probe", nil, disabledKeyPlain, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
}

// TestSessionOrAPIKey_ExclusiveCredential_MalformedBearerNeverFallsBack
// pins design D5's exclusive-credential rule: a non-empty Authorization
// header commits to the key path, full stop -- it never falls back to a
// SIMULTANEOUSLY VALID cookie, even a real admin session cookie.
func TestSessionOrAPIKey_ExclusiveCredential_MalformedBearerNeverFallsBack(t *testing.T) {
	srv, _, _, _, _, adminSess, _, _, _, _ := registerKeyOrSessionProbe(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/probe", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: adminSess.ID}) // a VALID session cookie
	req.Header.Set("Authorization", "Bearer not-a-real-key")               // AND a malformed bearer

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (the malformed bearer must win, never fall back to the valid cookie)", resp.StatusCode)
	}
}

// TestSessionOrAPIKey_401BodyUniform: every rejection reason returns a
// BYTE-IDENTICAL body that never names the reason (design D5's "one door,
// one answer" rule) -- mirrors TestHMACMiddleware_401BodyIdenticalAcrossReasons's
// exact assertion shape (authmw_test.go:207-254), NOT a hardcoded literal.
// This distinction matters and is corrected here from an earlier draft
// (caught by the plan-gate review, B-1): sessionOrAPIKeyMiddleware rejects
// via huma.WriteErr, the same call sessionMiddleware itself already uses --
// that produces huma's ErrorModel JSON shape (with a "$schema" field and a
// "detail" field), NOT the raw `{"error":"unauthorized"}` literal
// feed.TokenMiddleware writes. feed.TokenMiddleware is a plain stdlib
// http.Handler (mux.Handle, never registered through huma at all), so its
// literal-byte-write approach was never reachable from a huma middleware in
// the first place -- matching huma.WriteErr's shape is what makes this
// middleware's 401 CONSISTENT WITH sessionMiddleware's, which is the actual
// property design D5 needs (the "one door" is "every route in this huma API
// answers the same way", not "byte-identical to a completely different,
// non-huma-registered handler in a different package"). Never assert a
// hardcoded body literal against a huma.WriteErr call site; assert bodies
// are equal to EACH OTHER and never contain a reason word, exactly as this
// codebase's own HMAC precedent already does.
func TestSessionOrAPIKey_401BodyUniform(t *testing.T) {
	srv, _, _, _, _, _, _, _, _, _ := registerKeyOrSessionProbe(t)

	cases := []struct {
		name   string
		cookie *http.Cookie
		bearer string
	}{
		{"no credential at all", nil, ""},
		{"malformed bearer", nil, "not-even-close"},
		{"wrong prefix, right shape", nil, "ddf_" + "0123456789012345678901234567890123456789"},
	}
	bodies := make([]string, 0, len(cases))
	for _, tc := range cases {
		status, body := doProbe(t, http.MethodGet, srv.URL+"/api/v1/probe", tc.cookie, tc.bearer, "")
		if status != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401", tc.name, status)
		}
		bodies = append(bodies, string(body))
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Fatalf("401 body differs:\n  %s: %q\n  %s: %q", cases[0].name, bodies[0], cases[i].name, bodies[i])
		}
	}
	for _, leak := range []string{"malformed", "unknown", "disabled", "cancelled", "store_error", "ddf_"} {
		if strings.Contains(strings.ToLower(bodies[0]), leak) {
			t.Fatalf("401 body names a rejection reason (%q): %s", leak, bodies[0])
		}
	}
}

// TestCSRFGuard_SkippedOnlyForKeyAuthenticatedRequests: the CSRF guard
// added to csrfMiddleware (design D6) skips ONLY when
// sessionOrAPIKeyMiddleware itself set the flag on a SUCCESSFUL key auth --
// a cookie-authenticated POST still requires a valid CSRF token exactly as
// before, and a key-authenticated POST needs none.
func TestCSRFGuard_SkippedOnlyForKeyAuthenticatedRequests(t *testing.T) {
	srv, _, _, _, adminKeyPlain, adminSess, adminCSRF, _, _, _ := registerKeyOrSessionProbe(t)

	// Cookie + NO csrf header -> still 403, guard must not fire for session auth.
	status, body := doProbe(t, http.MethodPost, srv.URL+"/api/v1/probe",
		&http.Cookie{Name: testCookieName, Value: adminSess.ID}, "", "")
	if status != http.StatusForbidden {
		t.Fatalf("cookie without csrf: status = %d, want 403, body=%s", status, body)
	}

	// Cookie + correct csrf header -> 200, unaffected by this task's change.
	status, body = doProbe(t, http.MethodPost, srv.URL+"/api/v1/probe",
		&http.Cookie{Name: testCookieName, Value: adminSess.ID}, "", adminCSRF)
	if status != http.StatusOK {
		t.Fatalf("cookie with csrf: status = %d, want 200, body=%s", status, body)
	}

	// Key, no csrf header at all -> 200, the guard must skip.
	status, body = doProbe(t, http.MethodPost, srv.URL+"/api/v1/probe", nil, adminKeyPlain, "")
	if status != http.StatusOK {
		t.Fatalf("key without csrf: status = %d, want 200 (CSRF must be skipped for key auth), body=%s", status, body)
	}
}
