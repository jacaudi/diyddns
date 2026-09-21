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
// as every #149 mint always produces) + session + csrf token, and a second
// user (returned still ENABLED, name kept as "disabledUser" for its role in
// the disabled-user tests, which flip it live via st.Users().SetDisabled)
// with their own key, and the log buffer.
func registerKeyOrSessionProbe(t *testing.T) (srv *httptest.Server, st *store.Store, keySvc *service.APIKeyService,
	admin store.User, adminKeyPlain string, adminSess store.Session, adminCSRF string,
	disabledUser store.User, disabledKeyPlain string, buf *bytes.Buffer) {
	t.Helper()
	st = openTestStore(t)

	admin, err := st.Users().Create(t.Context(), store.User{Email: "mwadmin@example.com", Role: "admin"})
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	// Seeded ENABLED, deliberately: a test that needs to prove the
	// disabled-user check reads LIVE state (design B3) must mint the key
	// while the owner is enabled, confirm it works, and only then disable
	// the owner via st.Users().SetDisabled and reuse the same key plaintext.
	// Minting for an already-disabled user cannot distinguish a live check
	// from a mint-time snapshot.
	disabledUser, err = st.Users().Create(t.Context(), store.User{Email: "mwdisabled@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed second user: %v", err)
	}

	keySvc = service.NewAPIKeyService(st, discardServiceAudit{})
	_, adminKeyPlain, err = keySvc.MintKey(t.Context(), admin.ID, "admin-probe-key")
	if err != nil {
		t.Fatalf("mint admin key: %v", err)
	}
	_, disabledKeyPlain, err = keySvc.MintKey(t.Context(), disabledUser.ID, "disabled-probe-key")
	if err != nil {
		t.Fatalf("mint second user's key: %v", err)
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
// live, not just at mint time. Proven by minting the key while the owner is
// still ENABLED, confirming it works, then flipping Disabled on the SAME
// user via the users repo and reusing the SAME key plaintext -- an
// implementation that (wrongly) stamped Disabled onto the key row at mint
// time would fail this test, unlike a test that only ever mints for an
// already-disabled user.
func TestSessionOrAPIKey_DisabledUsersKeyRejected(t *testing.T) {
	srv, st, _, _, _, _, _, disabledUser, disabledKeyPlain, _ := registerKeyOrSessionProbe(t)

	status, body := doProbe(t, http.MethodGet, srv.URL+"/api/v1/probe", nil, disabledKeyPlain, "")
	if status != http.StatusOK {
		t.Fatalf("enabled user's key: status = %d, want 200, body=%s", status, body)
	}

	if err := st.Users().SetDisabled(t.Context(), disabledUser.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}

	status, body = doProbe(t, http.MethodGet, srv.URL+"/api/v1/probe", nil, disabledKeyPlain, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("disabled user's key: status = %d, want 401, body=%s", status, body)
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

// TestSessionOrAPIKey_ValidKeyWinsOverValidSessionCookie: design D5's
// exclusive-credential rule proven with a VALID key alongside a VALID
// session cookie for the SAME admin user, not just a malformed one (see
// TestSessionOrAPIKey_ExclusiveCredential_MalformedBearerNeverFallsBack for
// the malformed-bearer case). The admin's own key is capped (AdminScope=false,
// as every #149 mint produces), so if the key's identity wins the response
// reports role "user"; if the cookie's real session identity leaked through
// instead, it would report "admin". This is a positive proof, not an
// inference from the malformed-bearer test: a session lookup that ran only
// AFTER a successful key auth (e.g. as an unintended merge/fallback) could
// still pass every existing test while leaking the cookie's real role here.
func TestSessionOrAPIKey_ValidKeyWinsOverValidSessionCookie(t *testing.T) {
	srv, _, _, admin, adminKeyPlain, adminSess, _, _, _, _ := registerKeyOrSessionProbe(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/probe", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: adminSess.ID}) // a VALID session cookie, real admin role
	req.Header.Set("Authorization", "Bearer "+adminKeyPlain)               // AND a VALID capped key, same user

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, body)
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
		t.Errorf("Role = %q, want %q -- the key's capped identity must win over the cookie's real admin identity", got.Role, "user")
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
	srv, st, _, _, _, _, _, disabledUser, disabledKeyPlain, _ := registerKeyOrSessionProbe(t)

	// The helper returns disabledUser still ENABLED (design B3 fix); disable
	// it here so "real key, owner disabled after mint" below actually
	// exercises the disabled_user rejection path, not a 200.
	if err := st.Users().SetDisabled(t.Context(), disabledUser.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}

	// wrong prefix, right shape is a control -- never touches keys.Authenticate.
	// unknownKey has the real prefix but no corresponding row: exercises the
	// unknown_key rejection path (Authenticate -> store.ErrNotFound).
	unknownKey := service.APIKeyPrefix + "0000000000000000000000000000000000000000"

	cases := []struct {
		name   string
		cookie *http.Cookie
		bearer string
	}{
		{"no credential at all", nil, ""},
		{"malformed bearer", nil, "not-even-close"},
		{"wrong prefix, right shape", nil, "ddf_" + "0123456789012345678901234567890123456789"},
		{"syntactically valid, unknown key", nil, unknownKey},
		{"real key, owner disabled after mint", nil, disabledKeyPlain},
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
