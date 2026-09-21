package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// mintAKeyFor mints a real API key for the given already-seeded, already-
// logged-in user and returns its plaintext, so this file's tests can drive
// requests with a real Authorization header rather than a fabricated one.
func mintAKeyFor(t *testing.T, h fullHarness, cookie *http.Cookie, csrf string) string {
	t.Helper()
	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/account/keys",
		map[string]string{"label": "regression-probe"}, cookie, csrf)
	if status != http.StatusOK {
		t.Fatalf("mint key: status = %d, want 200, body=%s", status, body)
	}
	var minted struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(body, &minted); err != nil {
		t.Fatalf("decode mint response: %v, body=%s", err, body)
	}
	return minted.Secret
}

// doBearer issues method/path with ONLY a bearer Authorization header, no
// cookie and no body -- the shape every test below needs to prove a route
// is (or is not) reachable by a capped API key. Every route this file
// probes with doBearer is a GET or DELETE, none of which have a required
// request body -- see doBearerJSON for the one route that does.
func doBearer(t *testing.T, method, url, bearer string) (status int, body []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// doBearerJSON is doBearer plus a JSON-encoded body, mirroring doJSON's own
// body-marshaling shape (auth_ops_test.go) but with a bearer header instead
// of a cookie+CSRF pair. Needed because POST /api/v1/devices requires a
// non-empty body (mintCodeInput.Body.Label, devices.go:16-20) -- huma
// rejects an empty body with 400 before the handler ever runs, so a bearer
// probe against this route with no body cannot prove the middleware swap
// worked at all (fixed by the plan-gate review, B-2, which measured exactly
// this 400).
func doBearerJSON(t *testing.T, method, url string, body any, bearer string) (status int, respBody []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBytes
}

// ---------- B1/B2: the two account-takeover paths must reject a key ----------

// TestAPIKey_CannotTouchPasskeys pins design B1: every one of the five
// /api/v1/account/passkeys* operations rejects a valid API key with 401,
// proving the exclusion is enforced, not just documented. This is the
// regression suite that would have caught B1 before merge.
func TestAPIKey_CannotTouchPasskeys(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "b1-passkeys@example.com", "user")
	cookie, csrf := sessionFor(t, h, "b1-passkeys@example.com")
	key := mintAKeyFor(t, h, cookie, csrf)

	cases := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/account/passkeys/register/begin"},
		{http.MethodPost, "/api/v1/account/passkeys/register/finish"},
		{http.MethodGet, "/api/v1/account/passkeys"},
		{http.MethodPatch, "/api/v1/account/passkeys/some-id"},
		{http.MethodDelete, "/api/v1/account/passkeys/some-id"},
	}
	for _, c := range cases {
		status, body := doBearer(t, c.method, h.srv.URL+c.path, key)
		if status != http.StatusUnauthorized {
			t.Errorf("%s %s with a valid API key = %d, want 401 (session-only, per design B1), body=%s",
				c.method, c.path, status, body)
		}
	}
}

// TestAPIKey_CannotTouchEmailChange pins design B2: every one of the three
// /api/v1/account/email* operations rejects a valid API key with 401.
func TestAPIKey_CannotTouchEmailChange(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "b2-email@example.com", "user")
	cookie, csrf := sessionFor(t, h, "b2-email@example.com")
	key := mintAKeyFor(t, h, cookie, csrf)

	cases := []string{"/api/v1/account/email", "/api/v1/account/email/cancel", "/api/v1/account/email/confirm"}
	for _, path := range cases {
		status, body := doBearer(t, http.MethodPost, h.srv.URL+path, key)
		if status != http.StatusUnauthorized {
			t.Errorf("POST %s with a valid API key = %d, want 401 (session-only, per design B2), body=%s", path, status, body)
		}
	}
}

// TestAPIKey_CannotLogout and TestAPIKey_CannotManageAPIKeys pin design D6
// and D4 respectively: logout and the key-management surface itself are
// never reachable by any key.
func TestAPIKey_CannotLogout(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "d6-logout@example.com", "user")
	cookie, csrf := sessionFor(t, h, "d6-logout@example.com")
	key := mintAKeyFor(t, h, cookie, csrf)

	status, body := doBearer(t, http.MethodPost, h.srv.URL+"/api/v1/auth/logout", key)
	if status != http.StatusUnauthorized {
		t.Errorf("logout with a valid API key = %d, want 401, body=%s", status, body)
	}
}

func TestAPIKey_CannotManageAPIKeys(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "d4-keys@example.com", "user")
	cookie, csrf := sessionFor(t, h, "d4-keys@example.com")
	key := mintAKeyFor(t, h, cookie, csrf)

	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/account/keys"},
		{http.MethodPost, "/api/v1/account/keys"},
		{http.MethodDelete, "/api/v1/account/keys/some-id"},
	}
	for _, c := range cases {
		status, body := doBearer(t, c.method, h.srv.URL+c.path, key)
		if status != http.StatusUnauthorized {
			t.Errorf("%s %s with a valid API key = %d, want 401 (design D4), body=%s", c.method, c.path, status, body)
		}
	}
}

// ---------- D7: the routes that DO swap ----------

// TestAPIKey_CanReadOwnIdentityAndDevices pins the positive side of D7 --
// /auth/me and every device op are reachable by a capped key.
func TestAPIKey_CanReadOwnIdentityAndDevices(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "d7-devices@example.com", "user")
	cookie, csrf := sessionFor(t, h, "d7-devices@example.com")
	key := mintAKeyFor(t, h, cookie, csrf)

	status, body := doBearer(t, http.MethodGet, h.srv.URL+"/api/v1/auth/me", key)
	if status != http.StatusOK {
		t.Fatalf("GET /auth/me with a valid API key = %d, want 200, body=%s", status, body)
	}

	status, body = doBearer(t, http.MethodGet, h.srv.URL+"/api/v1/devices", key)
	if status != http.StatusOK {
		t.Fatalf("GET /devices with a valid API key = %d, want 200, body=%s", status, body)
	}

	status, body = doBearerJSON(t, http.MethodPost, h.srv.URL+"/api/v1/devices", map[string]string{"label": "d7-probe-device"}, key)
	if status != http.StatusOK {
		t.Fatalf("POST /devices (mint enrollment code) with a valid API key = %d, want 200, body=%s", status, body)
	}
}

// TestAPIKey_403sOnAdminRoute_EvenWhenMintedByAnAdmin pins design B4's
// resolved contradiction directly: a NON-admin-scoped key -- the only kind
// #149 can mint, even for an admin user -- reaches adminMW (not rejected
// earlier by a missing sessionOrKeyMW wiring) and is capped there, 403, not
// 401.
func TestAPIKey_403sOnAdminRoute_EvenWhenMintedByAnAdmin(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "b4-adminuser@example.com", "admin")
	cookie, csrf := sessionFor(t, h, "b4-adminuser@example.com")
	key := mintAKeyFor(t, h, cookie, csrf)

	status, body := doBearer(t, http.MethodGet, h.srv.URL+"/api/v1/admin/users", key)
	if status != http.StatusForbidden {
		t.Fatalf("admin's own (non-admin-scoped) key against an admin route = %d, want 403 (reaches adminMW and is capped there), body=%s",
			status, body)
	}
}

// TestAPIKey_AdminScopedKeyPassesAdminMW is the #167-readiness test named
// explicitly in design §3/NEW-4: no production path can set admin_scope
// today, so this test sets it directly via raw SQL against store.Store.DB(),
// proving the mechanism (not the not-yet-existing feature) already works.
func TestAPIKey_AdminScopedKeyPassesAdminMW(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "new4-adminscoped@example.com", "admin")
	cookie, csrf := sessionFor(t, h, "new4-adminscoped@example.com")
	key := mintAKeyFor(t, h, cookie, csrf)

	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/account/keys", nil, cookie, "")
	if status != http.StatusOK {
		t.Fatalf("list keys to find the id: status = %d, body=%s", status, body)
	}
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatalf("decode: %v, body=%s", err, body)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want exactly one key", rows)
	}
	id, _ := rows[0]["id"].(string)

	if _, err := h.st.DB().ExecContext(t.Context(), `UPDATE api_keys SET admin_scope = 1 WHERE id = ?`, id); err != nil {
		t.Fatalf("raw admin_scope update: %v", err)
	}

	status, body = doBearer(t, http.MethodGet, h.srv.URL+"/api/v1/admin/users", key)
	if status != http.StatusOK {
		t.Fatalf("admin-scoped key against an admin route = %d, want 200 (proves #167 needs zero adminMW changes), body=%s", status, body)
	}
}

// TestAPIKey_DisabledUserRejectedOnDeviceRoute is the route-level companion
// to Task 3's middleware-level TestSessionOrAPIKey_DisabledUsersKeyRejected
// -- proving the wiring, not just the middleware in isolation, enforces B3.
func TestAPIKey_DisabledUserRejectedOnDeviceRoute(t *testing.T) {
	h := newFullHarness(t)
	seedUser(t, h.st, "b3-disabled@example.com", "user")
	cookie, csrf := sessionFor(t, h, "b3-disabled@example.com")
	key := mintAKeyFor(t, h, cookie, csrf)

	usr, err := h.st.Users().GetByEmail(t.Context(), "b3-disabled@example.com")
	if err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	if err := h.st.Users().SetDisabled(t.Context(), usr.ID, true); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	status, body := doBearer(t, http.MethodGet, h.srv.URL+"/api/v1/devices", key)
	if status != http.StatusUnauthorized {
		t.Fatalf("disabled user's key against /devices = %d, want 401, body=%s", status, body)
	}
}
