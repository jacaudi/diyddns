package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// doNoAuth sends method to path on srv with no cookie, no CSRF header, and no
// HMAC signature headers, and returns the response status code. It is
// deliberately credential-free — the whole point of the guard test is to
// prove every protected operation rejects a bare request.
func doNoAuth(t *testing.T, srv *httptest.Server, method, path string) int {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestGuard_ProtectedPathsRejectUnauthenticated behaviorally proves every
// session/CSRF/HMAC-protected operation fails closed. huma per-op middleware
// is not introspectable from outside the package, so this asserts the one
// thing that actually matters: an unauthenticated request to a protected
// path never succeeds (2xx) and never reaches the handler to produce a 5xx —
// it must be rejected at the middleware layer with 401 or 403. A future op
// that forgets to attach its auth middleware fails this test.
func TestGuard_ProtectedPathsRejectUnauthenticated(t *testing.T) {
	srv := newFullHarness(t).srv
	cases := []struct{ method, path string }{
		{http.MethodPost, "/agent/v1/checkin"},
		{http.MethodGet, "/agent/v1/self"},
		{http.MethodPost, "/api/v1/auth/logout"},
		{http.MethodGet, "/api/v1/auth/me"},
		{http.MethodPost, "/api/v1/devices"},
		{http.MethodGet, "/api/v1/devices"},
		{http.MethodGet, "/api/v1/devices/some-id"},
		{http.MethodGet, "/api/v1/admin/users"},
		{http.MethodPost, "/api/v1/admin/users"},
		{http.MethodPatch, "/api/v1/admin/users/some-id"},
		{http.MethodDelete, "/api/v1/admin/users/some-id"},
		{http.MethodGet, "/api/v1/admin/devices"},
		{http.MethodGet, "/api/v1/admin/devices/ips"},
		{http.MethodGet, "/api/v1/admin/audit"},
		{http.MethodGet, "/api/v1/admin/server"},
		{http.MethodPost, "/api/v1/account/passkeys/register/begin"},
		{http.MethodPost, "/api/v1/account/passkeys/register/finish"},
		{http.MethodGet, "/api/v1/account/passkeys"},
		{http.MethodPatch, "/api/v1/account/passkeys/some-id"},
		{http.MethodDelete, "/api/v1/account/passkeys/some-id"},
		{http.MethodPost, "/api/v1/admin/users/some-id/recovery"},
	}
	for _, c := range cases {
		code := doNoAuth(t, srv, c.method, c.path)
		if code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Errorf("%s %s returned %d (fail-open!), want 401 or 403", c.method, c.path, code)
		}
	}
}

// TestGuard_FeedTokenRoutesRejectUnauthenticated is
// TestGuard_ProtectedPathsRejectUnauthenticated's feed-token counterpart.
// newFullHarness's harness (used above) leaves FeedEnabled false, so the
// three feed-token routes are structurally absent (404) there and never
// exercise this safety net — this test drives the same behavioral check
// against a harness with the feed feature ON, so a future feed-token op that
// forgets its auth middleware fails here the same way it would above.
func TestGuard_FeedTokenRoutesRejectUnauthenticated(t *testing.T) {
	srv := newFeedHarness(t, true).srv
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/admin/feed/tokens"},
		{http.MethodPost, "/api/v1/admin/feed/tokens"},
		{http.MethodDelete, "/api/v1/admin/feed/tokens/some-id"},
	}
	for _, c := range cases {
		code := doNoAuth(t, srv, c.method, c.path)
		if code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Errorf("%s %s returned %d (fail-open!), want 401 or 403", c.method, c.path, code)
		}
	}
}

// TestGuard_NotificationRoutesRejectUnauthenticated is
// TestGuard_ProtectedPathsRejectUnauthenticated's counterpart for the seven
// #152 notification-endpoint/delivery operations. It runs against
// newNotificationHarness rather than newFullHarness: newFullHarness's
// deps.Notify is nil (notifications disabled), which keeps these routes off
// the mux entirely and would make every case here 404 — a route that isn't
// registered can't prove its auth middleware is attached. Asserting a bare
// 401 here (not "401 or 403", unlike the table above) is deliberate: every
// case sends no session cookie, so sessionMW always rejects first, before
// adminMW ever runs — 403 is only reachable for an authenticated non-admin,
// which none of these requests are.
func TestGuard_NotificationRoutesRejectUnauthenticated(t *testing.T) {
	srv := newNotificationHarness(t).srv
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/admin/endpoints"},
		{http.MethodPost, "/api/v1/admin/endpoints"},
		{http.MethodGet, "/api/v1/admin/endpoints/some-id"},
		{http.MethodPatch, "/api/v1/admin/endpoints/some-id"},
		{http.MethodDelete, "/api/v1/admin/endpoints/some-id"},
		{http.MethodPost, "/api/v1/admin/endpoints/some-id/test"},
		{http.MethodPost, "/api/v1/admin/deliveries/1/redeliver"},
	}
	for _, c := range cases {
		code := doNoAuth(t, srv, c.method, c.path)
		if code != http.StatusUnauthorized {
			t.Errorf("%s %s returned %d (fail-open!), want 401", c.method, c.path, code)
		}
	}
}
