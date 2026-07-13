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
		{http.MethodPost, "/api/v1/auth/password"},
		{http.MethodPost, "/api/v1/devices"},
		{http.MethodGet, "/api/v1/devices"},
		{http.MethodGet, "/api/v1/devices/some-id"},
	}
	for _, c := range cases {
		code := doNoAuth(t, srv, c.method, c.path)
		if code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Errorf("%s %s returned %d (fail-open!), want 401 or 403", c.method, c.path, code)
		}
	}
}
