package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/api"
)

// enableFeed flips FeedEnabled on deps in place, mirroring webui's
// enableFeed(&deps) helper (webui/feed_test.go) so both packages spell the
// same intent the same way.
func enableFeed(deps *api.ServerDeps) { deps.FeedEnabled = true }

// newFeedHarness builds the full server harness with the feed feature's
// enabled flag set explicitly, so the absent-when-disabled and
// present-when-enabled cases each get their own harness rather than mutating
// a shared one mid-test.
func newFeedHarness(t *testing.T, enabled bool) fullHarness {
	t.Helper()
	st, deps := buildServerDeps(t)
	if enabled {
		enableFeed(&deps)
	}

	mux := http.NewServeMux()
	api.Build(mux, deps)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return fullHarness{srv: srv, st: st}
}

// ---------- conditional registration ----------

// TestFeedTokenRoutes_AbsentWhenDisabled mirrors webui's
// TestFeedRoutes_AbsentWhenDisabled: with feed.enabled=false the REST
// operations are absent (404), not merely guarded.
func TestFeedTokenRoutes_AbsentWhenDisabled(t *testing.T) {
	h := newFeedHarness(t, false)
	seedUser(t, h.st, "feed-admin-off@example.com", "admin")
	cookie, csrf := sessionFor(t, h, "feed-admin-off@example.com")

	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/admin/feed/tokens"},
		{http.MethodPost, "/api/v1/admin/feed/tokens"},
		{http.MethodDelete, "/api/v1/admin/feed/tokens/some-id"},
	}
	for _, c := range cases {
		status, _, body := doJSON(t, c.method, h.srv.URL+c.path, nil, cookie, csrf)
		if status != http.StatusNotFound {
			t.Errorf("%s %s with feed.enabled=false = %d, want 404, body=%s", c.method, c.path, status, body)
		}
	}
}

// ---------- auth boundary ----------

// TestFeedTokensList_RequiresAdmin proves GET /api/v1/admin/feed/tokens is
// session+admin gated: anon -> 401, non-admin -> 403, admin -> 200.
func TestFeedTokensList_RequiresAdmin(t *testing.T) {
	h := newFeedHarness(t, true)
	seedUser(t, h.st, "feed-admin1@example.com", "admin")
	seedUser(t, h.st, "feed-user1@example.com", "user")

	userCookie, _ := sessionFor(t, h, "feed-user1@example.com")
	status, _, body := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/feed/tokens", nil, userCookie, "")
	if status != http.StatusForbidden {
		t.Fatalf("user: status = %d, want 403, body=%s", status, body)
	}

	adminCookie, _ := sessionFor(t, h, "feed-admin1@example.com")
	status, _, body = doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/feed/tokens", nil, adminCookie, "")
	if status != http.StatusOK {
		t.Fatalf("admin: status = %d, want 200, body=%s", status, body)
	}

	status, _, body = doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/feed/tokens", nil, nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("anon: status = %d, want 401, body=%s", status, body)
	}
}

// TestFeedTokensMint_RequiresCSRF proves POST /api/v1/admin/feed/tokens
// requires a valid CSRF token from an admin session, matching every other
// admin-write endpoint in this package.
func TestFeedTokensMint_RequiresCSRF(t *testing.T) {
	h := newFeedHarness(t, true)
	seedUser(t, h.st, "feed-admin2@example.com", "admin")
	adminCookie, adminCSRF := sessionFor(t, h, "feed-admin2@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/feed/tokens",
		map[string]string{"label": "envoy"}, adminCookie, "")
	if status != http.StatusForbidden {
		t.Fatalf("no csrf: status = %d, want 403, body=%s", status, body)
	}

	status, _, body = doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/feed/tokens",
		map[string]string{"label": "envoy"}, adminCookie, adminCSRF)
	if status != http.StatusOK {
		t.Fatalf("with csrf: status = %d, want 200, body=%s", status, body)
	}
}

// ---------- happy path + show-once invariant ----------

// TestFeedTokensMint_RevealsSecretOnceThenListNever is the invariant this
// issue's REST parity could most easily regress: the plaintext secret must
// appear in the mint response and MUST NEVER appear in the list response,
// for that token or any other.
func TestFeedTokensMint_RevealsSecretOnceThenListNever(t *testing.T) {
	h := newFeedHarness(t, true)
	seedUser(t, h.st, "feed-admin3@example.com", "admin")
	adminCookie, adminCSRF := sessionFor(t, h, "feed-admin3@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/feed/tokens",
		map[string]string{"label": "envoy"}, adminCookie, adminCSRF)
	if status != http.StatusOK {
		t.Fatalf("mint: status = %d, want 200, body=%s", status, body)
	}
	var minted struct {
		Token struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"token"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(body, &minted); err != nil {
		t.Fatalf("decode mint response: %v, body=%s", err, body)
	}
	if minted.Secret == "" {
		t.Fatalf("mint response carried no secret, body=%s", body)
	}
	if minted.Token.Label != "envoy" || minted.Token.ID == "" {
		t.Fatalf("mint response = %+v, want a non-empty token.id and token.label=envoy", minted)
	}

	status, _, listBody := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/feed/tokens", nil, adminCookie, "")
	if status != http.StatusOK {
		t.Fatalf("list: status = %d, want 200, body=%s", status, listBody)
	}
	if strings.Contains(string(listBody), minted.Secret) {
		t.Fatalf("list response leaked the minted secret: %s", listBody)
	}
	if strings.Contains(string(listBody), "\"secret\"") {
		t.Fatalf("list response carries a secret field at all: %s", listBody)
	}

	var rows []map[string]any
	if err := json.Unmarshal(listBody, &rows); err != nil {
		t.Fatalf("decode list response: %v, body=%s", err, listBody)
	}
	if len(rows) != 1 || rows[0]["id"] != minted.Token.ID || rows[0]["label"] != "envoy" {
		t.Fatalf("list rows = %+v, want one row for the minted token", rows)
	}
}

// TestFeedTokensMint_DuplicateLabelConflict proves a duplicate label surfaces
// as 409, matching the rest of this package's store.ErrConflict mapping.
func TestFeedTokensMint_DuplicateLabelConflict(t *testing.T) {
	h := newFeedHarness(t, true)
	seedUser(t, h.st, "feed-admin4@example.com", "admin")
	adminCookie, adminCSRF := sessionFor(t, h, "feed-admin4@example.com")

	body := map[string]string{"label": "dup"}
	status, _, respBody := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/feed/tokens", body, adminCookie, adminCSRF)
	if status != http.StatusOK {
		t.Fatalf("first mint: status = %d, want 200, body=%s", status, respBody)
	}
	status, _, respBody = doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/feed/tokens", body, adminCookie, adminCSRF)
	if status != http.StatusConflict {
		t.Fatalf("duplicate mint: status = %d, want 409, body=%s", status, respBody)
	}
}

// ---------- revoke ----------

// TestFeedTokensRevoke_RemovesTokenAndReturns404OnSecondCall proves revoke
// returns 204, removes the token from the list, and revoking again reports
// 404 (already gone).
func TestFeedTokensRevoke_RemovesTokenAndReturns404OnSecondCall(t *testing.T) {
	h := newFeedHarness(t, true)
	seedUser(t, h.st, "feed-admin5@example.com", "admin")
	adminCookie, adminCSRF := sessionFor(t, h, "feed-admin5@example.com")

	status, _, mintBody := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/feed/tokens",
		map[string]string{"label": "to-revoke"}, adminCookie, adminCSRF)
	if status != http.StatusOK {
		t.Fatalf("mint: status = %d, want 200, body=%s", status, mintBody)
	}
	var minted struct {
		Token struct {
			ID string `json:"id"`
		} `json:"token"`
	}
	if err := json.Unmarshal(mintBody, &minted); err != nil {
		t.Fatalf("decode mint response: %v, body=%s", err, mintBody)
	}

	status, _, revokeBody := doJSON(t, http.MethodDelete, h.srv.URL+"/api/v1/admin/feed/tokens/"+minted.Token.ID, nil, adminCookie, adminCSRF)
	if status != http.StatusNoContent {
		t.Fatalf("revoke: status = %d, want 204, body=%s", status, revokeBody)
	}

	_, _, listBody := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/feed/tokens", nil, adminCookie, "")
	var rows []map[string]any
	if err := json.Unmarshal(listBody, &rows); err != nil {
		t.Fatalf("decode list response: %v, body=%s", err, listBody)
	}
	if len(rows) != 0 {
		t.Fatalf("list after revoke = %+v, want empty", rows)
	}

	status, _, revokeBody = doJSON(t, http.MethodDelete, h.srv.URL+"/api/v1/admin/feed/tokens/"+minted.Token.ID, nil, adminCookie, adminCSRF)
	if status != http.StatusNotFound {
		t.Fatalf("revoke again: status = %d, want 404, body=%s", status, revokeBody)
	}
}
