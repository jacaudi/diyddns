package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/api"
)

// newFeedHarness builds the full server harness with the feed feature's
// enabled flag set explicitly, so the absent-when-disabled and
// present-when-enabled cases each get their own harness rather than mutating
// a shared one mid-test.
func newFeedHarness(t *testing.T, enabled bool) fullHarness {
	t.Helper()
	st, deps := buildServerDeps(t)
	deps.FeedEnabled = enabled

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

	// GET and POST are discriminating on status code alone: wrongly
	// registered, they would answer 200, not 404.
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/admin/feed/tokens"},
		{http.MethodPost, "/api/v1/admin/feed/tokens"},
	}
	for _, c := range cases {
		status, _, body := doJSON(t, c.method, h.srv.URL+c.path, nil, cookie, csrf)
		if status != http.StatusNotFound {
			t.Errorf("%s %s with feed.enabled=false = %d, want 404, body=%s", c.method, c.path, status, body)
		}
	}

	// DELETE against a nonexistent id answers 404 whether or not the route is
	// registered — huma's "feed token not found" and the mux's own
	// absent-route 404 are both status 404 — so the status code alone cannot
	// prove the route is gone. Distinguish by body shape instead: an absent
	// route falls through to the stdlib mux's plain-text "404 page not
	// found", never huma's structured problem+json error body.
	status, _, body := doJSON(t, http.MethodDelete, h.srv.URL+"/api/v1/admin/feed/tokens/some-nonexistent-id", nil, cookie, csrf)
	if status != http.StatusNotFound {
		t.Fatalf("DELETE with feed.enabled=false = %d, want 404, body=%s", status, body)
	}
	if !strings.Contains(string(body), "page not found") {
		t.Errorf("DELETE with feed.enabled=false body = %s, want the stdlib mux's plain-text 404 (the route must be absent, not merely answering not-found)", body)
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

// TestFeedTokensMint_AnonymousUnauthorized proves POST
// /api/v1/admin/feed/tokens with no session is rejected 401, before CSRF or
// the admin role are ever checked.
func TestFeedTokensMint_AnonymousUnauthorized(t *testing.T) {
	h := newFeedHarness(t, true)

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/feed/tokens",
		map[string]string{"label": "envoy"}, nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("anon: status = %d, want 401, body=%s", status, body)
	}
}

// TestFeedTokensMint_NonAdminForbidden proves a non-admin session with a
// VALID CSRF token is still rejected 403 — the admin role check, not merely
// CSRF, gates mint (mirrors webui's TestFeedTokens_NonAdminIsForbidden).
func TestFeedTokensMint_NonAdminForbidden(t *testing.T) {
	h := newFeedHarness(t, true)
	seedUser(t, h.st, "feed-user-mint@example.com", "user")
	userCookie, userCSRF := sessionFor(t, h, "feed-user-mint@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/feed/tokens",
		map[string]string{"label": "envoy"}, userCookie, userCSRF)
	if status != http.StatusForbidden {
		t.Fatalf("non-admin with valid csrf: status = %d, want 403, body=%s", status, body)
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

// TestFeedTokensMint_EmptyLabelRejected proves an empty or whitespace-only
// label is rejected 422 via REST, matching the webui path's own validation
// (both now delegate to service.FeedService.MintToken's ErrInvalidLabel).
func TestFeedTokensMint_EmptyLabelRejected(t *testing.T) {
	h := newFeedHarness(t, true)
	seedUser(t, h.st, "feed-admin-empty@example.com", "admin")
	adminCookie, adminCSRF := sessionFor(t, h, "feed-admin-empty@example.com")

	for _, label := range []string{"", "   "} {
		status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/feed/tokens",
			map[string]string{"label": label}, adminCookie, adminCSRF)
		if status != http.StatusUnprocessableEntity {
			t.Errorf("label %q: status = %d, want 422, body=%s", label, status, body)
		}
	}

	status, _, listBody := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/feed/tokens", nil, adminCookie, "")
	if status != http.StatusOK {
		t.Fatalf("list: status = %d, want 200, body=%s", status, listBody)
	}
	var rows []map[string]any
	if err := json.Unmarshal(listBody, &rows); err != nil {
		t.Fatalf("decode list response: %v, body=%s", err, listBody)
	}
	if len(rows) != 0 {
		t.Errorf("list after rejected mints = %+v, want no rows", rows)
	}
}

// TestFeedTokensMint_TrimsLabel proves a label surrounded by whitespace is
// stored trimmed via REST, matching service.FeedService.MintToken's contract.
func TestFeedTokensMint_TrimsLabel(t *testing.T) {
	h := newFeedHarness(t, true)
	seedUser(t, h.st, "feed-admin-trim@example.com", "admin")
	adminCookie, adminCSRF := sessionFor(t, h, "feed-admin-trim@example.com")

	status, _, body := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/feed/tokens",
		map[string]string{"label": "  envoy  "}, adminCookie, adminCSRF)
	if status != http.StatusOK {
		t.Fatalf("mint: status = %d, want 200, body=%s", status, body)
	}
	var minted struct {
		Token struct {
			Label string `json:"label"`
		} `json:"token"`
	}
	if err := json.Unmarshal(body, &minted); err != nil {
		t.Fatalf("decode mint response: %v, body=%s", err, body)
	}
	if minted.Token.Label != "envoy" {
		t.Errorf("mint response label = %q, want %q (trimmed)", minted.Token.Label, "envoy")
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

// TestFeedTokensRevoke_RequiresAdminAndCSRF proves DELETE
// /api/v1/admin/feed/tokens/{id} rejects anon (401), a non-admin session with
// a VALID CSRF token (403), and an admin session with NO CSRF token (403) —
// exactly the regression class this test guards: feedWrite quietly
// downgraded to feedRead (dropping CSRF), or the admin check dropped, on a
// credential-revocation endpoint. A real token is seeded first and checked
// to still exist after every rejected attempt, so a wrongly-permissive gate
// would show up as the token being gone, not just a wrong status code.
func TestFeedTokensRevoke_RequiresAdminAndCSRF(t *testing.T) {
	h := newFeedHarness(t, true)
	seedUser(t, h.st, "feed-admin-revoke-auth@example.com", "admin")
	adminCookie, adminCSRF := sessionFor(t, h, "feed-admin-revoke-auth@example.com")
	seedUser(t, h.st, "feed-user-revoke-auth@example.com", "user")
	userCookie, userCSRF := sessionFor(t, h, "feed-user-revoke-auth@example.com")

	status, _, mintBody := doJSON(t, http.MethodPost, h.srv.URL+"/api/v1/admin/feed/tokens",
		map[string]string{"label": "revoke-auth-probe"}, adminCookie, adminCSRF)
	if status != http.StatusOK {
		t.Fatalf("seed mint: status = %d, want 200, body=%s", status, mintBody)
	}
	var minted struct {
		Token struct {
			ID string `json:"id"`
		} `json:"token"`
	}
	if err := json.Unmarshal(mintBody, &minted); err != nil {
		t.Fatalf("decode mint response: %v, body=%s", err, mintBody)
	}
	path := h.srv.URL + "/api/v1/admin/feed/tokens/" + minted.Token.ID

	if status, _, body := doJSON(t, http.MethodDelete, path, nil, nil, ""); status != http.StatusUnauthorized {
		t.Errorf("anon: status = %d, want 401, body=%s", status, body)
	}
	if status, _, body := doJSON(t, http.MethodDelete, path, nil, userCookie, userCSRF); status != http.StatusForbidden {
		t.Errorf("non-admin with valid csrf: status = %d, want 403, body=%s", status, body)
	}
	if status, _, body := doJSON(t, http.MethodDelete, path, nil, adminCookie, ""); status != http.StatusForbidden {
		t.Errorf("admin with no csrf: status = %d, want 403, body=%s", status, body)
	}

	status, _, listBody := doJSON(t, http.MethodGet, h.srv.URL+"/api/v1/admin/feed/tokens", nil, adminCookie, "")
	if status != http.StatusOK {
		t.Fatalf("list: status = %d, want 200, body=%s", status, listBody)
	}
	if !strings.Contains(string(listBody), minted.Token.ID) {
		t.Fatalf("token %s missing after rejected revoke attempts; one of them reached the handler, body=%s", minted.Token.ID, listBody)
	}
}
