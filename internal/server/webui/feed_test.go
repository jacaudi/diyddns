package webui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

func enableFeed(deps *Deps) { deps.Cfg.Feed.Enabled = true }

func TestFeedRoutes_AbsentWhenDisabled(t *testing.T) {
	deps, st := testDeps(t)
	h, _ := New(deps)
	cookie, sess := adminSession(t, deps, st, "admin@example.com")

	if rec := getPage(t, h, cookie, "/admin/feed"); rec.Code != http.StatusNotFound {
		t.Errorf("GET /admin/feed with feed.enabled=false = %d, want 404", rec.Code)
	}
	if rec := postForm(t, h, cookie, "/admin/feed/tokens", url.Values{"csrf": {sess.CSRFToken}, "label": {"x"}}); rec.Code != http.StatusNotFound {
		t.Errorf("POST /admin/feed/tokens with feed.enabled=false = %d, want 404", rec.Code)
	}
}

// TestFeedTokens_NonAdminIsForbidden: every feed-token route is admin-only.
// Both POST cases carry a VALID CSRF token from the non-admin's own session
// (requirePostAdmin checks CSRF before the role — see the equivalent comment
// on TestEndpoints_NonAdminIsForbidden), so a regression that dropped
// adminOnly from one of these routes would not stay green by accident.
func TestFeedTokens_NonAdminIsForbidden(t *testing.T) {
	deps, st := testDeps(t)
	enableFeed(&deps)
	h, _ := New(deps)
	now := store.NowUnix()
	tok := store.FeedToken{ID: store.NewID(), Label: "existing", TokenHash: "test-hash", CreatedAt: now}
	if err := st.FeedTokens().Create(t.Context(), tok); err != nil {
		t.Fatalf("seed feed token: %v", err)
	}
	usr := seedUser(t, st, "plain@example.com", "user")
	cookie := signIn(t, deps, usr)
	sess := sessionFor(t, deps, cookie)

	if rec := getPage(t, h, cookie, "/admin/feed"); rec.Code != http.StatusForbidden {
		t.Errorf("GET /admin/feed as a user = %d, want 403", rec.Code)
	}
	if rec := postForm(t, h, cookie, "/admin/feed/tokens", url.Values{"csrf": {sess.CSRFToken}, "label": {"x"}}); rec.Code != http.StatusForbidden {
		t.Errorf("POST /admin/feed/tokens as a user (valid csrf) = %d, want 403", rec.Code)
	}
	if rec := postForm(t, h, cookie, "/admin/feed/tokens/"+tok.ID+"/revoke", url.Values{"csrf": {sess.CSRFToken}}); rec.Code != http.StatusForbidden {
		t.Errorf("POST /admin/feed/tokens/{id}/revoke as a user (valid csrf) = %d, want 403", rec.Code)
	}
}

// TestFeedTokens_MintRevealsOnceThenRevoke: the plaintext appears in the mint
// response only, carries the ddf_ prefix, is absent from the next list
// render, and revoke removes the row.
func TestFeedTokens_MintRevealsOnceThenRevoke(t *testing.T) {
	deps, st := testDeps(t)
	enableFeed(&deps)
	h, _ := New(deps)
	cookie, sess := adminSession(t, deps, st, "admin@example.com")

	rec := postForm(t, h, cookie, "/admin/feed/tokens", url.Values{"csrf": {sess.CSRFToken}, "label": {"envoy"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("mint status = %d, want 200 (the reveal renders in the POST response), body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	m := dataCopyRe.FindStringSubmatch(body)
	if m == nil || !strings.HasPrefix(m[1], store.FeedTokenPrefix) {
		t.Fatalf("no ddf_ token in the reveal:\n%s", body)
	}
	plaintext := m[1]
	if !strings.Contains(body, "Shown once") || !strings.Contains(body, "envoy") {
		t.Error("reveal is missing the shown-once warning or the label")
	}

	list := getPage(t, h, cookie, "/admin/feed").Body.String()
	if strings.Contains(list, plaintext) {
		t.Error("the token plaintext leaked into a later render of the list")
	}
	if !strings.Contains(list, "envoy") || !strings.Contains(list, "admin@example.com") {
		t.Error("list is missing the token's label or its creator")
	}

	toks, err := st.FeedTokens().List(t.Context())
	if err != nil || len(toks) != 1 {
		t.Fatalf("tokens = %v, %v; want one", toks, err)
	}
	rec = postForm(t, h, cookie, "/admin/feed/tokens/"+toks[0].ID+"/revoke", url.Values{"csrf": {sess.CSRFToken}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/feed" {
		t.Fatalf("revoke status = %d Location = %q", rec.Code, rec.Header().Get("Location"))
	}
	if toks, _ := st.FeedTokens().List(t.Context()); len(toks) != 0 {
		t.Errorf("tokens after revoke = %v, want none", toks)
	}
	rec = postForm(t, h, cookie, "/admin/feed/tokens/"+toks[0].ID+"/revoke", url.Values{"csrf": {sess.CSRFToken}})
	if rec.Code != http.StatusNotFound {
		t.Errorf("revoke again = %d, want 404", rec.Code)
	}
}

func TestFeedTokens_DuplicateLabelReRendersWithMessage(t *testing.T) {
	deps, st := testDeps(t)
	enableFeed(&deps)
	h, _ := New(deps)
	cookie, sess := adminSession(t, deps, st, "admin@example.com")

	if rec := postForm(t, h, cookie, "/admin/feed/tokens", url.Values{"csrf": {sess.CSRFToken}, "label": {"envoy"}}); rec.Code != http.StatusOK {
		t.Fatalf("first mint = %d", rec.Code)
	}
	rec := postForm(t, h, cookie, "/admin/feed/tokens", url.Values{"csrf": {sess.CSRFToken}, "label": {"envoy"}})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "already exists") {
		t.Fatalf("duplicate mint = %d, body=%s; want 422 with the message", rec.Code, rec.Body.String())
	}
	if rec := postForm(t, h, cookie, "/admin/feed/tokens", url.Values{"csrf": {sess.CSRFToken}, "label": {""}}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("empty label = %d, want 422", rec.Code)
	}
}
