package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// feedTokenAPIRoutes are the three REST operations registerFeedTokenOps
// (internal/server/api/feed.go) registers under /api/v1/admin/feed/tokens.
// Hardcoded here rather than exported from api, mirroring
// TestGuard_ProtectedPathsRejectUnauthenticated's own hardcoded table in the
// api package.
var feedTokenAPIRoutes = []string{
	"GET /api/v1/admin/feed/tokens",
	"POST /api/v1/admin/feed/tokens",
	"DELETE /api/v1/admin/feed/tokens/{id}",
}

// TestFeedTokenAPIRoutes_AbsentUnlessEnabled is feed_routes_test.go's
// TestFeedRoutes_AbsentUnlessEnabled for the REST feed-token surface
// (#153 fix-wave Significant #3): apiDeps.FeedEnabled
// (internal/server/api.ServerDeps) is a hand-copied mirror of
// cfg.Feed.Enabled, written at exactly one production call site (server.go's
// buildMux). Every api-package test sets that field by hand, so deleting
// server.go's "FeedEnabled: cfg.Feed.Enabled" line would leave the entire
// api-package test suite green while production silently dropped all three
// REST routes for every operator running the (feed.enabled=true) default
// install. This drives the REAL wiring through buildMux, the same entry
// point the running server uses, not a hand-built ServerDeps.
func TestFeedTokenAPIRoutes_AbsentUnlessEnabled(t *testing.T) {
	// Deliberately not t.Parallel(): see TestWebUIPatternsAreReachable.
	off := routesTestConfig(t)
	off.Feed.Enabled = false
	mux, _, _, _, _, _, _, err := buildMux(off, openTestStore(t), discardLog())
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	for _, pattern := range feedTokenAPIRoutes {
		method, path, _ := strings.Cut(pattern, " ")
		req := httptest.NewRequest(method, concretePath(path), nil)
		if _, matched := mux.Handler(req); matched != "" {
			t.Errorf("%s resolved to %q with feed.enabled=false; the route must be absent", pattern, matched)
		}
	}

	on := routesTestConfig(t)
	on.Feed.Enabled = true
	mux, _, apiDeps, _, _, _, _, err := buildMux(on, openTestStore(t), discardLog())
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	if !apiDeps.FeedEnabled {
		t.Error("apiDeps.FeedEnabled = false with cfg.Feed.Enabled = true; the mirror in buildMux is out of sync")
	}
	for _, pattern := range feedTokenAPIRoutes {
		method, path, _ := strings.Cut(pattern, " ")
		req := httptest.NewRequest(method, concretePath(path), nil)
		if _, matched := mux.Handler(req); matched != pattern {
			t.Errorf("%s resolved to %q with feed.enabled=true", pattern, matched)
		}
	}
}
