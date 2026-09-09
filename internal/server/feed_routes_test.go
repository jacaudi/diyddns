package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/feed"
)

// TestFeedRoutes_AbsentUnlessEnabled: the whole /feed/v1 group is absent —
// not merely guarded — when feed.enabled is false, and every pattern in
// feed.Routes resolves when it is true.
func TestFeedRoutes_AbsentUnlessEnabled(t *testing.T) {
	// Deliberately not t.Parallel(): see TestWebUIPatternsAreReachable.
	off := routesTestConfig(t)
	mux, _, _, _, _, _, err := buildMux(off, openTestStore(t), discardLog())
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	for _, pattern := range feed.Routes {
		req := httptest.NewRequest(http.MethodGet, concretePath(pattern[len("GET "):]), nil)
		if _, matched := mux.Handler(req); matched != "" {
			t.Errorf("%s resolved to %q with feed.enabled=false; the group must be absent", pattern, matched)
		}
	}

	on := routesTestConfig(t)
	on.Feed.Enabled = true
	mux, _, _, _, _, hub, err := buildMux(on, openTestStore(t), discardLog())
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	if hub == nil {
		t.Fatal("buildMux returned a nil hub")
	}
	for _, pattern := range feed.Routes {
		req := httptest.NewRequest(http.MethodGet, concretePath(pattern[len("GET "):]), nil)
		if _, matched := mux.Handler(req); matched != pattern {
			t.Errorf("%s resolved to %q with feed.enabled=true", pattern, matched)
		}
	}
}
