package server

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/webui"
)

// routesTestConfig builds a config that handler() accepts. Both overrides are
// load-bearing and the server fails closed without them: auth.hmac.secret_key
// must decode to 32 bytes (server.go:55-58), and server.base_url must be set or
// WebAuthn RP resolution fails (server.go:91-95).
func routesTestConfig(t *testing.T) config.Server {
	t.Helper()
	v := viper.New()
	v.Set("database.path", ":memory:")
	v.Set("auth.hmac.secret_key", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32)))
	v.Set("server.base_url", "https://ddns.example.com")
	cfg, err := config.Load(v, "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

// TestWebUIPatternsAreReachable asserts every pattern webui.New returns is
// actually served by the outer mux.
//
// It matches on the PATTERN the mux resolves, not on a status code: GET
// /devices/{id} with a synthetic id legitimately answers 404, which a status
// check cannot distinguish from "never forwarded" — the exact bug that let GET /
// 404 in a browser while the webui unit tests, which drive the inner mux
// directly, stayed green.
func TestWebUIPatternsAreReachable(t *testing.T) {
	// Deliberately not t.Parallel(): store.Migrate (internal/store/migrate.go)
	// calls goose's package-level SetBaseFS/SetDialect with no synchronization.
	// Running this alongside TestReachabilityDetectsAnUnforwardedRoute — both
	// of which call openTestStore, and so store.Migrate — races under -race.
	// Out of scope for this task to fix (no store/migration changes); flagged
	// as a follow-up instead.
	_, patterns := webui.New(webui.Deps{})
	if len(patterns) == 0 {
		t.Fatal("webui.New returned no patterns")
	}

	mux, _, err := buildMux(routesTestConfig(t), openTestStore(t), discardLog())
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}

	for _, pattern := range patterns {
		method, path, found := strings.Cut(pattern, " ")
		if !found {
			t.Fatalf("pattern %q has no method prefix", pattern)
		}
		req := httptest.NewRequest(method, concretePath(path), nil)
		_, matched := mux.Handler(req)
		if matched != pattern {
			t.Errorf("pattern %q: outer mux resolved %q — the route is not forwarded", pattern, matched)
		}
	}
}

// concretePath turns a pattern path into a requestable one: "/devices/{id}" ->
// "/devices/pattern-probe", "/{$}" -> "/", "/static/" -> "/static/".
func concretePath(p string) string {
	p = strings.ReplaceAll(p, "{$}", "")
	for {
		open := strings.Index(p, "{")
		if open < 0 {
			return p
		}
		closeIdx := strings.Index(p[open:], "}")
		if closeIdx < 0 {
			return p
		}
		p = p[:open] + "pattern-probe" + p[open+closeIdx+1:]
	}
}

// TestReachabilityDetectsAnUnforwardedRoute proves the guard above can fail.
// A reachability test that cannot detect an unforwarded route is decoration.
func TestReachabilityDetectsAnUnforwardedRoute(t *testing.T) {
	// Deliberately not t.Parallel() — see TestWebUIPatternsAreReachable.
	mux, _, err := buildMux(routesTestConfig(t), openTestStore(t), discardLog())
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/never-registered", nil)
	if _, matched := mux.Handler(req); matched != "" {
		t.Errorf("an unregistered path resolved to pattern %q; the guard cannot detect drift", matched)
	}
}
