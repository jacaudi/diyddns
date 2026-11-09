package server

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/logtest"
	"github.com/jacaudi/diyddns/internal/server/webui"
)

// routesTestConfig builds a config that handler() accepts. Both overrides are
// load-bearing and the server fails closed without them: auth.hmac.secret_key
// must decode to 32 bytes (server.go:144-147), and server.base_url must be set or
// WebAuthn RP resolution fails (server.go:221-225).
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

	mux, _, _, _, _, _, _, err := buildMux(routesTestConfig(t), openTestStore(t), discardLog(), nil, nil)
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
		before, rest, ok := strings.Cut(p, "{")
		if !ok {
			return p
		}
		_, after, ok := strings.Cut(rest, "}")
		if !ok {
			return p
		}
		p = before + "pattern-probe" + after
	}
}

// TestReachabilityDetectsAnUnforwardedRoute proves the guard above can fail.
// A reachability test that cannot detect an unforwarded route is decoration.
func TestReachabilityDetectsAnUnforwardedRoute(t *testing.T) {
	// Deliberately not t.Parallel() — see TestWebUIPatternsAreReachable.
	mux, _, _, _, _, _, _, err := buildMux(routesTestConfig(t), openTestStore(t), discardLog(), nil, nil)
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/never-registered", nil)
	if _, matched := mux.Handler(req); matched != "" {
		t.Errorf("an unregistered path resolved to pattern %q; the guard cannot detect drift", matched)
	}
}

// buildMux hands the parsed trusted_proxies to the API dependencies, where the
// check-in handler reads them.
func TestBuildMuxThreadsTrustedProxies(t *testing.T) {
	// Deliberately not t.Parallel() — see TestWebUIPatternsAreReachable.
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	_, _, apiDeps, _, _, _, _, err := buildMux(routesTestConfig(t), openTestStore(t), discardLog(), nil, trusted)
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}

	if !slices.Equal(apiDeps.TrustedProxies, trusted) {
		t.Errorf("apiDeps.TrustedProxies = %v, want %v", apiDeps.TrustedProxies, trusted)
	}
}

func TestLogStartupWarnings(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*config.Server)
		want string // substring of the WARN message
	}{
		{
			name: "cookie_secure over plain HTTP",
			mut: func(c *config.Server) {
				c.Auth.Session.CookieSecure = true
				c.Server.BaseURL = "http://ddns.example.com"
			},
			want: "auth.session.cookie_secure",
		},
		{
			name: "trusted_proxies zero-length prefix",
			mut:  func(c *config.Server) { c.Server.TrustedProxies = []string{"0.0.0.0/0"} },
			want: "server.trusted_proxies",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := routesTestConfig(t)
			tt.mut(&cfg)
			log, buf := jsonLog()

			logStartupWarnings(cfg, log)

			var found bool
			for _, rec := range logtest.Records(t, buf.String()) {
				if msg, _ := rec["msg"].(string); rec["level"] == "WARN" && strings.Contains(msg, tt.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("no WARN containing %q in:\n%s", tt.want, buf.String())
			}
		})
	}
}
