package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server"
	"github.com/jacaudi/diyddns/internal/store"
)

// signInCookie mints a real session directly against st and returns the
// cookie a browser would send back. It mirrors internal/server/webui's own
// signIn test helper, but at the boundary this file drives through instead:
// the real composed server.Handler, not the inner webui mux.
func signInCookie(t *testing.T, cfg config.Server, st *store.Store, usr store.User) *http.Cookie {
	t.Helper()
	sessions := auth.NewSessionManager(st.Sessions(), st.Users(), cfg.Auth.Session.TTL, cfg.Auth.Session.SlideWindow)
	sess, err := sessions.Create(t.Context(), usr.ID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return &http.Cookie{Name: cfg.Auth.Session.CookieName, Value: sess.ID}
}

// TestNotFound_UnmatchedWebUIPath_Anonymous pins #168: an anonymous request
// to a path that matches no route anywhere in the server is redirected to
// /login, exactly like every other guarded webui page, instead of falling
// through to Go's stdlib 404.
func TestNotFound_UnmatchedWebUIPath_Anonymous(t *testing.T) {
	cfg := testConfig(t, validSecretKey())
	h, _, err := server.Handler(cfg, memStore(t), discard(), server.NopInstruments{})
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Get(srv.URL + "/no-such-page")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("GET /no-such-page (anonymous) = %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}
	if got := resp.Header.Get("Location"); got != "/login" {
		t.Errorf("Location = %q, want %q", got, "/login")
	}
	// The caught stdlib 404 (http.Error, under the hood) sets Content-Type and
	// X-Content-Type-Options on the real ResponseWriter's header map before
	// notFoundInterceptor.WriteHeader ever sees the call. Left in place, those
	// leak onto the redirect that replaces it: http.Redirect only sets its own
	// text/html Content-Type when none is already present, so the anonymous
	// redirect would ship as text/plain with a stray nosniff header instead of
	// matching every other 303 in this app (e.g. requireSession's).
	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q (no leaked stdlib-404 header)", got, "text/html; charset=utf-8")
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "" {
		t.Errorf("X-Content-Type-Options = %q, want empty (no leaked stdlib-404 header)", got)
	}
}

// TestNotFound_UnmatchedWebUIPath_Authenticated pins the other half of #168:
// a signed-in user hitting a genuinely unmatched webui path gets the app's
// own rendered 404 page, not a login loop and not stdlib's raw 404 text.
func TestNotFound_UnmatchedWebUIPath_Authenticated(t *testing.T) {
	cfg := testConfig(t, validSecretKey())
	st := memStore(t)
	usr, err := st.Users().Create(t.Context(), store.User{Email: "notfound@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h, _, err := server.Handler(cfg, st, discard(), server.NopInstruments{})
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/no-such-page", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(signInCookie(t, cfg, st, usr))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /no-such-page (signed in) = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want the app's rendered HTML page", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "That page doesn&#39;t exist.") {
		t.Errorf("body is not the rendered error page:\n%s", body)
	}
}

// TestNotFound_UnmatchedNonWebUIPath_Unaffected pins the boundary #168 must
// not cross: an unmatched path under a machine-consumed surface (/api/ or
// /agent/) must keep stdlib's bare 404, never a redirect to the
// browser-facing /login.
func TestNotFound_UnmatchedNonWebUIPath_Unaffected(t *testing.T) {
	tests := []struct {
		name, path string
	}{
		{"api", "/api/v1/typo-path"},
		{"agent", "/agent/v1/typo-path"},
		// Bare roots (no trailing slash, no such huma route) must stay
		// excluded too — isWebUIPath's prefixes are all "/api/"-shaped, which
		// does not match the bare "/api" itself.
		{"api bare root", "/api"},
		{"agent bare root", "/agent"},
		{"feed bare root", "/feed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(t, validSecretKey())
			h, _, err := server.Handler(cfg, memStore(t), discard(), server.NopInstruments{})
			if err != nil {
				t.Fatalf("server.Handler: %v", err)
			}
			srv := httptest.NewServer(h)
			t.Cleanup(srv.Close)
			client := srv.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

			resp, err := client.Get(srv.URL + tt.path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s = %d, want %d (unchanged)", tt.path, resp.StatusCode, http.StatusNotFound)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), "That page doesn") {
				t.Errorf("body looks like the app's rendered 404 page, want stdlib's default:\n%s", body)
			}
		})
	}
}

// TestNotFound_DisabledFeedPath_StaysNotFound proves the #168 composition
// survives end to end for a disabled-feature route group (design #106
// §8.1), not just at the webui-package layer that
// TestFeedRoutes_AbsentWhenDisabled already covers: /admin/feed with
// feed.enabled=false answers 404 for an authenticated admin, unchanged from
// before this change.
func TestNotFound_DisabledFeedPath_StaysNotFound(t *testing.T) {
	cfg := testConfig(t, validSecretKey())
	cfg.Feed.Enabled = false // feed.enabled defaults to true; disable explicitly
	st := memStore(t)
	admin, err := st.Users().Create(t.Context(), store.User{Email: "admin@example.com", Role: "admin"})
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	h, _, err := server.Handler(cfg, st, discard(), server.NopInstruments{})
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/admin/feed", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(signInCookie(t, cfg, st, admin))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /admin/feed (admin, feed disabled) = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// TestNotFound_MatchedRouteOwn404Survives_Anonymous pins the sharpest case
// for the r.Pattern discriminator: /static/ IS a registered pattern
// ("GET /static/", http.FileServerFS), so a request for a file that isn't
// there gets FileServerFS's own genuine 404 with r.Pattern non-empty. Unlike
// every other case in this file, the caller here is ALSO anonymous — proving
// this is gated on "did anything match", not on "is the caller signed in".
func TestNotFound_MatchedRouteOwn404Survives_Anonymous(t *testing.T) {
	cfg := testConfig(t, validSecretKey())
	h, _, err := server.Handler(cfg, memStore(t), discard(), server.NopInstruments{})
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Get(srv.URL + "/static/missing.css")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /static/missing.css (anonymous) = %d, want %d (FileServerFS's own 404, not a redirect)", resp.StatusCode, http.StatusNotFound)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "That page doesn") {
		t.Errorf("body looks like the app's rendered 404 page, want FileServerFS's default:\n%s", body)
	}
}

// TestNotFound_MatchedRouteOwn404Survives_SemanticMessage is the other half:
// an in-app semantic 404 (a matched route that decided for its own reasons to
// answer 404) keeps its own specific message, never the generic one
// NotFound's handleNotFound renders for a genuinely unmatched path.
func TestNotFound_MatchedRouteOwn404Survives_SemanticMessage(t *testing.T) {
	cfg := testConfig(t, validSecretKey())
	st := memStore(t)
	usr, err := st.Users().Create(t.Context(), store.User{Email: "device404@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h, _, err := server.Handler(cfg, st, discard(), server.NopInstruments{})
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/devices/no-such-device", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(signInCookie(t, cfg, st, usr))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /devices/no-such-device (signed in) = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "That device does not exist.") {
		t.Errorf("body does not show ownedDevice's own message:\n%s", body)
	}
	if strings.Contains(string(body), "That page doesn&#39;t exist.") {
		t.Errorf("body shows the generic NotFound message instead of the device's own:\n%s", body)
	}
}

// TestNotFound_DisabledFeedPath_StaysNotFound_MachineSurface is the /feed/
// counterpart to TestNotFound_DisabledFeedPath_StaysNotFound: nonWebUIPrefixes
// must exclude /feed/ even when the feed route group was never registered
// (feed.enabled=false) — the exact regression class the first (rejected)
// #168 implementation attempt introduced for /api and /agent, now pinned for
// /feed too.
func TestNotFound_DisabledFeedPath_StaysNotFound_MachineSurface(t *testing.T) {
	cfg := testConfig(t, validSecretKey())
	cfg.Feed.Enabled = false // feed.enabled defaults to true; disable explicitly
	h, _, err := server.Handler(cfg, memStore(t), discard(), server.NopInstruments{})
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Get(srv.URL + "/feed/v1/devices.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /feed/v1/devices.txt (feed disabled) = %d, want %d (unchanged, no redirect)", resp.StatusCode, http.StatusNotFound)
	}
}

// TestNotFound_WebUISpace405Unaffected proves a webui-space 405 (a path that
// matches a registered pattern for a different method) is structurally
// invisible to notFoundInterceptor, not merely "different by code
// inspection": WriteHeader(405) never equals the caught condition's
// http.StatusNotFound check, so it always forwards untouched.
func TestNotFound_WebUISpace405Unaffected(t *testing.T) {
	cfg := testConfig(t, validSecretKey())
	h, _, err := server.Handler(cfg, memStore(t), discard(), server.NopInstruments{})
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Post(srv.URL+"/login", "application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /login = %d, want %d (unaffected)", resp.StatusCode, http.StatusMethodNotAllowed)
	}
	if got := resp.Header.Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow = %q, want %q", got, "GET, HEAD")
	}
	if got := resp.Header.Get("Location"); got != "" {
		t.Errorf("Location = %q, want empty (not intercepted into a redirect)", got)
	}
}

// TestNotFound_DisabledFeedPath_Redirects_Anonymous is the anonymous
// counterpart to TestNotFound_DisabledFeedPath_StaysNotFound (which only
// covers an authenticated admin): a disabled feature's webui route group
// behaves the same as any other unmatched webui path for both auth states
// (AC3), so an anonymous caller gets the same /login redirect as
// /no-such-page, not stdlib's raw 404.
func TestNotFound_DisabledFeedPath_Redirects_Anonymous(t *testing.T) {
	cfg := testConfig(t, validSecretKey())
	cfg.Feed.Enabled = false // feed.enabled defaults to true; disable explicitly
	h, _, err := server.Handler(cfg, memStore(t), discard(), server.NopInstruments{})
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Get(srv.URL + "/admin/feed")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("GET /admin/feed (anonymous, feed disabled) = %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}
	if got := resp.Header.Get("Location"); got != "/login" {
		t.Errorf("Location = %q, want %q", got, "/login")
	}
}
