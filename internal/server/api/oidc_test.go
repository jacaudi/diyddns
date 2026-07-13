package api_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/oidc/oidctest"
)

// oidcTestCfg builds an enabled config.OIDCCfg pointed at idp, permissive
// enough (auto-link + signup) to drive the full browser flow end to end.
func oidcTestCfg(idp *oidctest.IdP) config.OIDCCfg {
	return config.OIDCCfg{
		Enabled:         true,
		Issuer:          idp.Issuer,
		ClientID:        "test-client",
		ClientSecret:    "secret",
		Scopes:          []string{"openid", "profile", "email"},
		AutoLinkByEmail: true,
		AllowOIDCSignup: true,
	}
}

// noRedirectClient returns an http.Client with a cookie jar that stops at the
// first redirect, so start/callback responses (Location + Set-Cookie) can be
// asserted directly instead of being silently followed.
func noRedirectClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestOIDCBrowserFlow_EndToEnd(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{})
	h := newOIDCHarness(t, oidcTestCfg(idp))
	client := noRedirectClient(t)

	// 1. /start -> 302 to the IdP, flow cookie set.
	resp, err := client.Get(h.srv.URL + "/api/v1/auth/oidc/start")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, idp.Issuer+"/authorize") {
		t.Fatalf("start: status=%d loc=%s", resp.StatusCode, loc)
	}
	if !hasCookie(resp, "diyddns_oidc_flow") {
		t.Fatal("start did not set the flow cookie")
	}

	// Stage the claims the IdP will mint, keyed to the nonce carried in the
	// authorize URL huma/oidc.Manager generated.
	nonce := mustQuery(t, loc, "nonce")
	idp.SetAuthCodeClaims(oidctest.Claims{
		Subject: "sub-1", Email: "new@x.com", EmailVerified: true,
		Nonce: nonce, Audience: "test-client",
	})

	// 2. Follow to the IdP authorize endpoint; it 302s back to our callback
	// with code+state. The cookie jar already carries the flow cookie.
	cbURL := followToCallback(t, client, loc)
	resp2, err := client.Get(cbURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("callback status=%d, want 302", resp2.StatusCode)
	}

	// 3. Session cookie set; the OIDC user exists.
	if !hasCookie(resp2, "diyddns_session") {
		t.Fatal("callback did not set the session cookie")
	}
	if _, err := h.st.Users().GetByOIDC(t.Context(), idp.Issuer, "sub-1"); err != nil {
		t.Fatalf("OIDC user not created: %v", err)
	}
}

func TestOIDCCallback_StateMismatchRejected(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{})
	h := newOIDCHarness(t, oidcTestCfg(idp))
	client := noRedirectClient(t)

	// Obtain a valid flow cookie via /start (the jar carries it forward).
	resp, err := client.Get(h.srv.URL + "/api/v1/auth/oidc/start")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status=%d", resp.StatusCode)
	}

	// Call back with a state that does not match the one sealed in the flow
	// cookie.
	resp2, err := client.Get(h.srv.URL + "/api/v1/auth/oidc/callback?code=whatever&state=wrong-state")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("callback status=%d, want 400", resp2.StatusCode)
	}
}

// mustQuery parses rawURL and returns the value of query parameter key,
// failing the test if the URL doesn't parse or the key is absent.
func mustQuery(t *testing.T, rawURL, key string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	v := u.Query().Get(key)
	if v == "" {
		t.Fatalf("query %q missing %q param", rawURL, key)
	}
	return v
}

// followToCallback GETs the IdP's authorize URL (idpAuthURL) and returns the
// Location it redirects to (our callback URL, with code+state attached).
func followToCallback(t *testing.T, client *http.Client, idpAuthURL string) string {
	t.Helper()
	resp, err := client.Get(idpAuthURL)
	if err != nil {
		t.Fatalf("follow to idp authorize: %v", err)
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || loc == "" {
		t.Fatalf("idp authorize: status=%d loc=%q", resp.StatusCode, loc)
	}
	return loc
}

// hasCookie reports whether resp's Set-Cookie headers include one named name.
func hasCookie(resp *http.Response, name string) bool {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return true
		}
	}
	return false
}
