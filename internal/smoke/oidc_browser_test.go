//go:build browser

// OIDC browser smoke: the only thing in this repo that completes an OIDC login
// in a real browser against a real server process.
//
// Same build tag, Node dependency, and skip-when-absent behaviour as
// browser_test.go — see that file's header for why this is not in the default
// build.
//
//	task smoke:browser
package smoke

import (
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/oidc/oidctest"
)

// oidcSmokeEmail is the email the mock IdP asserts. It is a fresh address, so
// the login exercises the signup branch of the link/signup policy rather than
// linking to a pre-existing account.
const oidcSmokeEmail = "oidc-browser@example.com"

func TestOIDCBrowserSmoke(t *testing.T) {
	work, ok := provisionPlaywright(t)
	if !ok {
		return // provisionPlaywright already skipped
	}

	repoRoot := repoRoot(t)

	// The mock IdP is an httptest server in THIS process; the server
	// subprocess and Chromium both reach it over loopback.
	idp := oidctest.New(t, oidctest.Options{})
	idp.SetAuthCodeClaims(oidctest.Claims{
		Subject:       "oidc-browser-sub",
		Email:         oidcSmokeEmail,
		EmailVerified: true,
		Audience:      "diyddns-smoke",
		// Nonce is deliberately unset: only the server knows the nonce it
		// generated, and the browser drives the flow, so the IdP has to echo
		// back the nonce it was asked to sign — as a real one does.
	})

	step(t, "build the server")
	serverBin := build(t, repoRoot, t.TempDir(), "diyddns-server")

	addr := freeAddr(t)
	baseURL := browserBaseURL(t, addr)

	// auth.oidc.required=true makes a discovery failure abort startup instead
	// of leaving OIDC silently disabled, so a broken IdP surfaces as a boot
	// failure rather than a missing button three steps later.
	step(t, "start the server with OIDC enabled")
	startServer(t, repoRoot, serverBin, addr,
		"DIYDDNS_AUTH_OIDC_ENABLED=true",
		"DIYDDNS_AUTH_OIDC_REQUIRED=true",
		"DIYDDNS_AUTH_OIDC_ISSUER="+idp.Issuer,
		"DIYDDNS_AUTH_OIDC_CLIENT_ID=diyddns-smoke",
		"DIYDDNS_AUTH_OIDC_CLIENT_SECRET=smoke-secret",
	)

	step(t, "wait for GET /healthz")
	waitHealthy(t, baseURL)

	step(t, "drive the OIDC login through Chromium")
	script := copyScript(t, repoRoot, work, "oidc.mjs")
	out, err := runIn(work, "node", script, baseURL, oidcSmokeEmail)
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("oidc browser smoke failed: %v", err)
	}
	if !strings.Contains(out, "OIDC BROWSER OK") {
		t.Fatalf("oidc browser smoke did not report success:\n%s", out)
	}
}
