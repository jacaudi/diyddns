//go:build smoke

// Package smoke holds the end-to-end smoke harness: it builds the real
// diyddns-server and diyddns-client binaries, runs the server as a
// subprocess against the shipped config.example.yaml, and drives the full
// first-run path an operator would take.
//
// It is behind the `smoke` build tag so `go test ./...` never picks it up:
// it builds binaries, binds a port, and (by default) makes real outbound
// requests to public IP-discovery providers.
//
//	task smoke                       # full path, needs internet
//	task smoke -- -skip-discovery    # stop after enrollment, no outbound calls
//
// # Why this is Go and not a shell script
//
// Claiming the first admin is a WebAuthn registration ceremony. It needs a
// party that can generate a credential and sign a challenge, which curl
// cannot do at any level of cleverness. virtualwebauthn supplies that party.
// The tag keeps it a test-only dependency, so the client binary's
// forbidden-import guard still proves the client never speaks WebAuthn.
package smoke

import (
	"flag"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
)

var skipDiscovery = flag.Bool("skip-discovery", false,
	"stop after enrollment; skip the check-in step and its outbound IP-discovery calls")

const (
	adminEmail  = "smoke-admin@example.com"
	deviceLabel = "smoketest"
	passkeyName = "smoke-authenticator"
)

// TestSmoke walks the whole first-run path in order. It is one test rather
// than several because every step depends on the state the previous one
// created; splitting it would only buy independently-failing subtests at the
// cost of re-running the entire setup for each.
func TestSmoke(t *testing.T) {
	repoRoot := repoRoot(t)
	binDir := t.TempDir()

	step(t, "build both binaries")
	serverBin := build(t, repoRoot, binDir, "diyddns-server")
	clientBin := build(t, repoRoot, binDir, "diyddns-client")

	addr := freeAddr(t)
	baseURL := browserBaseURL(t, addr)
	srv := startServer(t, repoRoot, serverBin, addr)

	step(t, "wait for GET /healthz")
	waitHealthy(t, baseURL)

	step(t, "scrape BOOTSTRAP_TOKEN from the server log")
	token := scrapeToken(t, srv)

	// A cookie jar is mandatory, not a convenience: the WebAuthn ceremony
	// carries its sealed challenge between begin and finish in a cookie.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}

	// The relying party must match what the server derived from
	// server.base_url, or every assertion fails origin validation.
	rp := virtualwebauthn.RelyingParty{
		Name:   "DIYDDNS",
		ID:     rpIDFor(t, addr),
		Origin: baseURL,
	}

	step(t, "POST /api/v1/register/begin (claim the first admin)")
	attOpts := beginClaim(t, client, baseURL, token)

	step(t, "sign the attestation with a virtual authenticator")
	authr := virtualwebauthn.NewAuthenticatorWithOptions(
		virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(attOpts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)
	attResp := virtualwebauthn.CreateAttestationResponse(rp, authr, cred, *attOpts)

	step(t, "POST /api/v1/register/finish (admin + first passkey)")
	finishClaim(t, client, baseURL, attResp)

	step(t, "passkey login (discoverable, no username)")
	passkeyLogin(t, client, baseURL, rp, authr, cred)

	step(t, "GET /api/v1/auth/me (extract the CSRF token)")
	csrf := fetchCSRF(t, client, baseURL)

	step(t, "POST /api/v1/devices (mint an enrollment code)")
	code := mintCode(t, client, baseURL, csrf)

	credsPath := filepath.Join(t.TempDir(), "credentials.json")
	step(t, "diyddns-client enroll --code")
	runClient(t, clientBin, "enroll", "--code", code, "--server", baseURL, "--credentials-file", credsPath)
	assertMode0600(t, credsPath)
	deviceID := credsField(t, credsPath, "device_id")

	if *skipDiscovery {
		t.Log("-skip-discovery: stopping before check-in; enrollment path verified")
		return
	}

	step(t, "diyddns-client run --once (discovery + check-in)")
	out := runClient(t, clientBin, "run", "--once", "--credentials-file", credsPath)
	reportedIP := field(t, out, `ipv4=([0-9.]+)`)
	t.Logf("    client reported ipv4=%s", reportedIP)

	step(t, "GET /api/v1/devices/{id}/history (find the reported IP)")
	assertHistoryHasIP(t, client, baseURL, deviceID, reportedIP)

	step(t, "GET /api/v1/devices/{id} (current_ipv4 + last_seen_at populated)")
	assertDeviceCurrent(t, client, baseURL, deviceID, reportedIP)

	t.Log("SMOKE OK")
}

// --- ceremony steps -------------------------------------------------------

func beginClaim(t *testing.T, c *http.Client, baseURL, token string) *virtualwebauthn.AttestationOptions {
	t.Helper()
	body := map[string]string{"token": token, "email": adminEmail}
	status, respBody := postJSON(t, c, baseURL+"/api/v1/register/begin", body, "")
	if status != http.StatusOK {
		t.Fatalf("register/begin: status = %d, body = %s", status, respBody)
	}
	opts, err := virtualwebauthn.ParseAttestationOptions(string(respBody))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v (body=%s)", err, respBody)
	}
	return opts
}

// finishClaim posts the signed attestation. The name is merged into the
// attestation JSON rather than sent alongside it because the handler reads
// both the ceremony response and its own fields off one raw body. No token
// is sent: a token here would route to the grant-redeem path instead of the
// bootstrap claim.
func finishClaim(t *testing.T, c *http.Client, baseURL, attResp string) {
	t.Helper()
	status, respBody := postRaw(t, c, baseURL+"/api/v1/register/finish",
		mergeField(t, attResp, "name", passkeyName), "")
	if status != http.StatusOK {
		t.Fatalf("register/finish: status = %d, body = %s", status, respBody)
	}
}

func passkeyLogin(t *testing.T, c *http.Client, baseURL string, rp virtualwebauthn.RelyingParty,
	authr virtualwebauthn.Authenticator, cred virtualwebauthn.Credential) {
	t.Helper()
	status, beginBody := postJSON(t, c, baseURL+"/api/v1/auth/passkey/login/begin", nil, "")
	if status != http.StatusOK {
		t.Fatalf("login/begin: status = %d, body = %s", status, beginBody)
	}
	assertOpts, err := virtualwebauthn.ParseAssertionOptions(string(beginBody))
	if err != nil {
		t.Fatalf("ParseAssertionOptions: %v (body=%s)", err, beginBody)
	}
	assertResp := virtualwebauthn.CreateAssertionResponse(rp, authr, cred, *assertOpts)

	// The session cookie lands in the jar; fetchCSRF proves it authenticates.
	status, respBody := postRaw(t, c, baseURL+"/api/v1/auth/passkey/login/finish", assertResp, "")
	if status != http.StatusOK {
		t.Fatalf("login/finish: status = %d, body = %s", status, respBody)
	}
}

func fetchCSRF(t *testing.T, c *http.Client, baseURL string) string {
	t.Helper()
	status, body := get(t, c, baseURL+"/api/v1/auth/me")
	if status != http.StatusOK {
		t.Fatalf("auth/me: status = %d, body = %s", status, body)
	}
	var me struct {
		CSRF string `json:"csrf"`
		User struct {
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"user"`
	}
	mustJSON(t, body, &me)
	if me.CSRF == "" {
		t.Fatalf("auth/me returned no csrf token: %s", body)
	}
	if me.User.Email != adminEmail || me.User.Role != "admin" {
		t.Fatalf("auth/me returned %+v, want %s / admin", me.User, adminEmail)
	}
	return me.CSRF
}

func mintCode(t *testing.T, c *http.Client, baseURL, csrf string) string {
	t.Helper()
	// The field is "label", not "name" — "name" returns 422.
	status, body := postJSON(t, c, baseURL+"/api/v1/devices", map[string]string{"label": deviceLabel}, csrf)
	if status != http.StatusOK {
		t.Fatalf("POST /devices: status = %d, body = %s", status, body)
	}
	var out struct {
		Code string `json:"code"`
	}
	mustJSON(t, body, &out)
	if out.Code == "" {
		t.Fatalf("POST /devices returned no code: %s", body)
	}
	return out.Code
}

func assertHistoryHasIP(t *testing.T, c *http.Client, baseURL, deviceID, wantIP string) {
	t.Helper()
	status, body := get(t, c, baseURL+"/api/v1/devices/"+deviceID+"/history")
	if status != http.StatusOK {
		t.Fatalf("history: status = %d, body = %s", status, body)
	}
	var out struct {
		Rows []struct {
			IPv4 string `json:"ipv4"`
		} `json:"rows"`
	}
	mustJSON(t, body, &out)
	for _, r := range out.Rows {
		if r.IPv4 == wantIP {
			return
		}
	}
	t.Fatalf("history has no row with ipv4=%s: %s", wantIP, body)
}

func assertDeviceCurrent(t *testing.T, c *http.Client, baseURL, deviceID, wantIP string) {
	t.Helper()
	status, body := get(t, c, baseURL+"/api/v1/devices/"+deviceID)
	if status != http.StatusOK {
		t.Fatalf("device: status = %d, body = %s", status, body)
	}
	var out struct {
		CurrentIPv4 string `json:"current_ipv4"`
		LastSeenAt  int64  `json:"last_seen_at"`
	}
	mustJSON(t, body, &out)
	if out.CurrentIPv4 != wantIP {
		t.Errorf("current_ipv4 = %q, want %q", out.CurrentIPv4, wantIP)
	}
	if out.LastSeenAt == 0 {
		t.Errorf("last_seen_at = 0, want it populated")
	}
}
