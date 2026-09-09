//go:build smoke

package smoke

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/descope/virtualwebauthn"
)

// feedTokenRe finds the once-only token from the mint reveal
// (admin-feed.html: {{template "copyValue" .Secret}} renders
// <span class="copy"><code>ddf_…</code>).
var feedTokenRe = regexp.MustCompile(`Feed token</label>\s*<span class="copy"><code>([^<]+)</code>`)

// TestFeedSmoke proves the README's "Feed" section end to end against the
// real binary: an admin mints a token from /admin/feed, a gateway-style
// client pulls both documents and opens the stream, a real signed check-in
// changes a device's address, and the change arrives on the stream as
// device.ip_changed; disabling the device arrives as device.removed.
func TestFeedSmoke(t *testing.T) {
	repoRoot := repoRoot(t)
	binDir := t.TempDir()

	step(t, "build diyddns-server and diyddns-client")
	serverBin := build(t, repoRoot, binDir, "diyddns-server")
	clientBin := build(t, repoRoot, binDir, "diyddns-client")

	addr := freeAddr(t)
	baseURL := browserBaseURL(t, addr)

	step(t, "start the server with the feed enabled")
	srv := startFeedServer(t, repoRoot, serverBin, addr)
	waitHealthy(t, baseURL)

	step(t, "claim the first admin and sign in")
	token := scrapeToken(t, srv)
	client := &http.Client{Jar: newJar(t), Timeout: 30 * time.Second}
	rp := virtualwebauthn.RelyingParty{Name: "DIYDDNS", ID: rpIDFor(t, addr), Origin: baseURL}
	attOpts := beginClaim(t, client, baseURL, token)
	authr := virtualwebauthn.NewAuthenticatorWithOptions(
		virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(attOpts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)
	finishClaim(t, client, baseURL, virtualwebauthn.CreateAttestationResponse(rp, authr, cred, *attOpts))
	passkeyLogin(t, client, baseURL, rp, authr, cred)
	csrf := fetchCSRF(t, client, baseURL)

	step(t, "POST /admin/feed/tokens (mint a feed token; shown once)")
	body := postForm(t, client, baseURL+"/admin/feed/tokens", csrf, map[string]string{"label": "smoke-gateway"})
	m := feedTokenRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("could not find the feed token in the mint response:\n%s", body)
	}
	feedToken := html.UnescapeString(m[1])
	if !strings.HasPrefix(feedToken, "ddf_") {
		t.Fatalf("token %q does not carry the documented ddf_ prefix", feedToken)
	}

	// A plain client with no cookie jar: the gateway holds only the token.
	gateway := &http.Client{Timeout: 10 * time.Second}

	step(t, "GET /feed/v1/devices.txt without a token is 401 with the uniform body")
	if status, b := feedGet(t, gateway, baseURL+"/feed/v1/devices.txt", ""); status != http.StatusUnauthorized || string(b) != `{"error":"unauthorized"}` {
		t.Fatalf("no token: status %d body %s", status, b)
	}

	step(t, "GET /feed/v1/devices.txt and .json with the token (empty feed still has the header line)")
	status, txt := feedGet(t, gateway, baseURL+"/feed/v1/devices.txt", feedToken)
	if status != http.StatusOK || string(txt) != "# diyddns feed v1\n" {
		t.Fatalf("empty text feed: status %d body %q", status, txt)
	}
	status, js := feedGet(t, gateway, baseURL+"/feed/v1/devices.json", feedToken)
	if status != http.StatusOK || strings.TrimSpace(string(js)) != `{"version":1,"cidrs":[],"devices":[]}` {
		t.Fatalf("empty json feed: status %d body %s", status, js)
	}

	step(t, "open the stream and receive the snapshot")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	conn, dialResp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(baseURL, "http")+"/feed/v1/stream", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + feedToken}},
	})
	if dialResp != nil && dialResp.Body != nil {
		defer dialResp.Body.Close() // nil on a successful upgrade: the library takes the conn over
	}
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	defer func() { _ = conn.CloseNow() }()
	if f := readStreamFrame(t, conn); f["type"] != "feed.snapshot" {
		t.Fatalf("first frame = %v, want feed.snapshot", f)
	}

	step(t, "enrol a device with the real client")
	code := mintCode(t, client, baseURL, csrf)
	credsPath := filepath.Join(t.TempDir(), "credentials.json")
	runClient(t, clientBin, "enroll", "--code", code, "--server", baseURL, "--credentials-file", credsPath)
	deviceID := credsField(t, credsPath, "device_id")
	secret, err := base64.StdEncoding.DecodeString(credsField(t, credsPath, "secret"))
	if err != nil {
		t.Fatalf("decode device secret: %v", err)
	}

	step(t, "a signed check-in changes the device's address → device.ip_changed on the stream")
	req := signedAgentRequest(t, baseURL, deviceID, secret, time.Now().Unix(), "smoke-feed-checkin")
	assertAgentStatus(t, gateway, req, http.StatusOK, "signed check-in")
	f := readStreamFrame(t, conn)
	if f["type"] != "device.ip_changed" {
		t.Fatalf("frame after check-in = %v, want device.ip_changed", f)
	}
	dev, _ := f["device"].(map[string]any)
	if dev["id"] != deviceID || len(dev) != 2 {
		t.Errorf("device object = %v, want exactly {id, label} for %s (D22)", dev, deviceID)
	}
	if cur, _ := f["current"].(map[string]any); cur["ipv4"] != "203.0.113.10" {
		t.Errorf("current = %v, want ipv4 203.0.113.10", cur)
	}

	step(t, "the REST feed now lists the address, with ETag/Last-Modified, and 304 on If-None-Match")
	status, txt = feedGet(t, gateway, baseURL+"/feed/v1/devices.txt", feedToken)
	if status != http.StatusOK || string(txt) != "# diyddns feed v1\n203.0.113.10/32\n" {
		t.Fatalf("text feed: status %d body %q", status, txt)
	}
	req2, _ := http.NewRequest(http.MethodGet, baseURL+"/feed/v1/devices.txt", nil)
	req2.Header.Set("Authorization", "Bearer "+feedToken)
	resp, err := gateway.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	etag, lastMod := resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
	if etag == "" || lastMod == "" {
		t.Fatalf("headers = %v, want ETag and Last-Modified", resp.Header)
	}
	req3, _ := http.NewRequest(http.MethodHead, baseURL+"/feed/v1/devices.txt", nil)
	req3.Header.Set("Authorization", "Bearer "+feedToken)
	if resp, err := gateway.Do(req3); err != nil || resp.StatusCode != 200 || resp.Header.Get("Last-Modified") == "" || resp.ContentLength <= 0 {
		t.Fatalf("HEAD: err=%v resp=%v", err, resp)
	} else {
		_ = resp.Body.Close()
	}
	req2.Header.Set("If-None-Match", etag)
	if resp, err := gateway.Do(req2); err != nil || resp.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match: err=%v status=%v, want 304", err, resp)
	} else {
		_ = resp.Body.Close()
	}

	step(t, "disable the device through the owner API → device.removed on the stream")
	disableDevice(t, client, baseURL, deviceID, csrf)
	f = readStreamFrame(t, conn)
	if f["type"] != "device.removed" {
		t.Fatalf("frame after disable = %v, want device.removed", f)
	}
	if prev, _ := f["previous"].(map[string]any); prev["ipv4"] != "203.0.113.10" {
		t.Errorf("removed previous = %v, want the withdrawn address", prev)
	}
	if cur, _ := f["current"].(map[string]any); cur["ipv4"] != nil || cur["ipv6"] != nil {
		t.Errorf("removed current = %v, want both null", cur)
	}
	status, txt = feedGet(t, gateway, baseURL+"/feed/v1/devices.txt", feedToken)
	if status != http.StatusOK || string(txt) != "# diyddns feed v1\n" {
		t.Fatalf("text feed after disable: status %d body %q", status, txt)
	}

	step(t, "revoke the token → the stream closes 4001 and the REST feed is 401")
	tokensPage := getPageBody(t, client, baseURL+"/admin/feed")
	idm := regexp.MustCompile(`action="/admin/feed/tokens/([^/"]+)/revoke"`).FindStringSubmatch(tokensPage)
	if idm == nil {
		t.Fatalf("could not find the token's revoke form:\n%s", tokensPage)
	}
	postFormExpect(t, client, fmt.Sprintf("%s/admin/feed/tokens/%s/revoke", baseURL, idm[1]), csrf, nil, http.StatusOK)
	rctx, rcancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer rcancel()
	if _, _, err := conn.Read(rctx); websocket.CloseStatus(err) != 4001 {
		t.Fatalf("after revoke: read err = %v, want close status 4001", err)
	}
	if status, _ := feedGet(t, gateway, baseURL+"/feed/v1/devices.txt", feedToken); status != http.StatusUnauthorized {
		t.Fatalf("revoked token: status %d, want 401", status)
	}

	t.Log("FEED SMOKE OK")
}

// startFeedServer starts diyddns-server with feed.enabled set in a minimal
// YAML file (see startNotifyServer for why a YAML file rather than the
// shipped example plus an env override).
func startFeedServer(t *testing.T, repoRoot, bin, addr string) *server {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "feed-config.yaml")
	if err := os.WriteFile(configPath, []byte("feed:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatalf("write feed config: %v", err)
	}
	dbPath := filepath.Join(t.TempDir(), "smoke.db")
	baseURL := browserBaseURL(t, addr)

	s := &server{}
	cmd := exec.Command(bin, "serve", "--config", configPath)
	cmd.Env = append(os.Environ(),
		"DIYDDNS_SERVER_LISTEN="+addr,
		"DIYDDNS_SERVER_BASE_URL="+baseURL,
		"DIYDDNS_DATABASE_PATH="+dbPath,
		"DIYDDNS_AUTH_HMAC_SECRET_KEY="+randomKeyB64(t),
	)
	cmd.Stdout = s
	cmd.Stderr = s
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	s.cmd = cmd
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		if t.Failed() {
			t.Logf("--- server log ---\n%s", s.log())
		}
	})
	return s
}

// feedGet performs a GET with an optional bearer token and returns status and body.
func feedGet(t *testing.T, c *http.Client, rawURL, token string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", rawURL, err)
	}
	return resp.StatusCode, b
}

func readStreamFrame(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	_, b, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("stream read: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("stream frame is not JSON: %v (%s)", err, b)
	}
	return m
}

// getPageBody GETs an HTML page with the session client.
func getPageBody(t *testing.T, c *http.Client, rawURL string) string {
	t.Helper()
	status, b := get(t, c, rawURL)
	if status != http.StatusOK {
		t.Fatalf("GET %s: status = %d, body = %s", rawURL, status, b)
	}
	return string(b)
}

// postFormExpect POSTs the session's CSRF token plus fields and asserts the
// FINAL status (after the client has followed redirects) equals want. It does
// the request itself rather than wrapping postForm (notify_smoke_test.go):
// postForm returns only a body and t.Fatalf's on anything but 200, so it has
// no status for a caller to assert.
func postFormExpect(t *testing.T, c *http.Client, rawURL, csrf string, fields map[string]string, want int) {
	t.Helper()
	form := url.Values{"csrf": {csrf}}
	for k, v := range fields {
		form.Set(k, v)
	}
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", rawURL, err)
	}
	if resp.StatusCode != want {
		t.Fatalf("POST %s: status = %d, want %d; body = %s", rawURL, resp.StatusCode, want, body)
	}
}
