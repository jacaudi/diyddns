//go:build smoke

package smoke

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
)

// TestNotifySmoke proves the README's "Notifications" section end to end: it
// starts a real server with notifications enabled, claims the first admin
// (mirroring TestSmoke's ceremony), creates a notification endpoint pointing
// at a local listener, presses "Test," and verifies the delivered signature
// using ONLY the header names, canonical form, and key derivation the README
// states — never anything read off the implementation. If verification here
// needs a fact the README does not state, the README is incomplete.
func TestNotifySmoke(t *testing.T) {
	repoRoot := repoRoot(t)
	binDir := t.TempDir()

	step(t, "build diyddns-server")
	serverBin := build(t, repoRoot, binDir, "diyddns-server")

	step(t, "start a local listener to receive the delivery")
	rx := newCapture()
	listener := httptest.NewServer(rx)
	defer listener.Close()

	addr := freeAddr(t)
	baseURL := browserBaseURL(t, addr)

	// Without this CIDR the dial-time guard denies loopback and nothing below
	// can work — the README states this is required for ANY private or
	// loopback destination, and the listener above is loopback.
	step(t, "start the server with notifications enabled for 127.0.0.0/8")
	srv := startNotifyServer(t, repoRoot, serverBin, addr)
	waitHealthy(t, baseURL)

	step(t, "scrape BOOTSTRAP_TOKEN from the server log")
	token := scrapeToken(t, srv)

	client := &http.Client{Jar: newBrowserJar(t), Timeout: 30 * time.Second}
	rp := virtualwebauthn.RelyingParty{Name: "DIYDDNS", ID: rpIDFor(t, addr), Origin: baseURL}

	step(t, "claim the first admin (WebAuthn ceremony)")
	attOpts := beginClaim(t, client, baseURL, token)
	authr := virtualwebauthn.NewAuthenticatorWithOptions(
		virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(attOpts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)
	finishClaim(t, client, baseURL, virtualwebauthn.CreateAttestationResponse(rp, authr, cred, *attOpts))
	passkeyLogin(t, client, baseURL, rp, authr, cred)
	csrf := fetchCSRF(t, client, baseURL)

	step(t, "POST /account/endpoints (create an endpoint pointing at the listener)")
	epID, secretB64 := createEndpoint(t, client, baseURL, csrf, listener.URL)

	step(t, "POST /account/endpoints/{id}/test")
	postForm(t, client, fmt.Sprintf("%s/account/endpoints/%s/test", baseURL, epID), csrf, nil)

	step(t, "poll the listener for the delivered request")
	req := rx.wait(t, 40*time.Second)

	step(t, "verify the signature exactly as the README documents")
	if err := verifyPerREADME(secretB64, req); err != nil {
		t.Fatalf("delivery failed README-derived verification: %v", err)
	}

	step(t, "check the verified body's contract: null families, id 0, type endpoint.test")
	var body struct {
		Type    string `json:"type"`
		ID      int64  `json:"id"`
		Device  any    `json:"device"`
		Changed []any  `json:"changed"`
		Current struct {
			IPv4 *string `json:"ipv4"`
			IPv6 *string `json:"ipv6"`
		} `json:"current"`
	}
	if err := json.Unmarshal(req.body, &body); err != nil {
		t.Fatalf("unmarshal verified body: %v (body=%s)", err, req.body)
	}
	if body.Type != "endpoint.test" {
		t.Errorf("type = %q, want endpoint.test", body.Type)
	}
	if body.ID != 0 {
		t.Errorf("id = %d, want 0 for endpoint.test", body.ID)
	}
	if body.Device != nil {
		t.Errorf("device = %v, want JSON null", body.Device)
	}
	if body.Current.IPv4 != nil {
		t.Errorf("current.ipv4 = %q, want JSON null, not empty string or a value", *body.Current.IPv4)
	}
	if body.Current.IPv6 != nil {
		t.Errorf("current.ipv6 = %q, want JSON null, not empty string or a value", *body.Current.IPv6)
	}
	// Confirm null is really null on the wire, not the empty string "" — a
	// consumer that unmarshals into a bare string would fail to tell the two
	// apart, which is exactly what the README warns against.
	if strings.Contains(string(req.body), `"ipv4":""`) || strings.Contains(string(req.body), `"ipv6":""`) {
		t.Errorf("payload carries an empty-string address family, want JSON null: %s", req.body)
	}

	t.Log("NOTIFY SMOKE OK")
}

// --- server startup ---------------------------------------------------------

// startNotifyServer starts diyddns-server against a config file that sets
// notifications.enabled and notifications.allowed_private_cidrs DIRECTLY in
// YAML, rather than reusing the shared startServer helper (config.example.yaml
// plus a DIYDDNS_NOTIFICATIONS_* env override).
//
// That combination is deliberately avoided: config.example.yaml's shipped
// "notifications:" section is present but has every child commented out, so
// it parses as YAML null. Driving the actual value through an env var
// override on top of that null section was measured to be NON-DETERMINISTIC
// — it depends on Go's randomized map iteration order inside config.Load's
// `for key, def := range keyDefaults` loop, and flips between the env value
// taking effect and silently falling back to the empty/false default across
// separate process runs of the identical test. See the task-10 report for
// the full reproduction; this is a real config-loading bug, reported rather
// than fixed here (internal/config is out of scope for this task). Setting
// the values directly in a minimal YAML file — with no null-valued
// "notifications:" section anywhere in it — sidesteps the bug entirely
// without touching internal/config or the shared startServer helper other
// tasks' tests depend on.
func startNotifyServer(t *testing.T, repoRoot, bin, addr string) *server {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "notify-config.yaml")
	config := "notifications:\n  enabled: true\n  allowed_private_cidrs: [\"127.0.0.0/8\"]\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write notify config: %v", err)
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

// --- README-derived verifier ------------------------------------------------

// verifyPerREADME re-derives the signature using ONLY what the README's
// "Verifying a delivery" section states, so a passing test is evidence the
// document is a complete, correct specification of the wire contract — not
// evidence that this test happens to agree with the implementation it was
// copied from.
func verifyPerREADME(secretB64 string, req capturedRequest) error {
	// Step 1: the raw key is the secret, base64 (standard encoding) DECODED —
	// never the base64 text itself.
	key, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		return fmt.Errorf("decode secret: %w", err)
	}

	ts := req.header.Get("X-Diyddns-Timestamp")
	nonce := req.header.Get("X-Diyddns-Nonce")
	sig := req.header.Get("X-Diyddns-Signature")
	if ts == "" || nonce == "" || sig == "" {
		return fmt.Errorf("missing one of the documented headers: ts=%q nonce=%q sig=%q", ts, nonce, sig)
	}

	// Step 2: hash the RAW received body bytes — never a re-marshalled copy.
	sum := sha256.Sum256(req.body)
	bodyHashHex := hex.EncodeToString(sum[:])

	// Step 3: the canonical string, LF-joined, with the nonce as the encoded
	// header STRING (not decoded back to raw bytes).
	canonical := strings.Join([]string{"diyddns-notify-v1", ts, nonce, bodyHashHex}, "\n")

	// Step 4: HMAC-SHA256 over the canonical string with the raw key, hex-encoded.
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(canonical))
	want := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(want), []byte(sig)) {
		return fmt.Errorf("signature mismatch: got %s, want %s (canonical=%q)", sig, want, canonical)
	}
	return nil
}

// --- receiving listener -----------------------------------------------------

// capturedRequest is everything the README's verification steps need out of
// the one request the listener receives.
type capturedRequest struct {
	header http.Header
	body   []byte
}

// capture is an http.Handler that records exactly one request and hands it
// to the first waiter. A buffered channel, not a shared field guarded by a
// mutex: the delivery arrives on the worker's own goroutine, concurrently
// with the test's poll, and a channel send is safe across goroutines on its
// own.
type capture struct {
	got chan capturedRequest
}

func newCapture() *capture {
	return &capture{got: make(chan capturedRequest, 1)}
}

func (c *capture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	select {
	case c.got <- capturedRequest{header: r.Header.Clone(), body: body}:
	default:
		// Already captured one; the worker's own retry/backoff behavior is
		// not under test here.
	}
	w.WriteHeader(http.StatusOK)
}

func (c *capture) wait(t *testing.T, timeout time.Duration) capturedRequest {
	t.Helper()
	select {
	case req := <-c.got:
		return req
	case <-time.After(timeout):
		t.Fatalf("no delivery arrived within %s", timeout)
		return capturedRequest{}
	}
}

// --- endpoint creation (HTML scraping — there is no JSON route) ------------

// endpointRowRe finds the newly-created endpoint's id from the refreshed
// endpoints list rendered in the create response (endpoints.html: the row's
// primary-cell link, "/account/endpoints/{id}").
var endpointRowRe = regexp.MustCompile(`href="/account/endpoints/([^"]+)"`)

// endpointSecretRe finds the one-time signing secret from the reveal card
// (endpoints.html: {{template "copyValue" .Secret}} renders
// <span class="copy"><code>SECRET</code>...).
var endpointSecretRe = regexp.MustCompile(`Signing secret \(base64\)</label>\s*<span class="copy"><code>([^<]+)</code>`)

// createEndpoint POSTs the create-endpoint form and scrapes the id and
// one-time secret out of the rendered HTML response — the design deliberately
// has no JSON route for endpoint management (§10.5), so this is the only path
// a headless client (or this smoke test) can use.
func createEndpoint(t *testing.T, c *http.Client, baseURL, csrf, targetURL string) (id, secretB64 string) {
	t.Helper()
	body := postForm(t, c, baseURL+"/account/endpoints", csrf, map[string]string{
		"label": "smoke-test-endpoint",
		"url":   targetURL,
	})

	secretMatch := endpointSecretRe.FindStringSubmatch(body)
	if secretMatch == nil {
		t.Fatalf("could not find signing secret in create response:\n%s", body)
	}

	idMatch := endpointRowRe.FindStringSubmatch(body)
	if idMatch == nil {
		t.Fatalf("could not find endpoint id in create response:\n%s", body)
	}
	// html/template HTML-escapes "+" (and other characters) even inside a
	// plain text node — a real browser decodes that back to "+" when it
	// parses the DOM, which is what a user's copy button actually reads. This
	// regex reads the raw HTML source instead of a parsed DOM, so it must
	// undo the same escaping by hand or a base64 secret containing "+" comes
	// out as the literal text "&#43;" about half the time.
	return idMatch[1], html.UnescapeString(secretMatch[1])
}

// postForm POSTs an application/x-www-form-urlencoded body carrying the
// session's CSRF token plus fields, and returns the response body. Every
// mutating web-UI route (as opposed to the JSON API) reads the CSRF token
// from a hidden form field named "csrf" rather than a header — see
// internal/server/webui/auth.go's requirePost.
func postForm(t *testing.T, c *http.Client, rawURL, csrf string, fields map[string]string) string {
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
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", rawURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: status = %d, body = %s", rawURL, resp.StatusCode, out)
	}
	return string(out)
}
