//go:build smoke

// HMAC rejection checks against the RUNNING server.
//
// internal/auth/hmac_test.go already covers Verifier.Verify's four rejection
// paths as unit tests. What it cannot cover is whether the wired-up server
// actually reaches that verifier and answers 401: the skew window comes from
// the shipped config.example.yaml, the replay set is a real SQLite table with a
// UNIQUE constraint rather than a fake, the device row is one a real
// `diyddns-client enroll` created, and disabling a device goes through the
// owner-scoped PATCH endpoint. Each of those is a place the check can be
// correct in the verifier and absent from the request path.
package smoke

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/shared"
)

// checkinPath is the agent check-in route. It appears in both the URL and the
// canonical string the signature covers, so it has one definition.
const checkinPath = "/agent/v1/checkin"

// staleOffset puts a timestamp outside config.example.yaml's 120s skew window
// by enough that clock jitter cannot bring it back inside.
const staleOffset = 10 * time.Minute

// checkinBody is the payload every request in this file signs. A documentation
// address (RFC 5737 TEST-NET-3) so it is never confused with a real discovery
// result in the history the earlier steps asserted against.
var checkinBody = []byte(`{"ipv4":"203.0.113.10"}`)

// assertHMACRejections proves a real signed check-in is accepted and that each
// of the four tampered variants is rejected, against the running server.
//
// The disabled-device case runs LAST and is not undone: it leaves the device
// unable to authenticate, so nothing may depend on it afterwards.
func assertHMACRejections(t *testing.T, c *http.Client, baseURL, credsPath, csrf, deviceID string) {
	t.Helper()

	secret, err := base64.StdEncoding.DecodeString(credsField(t, credsPath, "secret"))
	if err != nil {
		t.Fatalf("decode device secret: %v", err)
	}
	now := time.Now().Unix()

	step(t, "a correctly signed check-in is accepted")
	valid := signedAgentRequest(t, baseURL, deviceID, secret, now, "smoke-hmac-valid")
	assertAgentStatus(t, c, valid, http.StatusOK, "correctly signed check-in")

	// Replay is detected on the SIGNATURE, so the replayed request has to be
	// byte-identical — same timestamp and same nonce, not merely a repeat of
	// the same shape.
	step(t, "replaying that exact request is rejected")
	replay := signedAgentRequest(t, baseURL, deviceID, secret, now, "smoke-hmac-valid")
	assertAgentStatus(t, c, replay, http.StatusUnauthorized, "replayed check-in")

	// Fresh nonces from here on, so a 401 can only be the mutation under test
	// and never leftover replay detection.
	step(t, "a check-in signed with a stale timestamp is rejected")
	stale := signedAgentRequest(t, baseURL, deviceID, secret,
		time.Now().Add(-staleOffset).Unix(), "smoke-hmac-stale")
	assertAgentStatus(t, c, stale, http.StatusUnauthorized, "stale-timestamp check-in")

	step(t, "a check-in with a tampered signature is rejected")
	tampered := signedAgentRequest(t, baseURL, deviceID, secret, time.Now().Unix(), "smoke-hmac-tampered")
	tampered.Header.Set(shared.HeaderSignature, flipLastHexDigit(t, tampered.Header.Get(shared.HeaderSignature)))
	assertAgentStatus(t, c, tampered, http.StatusUnauthorized, "tampered-signature check-in")

	step(t, "disable the device through the owner API")
	disableDevice(t, c, baseURL, deviceID, csrf)

	step(t, "a correctly signed check-in from the disabled device is rejected")
	disabled := signedAgentRequest(t, baseURL, deviceID, secret, time.Now().Unix(), "smoke-hmac-disabled")
	assertAgentStatus(t, c, disabled, http.StatusUnauthorized, "disabled-device check-in")
}

// signedAgentRequest builds a POST /agent/v1/checkin signed exactly the way the
// real client signs it — via internal/shared, the same package the client
// binary uses — with the timestamp and nonce under the caller's control.
func signedAgentRequest(t *testing.T, baseURL, deviceID string, secret []byte, ts int64, nonce string) *http.Request {
	t.Helper()
	tsStr := strconv.FormatInt(ts, 10)
	canonical := shared.CanonicalRequest(http.MethodPost, checkinPath, tsStr, nonce, shared.BodyHashHex(checkinBody))

	req, err := http.NewRequest(http.MethodPost, baseURL+checkinPath, bytes.NewReader(checkinBody))
	if err != nil {
		t.Fatalf("new agent request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(shared.HeaderDevice, deviceID)
	req.Header.Set(shared.HeaderTimestamp, tsStr)
	req.Header.Set(shared.HeaderNonce, nonce)
	req.Header.Set(shared.HeaderSignature, shared.Sign(secret, canonical))
	return req
}

// assertAgentStatus sends req and fails unless the server answered want,
// naming the case so a failure says which mutation was not rejected.
func assertAgentStatus(t *testing.T, c *http.Client, req *http.Request, want int, name string) {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s: read body: %v", name, err)
	}
	if resp.StatusCode != want {
		t.Fatalf("%s: status = %d, want %d, body = %s", name, resp.StatusCode, want, body)
	}
	t.Logf("    %s -> %d", name, resp.StatusCode)
}

// flipLastHexDigit changes exactly one character of a hex signature, so the
// request stays well-formed and fails on the comparison rather than on
// parsing.
func flipLastHexDigit(t *testing.T, sig string) string {
	t.Helper()
	if sig == "" {
		t.Fatal("no signature to tamper with")
	}
	last := sig[len(sig)-1]
	replacement := byte('a')
	if last == 'a' {
		replacement = 'b'
	}
	return sig[:len(sig)-1] + string(replacement)
}

// disableDevice flips disabled=true through the owner-scoped PATCH endpoint —
// the same path the web UI uses — rather than writing to the database, so the
// check exercises the route an operator actually has.
func disableDevice(t *testing.T, c *http.Client, baseURL, deviceID, csrf string) {
	t.Helper()
	raw, err := json.Marshal(map[string]bool{"disabled": true})
	if err != nil {
		t.Fatalf("marshal disable body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPatch, baseURL+"/api/v1/devices/"+deviceID, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new PATCH request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("PATCH device: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH device: status = %d, body = %s", resp.StatusCode, body)
	}
	var out struct {
		Disabled bool `json:"disabled"`
	}
	mustJSON(t, body, &out)
	if !out.Disabled {
		t.Fatalf("PATCH device did not report the device disabled: %s", body)
	}
}
