package api_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/jacaudi/diyddns/internal/oidc/oidctest"
	"github.com/jacaudi/diyddns/internal/store"
)

// oidcStartResp is the decoded body of POST /agent/v1/enroll/oidc/start.
type oidcStartResp struct {
	FlowID                  string `json:"flow_id"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// oidcPollResp is the decoded body of POST /agent/v1/enroll/oidc/poll.
type oidcPollResp struct {
	Status   string `json:"status"`
	DeviceID string `json:"device_id"`
	Secret   string `json:"secret"`
}

// startDeviceFlow POSTs /agent/v1/enroll/oidc/start and returns the decoded
// response, failing the test if the call doesn't succeed or the response is
// incomplete.
func startDeviceFlow(t *testing.T, srvURL string) oidcStartResp {
	t.Helper()
	status, body := postJSON(t, srvURL+"/agent/v1/enroll/oidc/start", nil)
	if status != http.StatusOK {
		t.Fatalf("start status = %d, body=%s", status, body)
	}
	var start oidcStartResp
	if err := json.Unmarshal(body, &start); err != nil {
		t.Fatalf("decode start response: %v, body=%s", err, body)
	}
	if start.FlowID == "" || start.UserCode == "" {
		t.Fatalf("start incomplete: %+v", start)
	}
	return start
}

// pollDeviceFlow POSTs /agent/v1/enroll/oidc/poll for flowID and returns the
// status code plus the decoded poll response body.
func pollDeviceFlow(t *testing.T, srvURL, flowID string) (int, oidcPollResp) {
	t.Helper()
	var poll oidcPollResp
	status, body := postJSON(t, srvURL+"/agent/v1/enroll/oidc/poll", map[string]string{"flow_id": flowID})
	if status == http.StatusOK {
		if err := json.Unmarshal(body, &poll); err != nil {
			t.Fatalf("decode poll response: %v, body=%s", err, body)
		}
	}
	return status, poll
}

// TestOIDCDeviceEnroll_PendingThenSlowDown drives a single flow through two
// immediate polls: the first is always allowed (a fresh flow's
// last_polled_at is 0), and — because the device is never approved at the
// IdP — returns "pending"; the second poll, issued immediately after with no
// wait, always falls inside the flow's (floored-to-5s) pacing window and
// returns "slow_down". This exercises both states deterministically without
// any real sleep.
func TestOIDCDeviceEnroll_PendingThenSlowDown(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: true})
	h := newOIDCHarness(t, oidcTestCfg(idp))

	start := startDeviceFlow(t, h.srv.URL)
	if start.Interval < 5 {
		t.Fatalf("interval = %d, want floored to >= 5", start.Interval)
	}

	status, p1 := pollDeviceFlow(t, h.srv.URL, start.FlowID)
	if status != http.StatusOK || p1.Status != "pending" {
		t.Fatalf("first poll: status=%d body=%+v, want 200/pending", status, p1)
	}

	status, p2 := pollDeviceFlow(t, h.srv.URL, start.FlowID)
	if status != http.StatusOK || p2.Status != "slow_down" {
		t.Fatalf("second poll: status=%d body=%+v, want 200/slow_down", status, p2)
	}
}

// TestOIDCDeviceEnroll_Complete approves the device code at the IdP BEFORE
// the first poll, so that poll — always allowed on a fresh flow — resolves
// immediately to PollComplete without any wait.
func TestOIDCDeviceEnroll_Complete(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: true})
	h := newOIDCHarness(t, oidcTestCfg(idp))

	start := startDeviceFlow(t, h.srv.URL)
	idp.ApproveDevice("test-device-code", oidctest.Claims{
		Subject: "dsub", Email: "dev@x.com", EmailVerified: true, Audience: "test-client",
	})

	status, poll := pollDeviceFlow(t, h.srv.URL, start.FlowID)
	if status != http.StatusOK {
		t.Fatalf("poll status = %d, want 200", status)
	}
	if poll.DeviceID == "" || poll.Secret == "" {
		t.Fatalf("want device_id+secret, got %+v", poll)
	}

	if _, err := h.st.Users().GetByOIDC(t.Context(), idp.Issuer, "dsub"); err != nil {
		t.Fatalf("OIDC user not created: %v", err)
	}

	// The flow must be deleted on completion: polling again returns 410 Gone.
	status2, _ := pollDeviceFlow(t, h.srv.URL, start.FlowID)
	if status2 != http.StatusGone {
		t.Fatalf("poll after completion: status=%d, want 410", status2)
	}
}

// TestOIDCDeviceEnroll_RejectDeletesFlowAnd401 drives the terminal reject
// path: the device is approved at the IdP (so the first poll resolves to
// PollComplete), but the config has AllowOIDCSignup=false and the subject is
// unlinked with no matching account, so LoginOrLink deterministically
// rejects. The handler must return 401 AND delete the flow, leaving no
// reusable enrollment handle behind.
func TestOIDCDeviceEnroll_RejectDeletesFlowAnd401(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: true})
	cfg := oidcTestCfg(idp)
	cfg.AllowOIDCSignup = false // unlinked subject → LoginOrLink "signup disabled" reject
	h := newOIDCHarness(t, cfg)

	start := startDeviceFlow(t, h.srv.URL)
	idp.ApproveDevice("test-device-code", oidctest.Claims{
		Subject: "reject-sub", Email: "reject@x.com", EmailVerified: true, Audience: "test-client",
	})

	status, body := postJSON(t, h.srv.URL+"/agent/v1/enroll/oidc/poll", map[string]string{"flow_id": start.FlowID})
	if status != http.StatusUnauthorized {
		t.Fatalf("poll status = %d, want 401, body=%s", status, body)
	}

	// The reject path must delete the flow — no orphaned enrollment handle.
	if _, err := h.st.OIDCDeviceFlows().Get(t.Context(), start.FlowID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("flow Get after reject: err = %v, want store.ErrNotFound", err)
	}
}

// TestOIDCDeviceEnroll_MintFailureDeletesFlowAnd500 drives the terminal
// mint-failure path: the device is approved and LoginOrLink succeeds
// (signup enabled), but device minting is forced to fail by dropping the
// devices table out from under the store after the harness is built. The
// handler must return 500 AND delete the flow — a spent IdP device_code
// must never leave an orphan row for the pruner.
func TestOIDCDeviceEnroll_MintFailureDeletesFlowAnd500(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: true})
	h := newOIDCHarness(t, oidcTestCfg(idp)) // AllowOIDCSignup=true → LoginOrLink creates the user

	start := startDeviceFlow(t, h.srv.URL)
	idp.ApproveDevice("test-device-code", oidctest.Claims{
		Subject: "mint-sub", Email: "mint@x.com", EmailVerified: true, Audience: "test-client",
	})

	// Force EnrollForUser's Devices().Create to fail while leaving users and
	// oidc_device_flows intact, so LoginOrLink and the flow Delete still work.
	if _, err := h.st.DB().ExecContext(t.Context(), `DROP TABLE devices`); err != nil {
		t.Fatalf("drop devices table: %v", err)
	}

	status, body := postJSON(t, h.srv.URL+"/agent/v1/enroll/oidc/poll", map[string]string{"flow_id": start.FlowID})
	if status != http.StatusInternalServerError {
		t.Fatalf("poll status = %d, want 500, body=%s", status, body)
	}

	// The mint-failure path must delete the flow — no orphaned spent device_code.
	if _, err := h.st.OIDCDeviceFlows().Get(t.Context(), start.FlowID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("flow Get after mint failure: err = %v, want store.ErrNotFound", err)
	}
}

// TestOIDCDeviceStart_501WhenUnsupported drives /start against an IdP that
// does not advertise a device_authorization_endpoint.
func TestOIDCDeviceStart_501WhenUnsupported(t *testing.T) {
	idp := oidctest.New(t, oidctest.Options{SupportDevice: false})
	h := newOIDCHarness(t, oidcTestCfg(idp))

	status, body := postJSON(t, h.srv.URL+"/agent/v1/enroll/oidc/start", nil)
	if status != http.StatusNotImplemented {
		t.Fatalf("want 501, got %d, body=%s", status, body)
	}
}
