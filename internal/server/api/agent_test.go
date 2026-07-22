package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

// discardAgentAudit is a no-op AuditSink for this file's integration tests.
type discardAgentAudit struct{}

func (discardAgentAudit) Log(context.Context, store.AuditEntry) {}

// agentTestKey32 returns a fixed 32-byte AEAD key for enroll/checkin tests.
func agentTestKey32() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

// agentHarness bundles a full api.Build-assembled server with the concrete
// store and services needed to seed enrollment codes/users and drive the
// agent HTTP surface end to end.
type agentHarness struct {
	srv     *httptest.Server
	st      *store.Store
	enroll  *service.EnrollmentService
	checkin *service.CheckinService
}

// newAgentHarness assembles a real :memory: store, Verifier, and the
// enrollment/checkin services, wires them through api.Build onto a fresh
// mux, and returns everything a test needs to seed data and make requests.
func newAgentHarness(t *testing.T) agentHarness {
	t.Helper()
	st, err := store.Open(t.Context(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	key := agentTestKey32()
	verifier := auth.NewVerifier(st.Devices(), st.Users(), st.ReplayNonces(), key, 120*time.Second, 120*time.Second)
	enroll := service.NewEnrollmentService(st, key, 15*time.Minute, discardAgentAudit{})
	checkinSvc := service.NewCheckinService(st, discardAgentAudit{})

	mux := http.NewServeMux()
	api.Build(mux, api.ServerDeps{
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Store:    st,
		Verifier: verifier,
		Enroll:   enroll,
		Checkin:  checkinSvc,
		Info:     version.Info{Version: "v1.2.3"},
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return agentHarness{srv: srv, st: st, enroll: enroll, checkin: checkinSvc}
}

// seedAgentUser creates a bare user (no password) for enroll/code tests.
func seedAgentUser(t *testing.T, st *store.Store, email string) store.User {
	t.Helper()
	u, err := st.Users().Create(t.Context(), store.User{Email: email, Role: "user"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

// postJSON POSTs body (marshaled to JSON) to url with no auth headers,
// reads and closes the response body itself, and returns the status code
// plus raw response bytes so callers never have to manage the response
// lifecycle.
func postJSON(t *testing.T, url string, body any) (status int, respBody []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp.StatusCode, respBody
}

// decodeJSON unmarshals raw JSON bytes into v, failing the test on error.
func decodeJSON(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

// signedRequest builds an HMAC-signed request per the shared wire contract
// (internal/shared), ready to send with http.DefaultClient.
func signedRequest(t *testing.T, method, baseURL, path, deviceID string, secret, body []byte, nonce string) *http.Request {
	t.Helper()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	canonical := shared.CanonicalRequest(method, path, ts, nonce, shared.BodyHashHex(body))

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, baseURL+path, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(shared.HeaderDevice, deviceID)
	req.Header.Set(shared.HeaderTimestamp, ts)
	req.Header.Set(shared.HeaderNonce, nonce)
	req.Header.Set(shared.HeaderSignature, shared.Sign(secret, canonical))
	return req
}

type enrollResult struct {
	DeviceID string `json:"device_id"`
	Secret   string `json:"secret"`
}

func TestEnrollCode_ValidCodeReturnsDeviceAndSecret(t *testing.T) {
	h := newAgentHarness(t)
	usr := seedAgentUser(t, h.st, "code-user@example.com")
	code, _, err := h.enroll.CreateCode(t.Context(), usr.ID, "laptop")
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}

	status, body := postJSON(t, h.srv.URL+"/agent/v1/enroll/code", map[string]string{"code": code})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	var got enrollResult
	decodeJSON(t, body, &got)
	if got.DeviceID == "" {
		t.Fatal("empty device_id")
	}
	secretBytes, err := base64.StdEncoding.DecodeString(got.Secret)
	if err != nil {
		t.Fatalf("secret is not valid base64: %v", err)
	}
	if len(secretBytes) == 0 {
		t.Fatal("empty secret")
	}

	dev, err := h.st.Devices().GetByID(t.Context(), got.DeviceID)
	if err != nil {
		t.Fatalf("Devices.GetByID: %v", err)
	}
	if dev.UserID != usr.ID {
		t.Fatalf("device UserID = %q, want %q", dev.UserID, usr.ID)
	}
}

func TestEnrollCode_InvalidCodeReturns401(t *testing.T) {
	h := newAgentHarness(t)

	status, body := postJSON(t, h.srv.URL+"/agent/v1/enroll/code", map[string]string{"code": "never-issued"})
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
}

// enrollViaHTTP enrolls a fresh device via the real HTTP enroll/code
// endpoint, returning its id and plaintext secret for signing subsequent
// requests.
func enrollViaHTTP(t *testing.T, h agentHarness, userEmail, label string) (deviceID string, secret []byte) {
	t.Helper()
	usr := seedAgentUser(t, h.st, userEmail)
	code, _, err := h.enroll.CreateCode(t.Context(), usr.ID, label)
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	status, body := postJSON(t, h.srv.URL+"/agent/v1/enroll/code", map[string]string{"code": code})
	if status != http.StatusOK {
		t.Fatalf("enroll status = %d, body=%s", status, body)
	}
	var got enrollResult
	decodeJSON(t, body, &got)
	secretBytes, err := base64.StdEncoding.DecodeString(got.Secret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	return got.DeviceID, secretBytes
}

type selfView struct {
	DeviceID    string `json:"device_id"`
	CurrentIPv4 string `json:"current_ipv4"`
	CurrentIPv6 string `json:"current_ipv6"`
}

type checkinView struct {
	DeviceID    string `json:"device_id"`
	CurrentIPv4 string `json:"current_ipv4"`
	CurrentIPv6 string `json:"current_ipv6"`
	Stored      bool   `json:"stored"`
}

func TestCheckinAndSelf_SignedRoundTripAndIPv6MergeOnEmpty(t *testing.T) {
	h := newAgentHarness(t)
	deviceID, secret := enrollViaHTTP(t, h, "checkin-user@example.com", "laptop")

	// First signed checkin: sets both IPv4 and IPv6.
	body1, err := json.Marshal(map[string]string{"ipv4": "1.2.3.4", "ipv6": "2001:db8::1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req1 := signedRequest(t, http.MethodPost, h.srv.URL, "/agent/v1/checkin", deviceID, secret, body1, "nonce-1")
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp1.Body)
		t.Fatalf("checkin 1 status = %d, body=%s", resp1.StatusCode, b)
	}
	var checkin1 checkinView
	if err := json.NewDecoder(resp1.Body).Decode(&checkin1); err != nil {
		t.Fatalf("decode checkin 1 response: %v", err)
	}
	if !checkin1.Stored {
		t.Fatal("checkin 1: expected Stored=true (first report)")
	}
	if checkin1.CurrentIPv4 != "1.2.3.4" || checkin1.CurrentIPv6 != "2001:db8::1" {
		t.Fatalf("checkin 1 response = %+v", checkin1)
	}

	// Signed self: proves the checked-in state is visible via /self.
	reqSelf1 := signedRequest(t, http.MethodGet, h.srv.URL, "/agent/v1/self", deviceID, secret, nil, "nonce-self-1")
	respSelf1, err := http.DefaultClient.Do(reqSelf1)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer respSelf1.Body.Close()
	if respSelf1.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(respSelf1.Body)
		t.Fatalf("self 1 status = %d, body=%s", respSelf1.StatusCode, b)
	}
	var self1 selfView
	if err := json.NewDecoder(respSelf1.Body).Decode(&self1); err != nil {
		t.Fatalf("decode self 1 response: %v", err)
	}
	if self1.DeviceID != deviceID || self1.CurrentIPv4 != "1.2.3.4" || self1.CurrentIPv6 != "2001:db8::1" {
		t.Fatalf("self 1 = %+v", self1)
	}

	// Second signed checkin: reports a NEW IPv4 but OMITS ipv6 entirely.
	// Must NOT clobber the stored IPv6 (T7 merge-on-empty, proven through
	// the handler end to end).
	body2, err := json.Marshal(map[string]string{"ipv4": "5.6.7.8"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req2 := signedRequest(t, http.MethodPost, h.srv.URL, "/agent/v1/checkin", deviceID, secret, body2, "nonce-2")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("checkin 2 status = %d, body=%s", resp2.StatusCode, b)
	}
	var checkin2 checkinView
	if err := json.NewDecoder(resp2.Body).Decode(&checkin2); err != nil {
		t.Fatalf("decode checkin 2 response: %v", err)
	}
	if !checkin2.Stored {
		t.Fatal("checkin 2: expected Stored=true (ipv4 changed)")
	}
	if checkin2.CurrentIPv4 != "5.6.7.8" {
		t.Fatalf("checkin 2 CurrentIPv4 = %q, want 5.6.7.8", checkin2.CurrentIPv4)
	}
	if checkin2.CurrentIPv6 != "2001:db8::1" {
		t.Fatalf("checkin 2 CurrentIPv6 = %q, want unchanged 2001:db8::1 (merge-on-empty must preserve it)", checkin2.CurrentIPv6)
	}

	// Final signed self: confirms IPv6 truly persisted in storage, not just
	// echoed in the checkin response.
	reqSelf2 := signedRequest(t, http.MethodGet, h.srv.URL, "/agent/v1/self", deviceID, secret, nil, "nonce-self-2")
	respSelf2, err := http.DefaultClient.Do(reqSelf2)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer respSelf2.Body.Close()
	var self2 selfView
	if err := json.NewDecoder(respSelf2.Body).Decode(&self2); err != nil {
		t.Fatalf("decode self 2 response: %v", err)
	}
	if self2.CurrentIPv4 != "5.6.7.8" || self2.CurrentIPv6 != "2001:db8::1" {
		t.Fatalf("self 2 = %+v, want IPv4=5.6.7.8 IPv6=2001:db8::1 (unchanged)", self2)
	}
}

func TestCheckin_UnsignedRequestReturns401(t *testing.T) {
	h := newAgentHarness(t)

	status, body := postJSON(t, h.srv.URL+"/agent/v1/checkin", map[string]string{"ipv4": "1.2.3.4"})
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", status, body)
	}
}

func TestSelf_UnsignedRequestReturns401(t *testing.T) {
	h := newAgentHarness(t)

	resp, err := http.Get(h.srv.URL + "/agent/v1/self")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 401, body=%s", resp.StatusCode, body)
	}
}
