package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/api"
)

// observedCheckin is the check-in response shape these tests assert on.
type observedCheckin struct {
	CurrentIPv4 string            `json:"current_ipv4"`
	CurrentIPv6 string            `json:"current_ipv6"`
	IPSource    map[string]string `json:"ip_source"`
}

// newObservedHarness serves the main port with trusted as server.trusted_proxies
// and a capture logger, and enrolls one device.
func newObservedHarness(t *testing.T, trusted []netip.Prefix) (h agentHarness, logs *logCapture, deviceID string, secret []byte) {
	t.Helper()
	st, deps := buildServerDeps(t)
	logs = &logCapture{}
	deps.Log = logs.logger()
	deps.TrustedProxies = trusted
	mux := http.NewServeMux()
	api.Build(mux, deps)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	h = agentHarness{srv: srv, st: st, enroll: deps.Enroll}
	deviceID, secret = enrollViaHTTP(t, h, "observed@example.com", "laptop")
	return h, logs, deviceID, secret
}

// checkinXFF sends an HMAC-signed check-in with body {} and, when xff is not
// empty, that X-Forwarded-For header.
func checkinXFF(t *testing.T, h agentHarness, deviceID string, secret []byte, xff string) observedCheckin {
	t.Helper()
	nonceSeq++
	req := signedRequest(t, http.MethodPost, h.srv.URL, "/agent/v1/checkin", deviceID, secret, []byte("{}"), "observe-nonce-"+strconv.Itoa(nonceSeq))
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	status, body := do(t, http.DefaultClient, req)
	if status != http.StatusOK {
		t.Fatalf("checkin status = %d, want 200, body=%s", status, body)
	}
	var got observedCheckin
	decodeJSON(t, body, &got)
	return got
}

// wantSource fails unless got equals want, compared as JSON objects.
func wantSource(t *testing.T, got, want map[string]string) {
	t.Helper()
	gj, _ := json.Marshal(got)
	wj, _ := json.Marshal(want)
	if string(gj) != string(wj) {
		t.Errorf("ip_source = %s, want %s", gj, wj)
	}
}

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}

func TestMainCheckinObservesXFF(t *testing.T) {
	h, logs, id, secret := newObservedHarness(t, loopback)

	got := checkinXFF(t, h, id, secret, "1.1.1.1")

	wantSource(t, got.IPSource, map[string]string{"ipv4": "observed"})
	if got.CurrentIPv4 != "1.1.1.1" {
		t.Errorf("current_ipv4 = %q, want 1.1.1.1", got.CurrentIPv4)
	}
	dev, err := h.st.Devices().GetByID(t.Context(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if dev.CurrentIPv4 != "1.1.1.1" {
		t.Errorf("stored ipv4 = %q, want 1.1.1.1", dev.CurrentIPv4)
	}

	recs := withMsg(atLevel(logs.records(t), "INFO"), "check-in")
	if len(recs) != 1 {
		t.Fatalf("INFO check-in records = %d, want 1: %v", len(recs), recs)
	}
	for k, want := range map[string]string{
		"device_id":   id,
		"peer":        "127.0.0.1",
		"observed":    "1.1.1.1",
		"ipv4_source": "observed",
		"ipv6_source": "",
	} {
		if recs[0][k] != want {
			t.Errorf("log %s = %v, want %q", k, recs[0][k], want)
		}
	}
}

func TestMainCheckinIgnoresXFFFromUntrustedPeer(t *testing.T) {
	h, _, id, secret := newObservedHarness(t, nil)

	got := checkinXFF(t, h, id, secret, "1.1.1.1")

	// The peer (127.0.0.1) is the observation, and it is not public.
	wantSource(t, got.IPSource, map[string]string{"ipv4": "none"})
	if got.CurrentIPv4 != "" {
		t.Errorf("current_ipv4 = %q, want unchanged (empty)", got.CurrentIPv4)
	}
}

func TestMainCheckinNoObservationEmptySource(t *testing.T) {
	h, logs, id, secret := newObservedHarness(t, loopback)

	got := checkinXFF(t, h, id, secret, "")

	wantSource(t, got.IPSource, map[string]string{})
	if got.CurrentIPv4 != "" || got.CurrentIPv6 != "" {
		t.Errorf("recorded %q/%q, want nothing", got.CurrentIPv4, got.CurrentIPv6)
	}
	recs := withMsg(atLevel(logs.records(t), "INFO"), "check-in")
	if len(recs) != 1 {
		t.Fatalf("INFO check-in records = %d, want 1", len(recs))
	}
	if recs[0]["observed"] != "" {
		t.Errorf("log observed = %v, want empty when there is no observation", recs[0]["observed"])
	}
}

func TestAgentCheckinUsesPeer(t *testing.T) {
	l := newAgentListener(t)
	d := l.newDevice(t, "agent-peer@example.com")

	status, body := l.send(t, l.client(t, d.cert), http.MethodPost, "/agent/v1/checkin", d.id, d.secret, struct{}{})

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (client-cert check still passes), body=%s", status, body)
	}
	var got observedCheckin
	decodeJSON(t, body, &got)
	// The peer is 127.0.0.1: observed, but not public.
	wantSource(t, got.IPSource, map[string]string{"ipv4": "none"})
}

// A trusted peer on the agent listener is a proxy (or a PROXY LOCAL health
// probe): the peer is not an origin, so nothing is observed and nothing is
// recorded.
func TestAgentCheckinTrustedPeerHasNoObservation(t *testing.T) {
	l := newAgentListener(t, func(d *api.ServerDeps) { d.TrustedProxies = loopback })
	d := l.newDevice(t, "agent-trusted@example.com")

	status, body := l.send(t, l.client(t, d.cert), http.MethodPost, "/agent/v1/checkin", d.id, d.secret, struct{}{})

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	var got observedCheckin
	decodeJSON(t, body, &got)
	wantSource(t, got.IPSource, map[string]string{})
	if got.CurrentIPv4 != "" || got.CurrentIPv6 != "" {
		t.Errorf("recorded %q/%q, want nothing", got.CurrentIPv4, got.CurrentIPv6)
	}
}
