package server

// Tests for the #191 WWW-Authenticate fix, in the 7 project categories:
// unit, security, performance, retry, integration, functional, frame.

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── unit ──────────────────────────────────────────────────────────────────

func TestChallengeForPath(t *testing.T) {
	cases := map[string]string{
		"/agent/v1/self":        challengeAgent,
		"/agent/v1/checkin":     challengeAgent,
		"/feed/v1/devices.json": challengeFeed,
		"/feed/v1/stream":       challengeFeed,
		"/api/v1/account/keys":  challengeAPI,
		"/api/v1/devices":       challengeAPI,
		"/":                     challengeSession,
		"/login":                challengeSession,
		"/healthz":              challengeSession, // never 401s, but a defined challenge regardless
	}
	for path, want := range cases {
		if got := challengeForPath(path); got != want {
			t.Errorf("challengeForPath(%q) = %q, want %q", path, got, want)
		}
	}
}

// ── security ────────────────────────────────────────────────────────────────

// Basic (and Digest/Negotiate/NTLM) must never be advertised: the browser pops
// a native credentials prompt over the passkey/OIDC web UI on any such challenge
// to a fetch(). This is the load-bearing constraint of #191's fix.
func TestNoInteractiveSchemeIsEverAdvertised(t *testing.T) {
	all := []string{challengeAgent, challengeFeed, challengeAPI, challengeSession}
	for _, p := range []string{"/agent/v1/x", "/feed/v1/x", "/api/v1/x", "/", "/anything"} {
		all = append(all, challengeForPath(p))
	}
	for _, c := range all {
		lc := strings.ToLower(c)
		for _, bad := range []string{"basic", "digest", "negotiate", "ntlm"} {
			if strings.Contains(lc, bad) {
				t.Errorf("challenge %q advertises interactive scheme %q", c, bad)
			}
		}
	}
}

// ── performance ───────────────────────────────────────────────────────────

// The interceptor runs on every request; path classification must be trivial.
func TestChallengeForPathIsCheap(t *testing.T) {
	paths := []string{"/agent/v1/self", "/feed/v1/devices.json", "/api/v1/devices", "/login"}
	start := time.Now()
	for i := range 200000 {
		_ = challengeForPath(paths[i%len(paths)])
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("challengeForPath too slow: 200k calls took %v", d)
	}
}

// ── retry ───────────────────────────────────────────────────────────────────

// A client that retries after a 401 and now succeeds (200) must NOT receive a
// WWW-Authenticate header on the success, and a still-failing retry keeps
// getting it. The writer is per-request, so this guards against any leakage of
// the challenge onto a non-401 retry response.
func TestRetrySuccessCarriesNoChallenge(t *testing.T) {
	// First attempt: handler 401s. Retry: handler 200s. Same interceptor config.
	for _, tc := range []struct {
		name   string
		status int
		want   bool
	}{
		{"failing attempt", http.StatusUnauthorized, true},
		{"retry succeeds", http.StatusOK, false},
	} {
		rr := httptest.NewRecorder()
		h := wwwAuthenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
		}))
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil))
		has := rr.Header().Get("WWW-Authenticate") != ""
		if has != tc.want {
			t.Errorf("%s: WWW-Authenticate present=%v, want %v", tc.name, has, tc.want)
		}
	}
}

// ── integration ─────────────────────────────────────────────────────────────

// End to end through the fully-wrapped handler: every route group's 401 carries
// the challenge for its own scheme. This is the behaviour #191 reports missing.
func TestWWWAuthenticate_EndToEnd(t *testing.T) {
	h, _, err := Handler(routesTestConfig(t), openTestStore(t), discardLog(), NopInstruments{})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	cases := []struct {
		name, method, path, want string
	}{
		{"agent (hmac)", http.MethodGet, "/agent/v1/self", challengeAgent},
		{"feed (bearer token)", http.MethodGet, "/feed/v1/devices.json", challengeFeed},
		{"ui api (session or key)", http.MethodGet, "/api/v1/account/keys", challengeAPI},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s = %d, want 401 (so the challenge assertion is meaningful)", tc.method, tc.path, rr.Code)
			}
			if got := rr.Header().Get("WWW-Authenticate"); got != tc.want {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tc.want)
			}
		})
	}
}

// ── functional ──────────────────────────────────────────────────────────────

func TestWWWAuthWriter_OnlyAddsOn401(t *testing.T) {
	for _, code := range []int{200, 201, 204, 302, 400, 403, 404, 500} {
		rr := httptest.NewRecorder()
		w := &wwwAuthWriter{ResponseWriter: rr, challenge: challengeAPI}
		w.WriteHeader(code)
		if h := rr.Header().Get("WWW-Authenticate"); h != "" {
			t.Errorf("status %d got WWW-Authenticate %q, want none", code, h)
		}
	}
	rr := httptest.NewRecorder()
	w := &wwwAuthWriter{ResponseWriter: rr, challenge: challengeAPI}
	w.WriteHeader(http.StatusUnauthorized)
	if h := rr.Header().Get("WWW-Authenticate"); h != challengeAPI {
		t.Errorf("401 got %q, want %q", h, challengeAPI)
	}
}

// A handler that already set its own challenge is not overwritten.
func TestWWWAuthWriter_DoesNotClobberExisting(t *testing.T) {
	rr := httptest.NewRecorder()
	w := &wwwAuthWriter{ResponseWriter: rr, challenge: challengeAPI}
	w.Header().Set("WWW-Authenticate", `Bearer realm="custom"`)
	w.WriteHeader(http.StatusUnauthorized)
	if h := rr.Header().Get("WWW-Authenticate"); h != `Bearer realm="custom"` {
		t.Errorf("clobbered existing challenge: got %q", h)
	}
}

// An empty challenge (no classified group that wants one) adds nothing.
func TestWWWAuthWriter_EmptyChallengeAddsNothing(t *testing.T) {
	rr := httptest.NewRecorder()
	w := &wwwAuthWriter{ResponseWriter: rr, challenge: ""}
	w.WriteHeader(http.StatusUnauthorized)
	if h := rr.Header().Get("WWW-Authenticate"); h != "" {
		t.Errorf("empty challenge added %q", h)
	}
}

// ── frame ─────────────────────────────────────────────────────────────────

// The feed stream is a WebSocket upgrade: coder/websocket (and
// http.ResponseController) reach the connection's Hijacker/Flusher by walking
// Unwrap. If wwwAuthWriter did not expose Unwrap, every feed stream served
// through this layer would fail to upgrade. This pins that contract.
type hijackFlushRecorder struct {
	http.ResponseWriter
	hijacked, flushed bool
}

func (h *hijackFlushRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}
func (h *hijackFlushRecorder) Flush() { h.flushed = true }

func TestWWWAuthWriter_PreservesHijackAndFlushThroughUnwrap(t *testing.T) {
	under := &hijackFlushRecorder{ResponseWriter: httptest.NewRecorder()}
	w := &wwwAuthWriter{ResponseWriter: under, challenge: challengeFeed}

	rc := http.NewResponseController(w) // walks Unwrap to find Hijacker/Flusher
	if _, _, err := rc.Hijack(); err != nil {
		t.Fatalf("Hijack through wwwAuthWriter failed: %v", err)
	}
	if err := rc.Flush(); err != nil {
		t.Fatalf("Flush through wwwAuthWriter failed: %v", err)
	}
	if !under.hijacked || !under.flushed {
		t.Fatalf("underlying not reached: hijacked=%v flushed=%v", under.hijacked, under.flushed)
	}
}
