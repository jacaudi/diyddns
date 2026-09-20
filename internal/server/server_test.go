package server_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func memStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// validSecretKey returns a base64-encoded 32-byte AEAD key suitable for
// config.Auth.HMAC.SecretKey in tests. Not a real secret.
func validSecretKey() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32))
}

// testConfig resolves a config.Server the same way production does (via
// config.Load and its defaults), overriding database.path (required),
// auth.hmac.secret_key (the fail-closed knob under test), and
// server.base_url. base_url is now required by handler()'s fail-closed
// WebAuthn Relying Party resolution (passkey login is available by default,
// see TestHandler_FailsClosedOnUnresolvableWebAuthnRP) — most tests in this
// file only care about the server coming up, not about WebAuthn, so it is
// set here once rather than in every test.
func testConfig(t *testing.T, secretKey string) config.Server {
	t.Helper()
	v := viper.New()
	v.Set("database.path", ":memory:")
	v.Set("auth.hmac.secret_key", secretKey)
	v.Set("server.base_url", "https://ddns.example.com")
	cfg, err := config.Load(v, "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

func TestNew_FailsClosedOnBadSecretKey(t *testing.T) {
	tests := []struct {
		name      string
		secretKey string
	}{
		{"empty", ""},
		{"wrong length", base64.StdEncoding.EncodeToString([]byte("too-short"))},
		{"not base64", "not valid base64!!"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(t, tt.secretKey)
			if _, err := server.New(cfg, memStore(t), discard(), server.NopInstruments{}); err == nil {
				t.Fatalf("New() with secret_key %q = nil error, want fail-closed error", tt.secretKey)
			}
		})
	}
}

func TestServer_AllEndpoints(t *testing.T) {
	cfg := testConfig(t, validSecretKey())
	handler, _, err := server.Handler(cfg, memStore(t), discard(), server.NopInstruments{})
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	cases := []struct {
		path       string
		wantStatus int
		contains   string
	}{
		{"/healthz", 200, "ok"},
		{"/readyz", 200, "ready"},
		{"/agent/v1/capabilities", 200, "server_version"},
		{"/agent/v1/openapi.json", 200, "openapi"},
		{"/api/v1/openapi.json", 200, "openapi"},
		{"/agent/v1/docs", 200, "scalar"},
		{"/api/v1/docs", 200, "scalar"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			resp, err := http.Get(srv.URL + c.path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != c.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, c.wantStatus)
			}
			b, _ := io.ReadAll(resp.Body)
			if !strings.Contains(strings.ToLower(string(b)), c.contains) {
				t.Errorf("body missing %q", c.contains)
			}
			if resp.Header.Get("X-Request-Id") == "" {
				t.Error("missing X-Request-Id (middleware chain not applied)")
			}
		})
	}
}

func TestServer_RunShutsDownOnCancel(t *testing.T) {
	cfg := testConfig(t, validSecretKey())
	cfg.Server.Listen = "127.0.0.1:0"
	s, err := server.New(cfg, memStore(t), discard(), server.NopInstruments{})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not shut down within 5s")
	}
}

// TestServer_OIDCDegradesWhenNotRequired confirms that OIDC enabled with an
// unreachable IdP does not block startup when Required is false (degrade):
// Handler builds successfully and capabilities reports oidc_enabled=false
// since discovery never ran synchronously (only RetryLoop, started by Run,
// would retry it in the background).
func TestServer_OIDCDegradesWhenNotRequired(t *testing.T) {
	cfg := testConfig(t, validSecretKey())
	cfg.Server.BaseURL = "https://ddns.example.com"
	cfg.Auth.OIDC = config.OIDCCfg{
		Enabled:      true,
		Required:     false,
		Issuer:       "http://127.0.0.1:1/nope",
		ClientID:     "x",
		ClientSecret: "y",
		Scopes:       []string{"openid"},
	}

	handler, _, err := server.Handler(cfg, memStore(t), discard(), server.NopInstruments{})
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/agent/v1/capabilities")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"oidc_enabled":false`) {
		t.Errorf("capabilities body = %s, want oidc_enabled:false", body)
	}
}

// TestServer_OIDCFailsClosedWhenRequired confirms that OIDC enabled AND
// required with an unreachable IdP makes Handler fail closed (mirrors the
// HMAC-key fail-closed path).
func TestServer_OIDCFailsClosedWhenRequired(t *testing.T) {
	cfg := testConfig(t, validSecretKey())
	cfg.Server.BaseURL = "https://ddns.example.com"
	cfg.Auth.OIDC = config.OIDCCfg{
		Enabled:      true,
		Required:     true,
		Issuer:       "http://127.0.0.1:1/nope",
		ClientID:     "x",
		ClientSecret: "y",
		Scopes:       []string{"openid"},
	}

	if _, _, err := server.Handler(cfg, memStore(t), discard(), server.NopInstruments{}); err == nil {
		t.Fatal("server.Handler() = nil error, want fail-closed error when oidc required but discovery fails")
	}
}

// TestHandler_FailsClosedOnUnresolvableWebAuthnRP confirms that when passkey
// login is available (auth.hide_local_login_ui unset, the default) and its
// WebAuthn Relying Party cannot be resolved (no server.base_url, no explicit
// auth.webauthn.rp_origin), Handler fails closed rather than serving a
// passkey login button whose ceremonies could never verify (design §10,
// mirrors the HMAC-key and required-OIDC fail-closed paths).
func TestHandler_FailsClosedOnUnresolvableWebAuthnRP(t *testing.T) {
	v := viper.New()
	v.Set("database.path", ":memory:")
	v.Set("auth.hmac.secret_key", validSecretKey())
	cfg, err := config.Load(v, "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Server.BaseURL != "" || cfg.Auth.WebAuthn.RPOrigin != "" {
		t.Fatalf("test setup: expected empty base_url/rp_origin, got %q/%q", cfg.Server.BaseURL, cfg.Auth.WebAuthn.RPOrigin)
	}

	if _, _, err := server.Handler(cfg, memStore(t), discard(), server.NopInstruments{}); err == nil {
		t.Fatal("server.Handler() = nil error, want fail-closed error when passkey login is available but the WebAuthn RP is unresolvable")
	}
}

// TestHandler_TolerantOfUnresolvableWebAuthnRPWhenLocalLoginHidden confirms
// the other half of the §10 predicate: when auth.hide_local_login_ui is set,
// there is no passkey login to serve, so an unresolvable WebAuthn RP does
// NOT fail Handler closed — it simply leaves PasskeyService unconstructed
// (deps.Passkey stays nil, which already keeps the passkey routes off the
// mux, see api.Build).
func TestHandler_TolerantOfUnresolvableWebAuthnRPWhenLocalLoginHidden(t *testing.T) {
	v := viper.New()
	v.Set("database.path", ":memory:")
	v.Set("auth.hmac.secret_key", validSecretKey())
	v.Set("auth.hide_local_login_ui", true)
	cfg, err := config.Load(v, "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	if _, _, err := server.Handler(cfg, memStore(t), discard(), server.NopInstruments{}); err != nil {
		t.Fatalf("server.Handler() = %v, want no error when hide_local_login_ui tolerates an unresolvable RP", err)
	}
}

// TestServer_PasskeyRoutesWired confirms the live wiring: with a resolvable
// WebAuthn RP (base_url set, the default via testConfig), the web UI's
// /login page is mounted on the mux and the passkey login API is registered
// (deps.Passkey/deps.Grants are non-nil, not left nil per the old
// Task-8-era placeholder).
func TestServer_PasskeyRoutesWired(t *testing.T) {
	cfg := testConfig(t, validSecretKey())
	handler, _, err := server.Handler(cfg, memStore(t), discard(), server.NopInstruments{})
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login status = %d, want 200", resp.StatusCode)
	}

	beginResp, err := http.Post(srv.URL+"/api/v1/auth/passkey/login/begin", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer beginResp.Body.Close()
	if beginResp.StatusCode == http.StatusNotFound {
		t.Fatal("POST /api/v1/auth/passkey/login/begin = 404, want the passkey op registered (deps.Passkey non-nil)")
	}
	body, _ := io.ReadAll(beginResp.Body)
	if beginResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/v1/auth/passkey/login/begin status = %d, body = %s, want 200", beginResp.StatusCode, body)
	}
	if !strings.Contains(string(body), "publicKey") {
		t.Errorf("login/begin body = %s, want WebAuthn credential-request options", body)
	}
}

// TestServer_NotificationRoutesWired confirms the live wiring for #152: the
// real cfg.Notifications.Enabled -> server.go's notifyAPISvc gate ->
// api.Build's nil-tolerant deps.Notify check chain, not just a hand-built
// api.ServerDeps (see internal/server/api's newNotificationHarness for that
// narrower unit-level check, which this test complements rather than
// replaces). Checks both a read (GET list) and a mutation (PATCH) in each
// case: notifications.enabled=false must leave BOTH fully absent (404, not
// merely guarded), and =true must register BOTH — a disabled-case check that
// only covered GET would miss a registration bug isolated to the mutating
// ops.
func TestServer_NotificationRoutesWired(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
	}{
		{"disabled", false},
		{"enabled", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			v.Set("database.path", ":memory:")
			v.Set("auth.hmac.secret_key", validSecretKey())
			v.Set("server.base_url", "https://ddns.example.com")
			v.Set("notifications.enabled", tt.enabled)
			cfg, err := config.Load(v, "")
			if err != nil {
				t.Fatalf("config.Load: %v", err)
			}

			handler, _, err := server.Handler(cfg, memStore(t), discard(), server.NopInstruments{})
			if err != nil {
				t.Fatalf("server.Handler: %v", err)
			}
			srv := httptest.NewServer(handler)
			t.Cleanup(srv.Close)

			getResp, err := http.Get(srv.URL + "/api/v1/admin/endpoints")
			if err != nil {
				t.Fatal(err)
			}
			defer getResp.Body.Close()

			patchReq, err := http.NewRequest(http.MethodPatch, srv.URL+"/api/v1/admin/endpoints/some-id", strings.NewReader(`{}`))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			patchResp, err := http.DefaultClient.Do(patchReq)
			if err != nil {
				t.Fatal(err)
			}
			defer patchResp.Body.Close()

			if tt.enabled {
				if getResp.StatusCode == http.StatusNotFound {
					t.Error("GET /api/v1/admin/endpoints = 404 with notifications.enabled=true, want the route registered")
				}
				if patchResp.StatusCode == http.StatusNotFound {
					t.Error("PATCH /api/v1/admin/endpoints/{id} = 404 with notifications.enabled=true, want the route registered")
				}
			} else {
				if getResp.StatusCode != http.StatusNotFound {
					t.Errorf("GET /api/v1/admin/endpoints = %d with notifications.enabled=false, want 404 (route absent)", getResp.StatusCode)
				}
				if patchResp.StatusCode != http.StatusNotFound {
					t.Errorf("PATCH /api/v1/admin/endpoints/{id} = %d with notifications.enabled=false, want 404 (route absent)", patchResp.StatusCode)
				}
			}
		})
	}
}

// TestServer_ServeBoot is the happy-path serve boot test (follow-up #6): New
// + Run in a goroutine, hit a real endpoint over the network, cancel, and
// confirm a clean shutdown.
func TestServer_ServeBoot(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("ln.Close: %v", err)
	}

	cfg := testConfig(t, validSecretKey())
	cfg.Server.Listen = addr
	s, err := server.New(cfg, memStore(t), discard(), server.NopInstruments{})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	var resp *http.Response
	for range 50 {
		resp, err = http.Get("http://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v, want nil on clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not shut down within 5s")
	}
}

// TestVerifier_SurvivesRestart proves AEAD-at-rest repopulation across a
// process restart (design §12.5): a device is enrolled (its HMAC secret
// sealed under key K) by one store handle, then a BRAND-NEW Verifier is
// constructed over a freshly re-opened handle to the same on-disk database.
// Nothing survives from the enrolling process's in-memory state — a
// :memory: database would not, so this uses a temp-file DB — yet the new
// Verifier must still authenticate a signed check-in using only the
// persisted sealed secret.
func TestVerifier_SurvivesRestart(t *testing.T) {
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "diyddns.db")

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// --- process 1: enroll a device, then shut down ---
	st1, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	u, err := st1.Users().Create(ctx, store.User{Email: "restart@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	enroll := service.NewEnrollmentService(st1, key, 15*time.Minute, service.NewAuditWriter(st1))
	result, err := enroll.EnrollForUser(ctx, u.ID, "device.enroll.oidc", service.ClientMeta{Hostname: "restart-host"})
	if err != nil {
		t.Fatalf("EnrollForUser: %v", err)
	}
	if err := st1.Close(); err != nil {
		t.Fatalf("st1.Close: %v", err)
	}

	// --- process 2: reopen the same DB, construct a NEW Verifier with the
	// same key, and confirm a signed check-in verifies. ---
	st2, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("store.Open (restart): %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })

	v := auth.NewVerifier(st2.Devices(), st2.Users(), st2.ReplayNonces(), key, 120*time.Second, 120*time.Second)

	now := int64(1720000000)
	ts := strconv.FormatInt(now, 10)
	nonce := "restart-nonce"
	body := []byte(`{"ipv4":"1.2.3.4"}`)
	sig := shared.Sign(result.Secret, shared.CanonicalRequest("POST", "/agent/v1/checkin", ts, nonce, shared.BodyHashHex(body)))
	parts := auth.RequestParts{
		Device: result.DeviceID, Timestamp: ts, Nonce: nonce, Signature: sig,
		Method: "POST", Path: "/agent/v1/checkin", Body: body,
	}

	gotID, err := v.Verify(ctx, parts, now)
	if err != nil {
		t.Fatalf("Verify after restart: %v", err)
	}
	if gotID != result.DeviceID {
		t.Fatalf("Verify() device = %q, want %q", gotID, result.DeviceID)
	}
}

// bufferLogger returns a logger writing into buf, for asserting on log output.
func bufferLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

// retentionConfig builds a valid server config with the given retention keys.
// It does not reuse testConfig, whose signature takes only a secret key.
func retentionConfig(t *testing.T, ipDays, perDeviceMax, auditDays int) config.Server {
	t.Helper()
	v := viper.New()
	v.Set("database.path", ":memory:")
	v.Set("auth.hmac.secret_key", validSecretKey())
	v.Set("server.base_url", "https://ddns.example.com")
	v.Set("retention.ip_history_days", ipDays)
	v.Set("retention.ip_history_per_device_max", perDeviceMax)
	v.Set("retention.audit_log_days", auditDays)
	cfg, err := config.Load(v, "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

func TestNew_WarnsWhenRetentionEnabled(t *testing.T) {
	var buf bytes.Buffer
	if _, err := server.New(retentionConfig(t, 90, 0, 365), memStore(t), bufferLogger(&buf), server.NopInstruments{}); err != nil {
		t.Fatalf("server.New: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "retention enabled") {
		t.Errorf("startup log does not warn that retention is on:\n%s", out)
	}
	for _, want := range []string{
		"ip_history_days=90",
		"ip_history_per_device_max=0",
		"audit_log_days=365",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("startup warning does not name %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("retention notice is not at WARN level:\n%s", out)
	}
}

func TestNew_SilentWhenRetentionDisabled(t *testing.T) {
	var buf bytes.Buffer
	if _, err := server.New(retentionConfig(t, 0, 0, 0), memStore(t), bufferLogger(&buf), server.NopInstruments{}); err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if strings.Contains(buf.String(), "retention enabled") {
		t.Errorf("all-zero retention must warn about nothing:\n%s", buf.String())
	}
}

// D8 rests on r.Pattern resolving through the REAL handler for every route
// registration surface: the plain-mux health handlers, both huma groups, and
// the webui patterns. A hand-rolled mux cannot show that; only the real
// handler can. (It does not isolate the webui's NESTED mux -- server.go
// forwards webui.New's own pattern strings onto the OUTER mux, so the outer
// one resolves the template before the inner mux ever runs.)
//
// Every row is checked against the record its OWN request produced,
// correlated by the request id the response echoes back. An existential
// "some record carries this route" check cannot tell the 404 row from the
// 405 row -- both log an empty route -- so it would pass even if the 405
// request had 404'd, had leaked a template, or had never reached AccessLog.
func TestHandler_AccessLogRouteCoversEverySurface(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.json")
	// Level debug, not info: /healthz logs at Debug (it's polled every few
	// seconds by a liveness probe and would spam Info-level logs otherwise),
	// and the "plain mux health" row below needs its record to exist.
	log, err := server.NewLogger(config.LoggingSection{Level: "debug", Format: "json", Output: path}, nil)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	inst := newRecordingInstruments(t)
	h, _, err := server.Handler(testConfig(t, validSecretKey()), memStore(t), log, inst)
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// One request per row, so redirects must not be followed: /devices/{id}
	// answers 303 to /login when unauthenticated (webui/auth.go:34), and a
	// followed redirect returns /login's request id -- correlating the row to
	// the wrong record.
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	tests := []struct {
		name, method, target, wantRoute string
		wantStatus                      float64
	}{
		{"plain mux health", "GET", "/healthz", "GET /healthz", 200},
		{"huma api group", "GET", "/api/v1/devices/dev_01J8WABCDEF", "GET /api/v1/devices/{id}", 401},
		{"huma agent group", "POST", "/agent/v1/checkin", "POST /agent/v1/checkin", 401},
		{"webui nested mux", "GET", "/devices/dev_01J8WABCDEF", "GET /devices/{id}", 303},
		{"webui static prefix", "GET", "/static/app.css", "GET /static/", 200},
		{"unmatched (404)", "GET", "/nope/not/a/route", "", 404},
		// 405: the mux registers PATCH/DELETE on this path, not GET. Design
		// 11.4 lists it, and only the real handler has a route table where a
		// method mismatch is possible. wantStatus is what separates this row
		// from the 404 row above; both log an empty route.
		{"method mismatch (405)", "GET", "/api/v1/admin/users/usr_01J8WZZZ", "", 405},
	}

	ids := make([]string, len(tests)) // row -> the id its response echoed
	for i, tt := range tests {
		req, _ := http.NewRequest(tt.method, srv.URL+tt.target, strings.NewReader("{}"))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		_ = resp.Body.Close()
		ids[i] = resp.Header.Get("X-Request-Id")
		if ids[i] == "" {
			t.Fatalf("%s: response echoed no correlation header", tt.name)
		}
	}

	// WAIT for the records; do not assume one read catches them. AccessLog
	// emits its line only AFTER the inner handler returns -- it needs the final
	// status and byte count -- whereas client.Do returns as soon as the
	// response HEADERS arrive. The "webui static prefix" row ships a 30 KB
	// app.css, so wherever the socket buffers hold less than that (a Linux CI
	// runner; not macOS, whose threshold is far higher) the handler is still
	// writing its body, and has therefore not logged, when the loop above has
	// already fired the remaining rows and moved on. That is exactly the shape
	// CI reported: only the static row lost, and rows AFTER it still passed.
	//
	// Draining each response body would narrow this window, not close it --
	// the last body byte still reaches the client before the server reaches
	// log.LogAttrs. Polling for the condition removes it: the loop cannot
	// proceed until every row's record actually exists, so no host's buffer
	// size can change the outcome. Reproduced deterministically with a 1 MiB
	// body, where a single read loses on macOS too.
	var raw []byte
	byID := map[string]map[string]any{}
	deadline := time.Now().Add(10 * time.Second)
	for {
		raw, err = os.ReadFile(path)
		if err != nil {
			t.Fatalf("read log: %v", err)
		}
		clear(byID)
		for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) != nil || rec["msg"] != "request" {
				continue
			}
			id, _ := rec["request_id"].(string)
			byID[id] = rec
		}
		var missing []string
		for i, tt := range tests {
			if _, ok := byID[ids[i]]; !ok {
				missing = append(missing, tt.name+" ("+ids[i]+")")
			}
		}
		if len(missing) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no access-log record after 10s for %d of %d rows: %s",
				len(missing), len(tests), strings.Join(missing, ", "))
		}
		time.Sleep(5 * time.Millisecond)
	}
	for i, tt := range tests {
		rec := byID[ids[i]] // the wait above guarantees every row is present
		if got := rec["route"]; got != tt.wantRoute {
			t.Errorf("%s: route = %v, want %q", tt.name, got, tt.wantRoute)
		}
		if got := rec["status"]; got != tt.wantStatus {
			t.Errorf("%s: status = %v, want %v", tt.name, got, tt.wantStatus)
		}
		if got := rec["method"]; got != tt.method {
			t.Errorf("%s: method = %v, want %q", tt.name, got, tt.method)
		}
	}
	// The privacy rationale for D8 names device ids AND the user ids on
	// /api/v1/admin/users/{id}; both are driven through above, so pin both.
	for _, id := range []string{"dev_01J8WABCDEF", "usr_01J8WZZZ"} {
		if strings.Contains(string(raw), id) {
			t.Errorf("%q reached the access log", id)
		}
	}

	// Row 1 (huma api group) is unauthenticated, so sessionMiddleware also
	// emits a "session auth rejected" record for it. This is the branch's
	// headline property: a rejection record joins to the request that caused
	// it. Pinning it here, rather than in its own test, is what forces it
	// through the real server.NewLogger and the real server.Handler -- a bare
	// slog.New(slog.NewJSONHandler(...)) has no request_id ContextHandler, so
	// request_id could never appear in a hand-built buffer, and a door that
	// logs with context.Background() instead of the request context would
	// otherwise pass the entire suite while this join went silently missing.
	var rejectedID string
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == "session auth rejected" {
			rejectedID, _ = m["request_id"].(string)
			break
		}
	}
	if rejectedID != ids[1] {
		t.Errorf("session auth rejected: request_id = %q, want %q (huma api group's echoed id)", rejectedID, ids[1])
	}

	// THE §4.4 GUARD. For every row, the span name must match the same route
	// the access log recorded. Moving Trace inside AccessLog, or reading
	// r.Pattern instead of r2.Pattern, both fail this block too -- but BOTH
	// are already caught elsewhere in the tree (TestTrace_SpanNameIsRouteTemplate,
	// internal/server/middleware, catches the r.Pattern/r2.Pattern swap
	// directly). What is uniquely caught HERE, and by nothing else in the
	// tree (verified: `go test ./internal/...` against the mutation stays
	// green everywhere except this test), is deleting
	// middleware.Trace(inst.Tracer(), inst.RequestDuration()) from handler()'s
	// Chain call (server.go:369) entirely: nothing else in this repo drives a
	// request through server.Handler and asserts a span was ever produced.
	//
	// Read the ALREADY-COLLECTED spans; do not re-drive the requests. The rows
	// above are the only ones whose ids were captured, so a second pass would
	// produce spans no row can be correlated to.
	//
	// BUT FIRST, A BARRIER -- and the record wait above is not one. Chain
	// applies its middlewares in reverse (middleware.go:383), so server.go's
	// RequestID, Trace, AccessLog, Recover list puts Trace OUTSIDE AccessLog,
	// and span.End() is Trace's outermost defer. Every span therefore ends
	// AFTER the record the loop above waited for was written, across the
	// SetName/SetAttributes/dur.Record gap. The row at risk is whichever one's
	// record lands LAST: the loop breaks the moment that record appears, while
	// that row's span is still in flight. Only a row that flushes its response
	// before its handler returns can be that row -- a small body is buffered
	// until ServeHTTP returns, so client.Do already implies the span ended --
	// which is why the 30 KB static row is the exposure and why CI has never
	// lost this one. It is racy all the same.
	//
	// srv.Close is a happens-before edge rather than another timing guess, so
	// there is no deadline here to tune and none to wait out. It blocks on the
	// waitgroup httptest decrements when a connection reaches StateClosed or
	// StateHijacked, and net/http reaches either only after
	// serverHandler.ServeHTTP has returned -- hence after every deferred
	// span.End(). SimpleSpanProcessor exports inline from OnEnd, so a span
	// that has ended is a span this exporter already holds. The t.Cleanup
	// Close is then a no-op: Close guards its shutdown on s.closed and
	// re-waits an already-drained waitgroup.
	//
	// Reproduced deterministically (10/10 under -race) by padding the embedded
	// app.css to 1.3 MiB, moving the static row LAST, and wrapping this test's
	// histogram in one that sleeps 200ms inside Record -- the last statement
	// before span.End(). Without the Close every run reported 6 spans of 7.
	srv.Close()

	spans := inst.spans.GetSpans()
	switch {
	case len(spans) == 0:
		// The mutation this block exists for. Fails on the first read, with no
		// wait at all: Close already drained every handler goroutine.
		t.Fatalf("no spans at all, want %d (one per row): is middleware.Trace still in handler()'s Chain call?", len(tests))
	case len(spans) != len(tests):
		t.Fatalf("got %d spans, want %d (one per row); srv.Close above drained every handler, so a span is genuinely missing or surplus, not one still in flight", len(spans), len(tests))
	}
	// ORDER IS DELIBERATELY NOT ASSERTED -- matching spans[i] to tests[i] was a
	// real flake that CI caught and 60 local runs did not. span.End() is the
	// OUTERMOST deferred call in Trace, so it runs after the response has been
	// written; meanwhile these rows close their response bodies WITHOUT draining
	// them, which stops net/http reusing the connection (measured: 2 distinct
	// server connections for these 7 requests). So the next request can be
	// served by a second goroutine that reaches span.End() before the previous
	// one does, and the export order is whatever order the goroutines finish in.
	// Reproduced under -race with a 20ms sleep before span.End(): 9-14 of every
	// 20 runs failed, always swapping exactly these two rows --
	//   webui static prefix: span name = "HTTP GET", want "GET /static/"
	//   unmatched (404):     span name = "GET /static/", want "HTTP GET"
	// -- the pair straddling the connection boundary, which is precisely what CI
	// reported. Every name was individually correct; only the order was not.
	//
	// A multiset still fails on any wrong, missing or extra name, and the two
	// mutations this block exists for are both caught by it: deleting
	// middleware.Trace from handler()'s chain yields 0 spans (the check above),
	// and reading r.Pattern instead of r2.Pattern collapses every name to
	// "HTTP GET"/"HTTP POST". The per-row name-to-route correspondence is
	// already pinned against the access log earlier in this test.
	wantNames := map[string]int{}
	for _, tt := range tests {
		want := tt.wantRoute
		if want == "" {
			want = "HTTP " + tt.method // the 404 and 405 rows
		}
		wantNames[want]++
	}
	gotNames := map[string]int{}
	for _, s := range spans {
		gotNames[s.Name]++
	}
	if !maps.Equal(gotNames, wantNames) {
		t.Errorf("span names = %v, want %v (order is deliberately not asserted)", gotNames, wantNames)
	}
}

// recordingInstruments backs server.Instruments with an in-memory span
// exporter, so a test can assert on emitted spans. The meter provider it
// builds has no reader attached: RequestDuration/DeliveryCount exist only so
// Trace and notify.Worker have somewhere to record into without a nil
// panic -- nothing in this file asserts on their values, so no reader is
// wired up (fix round 2, I4: an earlier revision of this comment claimed a
// manual metric reader that was never built).
//
// SimpleSpanProcessor, NOT BatchSpanProcessor: batching exports asynchronously
// and every assertion against spans would race.
type recordingInstruments struct {
	spans      *tracetest.InMemoryExporter
	tracer     trace.Tracer
	requestDur metric.Float64Histogram
	deliveries metric.Int64Counter
}

func newRecordingInstruments(t *testing.T) *recordingInstruments {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })
	mp := sdkmetric.NewMeterProvider()
	t.Cleanup(func() { _ = mp.Shutdown(t.Context()) })
	meter := mp.Meter("test")
	dur, _ := meter.Float64Histogram("http.server.request.duration", metric.WithUnit("s"))
	cnt, _ := meter.Int64Counter("diyddns.notification.delivery", metric.WithUnit("{delivery}"))
	return &recordingInstruments{spans: exp, tracer: tp.Tracer("test"), requestDur: dur, deliveries: cnt}
}

func (r *recordingInstruments) Tracer() trace.Tracer                     { return r.tracer }
func (r *recordingInstruments) RequestDuration() metric.Float64Histogram { return r.requestDur }
func (r *recordingInstruments) DeliveryCount() metric.Int64Counter       { return r.deliveries }
func (r *recordingInstruments) ObserveDB(*sql.DB)                        {}

// observeDBRecorder embeds NopInstruments so it stays a working Instruments
// for every other method, and records only the *sql.DB ObserveDB receives --
// this is the seam TestNew_CallsObserveDB pins.
type observeDBRecorder struct {
	server.NopInstruments
	db *sql.DB
}

// ObserveDB records db for the test to inspect.
func (o *observeDBRecorder) ObserveDB(db *sql.DB) { o.db = db }

// TestNew_CallsObserveDB pins that New wires the store's *sql.DB into
// Instruments.ObserveDB. Nothing else in this task's suite drives New with an
// Instruments that can observe the call, so without this test deleting the
// inst.ObserveDB(st.DB()) line in New survives silently (fix round 1, B1).
func TestNew_CallsObserveDB(t *testing.T) {
	inst := &observeDBRecorder{}
	st := memStore(t)
	if _, err := server.New(testConfig(t, validSecretKey()), st, discard(), inst); err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if inst.db == nil {
		t.Fatal("server.New did not call inst.ObserveDB(st.DB())")
	}
	if inst.db != st.DB() {
		t.Errorf("inst.ObserveDB received %p, want the store's own *sql.DB (%p)", inst.db, st.DB())
	}
}
