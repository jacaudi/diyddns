package server_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"

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
	st, err := store.Open(context.Background(), ":memory:")
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
			if _, err := server.New(cfg, memStore(t), discard()); err == nil {
				t.Fatalf("New() with secret_key %q = nil error, want fail-closed error", tt.secretKey)
			}
		})
	}
}

func TestServer_AllEndpoints(t *testing.T) {
	cfg := testConfig(t, validSecretKey())
	handler, err := server.Handler(cfg, memStore(t), discard())
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
		{"/agent/openapi.json", 200, "openapi"},
		{"/api/openapi.json", 200, "openapi"},
		{"/agent/docs", 200, "scalar"},
		{"/api/docs", 200, "scalar"},
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
	s, err := server.New(cfg, memStore(t), discard())
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
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

	handler, err := server.Handler(cfg, memStore(t), discard())
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

	if _, err := server.Handler(cfg, memStore(t), discard()); err == nil {
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

	if _, err := server.Handler(cfg, memStore(t), discard()); err == nil {
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

	if _, err := server.Handler(cfg, memStore(t), discard()); err != nil {
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
	handler, err := server.Handler(cfg, memStore(t), discard())
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
	s, err := server.New(cfg, memStore(t), discard())
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
	if _, err := server.New(retentionConfig(t, 90, 0, 365), memStore(t), bufferLogger(&buf)); err != nil {
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
	if _, err := server.New(retentionConfig(t, 0, 0, 0), memStore(t), bufferLogger(&buf)); err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if strings.Contains(buf.String(), "retention enabled") {
		t.Errorf("all-zero retention must warn about nothing:\n%s", buf.String())
	}
}
