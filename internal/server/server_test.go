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
// config.Load and its defaults), overriding only database.path (required)
// and auth.hmac.secret_key (the fail-closed knob under test).
func testConfig(t *testing.T, secretKey string) config.Server {
	t.Helper()
	v := viper.New()
	v.Set("database.path", ":memory:")
	v.Set("auth.hmac.secret_key", secretKey)
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
	pw := "correct horse battery staple"
	hash, err := auth.HashPassword(pw, auth.Argon2Params{Time: 3, MemoryKiB: 65536, Parallelism: 2})
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	u, err := st1.Users().Create(ctx, store.User{Email: "restart@example.com", PasswordHash: hash, Role: "user"})
	if err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	enroll := service.NewEnrollmentService(st1, key, 15*time.Minute, service.NewAuditWriter(st1))
	result, err := enroll.EnrollCredentials(ctx, u.Email, pw, service.ClientMeta{Hostname: "restart-host"})
	if err != nil {
		t.Fatalf("EnrollCredentials: %v", err)
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
