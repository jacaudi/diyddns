package config_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/config"
)

// loadWithDB is a test helper that sets the required database.path and calls
// config.Load with a fresh viper instance.
func loadWithDB(t *testing.T) (config.Server, error) {
	t.Helper()
	v := viper.New()
	v.Set("database.path", ":memory:")
	return config.Load(v, "")
}

// mustLoadWithDB is loadWithDB but fails the test on error.
func mustLoadWithDB(t *testing.T) config.Server {
	t.Helper()
	cfg, err := loadWithDB(t)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestLoad_Defaults(t *testing.T) {
	v := viper.New()
	v.Set("database.path", ":memory:") // required field
	cfg, err := config.Load(v, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":8080" {
		t.Errorf("Listen = %q, want :8080", cfg.Server.Listen)
	}
	if cfg.Logging.Level != "info" || cfg.Logging.Format != "json" || cfg.Logging.Output != "stderr" {
		t.Errorf("logging defaults = %+v", cfg.Logging)
	}
}

func TestLoad_MissingDatabasePathIsError(t *testing.T) {
	v := viper.New()
	_, err := config.Load(v, "")
	if err == nil {
		t.Fatal("expected error for missing database.path")
	}
}

func TestLoad_FileOverridesDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listen: \":9999\"\ndatabase:\n  path: \"/tmp/x.db\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	v := viper.New()
	cfg, err := config.Load(v, path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":9999" {
		t.Errorf("Listen = %q, want :9999", cfg.Server.Listen)
	}
	if cfg.Database.Path != "/tmp/x.db" {
		t.Errorf("Path = %q", cfg.Database.Path)
	}
}

func TestLoad_EnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listen: \":9999\"\ndatabase:\n  path: \"/tmp/x.db\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DIYDDNS_SERVER_LISTEN", ":7000")
	v := viper.New()
	cfg, err := config.Load(v, path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":7000" {
		t.Errorf("Listen = %q, want :7000 (env wins over file)", cfg.Server.Listen)
	}
}

func TestLoad_FlagBeatsEnv(t *testing.T) {
	t.Setenv("DIYDDNS_SERVER_LISTEN", ":7000")
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.String("listen", "", "")
	_ = fs.Set("listen", ":6000") // marks the flag Changed
	v := viper.New()
	if err := v.BindPFlag("server.listen", fs.Lookup("listen")); err != nil {
		t.Fatal(err)
	}
	v.Set("database.path", ":memory:")
	cfg, err := config.Load(v, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":6000" {
		t.Errorf("Listen = %q, want :6000 (changed flag wins over env)", cfg.Server.Listen)
	}
}

func TestLoad_BaseURLMapsUnderscoreKey(t *testing.T) {
	t.Setenv("DIYDDNS_SERVER_BASE_URL", "https://ddns.example.com")
	v := viper.New()
	v.Set("database.path", ":memory:")
	cfg, err := config.Load(v, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.BaseURL != "https://ddns.example.com" {
		t.Errorf("BaseURL = %q", cfg.Server.BaseURL)
	}
}

func TestLoad_AuthDefaults(t *testing.T) {
	cfg := mustLoadWithDB(t)
	if cfg.Auth.Session.CookieName != "diyddns_session" {
		t.Errorf("Session.CookieName = %q, want diyddns_session", cfg.Auth.Session.CookieName)
	}
	if !cfg.Auth.Session.CookieSecure {
		t.Error("Session.CookieSecure = false, want true")
	}
	if cfg.Auth.Session.CookieSameSite != "lax" {
		t.Errorf("Session.CookieSameSite = %q, want lax", cfg.Auth.Session.CookieSameSite)
	}
	if cfg.Auth.Session.TTL != 720*time.Hour {
		t.Errorf("Session.TTL = %v, want 720h", cfg.Auth.Session.TTL)
	}
	if cfg.Auth.Session.SlideWindow != 168*time.Hour {
		t.Errorf("Session.SlideWindow = %v, want 168h", cfg.Auth.Session.SlideWindow)
	}
	if cfg.Auth.HMAC.SkewWindow != 120*time.Second {
		t.Errorf("HMAC.SkewWindow = %v, want 120s", cfg.Auth.HMAC.SkewWindow)
	}
	if cfg.Auth.HMAC.NonceTTL != 120*time.Second {
		t.Errorf("HMAC.NonceTTL = %v, want 120s", cfg.Auth.HMAC.NonceTTL)
	}
	if cfg.Auth.HMAC.SecretKey != "" {
		t.Errorf("HMAC.SecretKey = %q, want empty by default", cfg.Auth.HMAC.SecretKey)
	}
	if cfg.Auth.Password.Argon2Time != 3 {
		t.Errorf("Password.Argon2Time = %d, want 3", cfg.Auth.Password.Argon2Time)
	}
	if cfg.Auth.Password.Argon2MemoryKiB != 65536 {
		t.Errorf("Password.Argon2MemoryKiB = %d, want 65536", cfg.Auth.Password.Argon2MemoryKiB)
	}
	if cfg.Auth.Password.Argon2Parallelism != 2 {
		t.Errorf("Password.Argon2Parallelism = %d, want 2", cfg.Auth.Password.Argon2Parallelism)
	}
	if cfg.Auth.Password.MinLength != 12 {
		t.Errorf("Password.MinLength = %d, want 12", cfg.Auth.Password.MinLength)
	}
	if cfg.Auth.Bootstrap.AdminEmail != "" || cfg.Auth.Bootstrap.AdminPassword != "" {
		t.Errorf("Bootstrap = %+v, want empty by default", cfg.Auth.Bootstrap)
	}
}

func TestLoad_RejectsNonceTTLBelowSkew(t *testing.T) {
	t.Setenv("DIYDDNS_AUTH_HMAC_NONCE_TTL", "60s")
	t.Setenv("DIYDDNS_AUTH_HMAC_SKEW_WINDOW", "120s")
	if _, err := loadWithDB(t); err == nil {
		t.Fatal("expected nonce_ttl<skew_window error")
	}
}

// TestLoad_HMACSecretKeyEnvBinding is the regression guard for the top plan-review
// finding: config.Load has no viper.AutomaticEnv(), so every auth.* key MUST be
// registered in keyDefaults or its DIYDDNS_* env var is silently dropped. This test
// fails if auth.hmac.secret_key is ever missing from keyDefaults.
func TestLoad_HMACSecretKeyEnvBinding(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	want := base64.StdEncoding.EncodeToString(raw)
	t.Setenv("DIYDDNS_AUTH_HMAC_SECRET_KEY", want)
	cfg := mustLoadWithDB(t)
	if cfg.Auth.HMAC.SecretKey != want {
		t.Errorf("Auth.HMAC.SecretKey = %q, want %q (env var DIYDDNS_AUTH_HMAC_SECRET_KEY was dropped)", cfg.Auth.HMAC.SecretKey, want)
	}
}

// TestLoad_BootstrapAdminEmailEnvAlias asserts the spec §5C env-var name
// DIYDDNS_BOOTSTRAP_ADMIN_EMAIL binds to auth.bootstrap.admin_email, distinct from
// the auto-derived DIYDDNS_AUTH_BOOTSTRAP_ADMIN_EMAIL.
func TestLoad_BootstrapAdminEmailEnvAlias(t *testing.T) {
	t.Setenv("DIYDDNS_BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
	t.Setenv("DIYDDNS_BOOTSTRAP_ADMIN_PASSWORD", "hunter2hunter2")
	cfg := mustLoadWithDB(t)
	if cfg.Auth.Bootstrap.AdminEmail != "admin@example.com" {
		t.Errorf("Bootstrap.AdminEmail = %q, want admin@example.com", cfg.Auth.Bootstrap.AdminEmail)
	}
	if cfg.Auth.Bootstrap.AdminPassword != "hunter2hunter2" {
		t.Errorf("Bootstrap.AdminPassword = %q, want hunter2hunter2", cfg.Auth.Bootstrap.AdminPassword)
	}
}

func TestSecretKeyBytes_Requires32(t *testing.T) {
	if _, err := config.DecodeSecretKey(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
		t.Fatal("16-byte key must be rejected")
	}
	if _, err := config.DecodeSecretKey("not-valid-base64!!!"); err == nil {
		t.Fatal("non-base64 input must be rejected")
	}
	raw := make([]byte, 32)
	got, err := config.DecodeSecretKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("32-byte key must parse: %v", err)
	}
	if len(got) != 32 {
		t.Errorf("DecodeSecretKey returned %d bytes, want 32", len(got))
	}
}
