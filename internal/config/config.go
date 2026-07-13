// Package config loads the diyddns-server configuration from (in precedence
// order) command-line flags, DIYDDNS_* environment variables, an optional YAML
// file, and built-in defaults. The struct is intentionally minimal for the
// Plan 03 skeleton; new sections (tls, auth, oidc, retention) are added as new
// fields without restructuring existing callers.
package config

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Server is the fully-resolved server configuration.
type Server struct {
	Server   ServerSection
	Database DatabaseSection
	Logging  LoggingSection
	Auth     Auth
}

// ServerSection holds HTTP listener settings.
type ServerSection struct {
	Listen  string
	BaseURL string `mapstructure:"base_url"`
}

// DatabaseSection holds the SQLite database location.
type DatabaseSection struct {
	Path string
}

// LoggingSection holds structured-logging settings.
type LoggingSection struct {
	Level  string
	Format string
	Output string
}

// Auth holds all authentication-related configuration: browser sessions, agent
// HMAC signing, password hashing, and first-run bootstrap.
type Auth struct {
	Session   SessionCfg
	HMAC      HMACCfg
	Password  PasswordCfg
	Bootstrap BootstrapCfg
}

// SessionCfg holds browser session cookie settings.
//
// mapstructure tags are required for multi-word keys — viper lowercases field
// names but does not split them (see ServerSection.BaseURL above).
type SessionCfg struct {
	CookieName     string        `mapstructure:"cookie_name"`
	CookieSecure   bool          `mapstructure:"cookie_secure"`
	CookieSameSite string        `mapstructure:"cookie_samesite"`
	TTL            time.Duration `mapstructure:"ttl"`
	SlideWindow    time.Duration `mapstructure:"slide_window"`
}

// HMACCfg holds agent request-signing settings.
type HMACCfg struct {
	SkewWindow time.Duration `mapstructure:"skew_window"`
	NonceTTL   time.Duration `mapstructure:"nonce_ttl"`
	SecretKey  string        `mapstructure:"secret_key"` // base64 of 32 bytes; decoded via DecodeSecretKey at startup
}

// PasswordCfg holds argon2id hashing parameters and password policy.
type PasswordCfg struct {
	Argon2Time        uint32 `mapstructure:"argon2_time"`
	Argon2MemoryKiB   uint32 `mapstructure:"argon2_memory_kib"`
	Argon2Parallelism uint8  `mapstructure:"argon2_parallelism"`
	MinLength         int    `mapstructure:"min_length"`
}

// BootstrapCfg holds the first-run admin account settings.
type BootstrapCfg struct {
	AdminEmail    string `mapstructure:"admin_email"`
	AdminPassword string `mapstructure:"admin_password"`
}

// keyDefaults enumerates every config key, its default, and its env var. Keys
// with a corresponding CLI flag (server.listen) still carry a SetDefault here;
// viper ranks SetDefault above an unchanged flag's default, so a changed flag
// or an env var still wins.
//
// Env binding is explicit: config.Load has no viper.AutomaticEnv(), so every
// key MUST be listed here or its DIYDDNS_* env var is silently ignored.
var keyDefaults = map[string]any{
	"server.listen":                    ":8080",
	"server.base_url":                  "",
	"database.path":                    "",
	"logging.level":                    "info",
	"logging.format":                   "json",
	"logging.output":                   "stderr",
	"auth.session.cookie_name":         "diyddns_session",
	"auth.session.cookie_secure":       true,
	"auth.session.cookie_samesite":     "lax",
	"auth.session.ttl":                 "720h",
	"auth.session.slide_window":        "168h",
	"auth.hmac.skew_window":            "120s",
	"auth.hmac.nonce_ttl":              "120s",
	"auth.hmac.secret_key":             "",
	"auth.password.argon2_time":        3,
	"auth.password.argon2_memory_kib":  65536,
	"auth.password.argon2_parallelism": 2,
	"auth.password.min_length":         12,
	"auth.bootstrap.admin_email":       "",
	"auth.bootstrap.admin_password":    "",
}

// Load resolves configuration into a Server. Callers may pre-configure v (e.g.
// viper.BindPFlag for flags) before calling. If configPath is non-empty the
// file is read; a missing/invalid file is an error.
func Load(v *viper.Viper, configPath string) (Server, error) {
	v.SetEnvPrefix("DIYDDNS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	for key, def := range keyDefaults {
		v.SetDefault(key, def)
		if err := v.BindEnv(key); err != nil {
			return Server{}, fmt.Errorf("config: bind env %s: %w", key, err)
		}
	}
	// Explicit aliases for the spec §5C bootstrap env-var names, distinct from
	// the auto-derived DIYDDNS_AUTH_BOOTSTRAP_* names above.
	if err := v.BindEnv("auth.bootstrap.admin_email", "DIYDDNS_BOOTSTRAP_ADMIN_EMAIL"); err != nil {
		return Server{}, fmt.Errorf("config: bind env DIYDDNS_BOOTSTRAP_ADMIN_EMAIL: %w", err)
	}
	if err := v.BindEnv("auth.bootstrap.admin_password", "DIYDDNS_BOOTSTRAP_ADMIN_PASSWORD"); err != nil {
		return Server{}, fmt.Errorf("config: bind env DIYDDNS_BOOTSTRAP_ADMIN_PASSWORD: %w", err)
	}

	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return Server{}, fmt.Errorf("config: read %s: %w", configPath, err)
		}
	}

	var cfg Server
	if err := v.Unmarshal(&cfg); err != nil {
		return Server{}, fmt.Errorf("config: unmarshal: %w", err)
	}
	if cfg.Database.Path == "" {
		return Server{}, fmt.Errorf("config: database.path is required")
	}
	if cfg.Auth.HMAC.NonceTTL < cfg.Auth.HMAC.SkewWindow {
		return Server{}, fmt.Errorf("config: auth.hmac.nonce_ttl (%s) must be >= auth.hmac.skew_window (%s)",
			cfg.Auth.HMAC.NonceTTL, cfg.Auth.HMAC.SkewWindow)
	}
	return cfg, nil
}

// DecodeSecretKey decodes the base64 AEAD master key and requires exactly 32
// bytes. It does not validate presence — an empty auth.hmac.secret_key is
// allowed at config-load time; callers that need agent auth enforce
// fail-closed at startup by calling this and checking the error.
func DecodeSecretKey(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("config: auth.hmac.secret_key not valid base64: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("config: auth.hmac.secret_key must decode to 32 bytes, got %d", len(raw))
	}
	return raw, nil
}
