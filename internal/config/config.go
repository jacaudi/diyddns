// Package config loads the diyddns-server and diyddns-client configuration
// from (in precedence order) command-line flags, DIYDDNS_* environment
// variables, an optional YAML file, and built-in defaults. The struct is
// intentionally minimal for the Plan 03 skeleton; new sections (tls, auth,
// oidc, retention) are added as new fields without restructuring existing
// callers.
package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"slices"
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
	Email    EmailSection
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

// EmailSection holds SMTP settings for outbound account email (e.g. passkey
// recovery notices). Enabled gates whether the email subsystem is active.
type EmailSection struct {
	Enabled  bool
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLS      string // "none", "starttls", or "tls"
}

// Auth holds all authentication-related configuration: browser sessions, agent
// HMAC signing, password hashing, first-run bootstrap, and WebAuthn passkeys.
type Auth struct {
	Session          SessionCfg
	HMAC             HMACCfg
	Password         PasswordCfg
	Bootstrap        BootstrapCfg
	OIDC             OIDCCfg
	WebAuthn         WebAuthnCfg
	HideLocalLoginUI bool `mapstructure:"hide_local_login_ui"`
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

// OIDCCfg holds single-provider OpenID Connect settings. client_secret is
// supplied via DIYDDNS_AUTH_OIDC_CLIENT_SECRET and is never logged.
type OIDCCfg struct {
	Enabled         bool
	Required        bool // fail-closed startup if discovery fails (default false)
	Issuer          string
	ClientID        string `mapstructure:"client_id"`
	ClientSecret    string `mapstructure:"client_secret"`
	Scopes          []string
	AutoLinkByEmail bool `mapstructure:"auto_link_by_email"`
	AllowOIDCSignup bool `mapstructure:"allow_oidc_signup"`
}

// WebAuthnCfg holds WebAuthn (passkey) Relying Party settings. RPID and
// RPOrigin may be left empty to have ResolveWebAuthn derive them from
// server.base_url at startup.
type WebAuthnCfg struct {
	RPID          string        `mapstructure:"rp_id"`
	RPOrigin      string        `mapstructure:"rp_origin"`
	RPDisplayName string        `mapstructure:"rp_display_name"`
	Timeout       time.Duration `mapstructure:"timeout"`
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
	"auth.oidc.enabled":                false,
	"auth.oidc.required":               false,
	"auth.oidc.issuer":                 "",
	"auth.oidc.client_id":              "",
	"auth.oidc.client_secret":          "",
	// auth.oidc.scopes cannot be set via the DIYDDNS_AUTH_OIDC_SCOPES env var
	// (viper delivers env values as a single string, not []string). Configure
	// scopes via YAML or flags; the default covers the common case.
	"auth.oidc.scopes":              []string{"openid", "profile", "email"},
	"auth.oidc.auto_link_by_email":  true,
	"auth.oidc.allow_oidc_signup":   true,
	"auth.webauthn.rp_id":           "",
	"auth.webauthn.rp_origin":       "",
	"auth.webauthn.rp_display_name": "DIYDDNS",
	"auth.webauthn.timeout":         "120s",
	"auth.hide_local_login_ui":      false,
	"email.enabled":                 false,
	"email.host":                    "",
	"email.port":                    0,
	"email.username":                "",
	"email.password":                "",
	"email.from":                    "",
	"email.tls":                     "starttls",
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
	if err := validateOIDC(cfg); err != nil {
		return Server{}, err
	}
	return cfg, nil
}

// validateOIDC enforces the auth.oidc.* invariants when OIDC is enabled.
// Extracted from Load to keep Load's cyclomatic complexity under the
// project's gocyclo threshold (.golangci.yml, min-complexity: 15).
func validateOIDC(cfg Server) error {
	if !cfg.Auth.OIDC.Enabled {
		return nil
	}
	if cfg.Auth.OIDC.Issuer == "" || cfg.Auth.OIDC.ClientID == "" || cfg.Auth.OIDC.ClientSecret == "" {
		return fmt.Errorf("config: auth.oidc.enabled requires issuer, client_id, and client_secret")
	}
	if cfg.Server.BaseURL == "" {
		return fmt.Errorf("config: auth.oidc.enabled requires server.base_url (for the OIDC redirect_uri)")
	}
	if !slices.Contains(cfg.Auth.OIDC.Scopes, "openid") {
		return fmt.Errorf("config: auth.oidc.scopes must include \"openid\"")
	}
	return nil
}

// ResolveWebAuthn derives the WebAuthn Relying Party ID and origin, falling
// back to baseURL (typically server.base_url) when auth.webauthn.rp_id or
// auth.webauthn.rp_origin are left empty. It returns an error when a value
// cannot be resolved from either source, so callers can fail closed at
// startup rather than register passkeys against an unusable RP.
func (a Auth) ResolveWebAuthn(baseURL string) (rpID, rpOrigin string, err error) {
	rpID, rpOrigin = a.WebAuthn.RPID, a.WebAuthn.RPOrigin
	if rpID != "" && rpOrigin != "" {
		return rpID, rpOrigin, nil
	}
	if baseURL == "" {
		return "", "", fmt.Errorf("config: auth.webauthn.rp_id/rp_origin not set and server.base_url is empty")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", "", fmt.Errorf("config: parse server.base_url %q: %w", baseURL, err)
	}
	if u.Hostname() == "" {
		return "", "", fmt.Errorf("config: server.base_url %q has no host, cannot derive WebAuthn RP ID", baseURL)
	}
	if rpID == "" {
		rpID = u.Hostname()
	}
	if rpOrigin == "" {
		rpOrigin = u.Scheme + "://" + u.Host
	}
	return rpID, rpOrigin, nil
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
