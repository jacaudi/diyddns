// Package config loads the diyddns-server and diyddns-client configuration
// from (in precedence order) command-line flags, DIYDDNS_* environment
// variables, an optional YAML file, and built-in defaults. The struct is
// intentionally minimal for the Plan 03 skeleton; new sections (tls, auth,
// oidc, retention) are added as new fields without restructuring existing
// callers.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

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
	TLS      string // "starttls", "implicit", or "none" — see validateEmail
}

// Auth holds all authentication-related configuration: browser sessions, agent
// HMAC signing, single-provider OIDC, and WebAuthn passkeys.
type Auth struct {
	Session          SessionCfg
	HMAC             HMACCfg
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
	"server.listen":                ":8080",
	"server.base_url":              "",
	"database.path":                "",
	"logging.level":                "info",
	"logging.format":               "json",
	"logging.output":               "stderr",
	"auth.session.cookie_name":     "diyddns_session",
	"auth.session.cookie_secure":   true,
	"auth.session.cookie_samesite": "lax",
	"auth.session.ttl":             "720h",
	"auth.session.slide_window":    "168h",
	"auth.hmac.skew_window":        "120s",
	"auth.hmac.nonce_ttl":          "120s",
	"auth.hmac.secret_key":         "",
	"auth.oidc.enabled":            false,
	"auth.oidc.required":           false,
	"auth.oidc.issuer":             "",
	"auth.oidc.client_id":          "",
	"auth.oidc.client_secret":      "",
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
	if err := validateEmail(cfg); err != nil {
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

// validateEmailBaseURL enforces that outbound links can actually be followed.
// Non-empty is not enough: "ddns.example.com" is non-empty and yields
// "ddns.example.com/register?token=…", which is not a URL.
func validateEmailBaseURL(baseURL string) error {
	if baseURL == "" {
		return errors.New(`config: email.enabled requires server.base_url (outbound links must be absolute), e.g. "https://ddns.example.com"`)
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("config: email.enabled requires a parseable server.base_url: %w", err)
	}
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf(`config: email.enabled requires an absolute server.base_url with a scheme and host, got %q`, baseURL)
	}
	// Route 5 (#80): baseURL is prefixed onto every minted link and
	// interpolated into the message BODY, on a wire that declares 7bit. Checked
	// here rather than in Load, so it applies only when email is enabled --
	// server.base_url is also read by ResolveWebAuthn and
	// InsecureCookieWarning, and rejecting an IDN base URL for a deployment
	// that sends no mail is out of scope.
	if !isASCII(baseURL) {
		return fmt.Errorf(`config: email.enabled requires a 7-bit ASCII server.base_url (outbound messages declare 7bit and cannot carry it), got %q`, baseURL)
	}
	return nil
}

// isLocalhostHost mirrors net/smtp's own isLocalhost (net/smtp/auth.go), which
// is the exact set of hosts PlainAuth will authenticate to without TLS.
func isLocalhostHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// isASCII reports whether s is entirely 7-bit ASCII.
//
// This deliberately duplicates email.IsASCII. internal/config CANNOT import
// internal/email — internal/email imports internal/config, and reversing that
// would invert the dependency. Extracting a shared leaf package for two callers
// is more structure than they justify; promote it if a third appears. The two
// copies must stay in lockstep: if they diverge, a value accepted at startup
// could be rejected at send time, which is the permanently-unmailable state
// #80 exists to remove.
func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// validateFromAddress enforces route 4 (#80). It MUST accept exactly what
// internal/email's send-path check accepts, and nothing more.
//
// That is why it is not merely an isASCII call. cfg.Email.From reaches
// c.Mail(m.cfg.From) (smtp.go:171) as well as the From: header, and net/smtp
// passes it through verbatim — measured, a display-name value produces the
// malformed envelope `MAIL FROM:<DIYDDNS <noreply@example.com>>`, and a
// trailing space produces `MAIL FROM:<noreply@example.com >`. net/smtp accepts
// both without complaint; a real MTA does not. So a display-name email.from is
// ALREADY broken today, just later and less legibly.
//
// If this check and internal/email's diverge, a From accepted at startup is
// rejected at send and the deployment sends NOTHING while booting clean — the
// permanently-unmailable state #80 exists to remove, moved from one account to
// every message.
//
// FOLLOW-UP, deliberately out of scope: supporting a display name properly
// means passing addr.Address to c.Mail while writing the full form into the
// From: header. That is a feature; #80 is a boundary-rejection workstream. File
// it, do not build it here.
func validateFromAddress(from string) error {
	addr, err := mail.ParseAddress(from)
	if err != nil {
		return fmt.Errorf("config: email.from is not a valid address: %w", err)
	}
	if !isASCII(addr.Address) {
		return fmt.Errorf(`config: email.from must be 7-bit ASCII (outbound messages declare 7bit and cannot carry it), got %q`, from)
	}
	if addr.Address != from {
		return fmt.Errorf(`config: email.from must be a bare address with no display name or surrounding whitespace, e.g. %q rather than %q — net/smtp passes it to MAIL FROM verbatim`, addr.Address, from)
	}
	return nil
}

// validateEmail enforces that an enabled email subsystem is actually usable.
// Every problem is collected and reported together (go-standards §15.3), so an
// operator enabling email from scratch fixes it in one deploy cycle rather than
// discovering the next missing key on each restart.
func validateEmail(cfg Server) error {
	if !cfg.Email.Enabled {
		return nil
	}
	var problems []error

	// Outbound mail carries registration links built as
	// server.base_url + "/register?token=…" (service/grants.go). The web UI
	// repairs a bare path at render time, but the service has no *http.Request
	// to repair it from, so the link must already be absolute here.
	if err := validateEmailBaseURL(cfg.Server.BaseURL); err != nil {
		problems = append(problems, err)
	}
	if cfg.Email.Host == "" {
		problems = append(problems, errors.New(`config: email.enabled requires email.host, e.g. "smtp.example.com"`))
	}
	// Defaults to 0 (keyDefaults, config.go:152), which dials host:0. Nothing in
	// the repo supplies a default value.
	if cfg.Email.Port < 1 || cfg.Email.Port > 65535 {
		problems = append(problems, fmt.Errorf("config: email.enabled requires email.port in 1-65535, got %d (587 starttls, 465 implicit, 25 none)", cfg.Email.Port))
	}
	// An empty From sends "MAIL FROM:<>" — the null sender. Servers often accept
	// it and reject or spam-bin the message downstream, so it looks like success.
	if cfg.Email.From == "" {
		problems = append(problems, errors.New(`config: email.enabled requires email.from, e.g. "diyddns@example.com"`))
	} else if err := validateFromAddress(cfg.Email.From); err != nil {
		problems = append(problems, err)
	}
	switch cfg.Email.TLS {
	case "starttls", "implicit", "none":
	default:
		problems = append(problems, fmt.Errorf("config: email.tls must be one of starttls, implicit, none, got %q", cfg.Email.TLS))
	}
	// net/smtp's PlainAuth.Start refuses to send credentials over an unencrypted
	// connection unless the host is localhost, so this combination fails EVERY
	// send with "unencrypted connection" — detectable here instead.
	if cfg.Email.TLS == "none" && cfg.Email.Username != "" && !isLocalhostHost(cfg.Email.Host) {
		problems = append(problems, errors.New("config: email.username requires email.tls to be starttls or implicit; net/smtp refuses to send credentials over an unencrypted connection"))
	}

	return errors.Join(problems...)
}

// ResolveWebAuthn derives the WebAuthn Relying Party ID and origin, falling
// back to baseURL (typically server.base_url) when auth.webauthn.rp_id or
// auth.webauthn.rp_origin are left empty. It returns an error when a value
// cannot be resolved from either source, so callers can fail closed at
// startup rather than register passkeys against an unusable RP.
func (a Auth) ResolveWebAuthn(baseURL string) (rpID, rpOrigin string, err error) {
	rpID, rpOrigin = a.WebAuthn.RPID, a.WebAuthn.RPOrigin
	if rpID != "" && rpOrigin != "" {
		return rpID, rpOrigin, validateRPID(rpID)
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
	return rpID, rpOrigin, validateRPID(rpID)
}

// InsecureCookieWarning returns a startup warning when auth.session.
// cookie_secure marks the session cookie Secure but server.base_url is plain
// HTTP on a non-loopback host, and "" when the configuration is fine.
//
// This is a WARNING, not a validation error: secure-by-default is correct and
// the operator may legitimately be running TLS termination that base_url does
// not describe. But a browser only keeps a Secure cookie from a
// potentially-trustworthy origin, and plain HTTP qualifies on loopback and
// nowhere else — so in this configuration the browser silently discards both
// the session cookie and the in-flight OIDC flow cookie. The observable
// result is an OIDC login bouncing back to /login?error=no_account, which
// names neither cookies nor the scheme (issue #39).
//
// Loopback is the exemption because that is exactly what browsers exempt:
// localhost and the loopback IP ranges are potentially trustworthy over plain
// HTTP, which is why every localhost test of this configuration passes.
func InsecureCookieWarning(cfg Server) string {
	if !cfg.Auth.Session.CookieSecure || cfg.Server.BaseURL == "" {
		return ""
	}
	u, err := url.Parse(cfg.Server.BaseURL)
	if err != nil || u.Scheme != "http" {
		return "" // https, or unparseable — Load already reports parse failures where they matter
	}
	if isLoopbackHost(u.Hostname()) {
		return ""
	}
	return fmt.Sprintf(
		"auth.session.cookie_secure is true but server.base_url %q is plain HTTP on a "+
			"non-loopback host: browsers discard Secure cookies from this origin, so logins "+
			"will fail with no session and no explanation. Put TLS in front of the server "+
			"(recommended), or set auth.session.cookie_secure to false for plain-HTTP use.",
		cfg.Server.BaseURL)
}

// isLoopbackHost reports whether host is one browsers treat as a
// potentially-trustworthy origin over plain HTTP: the literal "localhost" (and
// its subdomains) or any loopback IP.
func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateRPID rejects an IP-address Relying Party ID. The WebAuthn spec
// requires the RP ID to be a valid domain string, and browsers enforce it —
// but nothing on the server side does, so without this check the server
// boots, the pages render, register/begin returns 200 with real-looking
// options, and the ceremony only fails in the browser with a generic
// "SecurityError: The operation is insecure" that names neither the RP ID
// nor the address. Fail closed at startup, and name the fix in the message.
//
// Note that 127.0.0.1 is a *trustworthy origin* but not a *valid RP ID*, so
// it is not interchangeable with localhost here even though both are loopback.
func validateRPID(rpID string) error {
	if net.ParseIP(rpID) == nil {
		return nil
	}
	return fmt.Errorf(
		"config: WebAuthn RP ID %q is an IP address, which browsers reject "+
			"(the spec requires a domain name); use a hostname such as localhost "+
			"in server.base_url, or set auth.webauthn.rp_id explicitly", rpID)
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
