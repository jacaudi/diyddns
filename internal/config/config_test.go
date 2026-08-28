package config_test

import (
	"cmp"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/email"
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

func TestLoad_OIDCValidation(t *testing.T) {
	base := func(v *viper.Viper) {
		v.Set("database.path", ":memory:")
		v.Set("auth.hmac.secret_key", "") // not required unless server starts
	}

	// enabled but missing issuer → error
	t.Run("missing issuer", func(t *testing.T) {
		v := viper.New()
		base(v)
		v.Set("auth.oidc.enabled", true)
		v.Set("server.base_url", "https://ddns.example.com")
		v.Set("auth.oidc.client_id", "cid")
		v.Set("auth.oidc.client_secret", "csecret")
		if _, err := config.Load(v, ""); err == nil {
			t.Fatal("expected error for enabled OIDC without issuer")
		}
	})

	// enabled but scopes lack openid → error
	t.Run("missing openid scope", func(t *testing.T) {
		v := viper.New()
		base(v)
		v.Set("auth.oidc.enabled", true)
		v.Set("server.base_url", "https://ddns.example.com")
		v.Set("auth.oidc.issuer", "https://idp.example.com")
		v.Set("auth.oidc.client_id", "cid")
		v.Set("auth.oidc.client_secret", "csecret")
		v.Set("auth.oidc.scopes", []string{"profile", "email"})
		if _, err := config.Load(v, ""); err == nil {
			t.Fatal("expected error for OIDC scopes missing 'openid'")
		}
	})

	// enabled + valid → defaults present
	t.Run("valid", func(t *testing.T) {
		v := viper.New()
		base(v)
		v.Set("auth.oidc.enabled", true)
		v.Set("server.base_url", "https://ddns.example.com")
		v.Set("auth.oidc.issuer", "https://idp.example.com")
		v.Set("auth.oidc.client_id", "cid")
		v.Set("auth.oidc.client_secret", "csecret")
		cfg, err := config.Load(v, "")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !cfg.Auth.OIDC.AutoLinkByEmail || !cfg.Auth.OIDC.AllowOIDCSignup {
			t.Fatalf("expected auto_link/signup defaults true, got %+v", cfg.Auth.OIDC)
		}
		if len(cfg.Auth.OIDC.Scopes) == 0 || cfg.Auth.OIDC.Scopes[0] != "openid" {
			t.Fatalf("expected default scopes with openid first, got %v", cfg.Auth.OIDC.Scopes)
		}
	})

	// disabled → no validation, loads clean
	t.Run("disabled", func(t *testing.T) {
		v := viper.New()
		base(v)
		if _, err := config.Load(v, ""); err != nil {
			t.Fatalf("Load with OIDC disabled: %v", err)
		}
	})
}

func TestLoad_WebAuthnEmailDefaults(t *testing.T) {
	cfg := mustLoadWithDB(t)
	if cfg.Auth.WebAuthn.RPID != "" {
		t.Errorf("WebAuthn.RPID = %q, want empty by default", cfg.Auth.WebAuthn.RPID)
	}
	if cfg.Auth.WebAuthn.RPOrigin != "" {
		t.Errorf("WebAuthn.RPOrigin = %q, want empty by default", cfg.Auth.WebAuthn.RPOrigin)
	}
	if cfg.Auth.WebAuthn.RPDisplayName != "DIYDDNS" {
		t.Errorf("WebAuthn.RPDisplayName = %q, want DIYDDNS", cfg.Auth.WebAuthn.RPDisplayName)
	}
	if cfg.Auth.WebAuthn.Timeout != 120*time.Second {
		t.Errorf("WebAuthn.Timeout = %v, want 120s", cfg.Auth.WebAuthn.Timeout)
	}
	if cfg.Auth.HideLocalLoginUI {
		t.Error("Auth.HideLocalLoginUI = true, want false by default")
	}
	if cfg.Email.Enabled {
		t.Error("Email.Enabled = true, want false by default")
	}
	if cfg.Email.TLS != "starttls" {
		t.Errorf("Email.TLS = %q, want starttls", cfg.Email.TLS)
	}
}

// TestLoad_EmailHostEnvBinding is the regression guard for the pattern noted
// on keyDefaults: config.Load has no viper.AutomaticEnv(), so every email.*
// key MUST be registered in keyDefaults or its DIYDDNS_* env var is silently
// dropped.
func TestLoad_EmailHostEnvBinding(t *testing.T) {
	t.Setenv("DIYDDNS_EMAIL_HOST", "smtp.example.com")
	cfg := mustLoadWithDB(t)
	if cfg.Email.Host != "smtp.example.com" {
		t.Errorf("Email.Host = %q, want smtp.example.com (env var DIYDDNS_EMAIL_HOST was dropped)", cfg.Email.Host)
	}
}

// TestLoad_EmailTLSValidation mirrors TestLoad_OIDCValidation: email.tls is
// only validated when email.enabled is true, and must be one of the three
// values the internal/email package understands (starttls, implicit, none).
func TestLoad_EmailTLSValidation(t *testing.T) {
	t.Run("enabled with invalid tls value is an error", func(t *testing.T) {
		v := viper.New()
		v.Set("database.path", ":memory:")
		v.Set("email.enabled", true)
		v.Set("email.tls", "tls") // old/typo value, not in the enum
		// The rest of the email config must be complete, or this subtest passes
		// on some other validator's error and stops exercising the enum at all.
		v.Set("server.base_url", "https://d.example.com")
		v.Set("email.host", "smtp.example.com")
		v.Set("email.port", 587)
		v.Set("email.from", "diyddns@example.com")
		if _, err := config.Load(v, ""); err == nil || !strings.Contains(err.Error(), "email.tls") {
			t.Fatalf("want an error naming email.tls, got %v", err)
		}
	})

	t.Run("enabled with each valid tls value loads clean", func(t *testing.T) {
		for _, tls := range []string{"starttls", "implicit", "none"} {
			v := viper.New()
			v.Set("database.path", ":memory:")
			v.Set("email.enabled", true)
			v.Set("email.tls", tls)
			v.Set("server.base_url", "https://d.example.com")
			v.Set("email.host", "smtp.example.com")
			v.Set("email.port", 587)
			v.Set("email.from", "diyddns@example.com")
			if _, err := config.Load(v, ""); err != nil {
				t.Errorf("Load with email.tls=%q: %v", tls, err)
			}
		}
	})

	t.Run("disabled skips validation even with a garbage tls value", func(t *testing.T) {
		v := viper.New()
		v.Set("database.path", ":memory:")
		v.Set("email.enabled", false)
		v.Set("email.tls", "not-a-real-value")
		if _, err := config.Load(v, ""); err != nil {
			t.Fatalf("Load with email disabled: %v", err)
		}
	})
}

func TestAuth_ResolveWebAuthn(t *testing.T) {
	t.Run("derives rpID and origin from baseURL", func(t *testing.T) {
		var a config.Auth
		rpID, rpOrigin, err := a.ResolveWebAuthn("https://ddns.example.com")
		if err != nil {
			t.Fatalf("ResolveWebAuthn: %v", err)
		}
		if rpID != "ddns.example.com" {
			t.Errorf("rpID = %q, want ddns.example.com", rpID)
		}
		if rpOrigin != "https://ddns.example.com" {
			t.Errorf("rpOrigin = %q, want https://ddns.example.com", rpOrigin)
		}
	})

	t.Run("empty baseURL and empty explicit fields is an error", func(t *testing.T) {
		var a config.Auth
		if _, _, err := a.ResolveWebAuthn(""); err == nil {
			t.Fatal("expected error when neither rp fields nor baseURL are set")
		}
	})

	// The WebAuthn spec requires the RP ID to be a valid domain string. An IP
	// address is not one, and every browser rejects it — Firefox reports the
	// generic "SecurityError: The operation is insecure", which names neither
	// the RP ID nor the address. Nothing downstream can detect this either:
	// the server boots, the pages render, register/begin returns 200 with
	// real-looking options, and the ceremony only dies in the browser. Fail
	// closed at startup instead.
	t.Run("rejects an IP-address host", func(t *testing.T) {
		for _, baseURL := range []string{
			"http://127.0.0.1:18080",
			"http://192.168.1.50:8080",
			"https://[::1]:8443",
			"https://[2001:db8::1]",
		} {
			var a config.Auth
			_, _, err := a.ResolveWebAuthn(baseURL)
			if err == nil {
				t.Errorf("ResolveWebAuthn(%q) = nil error, want a failure: an IP is not a valid RP ID", baseURL)
				continue
			}
			// The message has to name the fix, or the operator is left with
			// the same unactionable failure the browser already gave them.
			if !strings.Contains(err.Error(), "localhost") {
				t.Errorf("ResolveWebAuthn(%q) error = %q, want it to suggest a hostname such as localhost", baseURL, err)
			}
		}
	})

	// An explicit rp_id is no more valid for being explicit.
	t.Run("rejects an explicitly configured IP rp_id", func(t *testing.T) {
		a := config.Auth{WebAuthn: config.WebAuthnCfg{RPID: "127.0.0.1", RPOrigin: "http://127.0.0.1:18080"}}
		if _, _, err := a.ResolveWebAuthn(""); err == nil {
			t.Error("explicit IP rp_id = nil error, want a failure")
		}
	})

	t.Run("localhost is accepted", func(t *testing.T) {
		var a config.Auth
		rpID, rpOrigin, err := a.ResolveWebAuthn("http://localhost:18080")
		if err != nil {
			t.Fatalf("ResolveWebAuthn(localhost): %v", err)
		}
		if rpID != "localhost" {
			t.Errorf("rpID = %q, want localhost", rpID)
		}
		if rpOrigin != "http://localhost:18080" {
			t.Errorf("rpOrigin = %q, want http://localhost:18080", rpOrigin)
		}
	})
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

func TestInsecureCookieWarning(t *testing.T) {
	// The misconfiguration issue #39 describes: cookie_secure marks the
	// session cookie Secure, but a browser only keeps a Secure cookie from a
	// potentially-trustworthy origin. Plain HTTP is trustworthy on loopback
	// and nowhere else, so only the off-loopback plain-HTTP case warns.
	tests := []struct {
		name        string
		baseURL     string
		secure      bool
		wantWarning bool
	}{
		{"plain http on a LAN hostname warns", "http://diyddns.lan:8080", true, true},
		{"plain http on a LAN IP warns", "http://192.168.1.10:8080", true, true},
		{"localhost is trustworthy", "http://localhost:8080", true, false},
		{"127.0.0.1 is trustworthy", "http://127.0.0.1:8080", true, false},
		{"::1 is trustworthy", "http://[::1]:8080", true, false},
		{"https is fine anywhere", "https://diyddns.example.com", true, false},
		{"cookie_secure off is the operator's choice", "http://diyddns.lan:8080", false, false},
		{"no base_url, nothing to judge", "", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg config.Server
			cfg.Server.BaseURL = tt.baseURL
			cfg.Auth.Session.CookieSecure = tt.secure

			got := config.InsecureCookieWarning(cfg)
			if (got != "") != tt.wantWarning {
				t.Fatalf("InsecureCookieWarning() = %q, want warning=%v", got, tt.wantWarning)
			}
			if tt.wantWarning && !strings.Contains(got, "cookie_secure") {
				t.Errorf("warning must name the key to change; got %q", got)
			}
		})
	}
}

// TestLoad_EmailEnabledRequiresCompleteConfig locks the fail-closed contract:
// email.enabled requires every value the send path actually uses, and every
// problem is reported in ONE error (go-standards §15.3) rather than one per
// restart.
func TestLoad_EmailEnabledRequiresCompleteConfig(t *testing.T) {
	const (
		okURL  = "https://d.example.com"
		okHost = "smtp.example.com"
		okPort = 587
		okFrom = "diyddns@example.com"
	)
	tests := []struct {
		name     string
		enabled  bool
		baseURL  string
		host     string
		port     int
		from     string
		username string
		tls      string
		wantErr  []string // every substring the error must name; empty means expect success
	}{
		// Disabled short-circuits every check, even for an otherwise empty config.
		{name: "disabled skips every check", enabled: false},
		{name: "enabled and complete is accepted", enabled: true, baseURL: okURL, host: okHost, port: okPort, from: okFrom},

		{name: "no base_url", enabled: true, host: okHost, port: okPort, from: okFrom, wantErr: []string{"server.base_url"}},
		{name: "base_url is not absolute", enabled: true, baseURL: "ddns.example.com", host: okHost, port: okPort, from: okFrom, wantErr: []string{"absolute server.base_url"}},
		{name: "no host", enabled: true, baseURL: okURL, port: okPort, from: okFrom, wantErr: []string{"email.host"}},
		{name: "the zero port default", enabled: true, baseURL: okURL, host: okHost, from: okFrom, wantErr: []string{"email.port"}},
		{name: "out-of-range port", enabled: true, baseURL: okURL, host: okHost, port: 70000, from: okFrom, wantErr: []string{"email.port"}},
		{name: "no from", enabled: true, baseURL: okURL, host: okHost, port: okPort, wantErr: []string{"email.from"}},

		// #80 routes 4 and 5: a non-ASCII address or base URL would be written
		// raw onto a wire that declares 7bit.
		{name: "non-ascii from", enabled: true, baseURL: okURL, host: okHost, port: okPort,
			from: "nöreply@example.com", wantErr: []string{"email.from"}},
		{name: "display-name from", enabled: true, baseURL: okURL, host: okHost, port: okPort,
			from: "DIYDDNS <noreply@example.com>", wantErr: []string{"email.from"}},
		{name: "non-ascii base_url", enabled: true, baseURL: "https://exämple.test", host: okHost,
			port: okPort, from: okFrom, wantErr: []string{"server.base_url"}},

		// net/smtp refuses PLAIN auth over an unencrypted connection.
		{name: "auth over plaintext to a remote host", enabled: true, baseURL: okURL, host: okHost, port: 25, from: okFrom,
			username: "user", tls: "none", wantErr: []string{"email.username"}},
		{name: "auth over plaintext to localhost is allowed", enabled: true, baseURL: okURL, host: "localhost", port: 25, from: okFrom,
			username: "user", tls: "none"},

		// The aggregation requirement: ONE Load reports ALL of them.
		{name: "every problem is reported together", enabled: true,
			wantErr: []string{"server.base_url", "email.host", "email.port", "email.from"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			v.Set("database.path", ":memory:")
			v.Set("email.enabled", tt.enabled)
			v.Set("email.tls", cmp.Or(tt.tls, "starttls"))
			v.Set("server.base_url", tt.baseURL)
			v.Set("email.host", tt.host)
			v.Set("email.port", tt.port)
			v.Set("email.from", tt.from)
			v.Set("email.username", tt.username)

			_, err := config.Load(v, "")
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("Load: %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Load returned nil, want an error naming %v", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not name %q:\n%v", want, err)
				}
			}
		})
	}
}

// TestLoad_NonASCIIBaseURLIsAcceptedWhenEmailIsOff pins the deliberate
// asymmetry in #80's route-5 check: validateEmailBaseURL is reached only from
// validateEmail, which returns early when email is disabled. server.base_url is
// also read by ResolveWebAuthn and InsecureCookieWarning, and rejecting an IDN
// base URL for a deployment that sends no mail is a far larger behaviour change
// than #80 justifies. If this test ever starts failing, that is a scope
// decision, not a bug fix.
func TestLoad_NonASCIIBaseURLIsAcceptedWhenEmailIsOff(t *testing.T) {
	v := viper.New()
	v.Set("database.path", ":memory:")
	v.Set("email.enabled", false)
	v.Set("server.base_url", "https://exämple.test")

	if _, err := config.Load(v, ""); err != nil {
		t.Fatalf("Load with email disabled: %v, want nil", err)
	}
}

// TestFromValidationMatchesTheEmailPackage pins the ONE deliberate duplication
// in this change. internal/config cannot import internal/email without
// inverting the dependency, so it carries its own isASCII and its own
// validateFromAddress. If the two sides ever disagree, an email.from accepted at
// startup is rejected at every send and the deployment boots clean while mailing
// NOTHING — the permanently-unmailable state #80 exists to remove, scaled from
// one account to every message.
//
// It must pin BOTH halves. An earlier draft pinned only the 7-bit half and
// therefore passed while exactly that divergence shipped.
//
// config.isASCII and config.validateFromAddress are unexported and this is an
// external test package, so the config side is exercised through Load, which is
// the only caller that matters.
func TestFromValidationMatchesTheEmailPackage(t *testing.T) {
	tests := []struct {
		name    string
		from    string
		wantErr bool
	}{
		{name: "ascii", from: "diyddns@example.com"},
		{name: "accented", from: "nöreply@example.com", wantErr: true},
		{name: "cjk", from: "日本@example.com", wantErr: true},
		{name: "em dash", from: "a—b@example.com", wantErr: true},

		// The canonical half. These are pure ASCII, so an isASCII-only startup
		// check accepts them — and then internal/email's checkAddress rejects
		// every single send, so the deployment boots clean and mails nothing.
		// Measured on the wire: net/smtp emits
		// `MAIL FROM:<DIYDDNS <noreply@example.com>>` and
		// `MAIL FROM:<noreply@example.com >` for these, verbatim.
		{name: "display name", from: "DIYDDNS <noreply@example.com>", wantErr: true},
		{name: "trailing space", from: "noreply@example.com ", wantErr: true},
		{name: "quoted local part", from: `"john doe"@example.com`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			v.Set("database.path", ":memory:")
			v.Set("email.enabled", true)
			v.Set("email.tls", "starttls")
			v.Set("server.base_url", "https://d.example.com")
			v.Set("email.host", "smtp.example.com")
			v.Set("email.port", 587)
			v.Set("email.from", tt.from)

			_, err := config.Load(v, "")
			gotRejected := err != nil && strings.Contains(err.Error(), "email.from")
			if gotRejected != tt.wantErr {
				t.Fatalf("config rejected %q = %v, want %v (err=%v)", tt.from, gotRejected, tt.wantErr, err)
			}
			// The email package must agree, decision for decision. This is the
			// check that actually matters: NormalizeAddress is what the send
			// path applies, so if config accepts something it rejects, that
			// deployment boots clean and sends nothing.
			normalized, normErr := email.NormalizeAddress(tt.from)
			emailRejects := normErr != nil || normalized != tt.from
			if emailRejects != tt.wantErr {
				t.Errorf("internal/email %s %q but config %s it — the two sides have diverged",
					map[bool]string{true: "rejects", false: "accepts"}[emailRejects], tt.from,
					map[bool]string{true: "rejected", false: "accepted"}[gotRejected])
			}
		})
	}
}

func TestLoad_NotificationsDefaults(t *testing.T) {
	t.Setenv("DIYDDNS_DATABASE_PATH", "/tmp/x.db")

	cfg, err := config.Load(viper.New(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Notifications.Enabled {
		t.Error("notifications.enabled should default to false")
	}
	if got := cfg.Notifications.Timeout; got != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", got)
	}
	if got := cfg.Notifications.MaxAttempts; got != 8 {
		t.Errorf("max_attempts = %d, want 8", got)
	}
	if got := cfg.Notifications.MaxEndpointsPerUser; got != 5 {
		t.Errorf("max_endpoints_per_user = %d, want 5", got)
	}
	if len(cfg.Notifications.AllowedPrivateCIDRs) != 0 {
		t.Errorf("allowed_private_cidrs = %v, want empty", cfg.Notifications.AllowedPrivateCIDRs)
	}
}

// The security-critical key must come through the env, comma-separated. This is
// the measurement issue #98 is about: Unmarshal splits, GetStringSlice does not.
func TestLoad_AllowedPrivateCIDRsFromEnv(t *testing.T) {
	t.Setenv("DIYDDNS_DATABASE_PATH", "/tmp/x.db")
	t.Setenv("DIYDDNS_NOTIFICATIONS_ALLOWED_PRIVATE_CIDRS", "10.42.0.0/16,192.168.1.50/32")

	cfg, err := config.Load(viper.New(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"10.42.0.0/16", "192.168.1.50/32"}
	if len(cfg.Notifications.AllowedPrivateCIDRs) != len(want) {
		t.Fatalf("got %v, want %v", cfg.Notifications.AllowedPrivateCIDRs, want)
	}
	for i := range want {
		if cfg.Notifications.AllowedPrivateCIDRs[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, cfg.Notifications.AllowedPrivateCIDRs[i], want[i])
		}
	}
}

func TestLoad_NotificationsValidation(t *testing.T) {
	tests := []struct {
		name, key, val string
	}{
		{"bad cidr", "DIYDDNS_NOTIFICATIONS_ALLOWED_PRIVATE_CIDRS", "not-a-cidr"},
		{"zero timeout", "DIYDDNS_NOTIFICATIONS_TIMEOUT", "0s"},
		{"zero attempts", "DIYDDNS_NOTIFICATIONS_MAX_ATTEMPTS", "0"},
		{"too many attempts", "DIYDDNS_NOTIFICATIONS_MAX_ATTEMPTS", "17"},
		{"zero endpoints", "DIYDDNS_NOTIFICATIONS_MAX_ENDPOINTS_PER_USER", "0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DIYDDNS_DATABASE_PATH", "/tmp/x.db")
			t.Setenv("DIYDDNS_NOTIFICATIONS_ENABLED", "true")
			t.Setenv(tc.key, tc.val)
			if _, err := config.Load(viper.New(), ""); err == nil {
				t.Fatal("Load succeeded, want error")
			}
		})
	}
}

// TestLoad_NullSectionFailsLoud is the regression guard for B3(b): a
// top-level section with every child commented out parses as a nil-valued
// YAML mapping, which viper's env-var binding can silently confuse with that
// section's whole defaults sub-map (see TestLoad_ExampleConfigNotificationsEnvOverridesApply's
// doc comment for the mechanism). Rather than rely on every config file
// keeping at least one live child forever, Load itself must detect the shape
// and fail loud, naming the section, so an operator who comments out
// notifications.enabled gets a clear error instead of a config that silently
// reverts every DIYDDNS_NOTIFICATIONS_* env var to its default.
func TestLoad_NullSectionFailsLoud(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "null notifications section",
			content: "database:\n  path: \"/tmp/x.db\"\n" +
				"notifications:\n  # enabled: false\n",
			wantErr: "notifications",
		},
		{
			name: "null email section",
			content: "database:\n  path: \"/tmp/x.db\"\n" +
				"email:\n  # enabled: false\n",
			wantErr: "email",
		},
		{
			name: "live child is fine",
			content: "database:\n  path: \"/tmp/x.db\"\n" +
				"notifications:\n  enabled: false\n",
			wantErr: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := config.Load(viper.New(), path)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Load: unexpected error %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Load succeeded, want an error naming the null section")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to name %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestLoad_ExampleConfigNotificationsEnvOverridesApply is the regression guard
// for the #65 fix-wave finding: config.Load iterates keyDefaults (a Go map,
// randomized order per process) to call SetDefault/BindEnv for every key. When
// the config file's notifications: section has every child commented out, it
// parses as a nil-valued YAML mapping, and depending on iteration order that
// nil parent can shadow the DIYDDNS_NOTIFICATIONS_* env bindings underneath
// it — dropping them roughly half the time. Reproduced empirically: 12
// separate `go test -count=1` process invocations against the pre-fix
// shipped config.example.yaml gave PASS=1 FAIL=11 for this exact assertion.
//
// A single in-process run of this test CANNOT prove the bug is fixed — the
// randomization is per-process, so one passing run is not evidence; only a
// loop of separate process invocations is (see the fix-wave report for the
// before/after tally). What this test CAN assert in one run, and does:
//
//  1. Against the shipped config.example.yaml, the two notifications env
//     overrides apply in THIS run.
//  2. The shape guard: config.example.yaml's notifications: section has at
//     least one live (uncommented) child key, matching every other top-level
//     section (server, database, logging, auth, email). A null-valued
//     section is exactly the shape that triggers the shadowing above, so
//     keeping this assertion green is what keeps the bug from coming back
//     even though assertion #1 alone can't catch a regression reliably.
func TestLoad_ExampleConfigNotificationsEnvOverridesApply(t *testing.T) {
	const examplePath = "../../config.example.yaml"

	t.Setenv("DIYDDNS_NOTIFICATIONS_ENABLED", "true")
	t.Setenv("DIYDDNS_NOTIFICATIONS_ALLOWED_PRIVATE_CIDRS", "10.42.0.0/16")

	cfg, err := config.Load(viper.New(), examplePath)
	if err != nil {
		t.Fatalf("Load(%s): %v", examplePath, err)
	}
	if !cfg.Notifications.Enabled {
		t.Error("Notifications.Enabled = false, want true (DIYDDNS_NOTIFICATIONS_ENABLED was dropped)")
	}
	want := []string{"10.42.0.0/16"}
	if len(cfg.Notifications.AllowedPrivateCIDRs) != len(want) || cfg.Notifications.AllowedPrivateCIDRs[0] != want[0] {
		t.Errorf("Notifications.AllowedPrivateCIDRs = %v, want %v (DIYDDNS_NOTIFICATIONS_ALLOWED_PRIVATE_CIDRS was dropped)",
			cfg.Notifications.AllowedPrivateCIDRs, want)
	}

	// Shape guard: read the file with a bare viper instance (no SetDefault
	// calls at all) so this reflects the file's own shape, not Load's
	// defaults filling in the gap.
	shape := viper.New()
	shape.SetConfigFile(examplePath)
	if err := shape.ReadInConfig(); err != nil {
		t.Fatalf("ReadInConfig(%s): %v", examplePath, err)
	}
	section, ok := shape.Get("notifications").(map[string]any)
	if !ok || len(section) == 0 {
		t.Errorf("config.example.yaml notifications: section has no live children (got %#v) — "+
			"a null-valued section reproduces the env-drop bug; give it at least one live child, "+
			"as every other top-level section already has", shape.Get("notifications"))
	}
}

func TestNotificationsEgressWarning(t *testing.T) {
	var cfg config.Server
	cfg.Notifications.Enabled = true
	if got := config.NotificationsEgressWarning(cfg); got != "" {
		t.Errorf("no CIDRs: got %q, want empty", got)
	}
	cfg.Notifications.AllowedPrivateCIDRs = []string{"0.0.0.0/0"}
	if got := config.NotificationsEgressWarning(cfg); got == "" {
		t.Error("0.0.0.0/0: got empty, want a warning")
	}
}

// TestNotificationsEgressWarning_UnmaskedNAT64IsStillFlagged is the
// regression guard for the minor finding on NotificationsEgressWarning's
// literal p.String() == "64:ff9b::/96" comparison: ParseAllowed masks every
// prefix it accepts (host bits cleared), but this function re-parses the raw
// config strings directly, so an operator-typed "64:ff9b::1/96" (host bits
// set, same network) parses to a *different* String() and slipped past the
// comparison entirely — silently skipping the metadata-address warning for
// exactly the spelling an operator who fat-fingered a host bit would use.
func TestNotificationsEgressWarning_UnmaskedNAT64IsStillFlagged(t *testing.T) {
	var cfg config.Server
	cfg.Notifications.Enabled = true
	cfg.Notifications.AllowedPrivateCIDRs = []string{"64:ff9b::1/96"}
	if got := config.NotificationsEgressWarning(cfg); got == "" {
		t.Error("64:ff9b::1/96 (unmasked NAT64): got empty, want a warning")
	}
}
