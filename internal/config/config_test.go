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
