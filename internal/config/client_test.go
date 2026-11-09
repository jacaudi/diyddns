package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func TestLoadClientDefaults(t *testing.T) {
	cfg, err := LoadClient(viper.New(), "")
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.Server.URL != "" || cfg.Logging.Level != "info" || cfg.Logging.Format != "text" {
		t.Errorf("defaults wrong: %+v", cfg)
	}
}

func TestLoadClientFileThenEnvThenFlag(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(file, []byte("server:\n  url: https://from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// file wins over default
	cfg, err := LoadClient(viper.New(), file)
	if err != nil {
		t.Fatalf("LoadClient(file): %v", err)
	}
	if cfg.Server.URL != "https://from-file" {
		t.Errorf("file: got %q", cfg.Server.URL)
	}

	// env wins over file
	t.Setenv("DIYDDNS_SERVER_URL", "https://from-env")
	cfg, err = LoadClient(viper.New(), file)
	if err != nil {
		t.Fatalf("LoadClient(env): %v", err)
	}
	if cfg.Server.URL != "https://from-env" {
		t.Errorf("env: got %q", cfg.Server.URL)
	}

	// changed flag wins over env
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	fs.String("server", "", "")
	_ = fs.Set("server", "https://from-flag")
	v := viper.New()
	if err := v.BindPFlag("server.url", fs.Lookup("server")); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadClient(v, file)
	if err != nil {
		t.Fatalf("LoadClient(flag): %v", err)
	}
	if cfg.Server.URL != "https://from-flag" {
		t.Errorf("flag: got %q", cfg.Server.URL)
	}
}

func TestLoadClientMissingFileIsError(t *testing.T) {
	_, err := LoadClient(viper.New(), filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestLoadClient_RunDefaults(t *testing.T) {
	cfg, err := LoadClient(viper.New(), "")
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.Run.Interval != 5*time.Minute {
		t.Errorf("Interval = %v, want 5m", cfg.Run.Interval)
	}
	if cfg.Run.Quorum != 2 {
		t.Errorf("Quorum = %d, want 2", cfg.Run.Quorum)
	}
	if got := cfg.Run.AddressFamilies; len(got) != 2 || got[0] != "ipv4" || got[1] != "ipv6" {
		t.Errorf("AddressFamilies = %v, want [ipv4 ipv6]", got)
	}
	if len(cfg.Run.ProvidersV4) != 0 {
		t.Errorf("ProvidersV4 = %v, want empty", cfg.Run.ProvidersV4)
	}
}

func TestLoadClient_RunEnvOverrides(t *testing.T) {
	t.Setenv("DIYDDNS_RUN_INTERVAL", "90s")
	t.Setenv("DIYDDNS_RUN_QUORUM", "3")
	t.Setenv("DIYDDNS_RUN_PROVIDERS_V4", "https://a.example,https://b.example,https://c.example")
	cfg, err := LoadClient(viper.New(), "")
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.Run.Interval != 90*time.Second {
		t.Errorf("Interval = %v, want 90s", cfg.Run.Interval)
	}
	if cfg.Run.Quorum != 3 {
		t.Errorf("Quorum = %d, want 3", cfg.Run.Quorum)
	}
	want := []string{"https://a.example", "https://b.example", "https://c.example"}
	if !slices.Equal(cfg.Run.ProvidersV4, want) {
		t.Errorf("ProvidersV4 = %v, want %v (env comma-string → slice)", cfg.Run.ProvidersV4, want)
	}
}

func TestLoadClient_InsecureProvisionDefaultAndEnv(t *testing.T) {
	cfg, err := LoadClient(viper.New(), "")
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.Run.InsecureProvision {
		t.Error("InsecureProvision default = true, want false")
	}

	t.Setenv("DIYDDNS_RUN_INSECURE_PROVISION", "true")
	cfg, err = LoadClient(viper.New(), "")
	if err != nil {
		t.Fatalf("LoadClient(env): %v", err)
	}
	if !cfg.Run.InsecureProvision {
		t.Error("InsecureProvision with env = false, want true")
	}
}

func TestIPDiscoveryDefaultAuto(t *testing.T) {
	cfg, err := LoadClient(viper.New(), "")
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.Run.IPDiscovery != IPDiscoveryAuto {
		t.Errorf("IPDiscovery = %q, want %q", cfg.Run.IPDiscovery, IPDiscoveryAuto)
	}
}

func TestIPDiscoveryEnv(t *testing.T) {
	t.Setenv("DIYDDNS_RUN_IP_DISCOVERY", "always")
	cfg, err := LoadClient(viper.New(), "")
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.Run.IPDiscovery != IPDiscoveryAlways {
		t.Errorf("IPDiscovery = %q, want %q", cfg.Run.IPDiscovery, IPDiscoveryAlways)
	}
}

func TestIPDiscoveryUnknownRefuses(t *testing.T) {
	for _, bad := range []string{"on", "off", "Always"} {
		t.Run(bad, func(t *testing.T) {
			t.Setenv("DIYDDNS_RUN_IP_DISCOVERY", bad)
			_, err := LoadClient(viper.New(), "")
			if err == nil {
				t.Fatalf("LoadClient accepted ip_discovery %q", bad)
			}
			for _, want := range []string{"run.ip_discovery", "auto, always, never"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestProvidersWarning(t *testing.T) {
	tests := []struct {
		name string
		rc   ClientRunSection
		want string // substring; "" means no warning
	}{
		{"auto with v4 providers", ClientRunSection{IPDiscovery: IPDiscoveryAuto, ProvidersV4: []string{"https://x"}}, "fallback"},
		{"auto with v6 providers", ClientRunSection{IPDiscovery: IPDiscoveryAuto, ProvidersV6: []string{"https://x"}}, "fallback"},
		{"never with providers", ClientRunSection{IPDiscovery: IPDiscoveryNever, ProvidersV4: []string{"https://x"}}, "ignored"},
		{"always with providers", ClientRunSection{IPDiscovery: IPDiscoveryAlways, ProvidersV4: []string{"https://x"}}, ""},
		{"auto without providers", ClientRunSection{IPDiscovery: IPDiscoveryAuto}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProvidersWarning(tt.rc)
			if tt.want == "" {
				if got != "" {
					t.Errorf("got %q, want no warning", got)
				}
				return
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("got %q, want it to contain %q", got, tt.want)
			}
		})
	}
}
