package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/config"
)

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
