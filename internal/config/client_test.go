package config

import (
	"os"
	"path/filepath"
	"testing"

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
