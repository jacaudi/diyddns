// Package config loads the diyddns-server configuration from (in precedence
// order) command-line flags, DIYDDNS_* environment variables, an optional YAML
// file, and built-in defaults. The struct is intentionally minimal for the
// Plan 03 skeleton; new sections (tls, auth, oidc, retention) are added as new
// fields without restructuring existing callers.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Server is the fully-resolved server configuration.
type Server struct {
	Server   ServerSection
	Database DatabaseSection
	Logging  LoggingSection
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

// keyDefaults enumerates every config key, its default, and its env var. Keys
// with a corresponding CLI flag (server.listen) still carry a SetDefault here;
// viper ranks SetDefault above an unchanged flag's default, so a changed flag
// or an env var still wins.
var keyDefaults = map[string]string{
	"server.listen":   ":8080",
	"server.base_url": "",
	"database.path":   "",
	"logging.level":   "info",
	"logging.format":  "json",
	"logging.output":  "stderr",
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
	return cfg, nil
}
