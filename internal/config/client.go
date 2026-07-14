package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// ClientConfig is the fully-resolved diyddns-client configuration. Only the
// sections the enroll vertical needs today are present; run/status add fields
// without restructuring existing callers.
type ClientConfig struct {
	Server  ClientServerSection
	Logging LoggingSection
}

// ClientServerSection holds the target server URL and an optional CA bundle
// for self-signed homelab servers.
type ClientServerSection struct {
	URL      string `mapstructure:"url"`
	CABundle string `mapstructure:"ca_bundle"`
}

// clientKeyDefaults enumerates every client config key, its default, and (via
// BindEnv) its DIYDDNS_* env var. As with the server loader there is no
// AutomaticEnv, so every key MUST be listed or its env var is ignored.
var clientKeyDefaults = map[string]any{
	"server.url":       "",
	"server.ca_bundle": "",
	"logging.level":    "info",
	"logging.format":   "text", // spec §8: text default for the interactive client
}

// LoadClient resolves the client configuration. Callers may pre-configure v
// (e.g. viper.BindPFlag for flags) before calling. If configPath is non-empty
// the file is read; a missing/invalid file is an error.
func LoadClient(v *viper.Viper, configPath string) (ClientConfig, error) {
	v.SetEnvPrefix("DIYDDNS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	for key, def := range clientKeyDefaults {
		v.SetDefault(key, def)
		if err := v.BindEnv(key); err != nil {
			return ClientConfig{}, fmt.Errorf("config: bind env %s: %w", key, err)
		}
	}
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return ClientConfig{}, fmt.Errorf("config: read %s: %w", configPath, err)
		}
	}
	var cfg ClientConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return ClientConfig{}, fmt.Errorf("config: unmarshal: %w", err)
	}
	return cfg, nil
}
