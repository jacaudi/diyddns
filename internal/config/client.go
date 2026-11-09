package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// ClientConfig is the fully-resolved diyddns-client configuration. Only the
// sections the enroll vertical needs today are present; run/status add fields
// without restructuring existing callers.
type ClientConfig struct {
	Server  ClientServerSection
	Logging LoggingSection
	Run     ClientRunSection
}

// ClientServerSection holds the target server URL and an optional CA bundle
// for self-signed homelab servers.
type ClientServerSection struct {
	URL      string `mapstructure:"url"`
	CABundle string `mapstructure:"ca_bundle"`
}

// ClientRunSection configures the `run` reporting loop. Empty provider lists
// mean "use the built-in defaults" (see internal/client/ipdiscovery).
type ClientRunSection struct {
	Interval        time.Duration `mapstructure:"interval"`
	Quorum          int           `mapstructure:"quorum"`
	AddressFamilies []string      `mapstructure:"address_families"`
	ProvidersV4     []string      `mapstructure:"providers_v4"`
	ProvidersV6     []string      `mapstructure:"providers_v6"`
	// InsecureProvision lets `run` provision a device certificate over a plain
	// http:// main-port URL, which it otherwise refuses. Off by default.
	InsecureProvision bool `mapstructure:"insecure_provision"`
	// IPDiscovery is IPDiscoveryAuto, IPDiscoveryAlways or IPDiscoveryNever;
	// LoadClient refuses anything else.
	IPDiscovery string `mapstructure:"ip_discovery"`
}

// The run.ip_discovery values: auto lets the server observe the device's
// address and falls back to provider lookup, always keeps today's lookup-and-
// report behaviour, never leaves the address to the server entirely.
const (
	IPDiscoveryAuto   = "auto"
	IPDiscoveryAlways = "always"
	IPDiscoveryNever  = "never"
)

// clientKeyDefaults enumerates every client config key, its default, and (via
// BindEnv) its DIYDDNS_* env var. As with the server loader there is no
// AutomaticEnv, so every key MUST be listed or its env var is ignored.
var clientKeyDefaults = map[string]any{
	"server.url":             "",
	"server.ca_bundle":       "",
	"logging.level":          "info",
	"logging.format":         "text", // spec §8: text default for the interactive client
	"run.interval":           5 * time.Minute,
	"run.quorum":             2,
	"run.address_families":   []string{"ipv4", "ipv6"},
	"run.providers_v4":       []string{},
	"run.providers_v6":       []string{},
	"run.insecure_provision": false,
	"run.ip_discovery":       IPDiscoveryAuto,
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
	if err := validateIPDiscovery(cfg.Run); err != nil {
		return ClientConfig{}, err
	}
	return cfg, nil
}

// validateIPDiscovery refuses any run.ip_discovery other than the three
// documented values, so a typo ("on", "off") never silently picks a mode.
func validateIPDiscovery(rc ClientRunSection) error {
	switch rc.IPDiscovery {
	case IPDiscoveryAuto, IPDiscoveryAlways, IPDiscoveryNever:
		return nil
	}
	return fmt.Errorf("config: run.ip_discovery must be one of %s, %s, %s, got %q",
		IPDiscoveryAuto, IPDiscoveryAlways, IPDiscoveryNever, rc.IPDiscovery)
}

// ProvidersWarning returns a startup warning when run.providers_v4/v6 are set
// but ip_discovery makes them irrelevant or demotes them, and "" otherwise.
// Returned rather than logged, like NotificationsEgressWarning, so the binary
// owns output.
func ProvidersWarning(rc ClientRunSection) string {
	if len(rc.ProvidersV4) == 0 && len(rc.ProvidersV6) == 0 {
		return ""
	}
	switch rc.IPDiscovery {
	case IPDiscoveryAuto:
		return "run.providers_v4/run.providers_v6 are used only as a fallback when the server " +
			"does not observe this device's address (run.ip_discovery is auto)"
	case IPDiscoveryNever:
		return "run.providers_v4/run.providers_v6 are ignored because run.ip_discovery is never"
	}
	return ""
}
