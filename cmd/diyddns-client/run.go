package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/client/checkin"
	"github.com/jacaudi/diyddns/internal/client/credentials"
	"github.com/jacaudi/diyddns/internal/client/ipdiscovery"
	"github.com/jacaudi/diyddns/internal/client/mtls"
	"github.com/jacaudi/diyddns/internal/client/poller"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/version"
)

func newRunCmd() *cobra.Command {
	var (
		once       bool
		interval   time.Duration
		caCert     string
		credFile   string
		configFile string
		insecure   bool
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Discover this host's public IP and report it to the diyddns server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadRunConfig(cmd, configFile)
			if err != nil {
				return err
			}

			credPath, err := resolveCredPath(credFile)
			if err != nil {
				return err
			}
			creds, err := credentials.Load(credPath)
			if err != nil {
				if errors.Is(err, credentials.ErrNotFound) {
					return fmt.Errorf("no credentials at %s — run `diyddns-client enroll` first", credPath)
				}
				return err
			}

			disc, err := buildDiscoverer(cfg.Run)
			if err != nil {
				return err
			}
			fams, err := enabledFamilies(cfg.Run)
			if err != nil {
				return err
			}
			logger := newClientLogger(cfg.Logging)
			if w := config.ProvidersWarning(cfg.Run); w != "" {
				logger.Warn(w)
			}
			mcfg := mtls.Config{
				StatePath:         mtls.PathFor(credPath),
				Creds:             creds,
				CACertPath:        cfg.Server.CABundle,
				InsecureProvision: cfg.Run.InsecureProvision,
				Log:               logger,
				Now:               time.Now,
				Discovery:         cfg.Run.IPDiscovery,
				Families:          fams,
			}
			// pd stays a literal nil unless the poller discovers: a nil *Discoverer
			// stored in the interface would not be == nil and would panic.
			var pd poller.Discoverer
			switch cfg.Run.IPDiscovery {
			case config.IPDiscoveryAlways:
				pd = disc
			case config.IPDiscoveryAuto:
				mcfg.Lookup = disc.DiscoverFamily
			}
			mgr, err := mtls.NewManager(mcfg)
			if err != nil {
				return err
			}
			host, _ := os.Hostname()
			p := poller.New(pd, mgr, poller.Options{
				Interval:      cfg.Run.Interval,
				Logger:        logger,
				Hostname:      host,
				OS:            runtime.GOOS,
				ClientVersion: version.Current().Version,
			})
			if once {
				return explainRunError(p.RunOnce(cmd.Context()), creds.ServerURL)
			}
			return explainRunError(p.Run(cmd.Context()), creds.ServerURL)
		},
	}
	cmd.Flags().BoolVar(&once, "once", false, "run a single discover+check-in and exit")
	cmd.Flags().DurationVar(&interval, "interval", 5*time.Minute, "reporting interval (daemon mode)")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "PEM CA bundle to trust (self-signed servers)")
	cmd.Flags().StringVar(&credFile, "credentials-file", "", "path to credentials.json (default: user config dir)")
	cmd.Flags().StringVar(&configFile, "config", "", "path to client config.yaml")
	cmd.Flags().BoolVar(&insecure, "insecure-provision", false, "allow provisioning an mTLS certificate over a plain http:// server URL")
	return cmd
}

// loadRunConfig builds the client config for `run`: flags bound over the
// config file and env.
func loadRunConfig(cmd *cobra.Command, configFile string) (config.ClientConfig, error) {
	v := viper.New()
	if err := v.BindPFlag("run.interval", cmd.Flags().Lookup("interval")); err != nil {
		return config.ClientConfig{}, err
	}
	if err := v.BindPFlag("server.ca_bundle", cmd.Flags().Lookup("ca-cert")); err != nil {
		return config.ClientConfig{}, err
	}
	if err := v.BindPFlag("run.insecure_provision", cmd.Flags().Lookup("insecure-provision")); err != nil {
		return config.ClientConfig{}, err
	}
	return config.LoadClient(v, configFile)
}

// resolveCredPath returns the --credentials-file value, or the per-user default.
func resolveCredPath(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	return credentials.DefaultPath()
}

// explainRunError turns the poller's credential rejection into the message an
// operator reads in `docker logs` (#102): the cause and the remedy, not a bare
// "unauthorized". The wrapped sentinel is preserved so errors.Is still holds.
// Every other error — and nil — passes through untouched.
func explainRunError(err error, serverURL string) error {
	if errors.Is(err, checkin.ErrMTLSRequired) {
		return fmt.Errorf("%w. This client is too old or not provisioned for mTLS: upgrade diyddns-client, and check that it can reach the agent port advertised by %s", err, serverURL)
	}
	if err == nil || !errors.Is(err, checkin.ErrUnauthorized) {
		return err
	}
	return fmt.Errorf("the server rejected this device's credentials (%w): the device secret was rotated or the device was disabled. "+
		"Mint a new enrollment code at %s/devices/new, then run `diyddns-client enroll --server %s --code <code> --force`",
		err, serverURL, serverURL)
}

// enabledFamilies returns the families run.address_families enables, IPv4 before
// IPv6 whatever the config order, so every consumer visits them the same way.
func enabledFamilies(rc config.ClientRunSection) ([]ipdiscovery.Family, error) {
	var v4, v6 bool
	for _, fam := range rc.AddressFamilies {
		switch fam {
		case "ipv4":
			v4 = true
		case "ipv6":
			v6 = true
		default:
			return nil, fmt.Errorf("run: unknown address family %q", fam)
		}
	}
	var out []ipdiscovery.Family
	if v4 {
		out = append(out, ipdiscovery.FamilyV4)
	}
	if v6 {
		out = append(out, ipdiscovery.FamilyV6)
	}
	if len(out) == 0 {
		return nil, errors.New("run: no address families enabled")
	}
	return out, nil
}

// buildDiscoverer wires providers per enabled family (config override, else
// built-in defaults) and constructs the quorum Discoverer. In never mode no
// lookup ever runs, so it returns nil, nil without checking the quorum.
func buildDiscoverer(rc config.ClientRunSection) (*ipdiscovery.Discoverer, error) {
	if rc.IPDiscovery == config.IPDiscoveryNever {
		return nil, nil
	}
	var v4, v6 []ipdiscovery.Provider
	for _, fam := range rc.AddressFamilies {
		switch fam {
		case "ipv4":
			if len(rc.ProvidersV4) > 0 {
				v4 = ipdiscovery.ProvidersFromURLs(rc.ProvidersV4, ipdiscovery.FamilyV4)
			} else {
				v4 = ipdiscovery.DefaultProvidersV4()
			}
		case "ipv6":
			if len(rc.ProvidersV6) > 0 {
				v6 = ipdiscovery.ProvidersFromURLs(rc.ProvidersV6, ipdiscovery.FamilyV6)
			} else {
				v6 = ipdiscovery.DefaultProvidersV6()
			}
		default:
			return nil, fmt.Errorf("run: unknown address family %q", fam)
		}
	}
	if v4 == nil && v6 == nil {
		return nil, fmt.Errorf("run: no address families enabled")
	}
	return ipdiscovery.NewDiscoverer(v4, v6, rc.Quorum, 5*time.Second)
}

// newClientLogger builds a minimal slog.Logger from the client's logging
// config. Unlike internal/server.NewLogger, this cannot be shared: the
// server package is off-limits to the client binary (deps guard), and the
// client only ever logs to stderr (no file-output option), so this stays
// deliberately smaller than the server's constructor.
func newClientLogger(l config.LoggingSection) *slog.Logger {
	lvl := slog.LevelInfo
	parseErr := lvl.UnmarshalText([]byte(l.Level))
	var h slog.Handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	if l.Format == "json" {
		h = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	}
	logger := slog.New(h)
	if parseErr != nil && l.Level != "" {
		logger.Warn("invalid log level, falling back to info", "level", l.Level, "error", parseErr)
	}
	return logger
}
