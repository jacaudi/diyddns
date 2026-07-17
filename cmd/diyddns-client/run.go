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
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Discover this host's public IP and report it to the diyddns server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := viper.New()
			if err := v.BindPFlag("run.interval", cmd.Flags().Lookup("interval")); err != nil {
				return err
			}
			if err := v.BindPFlag("server.ca_bundle", cmd.Flags().Lookup("ca-cert")); err != nil {
				return err
			}
			cfg, err := config.LoadClient(v, configFile)
			if err != nil {
				return err
			}

			credPath := credFile
			if credPath == "" {
				dp, err := credentials.DefaultPath()
				if err != nil {
					return err
				}
				credPath = dp
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
			chk, err := checkin.NewClient(creds.ServerURL, creds.DeviceID, creds.Secret,
				checkin.Options{CACertPath: cfg.Server.CABundle})
			if err != nil {
				return err
			}
			host, _ := os.Hostname()
			p := poller.New(disc, chk, poller.Options{
				Interval:      cfg.Run.Interval,
				Logger:        newClientLogger(cfg.Logging),
				Hostname:      host,
				OS:            runtime.GOOS,
				ClientVersion: version.Current().Version,
			})
			if once {
				return p.RunOnce(cmd.Context())
			}
			return p.Run(cmd.Context())
		},
	}
	cmd.Flags().BoolVar(&once, "once", false, "run a single discover+check-in and exit")
	cmd.Flags().DurationVar(&interval, "interval", 5*time.Minute, "reporting interval (daemon mode)")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "PEM CA bundle to trust (self-signed servers)")
	cmd.Flags().StringVar(&credFile, "credentials-file", "", "path to credentials.json (default: user config dir)")
	cmd.Flags().StringVar(&configFile, "config", "", "path to client config.yaml")
	return cmd
}

// buildDiscoverer wires providers per enabled family (config override, else
// built-in defaults) and constructs the quorum Discoverer.
func buildDiscoverer(rc config.ClientRunSection) (*ipdiscovery.Discoverer, error) {
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
	_ = lvl.UnmarshalText([]byte(l.Level))
	var h slog.Handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	if l.Format == "json" {
		h = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	}
	return slog.New(h)
}
