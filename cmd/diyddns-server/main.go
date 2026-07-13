// Command diyddns-server is the DIYDDNS HTTP server.
package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "diyddns-server:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "diyddns-server",
		Short:         "DIYDDNS server",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(serveCmd(), versionCmd())
	return root
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "diyddns-server", version.Current().String())
			return err
		},
	}
}

func serveCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the HTTP server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := viper.New()
			if err := v.BindPFlag("server.listen", cmd.Flags().Lookup("listen")); err != nil {
				return err
			}
			cfg, err := config.Load(v, cfgPath)
			if err != nil {
				return err
			}
			log, err := server.NewLogger(cfg.Logging)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			st, err := store.Open(ctx, cfg.Database.Path)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer func() { _ = st.Close() }()

			bootstrap := service.NewBootstrapService(st, cfg.Auth.Bootstrap, cfg.Auth.Password, log, service.NewAuditWriter(st), nil)
			if err := bootstrap.Startup(ctx); err != nil {
				return fmt.Errorf("bootstrap startup: %w", err)
			}

			log.LogAttrs(ctx, slog.LevelInfo, "starting diyddns-server",
				slog.String("version", version.Current().String()),
				slog.String("listen", cfg.Server.Listen),
			)
			srv, err := server.New(cfg, st, log)
			if err != nil {
				return err // already wrapped with "server: ..." context by New/Handler
			}
			return srv.Run(ctx)
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "path to server config file")
	cmd.Flags().String("listen", "", "HTTP listen address (overrides config)")
	return cmd
}
