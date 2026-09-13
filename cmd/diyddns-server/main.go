// Command diyddns-server is the DIYDDNS HTTP server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"go.opentelemetry.io/otel"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/telemetry"
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
			logLevel, err := server.ParseLogLevel(cfg.Logging.Level)
			if err != nil {
				return err
			}

			// otlpSlot starts empty; NewLogger's MultiHandler branch built around
			// it is a safe no-op until telemetry.New's real provider lands in it
			// below (server.LazyLoggerProvider's doc comment).
			var otlpSlot server.LazyLoggerProvider
			log, err := server.NewLogger(cfg.Logging, &otlpSlot)
			if err != nil {
				return err
			}

			// MUST run before telemetry.New: a malformed OTEL_* variable is
			// reported from INSIDE exporter construction (New's package doc
			// comment, Revision 6), and otel.SetLogger is the only channel that
			// ever catches it. That is why it cannot move below.
			//
			// GATED on Enabled because design D10 says "off by default" means
			// INERT: with observability.otlp.enabled false nothing else in the
			// process may change, and otel.SetLogger installs a process-wide
			// OTel global. Nothing would ever call it on that path -- New
			// short-circuits before touching a single OTEL_* variable
			// (telemetry.New's !cfg.Enabled return) -- so the install is
			// state-without-a-requirement, exactly what D10 removed for the
			// provider globals. Note there is no way to assert this from a
			// test: OTel exposes no GetLogger and its internal/global package
			// is unimportable (telemetry.OtelLogr's doc comment).
			if cfg.Observability.OTLP.Enabled {
				otel.SetLogger(telemetry.OtelLogr(log))
			}

			// Constructed -- and its Shutdown deferred -- before
			// signal.NotifyContext, so that defer registers first and therefore
			// runs LAST: after stop() has run and srv.Run has drained the HTTP
			// server, so shutdown-time records still export.
			tel, status := telemetry.New(cmd.Context(), cfg.Observability.OTLP, logLevel, version.Current())
			if status.Reason != "" {
				log.LogAttrs(cmd.Context(), slog.LevelWarn, "telemetry not exporting",
					slog.String("reason", status.Reason),
					slog.Bool("fatal", status.Fatal),
				)
			}
			otlpSlot.Store(tel.LoggerProvider())
			tel.SetErrorHandler(log)
			defer func() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), server.TelemetryShutdownTimeout)
				defer cancel()
				if err := tel.Shutdown(shutdownCtx); err != nil {
					log.LogAttrs(cmd.Context(), slog.LevelWarn, "telemetry shutdown incomplete", slog.Any("error", err))
				}
			}()

			// THE FATAL RULE's other half (telemetry.Status's doc comment,
			// design §6.1/§9.3): a Status this server may not run through. Only
			// two conditions set it -- a malformed endpoint, and a semconv
			// schema-URL conflict -- and both fail SILENTLY if boot continues:
			// the exporter POSTs to "http:///" forever, or records export with
			// no schema, while Shutdown reports success either way. A MISSING
			// endpoint is deliberately not Fatal and reaches only the Warn above.
			//
			// Reason already carries its own "telemetry: " prefix (endpoint.go,
			// resource.go); do not add a second one.
			//
			// Placed AFTER the shutdown defer, matching design §6.3, even though
			// New's Fatal paths all return inert() -- whose shutdown slice is
			// empty, so there is provably nothing to drain today. Registering
			// first costs nothing and keeps the drain correct if New ever starts
			// returning a partially-built Providers alongside a Fatal Status.
			if status.Fatal {
				return errors.New(status.Reason)
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			st, err := store.Open(ctx, cfg.Database.Path)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer func() { _ = st.Close() }()

			// passkeys/sealKey are nil here: this one-shot Startup-only
			// instance never calls BeginClaim/FinishClaim (those are driven
			// by the HTTP-serving BootstrapService server.New wires up
			// separately, with a real PasskeyService when WebAuthn resolves).
			bootstrap := service.NewBootstrapService(st, log, service.NewAuditWriter(st), nil, nil, nil)
			if err := bootstrap.Startup(ctx); err != nil {
				return fmt.Errorf("bootstrap startup: %w", err)
			}

			log.LogAttrs(ctx, slog.LevelInfo, "starting diyddns-server",
				slog.String("version", version.Current().String()),
				slog.String("listen", cfg.Server.Listen),
			)
			srv, err := server.New(cfg, st, log, tel)
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
