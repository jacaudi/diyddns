package main

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/agenttls"
	"github.com/jacaudi/diyddns/internal/store"
)

// caCmd groups the agent CA operator commands (#173). Both are one-off
// processes that take the agent.tls.dir lock, so they refuse to run while the
// server is up.
func caCmd() *cobra.Command {
	ca := &cobra.Command{
		Use:   "ca",
		Short: "Manage the agent CA (server must be stopped)",
	}
	ca.AddCommand(promoteBackupCmd(), resetCmd())
	return ca
}

func promoteBackupCmd() *cobra.Command {
	var cfgPath, backupKey string
	cmd := &cobra.Command{
		Use:   "promote-backup",
		Short: "Make the backup agent CA the active one",
		Long: "promote-backup makes the backup agent CA active, generates a new backup CA, and clears every " +
			"device's recorded certificate. --backup-key is the offline copy of the backup CA's private key. " +
			"The server must be stopped. Devices re-provision on their own. Safe to run again.",
		Example: "  diyddns-server ca promote-backup --backup-key /mnt/usb/ca-backup.key --config /etc/diyddns/server.yaml",
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, dir, log, err := openCAStore(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			res, err := agenttls.PromoteBackup(cmd.Context(), st, dir, backupKey, time.Now(), log)
			if err != nil {
				return err
			}
			lines := res.Notes
			if res.NewBackupKeyPath != "" {
				lines = append(lines, "Backup CA promoted. A new backup key was written to "+res.NewBackupKeyPath+
					`: move it offline now (see docs/deployment.md, "Agent CA backups").`)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), strings.Join(lines, "\n"))
			return err
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "path to server config file")
	cmd.Flags().StringVar(&backupKey, "backup-key", "", "path to the offline backup CA private key")
	if err := cmd.MarkFlagRequired("backup-key"); err != nil {
		panic(err) //nolint:tricorder // libpanic: the flag was defined one line above; a failure is a programming error
	}
	return cmd
}

func resetCmd() *cobra.Command {
	var cfgPath string
	var confirm bool
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Delete the agent CA and start over (last resort)",
		Long: "reset deletes the recorded agent CA pair, clears every device's recorded certificate, and renames " +
			"ca*.key and agent.* in agent.tls.dir to <name>.reset-<timestamp>. The next server start generates " +
			"a fresh pair; every committed device must then run \"diyddns-client mtls reset\". The server must " +
			"be stopped. Requires --confirm.",
		Example: "  diyddns-server ca reset --confirm --config /etc/diyddns/server.yaml",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !confirm {
				return errors.New("ca reset discards the agent CA and strands every committed device: pass --confirm to proceed")
			}
			st, dir, _, err := openCAStore(cmd, cfgPath)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			renamed, err := agenttls.Reset(cmd.Context(), st, dir, time.Now())
			out := cmd.OutOrStdout()
			for _, p := range renamed {
				if _, werr := fmt.Fprintf(out, "Renamed %s\n", filepath.Clean(p)); werr != nil {
					err = errors.Join(err, werr)
				}
			}
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(out, `Every committed device must run "diyddns-client mtls reset".`)
			return err
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "path to server config file")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "acknowledge that this discards the agent CA")
	return cmd
}

// openCAStore loads the server config and opens its database. It returns the
// store, agent.tls.dir and the logger it used, whose warnings go to stderr.
func openCAStore(cmd *cobra.Command, cfgPath string) (*store.Store, string, *slog.Logger, error) {
	cfg, err := config.Load(viper.New(), cfgPath)
	if err != nil {
		return nil, "", nil, err
	}
	log := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelWarn}))
	st, err := store.Open(cmd.Context(), cfg.Database.Path, log)
	if err != nil {
		return nil, "", nil, fmt.Errorf("open store: %w", err)
	}
	return st, cfg.Agent.TLS.Dir, log, nil
}
