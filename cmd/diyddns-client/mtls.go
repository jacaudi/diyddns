package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jacaudi/diyddns/internal/client/mtls"
)

// newMTLSCmd builds the `mtls` command group.
func newMTLSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mtls",
		Short: "Manage this device's mTLS state",
	}
	cmd.AddCommand(newMTLSResetCmd())
	return cmd
}

// newMTLSResetCmd builds `mtls reset`: it forgets the local certificate so the
// next run provisions again. The server refuses a second certificate until an
// admin resets it there, so the output says so.
func newMTLSResetCmd() *cobra.Command {
	var credFile string
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Delete the local mTLS state (mtls.json) so this device provisions a new certificate",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			credPath, err := resolveCredPath(credFile)
			if err != nil {
				return err
			}
			statePath := mtls.PathFor(credPath)
			if _, err := os.Stat(statePath); errors.Is(err, os.ErrNotExist) {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No mTLS state at %s; nothing to delete.\n", statePath)
				return nil
			}
			if err := mtls.Remove(statePath); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted %s. Now ask an admin to click \"Reset certificate\" for this device on the server, or the server will refuse to issue a new certificate.\n", statePath)
			return nil
		},
	}
	cmd.Flags().StringVar(&credFile, "credentials-file", "", "path to credentials.json (default: user config dir)")
	return cmd
}
