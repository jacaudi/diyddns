package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jacaudi/diyddns/internal/version"
)

// newVersionCmd prints the build identity and exits. --json emits the machine
// form (go-standards §9.2: version available in both text and JSON).
func newVersionCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(version.Current())
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "diyddns-client", version.Current().String())
			return err
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print version as JSON")
	return cmd
}
