package main

import "github.com/spf13/cobra"

// newRootCmd builds the diyddns-client root command and registers subcommands.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "diyddns-client",
		Short:         "DIYDDNS reporting agent",
		SilenceUsage:  true, // don't dump usage on a runtime error
		SilenceErrors: false,
	}
	root.AddCommand(newVersionCmd())
	return root
}
