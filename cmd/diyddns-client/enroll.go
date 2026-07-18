package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jacaudi/diyddns/internal/client/credentials"
	"github.com/jacaudi/diyddns/internal/client/enroll"
	"github.com/jacaudi/diyddns/internal/config"
)

// newEnrollCmd builds the `enroll` command. Only --oidc mode is implemented in
// Plan 06; --code/--user are future additive modes.
func newEnrollCmd() *cobra.Command {
	var (
		useOIDC    bool
		serverFlag string
		caCert     string
		force      bool
		credFile   string
		configFile string
	)
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this device with a diyddns server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !useOIDC {
				return fmt.Errorf("only --oidc enrollment is supported in this version")
			}
			v := viper.New()
			if err := v.BindPFlag("server.url", cmd.Flags().Lookup("server")); err != nil {
				return err
			}
			if err := v.BindPFlag("server.ca_bundle", cmd.Flags().Lookup("ca-cert")); err != nil {
				return err
			}
			cfg, err := config.LoadClient(v, configFile)
			if err != nil {
				return err
			}
			return runOIDCEnroll(cmd.Context(), enrollParams{
				out:      cmd.ErrOrStderr(),
				server:   cfg.Server.URL,
				caCert:   cfg.Server.CABundle,
				force:    force,
				credFile: credFile,
			})
		},
	}
	cmd.Flags().BoolVar(&useOIDC, "oidc", false, "use OIDC device-code enrollment")
	cmd.Flags().StringVar(&serverFlag, "server", "", "diyddns server base URL")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "PEM CA bundle to trust (self-signed servers)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing credentials.json")
	cmd.Flags().StringVar(&credFile, "credentials-file", "", "path to credentials.json (default: user config dir)")
	cmd.Flags().StringVar(&configFile, "config", "", "path to client config.yaml")
	return cmd
}

type enrollParams struct {
	out      io.Writer
	server   string
	caCert   string
	force    bool
	credFile string
}

// finishEnroll is the shared orchestration for every enroll mode. It resolves the
// credentials path and refuses to overwrite existing credentials BEFORE any
// server contact (so a re-enroll without --force spends nothing), normalizes
// and requires the server URL, builds the enroll client, runs the mode-specific
// operation, and persists the resulting credentials.
func finishEnroll(ctx context.Context, p enrollParams, do func(context.Context, *enroll.Client) (enroll.Result, error)) error {
	credPath := p.credFile
	if credPath == "" {
		dp, err := credentials.DefaultPath()
		if err != nil {
			return err
		}
		credPath = dp
	}

	// Guard existing credentials BEFORE contacting the server, so a re-enroll
	// without --force never spends a code/login and never prompts for input.
	if !p.force {
		switch _, err := credentials.Load(credPath); {
		case err == nil:
			return fmt.Errorf("credentials already exist at %s (use --force to overwrite)", credPath)
		case !errors.Is(err, credentials.ErrNotFound):
			return err
		}
	}

	// Normalize once so the persisted ServerURL matches the URL requests use
	// (the future check-in client reads this field).
	p.server = strings.TrimRight(p.server, "/")
	if p.server == "" {
		return fmt.Errorf("server URL is required (--server or config server.url)")
	}
	c, err := enroll.NewClient(p.server, enroll.ClientOptions{CACertPath: p.caCert})
	if err != nil {
		return err
	}
	res, err := do(ctx, c)
	if err != nil {
		return err
	}
	if err := credentials.Save(credPath, credentials.Credentials{
		ServerURL: p.server,
		DeviceID:  res.DeviceID,
		Secret:    res.Secret,
	}, p.force); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(p.out, "Device %s enrolled. Credentials written to %s\n", res.DeviceID, credPath)
	return nil
}

// runOIDCEnroll runs the OIDC device-code flow through the shared orchestrator.
func runOIDCEnroll(ctx context.Context, p enrollParams) error {
	return finishEnroll(ctx, p, func(ctx context.Context, c *enroll.Client) (enroll.Result, error) {
		caps, err := c.Capabilities(ctx)
		if err != nil {
			return enroll.Result{}, fmt.Errorf("contacting server: %w", err)
		}
		if !caps.OIDCDeviceEnabled {
			return enroll.Result{}, fmt.Errorf("server does not support OIDC device enrollment")
		}
		return enroll.DeviceCodeEnroll(ctx, c, stderrPrompter{w: p.out}, enroll.NewSystemClock())
	})
}

// stderrPrompter renders the device-code prompt for the operator. It never
// prints the flow_id or the secret. Writes are best-effort: a failure to
// write operator UX to stderr does not change the enrollment outcome.
type stderrPrompter struct{ w io.Writer }

func (s stderrPrompter) ShowUserCode(ds enroll.DeviceStart) {
	_, _ = fmt.Fprintf(s.w, "To authorize this device, visit:\n    %s\n", ds.VerificationURI)
	_, _ = fmt.Fprintf(s.w, "and enter code: %s\n", ds.UserCode)
	if ds.VerificationURIComplete != "" {
		_, _ = fmt.Fprintf(s.w, "(or open directly: %s)\n", ds.VerificationURIComplete)
	}
}

func (s stderrPrompter) Waiting() {
	_, _ = fmt.Fprintln(s.w, "Waiting for authorization…")
}
