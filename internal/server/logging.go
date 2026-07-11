package server

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/jacaudi/diyddns/internal/config"
)

// NewLogger builds a slog.Logger from the logging config: level (debug|info|
// warn|error), format (json|text), and output (stderr|stdout|<path>).
func NewLogger(cfg config.LoggingSection) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToUpper(cfg.Level))); err != nil {
		return nil, fmt.Errorf("server: log level %q: %w", cfg.Level, err)
	}

	var w io.Writer
	switch cfg.Output {
	case "", "stderr":
		w = os.Stderr
	case "stdout":
		w = os.Stdout
	default:
		// 0o600 (owner-only): gosec G302 flags anything more permissive, and log
		// files may contain sensitive request context, so restrict access to the
		// process owner.
		f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("server: log output %q: %w", cfg.Output, err)
		}
		w = f
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch cfg.Format {
	case "", "json":
		handler = slog.NewJSONHandler(w, opts)
	case "text":
		handler = slog.NewTextHandler(w, opts)
	default:
		return nil, fmt.Errorf("server: log format %q: must be json or text", cfg.Format)
	}
	return slog.New(handler), nil
}
