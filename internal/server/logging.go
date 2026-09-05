package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/middleware"
)

// requestIDHandler adds the request correlation id to every record emitted
// with a request-scoped context, so no call site has to pass it. It must be a
// Handler rather than a HandlerOptions.ReplaceAttr: ReplaceAttr is
// func(groups []string, a Attr) Attr and never receives a context
// (log/slog/handler.go:172).
//
// Records with no request-scoped context emit no request_id key at all,
// rather than an empty one: absent reads as "not a request", empty reads as
// "correlation failed" (design D2).
type requestIDHandler struct{ inner slog.Handler }

func (h requestIDHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h requestIDHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := middleware.RequestIDFromContext(ctx); id != "" {
		r = r.Clone() // Record shares a backing array; mutate a copy
		r.AddAttrs(slog.String("request_id", id))
	}
	return h.inner.Handle(ctx, r)
}

// WithAttrs and WithGroup MUST re-wrap. Returning h.inner.WithAttrs(as)
// directly unwraps the handler and silently stops adding ids.
func (h requestIDHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return requestIDHandler{inner: h.inner.WithAttrs(as)}
}

func (h requestIDHandler) WithGroup(name string) slog.Handler {
	// Known limitation: under a group the id nests inside it. The tree has
	// zero WithGroup call sites, and there is no correct general fix -- the
	// handler cannot know the nesting is unintended.
	return requestIDHandler{inner: h.inner.WithGroup(name)}
}

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
	return slog.New(requestIDHandler{inner: handler}), nil
}
