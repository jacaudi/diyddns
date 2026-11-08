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
	"github.com/jacaudi/diyddns/internal/telemetry"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	// otellog is aliased: see internal/telemetry/telemetry.go's identical
	// alias for why a bare `log` identifier would be ambiguous here.
	otellog "go.opentelemetry.io/otel/log"
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

// ParseLogLevel parses cfg.Logging.Level (debug|info|warn|error, case
// insensitive) into a slog.Level.
//
// Extracted from NewLogger (Task 13, Step 13.0) so cmd/diyddns-server can
// parse the level once and hand the result to telemetry.New, which needs the
// already-parsed level to feed its minsev log processor and cannot get it
// from NewLogger's return value (NewLogger returns only a *slog.Logger).
// NewLogger itself keeps calling this so the two never drift.
func ParseLogLevel(level string) (slog.Level, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(strings.ToUpper(level))); err != nil {
		return 0, fmt.Errorf("server: log level %q: %w", level, err)
	}
	return l, nil
}

// NewLogger builds a slog.Logger from the logging config: level (debug|info|
// warn|error), format (json|text), and output (stderr|stdout|<path>). It has
// no OTLP branch; WithOTLP adds one once the provider exists.
func NewLogger(cfg config.LoggingSection) (*slog.Logger, error) {
	level, err := ParseLogLevel(cfg.Level)
	if err != nil {
		return nil, err
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

// WithOTLP returns log with the OTLP logs bridge added alongside its existing
// output, or log itself when lp is nil (telemetry off or inert).
//
// cmd/diyddns-server calls NewLogger BEFORE telemetry.New, so otel.SetLogger
// can catch a malformed OTEL_* variable reported from inside exporter
// construction, and calls this once the provider exists. Reusing log's
// handler rather than calling NewLogger again keeps a file output opened once.
//
// The nil check is a COST decision: otelslog.NewHandler defaults to OTel's
// global provider, so an unconditional branch would still be correct, but
// would pay a Record.Clone plus attribute conversion per record for nothing.
func WithOTLP(log *slog.Logger, lp otellog.LoggerProvider) *slog.Logger {
	if lp == nil {
		return log
	}
	inner := log.Handler()
	if rh, ok := inner.(requestIDHandler); ok {
		inner = rh.inner
	}
	// slog.NewMultiHandler is stdlib as of Go 1.27 and is already correct
	// on the four things a hand-rolled fanout gets wrong: Enabled is the
	// union of its children; Handle RE-CHECKS Enabled per child, so each
	// branch filters independently; Handle clones the Record per child;
	// and WithAttrs/WithGroup re-wrap rather than unwrapping.
	//
	// requestIDHandler stays OUTERMOST so request_id is added once and
	// cloned into both branches.
	return slog.New(requestIDHandler{inner: slog.NewMultiHandler(inner, otelslog.NewHandler(
		telemetry.InstrumentationName,
		otelslog.WithLoggerProvider(lp),
	))})
}
