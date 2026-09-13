package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/middleware"
	"github.com/jacaudi/diyddns/internal/telemetry"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	// otellog is aliased: see internal/telemetry/telemetry.go's identical
	// alias for why a bare `log` identifier would be ambiguous here.
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
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
//
// lp is the OTLP logs bridge's provider. A literal nil is still meaningful and
// must be an explicit branch (with nil, this builds exactly the handler it
// built before #101 and stdout output is unchanged), but in production it is
// NOT what "telemetry is off" looks like: cmd/diyddns-server (Task 13) always
// passes a *LazyLoggerProvider, enabled or not, and it is THAT type's own
// empty-vs-filled state -- not lp's nilness -- that tracks whether telemetry
// is on. lp == nil is a secondary path for a caller with no lazy slot to
// offer at all (direct unit tests today; any future caller that doesn't
// participate in Revision 6's startup ordering).
//
// The nil check is a COST decision, not a correctness one. OTel's log API does
// have a global (otel/log/global), and otelslog.NewHandler defaults to it, so
// omitting the check would still be correct -- it would just always add the
// second MultiHandler branch, paying a Record.Clone plus attribute conversion
// per record on a server with no provider to offer at all.
func NewLogger(cfg config.LoggingSection, lp otellog.LoggerProvider) (*slog.Logger, error) {
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
	if lp != nil {
		// slog.NewMultiHandler is stdlib as of Go 1.27 and is already correct
		// on the four things a hand-rolled fanout gets wrong: Enabled is the
		// union of its children; Handle RE-CHECKS Enabled per child, so each
		// branch filters independently; Handle clones the Record per child;
		// and WithAttrs/WithGroup re-wrap rather than unwrapping.
		//
		// requestIDHandler stays OUTERMOST so request_id is added once and
		// cloned into both branches.
		handler = slog.NewMultiHandler(handler, otelslog.NewHandler(
			telemetry.InstrumentationName,
			otelslog.WithLoggerProvider(lp),
		))
	}
	return slog.New(requestIDHandler{inner: handler}), nil
}

// LazyLoggerProvider is an otellog.LoggerProvider whose backing provider
// starts empty and is filled in exactly once, after telemetry.New has
// constructed the real one (Revision 6). cmd/diyddns-server passes it to
// NewLogger before telemetry.New runs -- the ordering Task 6's two-phase
// bootstrap install existed to solve a different way -- then calls Store once
// the real provider exists.
//
// While empty, every Logger it returns reports Enabled false and drops every
// Emit, so the MultiHandler branch built around it is safe to install
// unconditionally even on the telemetry-disabled path: see NewLogger's cost
// comment, and Logger.Enabled's own doc comment ("The returned value is not
// static and may change over time. A cached value can become stale."), which
// sanctions exactly this nil-then-filled slot.
type LazyLoggerProvider struct {
	embedded.LoggerProvider

	p atomic.Pointer[otellog.LoggerProvider]
}

// Compile-time check that *LazyLoggerProvider satisfies otellog.LoggerProvider.
// Nothing in this package's production code assigns *LazyLoggerProvider to an
// otellog.LoggerProvider-typed value (that only happens in cmd/diyddns-server,
// Task 13), so without this line, deleting the embedded.LoggerProvider field
// above -- the sealing type the interface requires from outside this module --
// would leave `go vet` clean and every test in this package passing (Fix
// round 1, I1).
var _ otellog.LoggerProvider = (*LazyLoggerProvider)(nil)

// Store sets the backing provider. Called once, from the goroutine that
// constructs telemetry.Providers. Logger's returned values may observe the
// change from any goroutine at any time through the atomic pointer -- EXCEPT
// a Logger that has already resolved and cached a real otellog.Logger (see
// lazyLogger.real): a later Store is not observed by that already-resolved
// Logger, only by ones that were still empty when it landed.
func (l *LazyLoggerProvider) Store(lp otellog.LoggerProvider) {
	l.p.Store(&lp)
}

// Logger implements otellog.LoggerProvider. The returned Logger consults the
// slot on every call rather than resolving it once at construction time,
// since otelslog.NewHandler calls Logger exactly once and holds the result
// for the handler's lifetime -- before the slot has necessarily been filled.
func (l *LazyLoggerProvider) Logger(name string, opts ...otellog.LoggerOption) otellog.Logger {
	return &lazyLogger{provider: l, name: name, opts: opts}
}

func (l *LazyLoggerProvider) current() otellog.LoggerProvider {
	p := l.p.Load()
	if p == nil {
		return nil
	}
	return *p
}

// lazyLogger is the otellog.Logger LazyLoggerProvider.Logger returns. It
// resolves the real Logger lazily and caches it once the slot is filled, so a
// filled slot pays one otellog.LoggerProvider.Logger call total (which, for
// the SDK's own provider, takes an internal mutex) rather than one per
// emitted record.
type lazyLogger struct {
	embedded.Logger

	provider *LazyLoggerProvider
	name     string
	opts     []otellog.LoggerOption

	resolved atomic.Pointer[otellog.Logger]
}

func (l *lazyLogger) real() otellog.Logger {
	if r := l.resolved.Load(); r != nil {
		return *r
	}
	lp := l.provider.current()
	if lp == nil {
		return nil
	}
	logger := lp.Logger(l.name, l.opts...)
	l.resolved.Store(&logger)
	return logger
}

func (l *lazyLogger) Enabled(ctx context.Context, param otellog.EnabledParameters) bool {
	r := l.real()
	return r != nil && r.Enabled(ctx, param)
}

func (l *lazyLogger) Emit(ctx context.Context, record otellog.Record) {
	if r := l.real(); r != nil {
		r.Emit(ctx, record)
	}
}
