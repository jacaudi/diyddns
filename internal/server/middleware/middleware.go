// Package middleware provides the cross-cutting net/http middleware wrapped
// around the diyddns-server mux: request-id assignment, structured access
// logging, and panic recovery. Auth middleware (HMAC, session/CSRF) is added by
// later plans and is intentionally absent here.
package middleware

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"time"
	"uuid"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/semconv/v1.43.0/httpconv"
	"go.opentelemetry.io/otel/trace"
)

// maxRequestIDLen bounds an inbound correlation id. 128 admits a UUIDv7 (36)
// and a W3C traceparent (55), so #101's correlation header stays adoptable,
// while bounding what an unauthenticated caller can write into every log
// record of its request -- the value now reaches every record, not just two,
// and Go's default MaxHeaderBytes permits 1 MiB.
const maxRequestIDLen = 128

type ctxKey int

const requestIDKey ctxKey = iota

// RequestIDFromContext returns the request id stored by RequestID, or "".
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// validRequestID accepts a correlation id from an untrusted client: non-empty,
// at most maxRequestIDLen bytes, and printable ASCII only.
//
// The bound is what keeps the value safe to embed in every log record it now
// reaches -- but not for the reason it looks like. It is NOT log injection:
// both slog handlers escape a newline inside a value, so the record stays one
// line, and net/http answers 400 for a control byte in a header value before
// this middleware ever runs. What actually reaches here is obs-text
// (httpguts.ValidHeaderFieldValue permits 0x80-0xFF, so arbitrary non-ASCII
// arrives intact) and an over-length value, whole, up to MaxHeaderBytes.
// Bounding those two is the real job: an unauthenticated caller must not get
// to write unbounded or non-ASCII bytes into every record of its request.
//
// This bound is deliberately NOT shared with config.validateObservability's
// check on the header NAME. That one enforces an RFC 7230 field-name token and
// is set by what this server writes; this one is set by what upstream proxies
// emit. They are different rules over different values and are expected to
// diverge.
//
// It is likewise not shared with api.claimedDeviceID, which applies the same
// 128-byte printable-ASCII bound to the agent device header. That one's limit
// is set by what this server mints, this one's by what upstream proxies emit,
// and internal/server/api does not import this package — unifying them would
// buy a cross-package edge for a rule the two sides do not co-own. Identical
// today; keep them in step or diverge them deliberately.
func validRequestID(s string) bool {
	if s == "" || len(s) > maxRequestIDLen {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

// RequestID assigns each request a correlation id: it honors an inbound
// header value when that value is valid, otherwise generates a UUIDv7. The id
// is placed in the request context and echoed in the response header.
//
// An invalid inbound value is DISCARDED and replaced, never truncated: a
// truncated id still looks like the client's but no longer matches the
// proxy's own logs, which is a false correlation rather than an honest new
// one.
//
// header is the configured observability.request_id_header. It is validated
// at startup (config.validateObservability), so it is never empty here.
func RequestID(header string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get(header)
			if !validRequestID(id) {
				id = uuid.NewV7().String()
			}
			w.Header().Set(header, id)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Unwrap exposes the wrapped writer so http.ResponseController — and a
// WebSocket upgrade, which walks Unwrap looking for http.Hijacker — can reach
// the connection through this recorder. Without it every upgrade served
// through AccessLog fails with 501 (design #106 §5.1). Nothing in net/http
// calls it except ResponseController, so status and byte capture are
// unaffected.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// AccessLog emits exactly one structured info line per request. Sensitive
// headers are never logged.
func AccessLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			if rec.status == 0 {
				rec.status = http.StatusOK
			}
			log.LogAttrs(r.Context(), slog.LevelInfo, "request",
				slog.String("method", r.Method),
				// r.Pattern is the low-cardinality route template (Go 1.23+).
				// r.URL.Path carries device and user ids, so logging it wrote a
				// per-user activity trail on every request. Empty on 404 and on
				// 405 (path matched, method did not); status distinguishes them.
				slog.String("route", r.Pattern),
				slog.Int("status", rec.status),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()),
				slog.Int("bytes_out", rec.bytes),
			)
		})
	}
}

// Recover converts a handler panic into a 500 and logs it, keeping the process
// alive.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.LogAttrs(r.Context(), slog.LevelError, "panic recovered",
						slog.Any("panic", rec),
					)
					w.WriteHeader(http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// spanName builds a LOW-CARDINALITY span name. pattern is r.Pattern, the route
// template the mux annotated; it is empty on a 404 and on a 405 (path matched,
// method did not). The raw path is never used: it carries device and user ids.
//
// DELIBERATE DIVERGENCE from design §4.5, which writes the formula as
// `method + " " + pattern`. r.Pattern ALREADY carries the method -- it is
// "GET /devices/{id}", not "/devices/{id}" (verified against
// net/http/server.go's findHandler, which returns the pattern's own str field,
// the literal registration string; see the design's own §4.2 table) -- so the
// design's formula would render "GET GET /devices/{id}". Returning pattern
// alone is correct. Do not "fix" this against the design text.
func spanName(method, pattern string) string {
	if pattern == "" {
		return "HTTP " + method
	}
	return pattern
}

// maxServerAddressLen bounds what r.Host may contribute to a span attribute.
// 253 is the maximum length of a DNS name, so no legitimate Host header --
// registered name, punycode IDN, or IP literal -- is refused by it.
//
// The bound is needed for the same reason maxRequestIDLen is: r.Host is
// attacker-chosen, server.go sets no MaxHeaderBytes so an over-length value
// arrives whole up to Go's 1 MiB default, and the trace SDK's default
// AttributeValueLengthLimit is -1, unlimited
// (sdk/trace@v1.46.0/span_limits.go:9-11). The span then sits in the batch
// processor's 2048-slot queue across the export window, so the bytes are
// RETAINED rather than freed at end of request -- an unauthenticated caller
// must not get to write unbounded bytes into a buffer with that lifetime.
//
// Kept separate from maxRequestIDLen deliberately: that one is sized to admit
// a W3C traceparent, this one by what a hostname can be. Same hazard,
// different rules over different values; expected to diverge.
const maxServerAddressLen = 253

// serverAddress returns the host without the port, or "" when the host is
// longer than maxServerAddressLen or carries a byte outside printable ASCII.
// semconv defines server.address as the host alone, with server.port a separate
// attribute this design does not emit; r.Host carries both.
//
// An out-of-range host is DROPPED, not truncated or scrubbed, mirroring
// validRequestID: this package does not repair an untrusted value. Truncating
// would also split a multi-byte sequence mid-rune and would leave a
// plausible-looking host that is not the one the client sent.
//
// THE ASCII CHECK IS NOT COSMETIC, and length does not subsume it.
// httpguts.ValidHeaderFieldValue permits 0x80-0xFF, so net/http hands those
// bytes through intact, and an OTLP attribute value is a protobuf `string`
// field -- which google.golang.org/protobuf REFUSES to marshal when it is not
// valid UTF-8 ("string field contains invalid UTF-8", measured directly against
// proto.Marshal of a KeyValue holding "\xff\xfe"). The exporter marshals a
// whole batch at once, so ONE request with a two-byte non-ASCII Host drops
// every span batched with it, and a caller repeating it stops trace export
// process-wide. That is a remote, unauthenticated denial of observability.
//
// The predicate is duplicated from validRequestID rather than extracted, for
// the same reason the two length bounds are separate: a correlation id and a
// hostname have different legitimate alphabets and are expected to diverge.
// They coincide at printable ASCII today by arithmetic, not by a shared rule.
//
// IPv6 is asymmetric here, and deliberately so: net.SplitHostPort splits
// "[2001:db8::1]:8080" into "2001:db8::1" (port AND brackets stripped), but
// "[2001:db8::1]" alone has no port for SplitHostPort to find, so it errors
// and this function returns the bracketed literal UNCHANGED. Both are valid
// server.address values for the same host; verified against net.SplitHostPort
// directly, not assumed.
func serverAddress(host string) string {
	if len(host) > maxServerAddressLen {
		return ""
	}
	for i := range len(host) {
		if host[i] < 0x20 || host[i] > 0x7E {
			return ""
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// knownHTTPMethods is the semconv-known method set, read from the pinned
// go.opentelemetry.io/otel/semconv/v1.43.0/httpconv package's own
// RequestMethod* constants -- NOT hand-typed. That package lists TEN methods,
// not the nine RFC 9110 verbs alone: it also carries QUERY, the
// httpbis-safe-method-w-body draft method semconv's own attribute_group.go
// documents alongside RFC 9110 and RFC 5789 (PATCH) as sources for the
// "known" set (attribute_group.go:7222-7226 in the pinned semconv).
var knownHTTPMethods = map[string]struct{}{
	string(httpconv.RequestMethodConnect): {},
	string(httpconv.RequestMethodDelete):  {},
	string(httpconv.RequestMethodGet):     {},
	string(httpconv.RequestMethodHead):    {},
	string(httpconv.RequestMethodOptions): {},
	string(httpconv.RequestMethodPatch):   {},
	string(httpconv.RequestMethodPost):    {},
	string(httpconv.RequestMethodPut):     {},
	string(httpconv.RequestMethodTrace):   {},
	string(httpconv.RequestMethodQuery):   {},
}

// normalizeMethod maps a method semconv knows to itself, and everything else
// to httpconv.RequestMethodOther ("_OTHER"), per semconv's http.request.method
// definition: "If the HTTP request method is not known to instrumentation, it
// MUST set the http.request.method attribute to _OTHER"
// (attribute_group.go:7228-7229, pinned semconv v1.43.0).
//
// Matching is CASE-SENSITIVE, deliberately: the same definition also states
// "HTTP method names are case-sensitive and http.request.method attribute
// value MUST match a known HTTP method name exactly" (attribute_group.go:
// 7249-7250) -- so "get" is not "GET" and normalizes to _OTHER exactly like
// any other unknown token.
//
// Without this, Go's net/http server accepts any RFC 9110 token as a method
// and hands it straight to the handler: an unauthenticated caller can mint
// one span name and one metric time series per junk verb sent over raw TCP.
// The SDK's default cardinality limit (sdk/metric@v1.46.0's
// defaultCardinalityLimit, 2000 datapoints) turns that into a
// denial-of-telemetry rather than an OOM -- legitimate routes spill into
// otel.metric.overflow once the budget fills, permanently under cumulative
// temporality.
func normalizeMethod(method string) string {
	if _, ok := knownHTTPMethods[method]; ok {
		return method
	}
	return string(httpconv.RequestMethodOther)
}

// Trace starts a server span per request and records its duration.
//
// IT MUST SIT OUTSIDE AccessLog. Trace calls r.WithContext, and any middleware
// doing so between AccessLog and the mux makes the mux annotate a COPY, which
// silently empties r.Pattern on every access-log record (server.go:294-300).
//
// It reads Pattern off the request it passed DOWN, never off its own r. That
// looks like a typo and is not: r is the outer request the mux never touches.
//
// tracer and dur are INJECTED, never read from the OTel globals. Reading
// globals would put process-wide state under the test suite and make these
// tests order-dependent.
func Trace(tracer trace.Tracer, dur metric.Float64Histogram) func(http.Handler) http.Handler {
	prop := propagation.TraceContext{}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := prop.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			// Normalized once, used everywhere r.Method would otherwise feed a
			// cardinality surface (fix round 1, B1): the span name fallback
			// below, the span attribute, and the histogram label. A raw,
			// unauthenticated method must never reach any of the three.
			method := normalizeMethod(r.Method)
			ctx, span := tracer.Start(ctx, "HTTP "+method, trace.WithSpanKind(trace.SpanKindServer))
			defer span.End()

			start := time.Now()
			// The SAME statusRecorder type AccessLog uses. That is load-bearing,
			// not convenience: it implements Unwrap (see its comment), which a
			// WebSocket upgrade walks looking for http.Hijacker. A bespoke
			// writer wrapper without Unwrap 501s every /feed stream.
			rec := &statusRecorder{ResponseWriter: w}

			r2 := r.WithContext(ctx)
			next.ServeHTTP(rec, r2)

			if rec.status == 0 {
				rec.status = http.StatusOK // same defaulting AccessLog applies
			}

			// r2, NEVER r. See the doc comment.
			route := r2.Pattern
			span.SetName(spanName(method, route))

			// attrs holds the THREE attributes the span and the histogram
			// share; server.address is span-only (never on the metric -- the
			// original design's histogram carries method, route, and status
			// only, per TestTrace_HistogramAttributeSet) and is appended just
			// for the span. Built once and sliced, not duplicated: a second
			// hand-typed list is exactly how the _OTHER normalization above
			// could drift between the span and the metric (fix round 1, S1's
			// mutation and the risk B1 raised for the histogram specifically).
			attrs := [4]attribute.KeyValue{
				semconv.HTTPRequestMethodKey.String(method),
				semconv.HTTPRouteKey.String(route),
				semconv.HTTPResponseStatusCodeKey.Int(rec.status),
				semconv.ServerAddressKey.String(serverAddress(r.Host)),
			}
			span.SetAttributes(attrs[:]...)
			if rec.status >= 500 {
				// 4xx is not a server fault: a rejected credential must not mark
				// the span Error.
				span.SetStatus(codes.Error, http.StatusText(rec.status))
			}

			// attrs[:3:3], not attrs[:3]: the full-slice expression caps the
			// capacity at 3 so a future append here cannot silently overwrite
			// server.address at attrs[3] and put an attacker-chosen host on the
			// metric, where the SDK's cardinality limit turns it into a
			// denial-of-telemetry (see normalizeMethod's comment). No append
			// exists yet -- today only statement order protects it, since
			// metric.WithAttributes copies before sorting.
			dur.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs[:3:3]...))
		})
	}
}

// Chain wraps h with mws so that mws[0] is the outermost layer (runs first).
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for _, v := range slices.Backward(mws) {
		h = v(h)
	}
	return h
}
