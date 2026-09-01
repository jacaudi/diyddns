// Package middleware provides the cross-cutting net/http middleware wrapped
// around the diyddns-server mux: request-id assignment, structured access
// logging, and panic recovery. Auth middleware (HMAC, session/CSRF) is added by
// later plans and is intentionally absent here.
package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
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
// Printable-ASCII is what keeps the value safe to embed in every log record it
// now reaches: a control byte would let an unauthenticated caller inject a
// newline (a forged second record in a line-oriented log) or a NUL.
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
				if v7, err := uuid.NewV7(); err == nil {
					id = v7.String()
				} else {
					id = uuid.NewString()
				}
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

// Chain wraps h with mws so that mws[0] is the outermost layer (runs first).
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for _, v := range slices.Backward(mws) {
		h = v(h)
	}
	return h
}
