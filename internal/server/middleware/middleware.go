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

// RequestIDHeader is the request/response header carrying the correlation id.
const RequestIDHeader = "X-Request-Id"

type ctxKey int

const requestIDKey ctxKey = iota

// RequestIDFromContext returns the request id stored by RequestID, or "".
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// RequestID assigns each request a correlation id: it honors an incoming
// X-Request-Id, otherwise generates a UUIDv7. The id is placed in the request
// context and echoed in the response header.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if id == "" {
			if v7, err := uuid.NewV7(); err == nil {
				id = v7.String()
			} else {
				id = uuid.NewString()
			}
		}
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
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
				slog.String("request_id", RequestIDFromContext(r.Context())),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
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
						slog.String("request_id", RequestIDFromContext(r.Context())),
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
