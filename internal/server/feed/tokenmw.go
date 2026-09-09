package feed

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jacaudi/diyddns/internal/store"
)

// Authenticator resolves a presented feed-token plaintext to its live token.
// Satisfied by *service.FeedService; declared here at the consumer so feed
// never imports service. It must return store.ErrNotFound for an unknown or
// revoked token; any other error is a store failure.
type Authenticator interface {
	Authenticate(ctx context.Context, plaintext string) (store.FeedToken, error)
}

type ctxKey int

const tokenIDKey ctxKey = iota

// TokenIDFrom returns the authenticated token id set by TokenMiddleware, or
// "" if none is present in ctx.
func TokenIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(tokenIDKey).(string)
	return id
}

// unauthorizedBody is the ONE body every rejection returns. The reason goes
// to the log, never to the client (#100's door rule).
const unauthorizedBody = `{"error":"unauthorized"}`

// TokenMiddleware authenticates `Authorization: Bearer ddf_…` on every feed
// route (design §3.4). Every rejection is a 401 with the uniform body; the
// reason and route go to one Warn record. The presented value is never
// logged.
func TokenMiddleware(auth Authenticator, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reject := func(reason string) {
				log.LogAttrs(r.Context(), slog.LevelWarn, "feed auth rejected",
					slog.String("reason", reason),
					slog.String("route", r.Pattern))
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(unauthorizedBody))
			}

			header := r.Header.Get("Authorization")
			if header == "" {
				reject("no_token")
				return
			}
			plaintext, ok := strings.CutPrefix(header, "Bearer ")
			if !ok || !strings.HasPrefix(plaintext, store.FeedTokenPrefix) || strings.ContainsAny(plaintext, " \t") {
				reject("malformed")
				return
			}

			tok, err := auth.Authenticate(r.Context(), plaintext)
			switch {
			case err == nil:
			case errors.Is(err, store.ErrNotFound):
				reject("unknown_token")
				return
			case r.Context().Err() != nil, errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
				// The request went away mid-lookup (or the store reported the
				// cancellation): not a store failure, and not worth an operator's
				// attention as one.
				reject("cancelled")
				return
			default:
				reject("store_error")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tokenIDKey, tok.ID)))
		})
	}
}
