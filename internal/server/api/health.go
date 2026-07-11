package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

// RegisterHealth wires the operational health endpoints onto mux. They are
// plain handlers, deliberately outside both OpenAPI documents (plaintext,
// operational, not part of the API contract).
func RegisterHealth(mux *http.ServeMux, log *slog.Logger, st *store.Store) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if err := st.DB().PingContext(ctx); err != nil {
			log.LogAttrs(r.Context(), slog.LevelWarn, "readiness check failed", slog.Any("error", err))
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
			return
		}
		_, _ = w.Write([]byte("ready"))
	})
}
