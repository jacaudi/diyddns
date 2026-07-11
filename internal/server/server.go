// Package server assembles the diyddns-server HTTP stack (mux + middleware +
// huma APIs) and owns its lifecycle (listen + graceful shutdown).
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/server/middleware"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

const shutdownTimeout = 15 * time.Second

// Server owns the HTTP server lifecycle.
type Server struct {
	httpServer *http.Server
	log        *slog.Logger
}

// Handler builds the fully-wrapped http.Handler: the mux (health + two huma
// APIs) inside the RequestID → AccessLog → Recover middleware chain. Exported
// for black-box testing via httptest.
func Handler(log *slog.Logger, st *store.Store) http.Handler {
	mux := http.NewServeMux()
	api.Build(mux, log, st, version.Current())
	return middleware.Chain(mux,
		middleware.RequestID,
		middleware.AccessLog(log),
		middleware.Recover(log),
	)
}

// New constructs a Server bound to cfg.Server.Listen.
func New(cfg config.Server, st *store.Store, log *slog.Logger) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:              cfg.Server.Listen,
			Handler:           Handler(log, st),
			ReadHeaderTimeout: 10 * time.Second,
		},
		log: log,
	}
}

// Run starts the listener and blocks until ctx is cancelled, then gracefully
// drains in-flight requests. Returns nil on a clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.LogAttrs(ctx, slog.LevelInfo, "server listening", slog.String("addr", s.httpServer.Addr))
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("server: listen: %w", err)
	case <-ctx.Done():
		s.log.LogAttrs(ctx, slog.LevelInfo, "server shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server: shutdown: %w", err)
		}
		return nil
	}
}
