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

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/server/middleware"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

const shutdownTimeout = 15 * time.Second

// enrollmentCodeTTL is how long a freshly-minted enrollment code stays valid
// before it must be redeemed. Fixed for Plan 04 — no config key yet.
const enrollmentCodeTTL = 15 * time.Minute

// Server owns the HTTP server lifecycle.
type Server struct {
	httpServer *http.Server
	log        *slog.Logger
	st         *store.Store
}

// Handler builds the fully-wrapped http.Handler: the mux (health + two huma
// APIs) inside the RequestID → AccessLog → Recover middleware chain, wired to
// the real HMAC verifier, session manager, and service layer. Exported for
// black-box testing via httptest.
//
// FAILS CLOSED: cfg.Auth.HMAC.SecretKey must decode to a 32-byte AEAD key or
// Handler returns an error and builds nothing. A server that can enroll
// devices but can never verify their signed requests is worse than one that
// refuses to start.
func Handler(cfg config.Server, st *store.Store, log *slog.Logger) (http.Handler, error) {
	key, err := config.DecodeSecretKey(cfg.Auth.HMAC.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}

	verifier := auth.NewVerifier(st.Devices(), st.Users(), st.ReplayNonces(), key, cfg.Auth.HMAC.SkewWindow, cfg.Auth.HMAC.NonceTTL)
	sessions := auth.NewSessionManager(st.Sessions(), st.Users(), cfg.Auth.Session.TTL, cfg.Auth.Session.SlideWindow)

	audit := service.NewAuditWriter(st)
	authSvc, err := service.NewAuthService(st, sessions, cfg.Auth.Password, audit)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}

	mux := http.NewServeMux()
	api.Build(mux, api.ServerDeps{
		Log:       log,
		Store:     st,
		Verifier:  verifier,
		Sessions:  sessions,
		Enroll:    service.NewEnrollmentService(st, key, enrollmentCodeTTL, audit),
		Devices:   service.NewDeviceService(st),
		Checkin:   service.NewCheckinService(st, audit),
		Auth:      authSvc,
		Bootstrap: service.NewBootstrapService(st, cfg.Auth.Bootstrap, cfg.Auth.Password, log, audit, nil),
		Cfg:       cfg.Auth,
		Info:      version.Current(),
	})
	return middleware.Chain(mux,
		middleware.RequestID,
		middleware.AccessLog(log),
		middleware.Recover(log),
	), nil
}

// New constructs a Server bound to cfg.Server.Listen, wiring the full auth
// and service dependency graph via Handler. Returns an error if
// cfg.Auth.HMAC.SecretKey is missing or invalid (fail-closed).
func New(cfg config.Server, st *store.Store, log *slog.Logger) (*Server, error) {
	handler, err := Handler(cfg, st, log)
	if err != nil {
		return nil, err
	}
	return &Server{
		httpServer: &http.Server{
			Addr:              cfg.Server.Listen,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		},
		log: log,
		st:  st,
	}, nil
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
	go runPruner(ctx, s.st, s.log)

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
