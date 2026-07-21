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
	"github.com/jacaudi/diyddns/internal/email"
	"github.com/jacaudi/diyddns/internal/oidc"
	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/server/middleware"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

// oidcDiscoverTimeout bounds the synchronous discovery attempt made at
// startup when OIDC is enabled AND required (fail-closed).
const oidcDiscoverTimeout = 15 * time.Second

const shutdownTimeout = 15 * time.Second

// enrollmentCodeTTL is how long a freshly-minted enrollment code stays valid
// before it must be redeemed. Fixed for Plan 04 — no config key yet.
const enrollmentCodeTTL = 15 * time.Minute

// Server owns the HTTP server lifecycle.
type Server struct {
	httpServer *http.Server
	log        *slog.Logger
	st         *store.Store
	oidcMgr    *oidc.Manager
}

// handler builds the fully-wrapped http.Handler: the mux (health + two huma
// APIs) inside the RequestID → AccessLog → Recover middleware chain, wired to
// the real HMAC verifier, session manager, and service layer. It also
// constructs the OIDC manager and returns it, so New/Run can launch its
// background RetryLoop.
//
// FAILS CLOSED: cfg.Auth.HMAC.SecretKey must decode to a 32-byte AEAD key or
// handler returns an error and builds nothing. A server that can enroll
// devices but can never verify their signed requests is worse than one that
// refuses to start. Likewise, if OIDC is enabled AND required, a failed
// discovery attempt at startup also fails closed.
func handler(cfg config.Server, st *store.Store, log *slog.Logger) (http.Handler, *oidc.Manager, error) {
	key, err := config.DecodeSecretKey(cfg.Auth.HMAC.SecretKey)
	if err != nil {
		return nil, nil, fmt.Errorf("server: %w", err)
	}

	verifier := auth.NewVerifier(st.Devices(), st.Users(), st.ReplayNonces(), key, cfg.Auth.HMAC.SkewWindow, cfg.Auth.HMAC.NonceTTL)
	sessions := auth.NewSessionManager(st.Sessions(), st.Users(), cfg.Auth.Session.TTL, cfg.Auth.Session.SlideWindow)

	audit := service.NewAuditWriter(st)
	authSvc, err := service.NewAuthService(st, sessions, cfg.Auth.Password, audit)
	if err != nil {
		return nil, nil, fmt.Errorf("server: %w", err)
	}

	oidcMgr := oidc.NewManager(cfg.Auth.OIDC, cfg.Server.BaseURL, log)
	if cfg.Auth.OIDC.Enabled && cfg.Auth.OIDC.Required {
		// Fail-closed: an operator who marked OIDC required wants the server to
		// refuse to start if the IdP is unreachable (mirrors the HMAC-key path).
		dctx, cancel := context.WithTimeout(context.Background(), oidcDiscoverTimeout)
		defer cancel()
		if err := oidcMgr.Discover(dctx); err != nil {
			return nil, nil, fmt.Errorf("server: oidc required but discovery failed: %w", err)
		}
	}
	oidcSvc := service.NewOIDCService(st, sessions, cfg.Auth.OIDC, audit, log)

	// passkeys is best-effort: WebAuthn's Relying Party identity can only be
	// resolved once server.base_url is set (or auth.webauthn.rp_id/rp_origin
	// are set explicitly). Until the passkey/bootstrap-claim HTTP routes are
	// wired (a later task), an unresolved RP degrades WebAuthn-dependent
	// features (bootstrap claim, registration grants) to
	// ErrWebAuthnUnavailable rather than failing server startup — avoiding a
	// behavior change for deployments that don't set base_url yet. The
	// eventual fail-closed policy (base_url required whenever passkey login
	// is the only path, with a hide_local_login_ui bypass) belongs to the
	// task that turns those routes on.
	var passkeys *service.PasskeyService
	if rpID, rpOrigin, rerr := cfg.Auth.ResolveWebAuthn(cfg.Server.BaseURL); rerr != nil {
		log.Warn("webauthn relying party unresolved; passkey features unavailable", "err", rerr)
	} else if p, perr := service.NewPasskeyService(st, sessions, key, cfg.Auth.WebAuthn, rpID, rpOrigin, audit); perr != nil {
		return nil, nil, fmt.Errorf("server: %w", perr)
	} else {
		passkeys = p
	}

	mailer := email.New(cfg.Email, log)
	grants := service.NewGrantService(st, passkeys, mailer, cfg.Server.BaseURL, audit, log)

	mux := http.NewServeMux()
	api.Build(mux, api.ServerDeps{
		Log:       log,
		Store:     st,
		Verifier:  verifier,
		Sessions:  sessions,
		Enroll:    service.NewEnrollmentService(st, key, enrollmentCodeTTL, audit),
		Devices:   service.NewDeviceService(st, key, verifier, audit),
		Checkin:   service.NewCheckinService(st, audit),
		Auth:      authSvc,
		Bootstrap: service.NewBootstrapService(st, cfg.Auth.Bootstrap, cfg.Auth.Password, log, audit, nil, passkeys, key),
		OIDC:      oidcSvc,
		Admin:     service.NewAdminService(st, cfg.Auth.Password, audit, grants),
		OIDCMgr:   oidcMgr,
		HMACKey:   key,
		Cfg:       cfg.Auth,
		Info:      version.Current(),
	})
	chain := middleware.Chain(mux,
		middleware.RequestID,
		middleware.AccessLog(log),
		middleware.Recover(log),
	)
	return chain, oidcMgr, nil
}

// Handler builds the fully-wrapped http.Handler (see handler). Exported for
// black-box testing via httptest; the OIDC manager it constructs is only
// needed by New/Run to launch RetryLoop, so this wrapper discards it.
func Handler(cfg config.Server, st *store.Store, log *slog.Logger) (http.Handler, error) {
	h, _, err := handler(cfg, st, log)
	return h, err
}

// New constructs a Server bound to cfg.Server.Listen, wiring the full auth,
// OIDC, and service dependency graph via handler. Returns an error if
// cfg.Auth.HMAC.SecretKey is missing or invalid, or OIDC is required but
// unreachable (fail-closed).
func New(cfg config.Server, st *store.Store, log *slog.Logger) (*Server, error) {
	h, mgr, err := handler(cfg, st, log)
	if err != nil {
		return nil, err
	}
	return &Server{
		httpServer: &http.Server{
			Addr:              cfg.Server.Listen,
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
		},
		log:     log,
		st:      st,
		oidcMgr: mgr,
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
	go s.oidcMgr.RetryLoop(ctx)

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
