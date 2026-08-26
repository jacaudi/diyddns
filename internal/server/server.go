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
	"github.com/jacaudi/diyddns/internal/server/webui"
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
	retention  config.RetentionSection
}

// buildMux assembles the outer ServeMux — the JSON API, the agent routes, the
// health endpoints, and the forwarded web UI patterns — along with the whole
// service dependency graph they need. handler wraps the result in middleware;
// tests call this directly to inspect route resolution, which a wrapped
// http.Handler does not permit.
//
// It returns the OIDC manager because only New/Run need it, to launch
// RetryLoop; nothing in the mux itself does.
//
// It also returns the api.ServerDeps and webui.Deps it built, so tests can
// prove the two adapters share one instance per service rather than each
// building its own (see webui.Deps's doc comment and the "One construction
// site per service" comment below) — production callers (handler) discard
// them.
//
// FAILS CLOSED: cfg.Auth.HMAC.SecretKey must decode to a 32-byte AEAD key or
// buildMux returns an error and builds nothing. A server that can enroll
// devices but can never verify their signed requests is worse than one that
// refuses to start. Likewise, if OIDC is enabled AND required, a failed
// discovery attempt at startup also fails closed.
func buildMux(cfg config.Server, st *store.Store, log *slog.Logger) (*http.ServeMux, *oidc.Manager, api.ServerDeps, webui.Deps, error) {
	key, err := config.DecodeSecretKey(cfg.Auth.HMAC.SecretKey)
	if err != nil {
		return nil, nil, api.ServerDeps{}, webui.Deps{}, fmt.Errorf("server: %w", err)
	}

	// A warning, not a fail-closed: the operator may be terminating TLS in
	// front of a base_url that does not say so. But if they are not, every
	// login silently loses its cookie and the UI blames the account (#39), so
	// say it at boot where it can still be acted on.
	if w := config.InsecureCookieWarning(cfg); w != "" {
		log.LogAttrs(context.Background(), slog.LevelWarn, w)
	}

	verifier := auth.NewVerifier(st.Devices(), st.Users(), st.ReplayNonces(), key, cfg.Auth.HMAC.SkewWindow, cfg.Auth.HMAC.NonceTTL)
	sessions := auth.NewSessionManager(st.Sessions(), st.Users(), cfg.Auth.Session.TTL, cfg.Auth.Session.SlideWindow)

	audit := service.NewAuditWriter(st)
	authSvc := service.NewAuthService(sessions, audit)

	oidcMgr := oidc.NewManager(cfg.Auth.OIDC, cfg.Server.BaseURL, log)
	if cfg.Auth.OIDC.Enabled && cfg.Auth.OIDC.Required {
		// Fail-closed: an operator who marked OIDC required wants the server to
		// refuse to start if the IdP is unreachable (mirrors the HMAC-key path).
		dctx, cancel := context.WithTimeout(context.Background(), oidcDiscoverTimeout)
		defer cancel()
		if err := oidcMgr.Discover(dctx); err != nil {
			return nil, nil, api.ServerDeps{}, webui.Deps{}, fmt.Errorf("server: oidc required but discovery failed: %w", err)
		}
	}
	oidcSvc := service.NewOIDCService(st, sessions, cfg.Auth.OIDC, audit, log)

	// Passkey login is the default local credential and is always available
	// unless auth.hide_local_login_ui is set — there is no separate
	// auth.webauthn.enabled toggle (design §10). Resolving the WebAuthn
	// Relying Party from server.base_url can fail (no base_url and no
	// explicit auth.webauthn.rp_origin); when passkey login is available that
	// failure FAILS CLOSED, mirroring the HMAC-key and required-OIDC paths
	// above — a server that advertises "sign in with a passkey" but can never
	// verify the ceremony is worse than one that refuses to start. When
	// hide_local_login_ui is set, an unresolved RP is tolerable: there is no
	// passkey login to serve, so PasskeyService is simply left nil (deps.
	// Passkey==nil already keeps the passkey routes off the mux, see
	// api.Build).
	var passkeySvc *service.PasskeyService
	rpID, rpOrigin, rpErr := cfg.Auth.ResolveWebAuthn(cfg.Server.BaseURL)
	if rpErr != nil {
		if !cfg.Auth.HideLocalLoginUI {
			return nil, nil, api.ServerDeps{}, webui.Deps{}, fmt.Errorf("server: %w", rpErr)
		}
	} else {
		passkeySvc, err = service.NewPasskeyService(st, sessions, key, cfg.Auth.WebAuthn, rpID, rpOrigin, audit, log)
		if err != nil {
			return nil, nil, api.ServerDeps{}, webui.Deps{}, fmt.Errorf("server: %w", err)
		}
	}

	mailer := email.New(cfg.Email, log)
	grantSvc := service.NewGrantService(st, passkeySvc, mailer, cfg.Server.BaseURL, audit, log)

	// One construction site per service. api.Build and webui.New receive the
	// same instances: they are two thin presentation layers over one service
	// layer, and a dependency added to a service later must not silently exist
	// twice.
	devicesSvc := service.NewDeviceService(st, key, verifier, audit)
	enrollSvc := service.NewEnrollmentService(st, key, enrollmentCodeTTL, audit)
	adminSvc := service.NewAdminService(st, audit, grantSvc)

	mux := http.NewServeMux()
	apiDeps := api.ServerDeps{
		Log:       log,
		Store:     st,
		Verifier:  verifier,
		Sessions:  sessions,
		Enroll:    enrollSvc,
		Devices:   devicesSvc,
		Checkin:   service.NewCheckinService(st, audit),
		Auth:      authSvc,
		Bootstrap: service.NewBootstrapService(st, log, audit, nil, passkeySvc, key),
		OIDC:      oidcSvc,
		Admin:     adminSvc,
		Passkey:   passkeySvc,
		Grants:    grantSvc,
		Mailer:    mailer,
		OIDCMgr:   oidcMgr,
		HMACKey:   key,
		Cfg:       cfg.Auth,
		Info:      version.Current(),
	}
	api.Build(mux, apiDeps)

	// The web UI's own mux already declares "GET /login" etc. as its route
	// patterns; mounting the same patterns on the outer mux forwards matching
	// requests straight into it. Distinct prefixes from /api, /agent,
	// /healthz, /readyz — no collision.
	// Every pattern the webui mux serves must ALSO be forwarded here, or the
	// inner route is unreachable — the two lists are the same knowledge in
	// two places, so webui.New's returned pattern slice is the single source
	// and this loop copies it rather than restating it. (A "/" catch-all
	// instead would swallow unmatched /api and /agent URLs.)
	webDeps := webui.Deps{
		Sessions:  sessions,
		Cfg:       cfg,
		Log:       log,
		Devices:   devicesSvc,
		Enroll:    enrollSvc,
		Admin:     adminSvc,
		Grants:    grantSvc,
		Info:      version.Current(),
		StartedAt: time.Now(),
	}
	webHandler, webPatterns := webui.New(webDeps)
	for _, pattern := range webPatterns {
		mux.Handle(pattern, webHandler)
	}

	return mux, oidcMgr, apiDeps, webDeps, nil
}

// handler builds the fully-wrapped handler: buildMux's ServeMux inside the
// RequestID → AccessLog → Recover middleware chain. It also returns the OIDC
// manager buildMux constructs, so New/Run can launch its background
// RetryLoop.
func handler(cfg config.Server, st *store.Store, log *slog.Logger) (http.Handler, *oidc.Manager, error) {
	mux, oidcMgr, _, _, err := buildMux(cfg, st, log)
	if err != nil {
		return nil, nil, err
	}
	return middleware.Chain(mux,
		middleware.RequestID,
		middleware.AccessLog(log),
		middleware.Recover(log),
	), oidcMgr, nil
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
		log:       log,
		st:        st,
		oidcMgr:   mgr,
		retention: cfg.Retention,
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
	go runPruner(ctx, s.st, s.retention, s.log)
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
