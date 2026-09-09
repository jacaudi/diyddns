// Package server assembles the diyddns-server HTTP stack (mux + middleware +
// huma APIs) and owns its lifecycle (listen + graceful shutdown).
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/email"
	"github.com/jacaudi/diyddns/internal/oidc"
	"github.com/jacaudi/diyddns/internal/server/api"
	"github.com/jacaudi/diyddns/internal/server/feed"
	"github.com/jacaudi/diyddns/internal/server/middleware"
	"github.com/jacaudi/diyddns/internal/server/notify"
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
	notifier   *notify.Worker // nil when notifications are disabled
	hub        *feed.Hub      // always non-nil; closes live streams on shutdown
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
func buildMux(cfg config.Server, st *store.Store, log *slog.Logger) (*http.ServeMux, *oidc.Manager, api.ServerDeps, webui.Deps, []netip.Prefix, *feed.Hub, error) {
	key, err := config.DecodeSecretKey(cfg.Auth.HMAC.SecretKey)
	if err != nil {
		return nil, nil, api.ServerDeps{}, webui.Deps{}, nil, nil, fmt.Errorf("server: %w", err)
	}

	// A warning, not a fail-closed: the operator may be terminating TLS in
	// front of a base_url that does not say so. But if they are not, every
	// login silently loses its cookie and the UI blames the account (#39), so
	// say it at boot where it can still be acted on.
	if w := config.InsecureCookieWarning(cfg); w != "" {
		log.LogAttrs(context.Background(), slog.LevelWarn, w)
	}
	// Same rationale as InsecureCookieWarning immediately above: a broad
	// allowed_private_cidrs entry is a valid operator choice, not a startup
	// failure, but it re-opens a whole address family and deserves saying so
	// where it can still be acted on.
	if w := config.NotificationsEgressWarning(cfg); w != "" {
		log.LogAttrs(context.Background(), slog.LevelWarn, w)
	}

	// config.validateNotifications already rejected malformed entries at
	// startup; this is belt-and-braces on the same values, and fails closed
	// the same way the HMAC-key and required-OIDC checks above do.
	// service.NewNotificationService (below) is the consumer of the parsed
	// prefixes.
	allowedPrivateCIDRs, err := notify.ParseAllowed(cfg.Notifications.AllowedPrivateCIDRs)
	if err != nil {
		return nil, nil, api.ServerDeps{}, webui.Deps{}, nil, nil, err
	}

	hub, notifier, devNotifier := buildFanout(cfg, st, log)

	// Retention deletes user-visible history irreversibly and is opt-in, so say
	// at boot that it is on and with what windows. This is the cheapest safety
	// net there is: it makes a first sweep attributable after the fact instead
	// of a mystery, and it costs nothing on the default (all-zero) config.
	if cfg.Retention != (config.RetentionSection{}) {
		log.LogAttrs(context.Background(), slog.LevelWarn, "retention enabled: matching rows will be permanently deleted",
			slog.Int("ip_history_days", cfg.Retention.IPHistoryDays),
			slog.Int("ip_history_per_device_max", cfg.Retention.IPHistoryPerDeviceMax),
			slog.Int("audit_log_days", cfg.Retention.AuditLogDays),
		)
	}

	verifier := auth.NewVerifier(st.Devices(), st.Users(), st.ReplayNonces(), key, cfg.Auth.HMAC.SkewWindow, cfg.Auth.HMAC.NonceTTL)
	sessions := auth.NewSessionManager(st.Sessions(), st.Users(), cfg.Auth.Session.TTL, cfg.Auth.Session.SlideWindow)

	audit := service.NewAuditWriter(st)
	authSvc := service.NewAuthService(sessions, audit)
	notifySvc := service.NewNotificationService(st, key, allowedPrivateCIDRs, audit)
	feedSvc := service.NewFeedService(st, hub, audit)

	oidcMgr := oidc.NewManager(cfg.Auth.OIDC, cfg.Server.BaseURL, log)
	if cfg.Auth.OIDC.Enabled && cfg.Auth.OIDC.Required {
		// Fail-closed: an operator who marked OIDC required wants the server to
		// refuse to start if the IdP is unreachable (mirrors the HMAC-key path).
		dctx, cancel := context.WithTimeout(context.Background(), oidcDiscoverTimeout)
		defer cancel()
		if err := oidcMgr.Discover(dctx); err != nil {
			return nil, nil, api.ServerDeps{}, webui.Deps{}, nil, nil, fmt.Errorf("server: oidc required but discovery failed: %w", err)
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
			return nil, nil, api.ServerDeps{}, webui.Deps{}, nil, nil, fmt.Errorf("server: %w", rpErr)
		}
	} else {
		passkeySvc, err = service.NewPasskeyService(st, sessions, key, cfg.Auth.WebAuthn, rpID, rpOrigin, audit, log)
		if err != nil {
			return nil, nil, api.ServerDeps{}, webui.Deps{}, nil, nil, fmt.Errorf("server: %w", err)
		}
	}

	mailer := email.New(cfg.Email, log)
	grantSvc := service.NewGrantService(st, passkeySvc, mailer, cfg.Server.BaseURL, audit, log)

	// One construction site per service. api.Build and webui.New receive the
	// same instances: they are two thin presentation layers over one service
	// layer, and a dependency added to a service later must not silently exist
	// twice.
	devicesSvc := service.NewDeviceService(st, key, verifier, audit, devNotifier)
	enrollSvc := service.NewEnrollmentService(st, key, enrollmentCodeTTL, audit)
	adminSvc := service.NewAdminService(st, audit, grantSvc, devNotifier)

	mux := http.NewServeMux()
	apiDeps := api.ServerDeps{
		Log:       log,
		Store:     st,
		Verifier:  verifier,
		Sessions:  sessions,
		Enroll:    enrollSvc,
		Devices:   devicesSvc,
		Checkin:   service.NewCheckinService(st, notifier),
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
		Notify:    notifySvc,
		Feed:      feedSvc,
		Info:      version.Current(),
		StartedAt: time.Now(),
	}
	webHandler, webPatterns := webui.New(webDeps)
	for _, pattern := range webPatterns {
		mux.Handle(pattern, webHandler)
	}

	registerFeed(mux, cfg, st, feedSvc, hub, log)

	return mux, oidcMgr, apiDeps, webDeps, allowedPrivateCIDRs, hub, nil
}

// buildFanout constructs the stream hub and the two notifier seams buildMux
// hands to the service layer. The hub is ALWAYS constructed (design §5.3):
// with the feed off no route registers against it and Broadcast finds no
// subscribers, so nothing downstream needs a nil check. The fan-out is wired
// when EITHER transport is on; with both off the nop notifiers keep check-in
// and the admin seams free of side effects.
func buildFanout(cfg config.Server, st *store.Store, log *slog.Logger) (*feed.Hub, service.Notifier, service.DeviceNotifier) {
	hub := feed.New()
	var (
		notifier    service.Notifier       = service.NopNotifier{}
		devNotifier service.DeviceNotifier = service.NopDeviceNotifier{}
	)
	if cfg.Notifications.Enabled || cfg.Feed.Enabled {
		var enqueuer *notify.Enqueuer
		if cfg.Notifications.Enabled {
			enqueuer = notify.NewEnqueuer(st, log)
		}
		fo := newFanout(st, enqueuer, hub, log)
		notifier, devNotifier = fo, fo
	}
	return hub, notifier, devNotifier
}

// registerFeed mounts the feed route group. The group is absent, not guarded,
// when the feed is off — the same rule the notification routes follow in
// webui.New. The Authenticator parameter is named feedAuth, not auth: revive's
// import-shadowing rule rejects a parameter that shadows the `auth` import.
func registerFeed(mux *http.ServeMux, cfg config.Server, st *store.Store, feedAuth feed.Authenticator, hub *feed.Hub, log *slog.Logger) {
	if !cfg.Feed.Enabled {
		return
	}
	feed.Register(mux, feed.Deps{Store: st, Auth: feedAuth, Hub: hub, Log: log})
	log.LogAttrs(context.Background(), slog.LevelInfo, "feed enabled")
}

// handler builds the fully-wrapped handler: buildMux's ServeMux inside the
// RequestID → AccessLog → Recover middleware chain. It also returns the OIDC
// manager buildMux constructs, so New/Run can launch its background
// RetryLoop.
func handler(cfg config.Server, st *store.Store, log *slog.Logger) (http.Handler, *oidc.Manager, []netip.Prefix, *feed.Hub, error) {
	mux, oidcMgr, _, _, allowedPrivateCIDRs, hub, err := buildMux(cfg, st, log)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// This order is load-bearing, not stylistic. AccessLog reads r.Pattern
	// AFTER next.ServeHTTP returns, and that works only because
	// ServeMux.ServeHTTP sets Pattern on the very *http.Request the caller
	// handed it. Insert any middleware between AccessLog and mux that calls
	// r.WithContext or r.Clone and the mux annotates a copy instead: route
	// silently goes empty on every access-log record, with nothing failing.
	// (Recover is safe here precisely because it forwards r untouched.)
	return middleware.Chain(mux,
		middleware.RequestID(cfg.Observability.RequestIDHeader),
		middleware.AccessLog(log),
		middleware.Recover(log),
	), oidcMgr, allowedPrivateCIDRs, hub, nil
}

// Handler builds the fully-wrapped http.Handler (see handler) and returns the
// stream hub beside it. Exported for black-box testing via httptest: the hub
// lets a test revoke a token's streams or drive Shutdown, which no HTTP
// route can. The OIDC manager is only needed by New/Run, so this discards it.
func Handler(cfg config.Server, st *store.Store, log *slog.Logger) (http.Handler, *feed.Hub, error) {
	h, _, _, hub, err := handler(cfg, st, log)
	return h, hub, err
}

// New constructs a Server bound to cfg.Server.Listen, wiring the full auth,
// OIDC, and service dependency graph via handler. Returns an error if
// cfg.Auth.HMAC.SecretKey is missing or invalid, or OIDC is required but
// unreachable (fail-closed).
func New(cfg config.Server, st *store.Store, log *slog.Logger) (*Server, error) {
	// allowedPrivateCIDRs is parsed once inside handler->buildMux and returned
	// here rather than re-parsed: commit 74930fa claimed this reuse without
	// actually doing it (New called notify.ParseAllowed a second time on the
	// same config value), so this is now the genuine single call.
	h, mgr, allowedPrivateCIDRs, hub, err := handler(cfg, st, log)
	if err != nil {
		return nil, err
	}

	var notifier *notify.Worker
	if cfg.Notifications.Enabled {
		key, err := config.DecodeSecretKey(cfg.Auth.HMAC.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("server: %w", err)
		}
		clients := notify.NewClients(allowedPrivateCIDRs, cfg.Notifications.Timeout)
		// rand.Float64 here is math/rand/v2, not the legacy math/rand gosec's
		// G404 flags: it needs no seeding and jitter timing is not
		// security-sensitive regardless (see poller.go's defaultRandFloat).
		notifier = notify.NewWorker(st, clients, key, cfg.Notifications.MaxAttempts,
			service.NewAuditWriter(st), rand.Float64, log)
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
		notifier:  notifier,
		hub:       hub,
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
	if s.notifier != nil {
		go s.notifier.Run(ctx)
	}

	select {
	case err := <-errCh:
		return fmt.Errorf("server: listen: %w", err)
	case <-ctx.Done():
		s.log.LogAttrs(ctx, slog.LevelInfo, "server shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		// http.Server.Shutdown ignores hijacked connections, so the hub's
		// shutdown is the only thing that closes live streams. The two run
		// concurrently and BOTH are waited for; an error from either is
		// collected, not returned early.
		hubErr := make(chan error, 1)
		go func() { hubErr <- s.hub.Shutdown(shutdownCtx) }()
		httpErr := s.httpServer.Shutdown(shutdownCtx)
		if err := <-hubErr; err != nil {
			s.log.LogAttrs(ctx, slog.LevelWarn, "feed hub shutdown incomplete", slog.Any("error", err))
		}
		if httpErr != nil {
			return fmt.Errorf("server: shutdown: %w", httpErr)
		}
		return nil
	}
}
