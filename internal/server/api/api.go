// Package api builds the diyddns-server HTTP API: two independent huma APIs
// (one per route group, each with its own OpenAPI document and Scalar UI) plus
// the operational health handlers. Business operations and auth are added by
// later plans onto the same mux/APIs.
package api

import (
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/email"
	"github.com/jacaudi/diyddns/internal/oidc"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

// ServerDeps carries every dependency the API operations need: the store and
// logger (always populated), the auth verifier/session manager and the
// service layer (wired by Task 15), and the resolved auth config. Build and
// the register* op functions read from deps rather than taking individual
// parameters, so adding an operation never changes Build's signature.
type ServerDeps struct {
	Log         *slog.Logger
	Store       *store.Store
	Verifier    *auth.Verifier
	Sessions    *auth.SessionManager
	Enroll      *service.EnrollmentService
	Devices     *service.DeviceService
	Checkin     *service.CheckinService
	Auth        *service.AuthService
	Bootstrap   *service.BootstrapService
	OIDC        *service.OIDCService
	Admin       *service.AdminService
	EmailChange *service.EmailChangeService  // unconditionally constructed (server.go) — the self-service and admin-set email-change ops register unconditionally too, like registerDeviceOps, not gated the way Passkey/Grants/Notify below are
	Passkey     *service.PasskeyService      // nil until the WebAuthn Relying Party is resolved (fail-closed, Task 9) — passkey ops are only registered when non-nil, see Build
	Grants      *service.GrantService        // nil alongside Passkey — see Build
	Notify      *service.NotificationService // nil unless notifications.enabled (#152) — the outbound-webhook admin ops are only registered when non-nil, see Build; mirrors the Passkey/Grants nil-tolerant gate
	Mailer      email.Mailer                 // SMTP transport backing GrantService's self-service recovery emails; nil until Task 9 wires it
	OIDCMgr     *oidc.Manager
	HMACKey     []byte // decoded AEAD master key, for sealing the OIDC flow cookie
	Cfg         config.Auth
	Info        version.Info

	Feed        *service.FeedService
	FeedEnabled bool // mirrors cfg.Feed.Enabled; the feed-token REST ops are absent, not just guarded, when off — see Build (issue #153, mirrors webui.go's own feed.enabled gate)

	// APIKeys is unconditionally constructed (server.go) and unconditionally
	// registered below, like EmailChange -- unlike Passkey/Grants/Notify/Feed,
	// there is no config flag that turns account-scoped API keys off (#149).
	APIKeys *service.APIKeyService
}

// Build registers both huma APIs, their operations, and the health handlers
// onto mux.
func Build(mux *http.ServeMux, deps ServerDeps) {
	agentAPI := humago.New(mux, groupConfig("DIYDDNS Agent API", "/agent/v1", deps.Info.Version))
	registerCapabilities(agentAPI, deps)
	registerAgentOps(agentAPI, deps)

	apiAPI := humago.New(mux, groupConfig("DIYDDNS UI API", "/api/v1", deps.Info.Version))
	registerAuthOps(apiAPI, deps)
	registerDeviceOps(apiAPI, deps)
	registerDeviceMgmtOps(apiAPI, deps)
	registerAccountEmailOps(apiAPI, deps)
	registerAPIKeyOps(apiAPI, deps)
	registerAdminOps(apiAPI, deps)
	// Passkey ops depend on BOTH Passkey and Grants being wired (register/begin
	// and /finish drive a grant redeem via Grants; account passkey management
	// drives Passkey directly). Both are nil until the WebAuthn Relying Party
	// is resolved (Task 9) — registering these routes against a nil service
	// would panic the first request, so the whole vertical stays off the mux
	// until construction succeeds, matching Bootstrap/Admin's existing
	// nil-tolerant pattern for their own passkey-dependent paths.
	if deps.Passkey != nil && deps.Grants != nil {
		registerPasskeyOps(apiAPI, deps)
	}
	// The feed-token management routes are absent, not just guarded, when the
	// feed feature is off (design #106 §8.1's route-absence convention,
	// mirrored from webui.go's own deps.Cfg.Feed.Enabled gate).
	if deps.FeedEnabled {
		registerFeedTokenOps(apiAPI, deps)
	}
	// deps.Notify is nil whenever notifications.enabled is false (#152) —
	// same nil-tolerant gate as Passkey/Grants above, so a disabled feature
	// has no REST surface at all, matching the `if deps.Cfg.Notifications.Enabled`
	// block in webui.New instead of merely 403/404ing per request.
	if deps.Notify != nil {
		registerNotificationOps(apiAPI, deps)
	}

	RegisterHealth(mux, deps.Log, deps.Store)
}

// registerAgentOps registers the agent-facing operations (enroll, checkin,
// self) onto agentAPI. Each vertical is isolated in its own file
// (enroll.go, checkin.go) so a future agent op is a new file plus a line
// here, not an edit to an existing one.
func registerAgentOps(a huma.API, deps ServerDeps) {
	registerEnrollOps(a, deps)
	registerCheckinOps(a, deps)
}

// groupConfig returns a huma.Config whose OpenAPI, Docs, and Schemas paths are
// all prefixed under prefix. prefix carries its own /v1 segment (e.g.
// "/api/v1") so these meta paths stay versioned in step with every real
// operation (issue #148) — it is used only here, never to derive an
// operation's own Path, which is a hardcoded literal that already includes
// /v1 in its own registration. Distinct SchemasPath per group is REQUIRED:
// both APIs share one ServeMux, and two APIs left at the default "/schemas"
// would register the same route twice and panic the mux.
func groupConfig(title, prefix, ver string) huma.Config {
	cfg := huma.DefaultConfig(title, ver)
	cfg.OpenAPIPath = prefix + "/openapi"
	cfg.DocsPath = prefix + "/docs"
	cfg.SchemasPath = prefix + "/schemas"
	cfg.DocsRenderer = huma.DocsRendererScalar
	return cfg
}
