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
	Log       *slog.Logger
	Store     *store.Store
	Verifier  *auth.Verifier
	Sessions  *auth.SessionManager
	Enroll    *service.EnrollmentService
	Devices   *service.DeviceService
	Checkin   *service.CheckinService
	Auth      *service.AuthService
	Bootstrap *service.BootstrapService
	OIDC      *service.OIDCService
	Admin     *service.AdminService
	Passkey   *service.PasskeyService // nil until the WebAuthn Relying Party is resolved (fail-closed, Task 9) — passkey ops are only registered when non-nil, see Build
	Grants    *service.GrantService   // nil alongside Passkey — see Build
	Mailer    email.Mailer            // SMTP transport backing GrantService's self-service recovery emails; nil until Task 9 wires it
	OIDCMgr   *oidc.Manager
	HMACKey   []byte // decoded AEAD master key, for sealing the OIDC flow cookie
	Cfg       config.Auth
	Info      version.Info
}

// Build registers both huma APIs, their operations, and the health handlers
// onto mux.
func Build(mux *http.ServeMux, deps ServerDeps) {
	agentAPI := humago.New(mux, groupConfig("DIYDDNS Agent API", "/agent", deps.Info.Version))
	registerCapabilities(agentAPI, deps)
	registerAgentOps(agentAPI, deps)

	apiAPI := humago.New(mux, groupConfig("DIYDDNS UI API", "/api", deps.Info.Version))
	registerAuthOps(apiAPI, deps)
	registerDeviceOps(apiAPI, deps)
	registerDeviceMgmtOps(apiAPI, deps)
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
// all prefixed under prefix. Distinct SchemasPath per group is REQUIRED: both
// APIs share one ServeMux, and two APIs left at the default "/schemas" would
// register the same route twice and panic the mux.
func groupConfig(title, prefix, ver string) huma.Config {
	cfg := huma.DefaultConfig(title, ver)
	cfg.OpenAPIPath = prefix + "/openapi"
	cfg.DocsPath = prefix + "/docs"
	cfg.SchemasPath = prefix + "/schemas"
	cfg.DocsRenderer = huma.DocsRendererScalar
	return cfg
}
