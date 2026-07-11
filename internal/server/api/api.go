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

	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

// Build registers both huma APIs and the health handlers onto mux.
func Build(mux *http.ServeMux, log *slog.Logger, st *store.Store, info version.Info) {
	agentAPI := humago.New(mux, groupConfig("DIYDDNS Agent API", "/agent", info.Version))
	registerCapabilities(agentAPI, info)

	// UI-facing API: no operations yet (added by later plans). Registering it
	// now serves an (empty) /api/openapi.json + Scalar docs and reserves the
	// route-group seam.
	humago.New(mux, groupConfig("DIYDDNS UI API", "/api", info.Version))

	RegisterHealth(mux, log, st)
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
