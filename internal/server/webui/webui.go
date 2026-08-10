// Package webui serves the minimal server-rendered passkey login, register,
// and account pages: three html/template pages plus one vendored JS ceremony
// helper (static/passkey.js), embedded via go:embed and parsed once in New.
// It is a self-contained, additive package — a later task mounts New's
// handler onto the server's mux; this package does not touch server.go.
package webui

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/version"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Deps are the dependencies the web UI handler needs. The service values are the
// SAME instances the JSON API is built with (see internal/server/server.go): the
// two adapters share one service layer, which is the whole point of rendering
// HTML here rather than calling the JSON API over loopback.
type Deps struct {
	Sessions *auth.SessionManager
	Cfg      config.Server
	Log      *slog.Logger

	Devices *service.DeviceService
	Enroll  *service.EnrollmentService
	Admin   *service.AdminService
	Grants  *service.GrantService

	Info      version.Info
	StartedAt time.Time // handler-build time; the /admin/server uptime tile reads it
}

// handler holds the parsed page templates and deps used to render them.
type handler struct {
	pages map[string]*template.Template
	deps  Deps
}

// route pairs a ServeMux pattern with the handler that serves it. The field is
// http.Handler rather than http.HandlerFunc because /static/ is served by
// http.FileServerFS.
type route struct {
	pattern string
	handler http.Handler
}

// New builds the server-rendered web UI and returns it together with every
// pattern it serves. The caller must forward exactly these patterns.
//
// The returned slice and the mux are built from one table, which is what keeps
// them from disagreeing: a route added here is forwarded automatically. When
// they were two separate lists, GET / was registered on this mux but missing
// from the forwarded list, so it 404'd in a browser while the unit tests — which
// drive this mux directly — stayed green.
//
// "GET /{$}" matches ONLY "/". A bare "/" is a prefix match in Go's ServeMux and
// would swallow every unmatched URL, including /api and /agent.
func New(deps Deps) (http.Handler, []string) {
	h := &handler{pages: parsePages(), deps: deps}

	routes := []route{
		{"GET /{$}", http.HandlerFunc(h.handleRoot)},
		{"GET /login", http.HandlerFunc(h.handleLogin)},
		{"GET /register", http.HandlerFunc(h.handleRegister)},
		{"GET /account", h.requireSession(h.handleAccount)},
		{"GET /static/", http.FileServerFS(staticFS)},
	}

	mux := http.NewServeMux()
	patterns := make([]string, 0, len(routes))
	for _, r := range routes {
		mux.Handle(r.pattern, r.handler)
		patterns = append(patterns, r.pattern)
	}
	return mux, patterns
}

// parsePages parses every page template against its shell, once, at
// construction. Each page gets its own parse tree rather than one combined tree
// over templates/*.html: every page defines a "content" block, and
// html/template would let the last-parsed definition silently win.
func parsePages() map[string]*template.Template {
	pages := make(map[string]*template.Template, len(authPages))
	for _, name := range authPages {
		pages[name] = template.Must(template.ParseFS(templateFS,
			"templates/layout.html", "templates/"+name+".html"))
	}
	return pages
}

// authPages are the pre-session pages, rendered in the narrow layout.html shell.
var authPages = []string{"login", "register", "account"}

// handleRoot sends the bare base URL somewhere useful instead of 404ing.
// There is no dashboard yet, so /account is the closest thing to a home
// page; requireSession redirects on to /login when there is no session, so
// this needs no session check of its own.
//
// The "/{$}" pattern matches ONLY the root path — a bare "/" in Go's
// ServeMux is a catch-all prefix and would swallow every unmatched URL,
// turning genuine 404s into redirects.
func (h *handler) handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
