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

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// pageNames lists every page New parses at construction. Adding a fourth
// page is an additive change — a new templates/<name>.html plus a
// mux.HandleFunc line in New — the other pages are untouched (no-wall).
var pageNames = []string{"login", "register", "account"}

// Deps are the dependencies the web UI handler needs.
type Deps struct {
	Sessions *auth.SessionManager
	Cfg      config.Server
	Log      *slog.Logger
}

// handler holds the parsed page templates and deps used to render them.
type handler struct {
	pages map[string]*template.Template
	deps  Deps
}

// New builds the server-rendered web UI: GET /login, /register, /account
// (session-guarded), and static assets under /static/. Every page template
// (layout.html + the page's own content block) is parsed once here, not
// per-request.
func New(deps Deps) http.Handler {
	pages := make(map[string]*template.Template, len(pageNames))
	for _, name := range pageNames {
		// Each page gets its own parse tree (layout.html + one page file)
		// rather than one combined tree over templates/*.html: every page
		// defines a "content" block, and html/template would let the last
		// parsed file's "content" definition silently win if all files
		// shared one tree.
		pages[name] = template.Must(template.ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html"))
	}
	h := &handler{pages: pages, deps: deps}

	mux := http.NewServeMux()
	mux.HandleFunc(patternRoot, h.handleRoot)
	mux.HandleFunc(patternLogin, h.handleLogin)
	mux.HandleFunc(patternRegister, h.handleRegister)
	mux.HandleFunc(patternAccount, h.requireSession(h.handleAccount))
	mux.Handle(patternStatic, http.FileServerFS(staticFS))
	return mux
}

// The ServeMux patterns this package serves. patternRoot uses "{$}" so it
// matches ONLY "/" — a bare "/" is a prefix match in Go's ServeMux and would
// swallow every unmatched URL, including /api and /agent.
const (
	patternRoot     = "GET /{$}"
	patternLogin    = "GET /login"
	patternRegister = "GET /register"
	patternAccount  = "GET /account"
	patternStatic   = "GET /static/"
)

// Patterns returns every pattern New's handler serves, so the server that
// mounts it can forward exactly these and no more. Without this the two route
// lists live in separate files and drift: a route added here but not
// forwarded there is simply unreachable, which is how GET / kept 404ing after
// it was added.
func Patterns() []string {
	return []string{patternRoot, patternLogin, patternRegister, patternAccount, patternStatic}
}

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
