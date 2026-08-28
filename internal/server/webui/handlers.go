package webui

import (
	"bytes"
	"log/slog"
	"net/http"

	"github.com/jacaudi/diyddns/internal/store"
)

// pageData is embedded in every page's template data. It carries the
// session-scoped CSRF token layout.html renders into a shared
// <meta name="csrf"> tag (design §9/N2's shared browser-auth contract): "" on
// the pre-session login/register pages unless a still-valid session cookie
// happens to be present, always populated on the session-guarded account
// page.
type pageData struct {
	CSRFToken string
}

// appData is embedded in every app-shell page's template data. It carries what
// the topbar renders plus the CSRF token every form needs.
type appData struct {
	pageData
	Title    string
	Nav      string // "devices" | "account" | "admin-users" | "admin-audit" | "admin-server"
	Email    string
	Initials string
	IsAdmin  bool
}

// newAppData builds the shell data for a page rendered to an authenticated user.
func (h *handler) newAppData(usr store.User, sess store.Session, title, nav string) appData {
	return appData{
		pageData: pageData{CSRFToken: sess.CSRFToken},
		Title:    title,
		Nav:      nav,
		Email:    usr.Email,
		Initials: initials(usr.Email),
		IsAdmin:  usr.Role == "admin",
	}
}

// errorData is error.html's template data. LinkText/LinkURL are the optional
// caller-supplied action; the page always offers "Back to devices" beside it.
type errorData struct {
	appData
	Status   int
	Message  string
	LinkText string
	LinkURL  string
}

// renderError renders the shared error page. Callers pass a message safe to show
// a user: internal detail belongs in the log, never on the page.
//
// The zero store.User is acceptable — the shell simply renders an empty user
// chip — so guards can call this before a user is resolved.
func (h *handler) renderError(w http.ResponseWriter, r *http.Request, usr store.User, status int, message string) {
	h.renderErrorLink(w, r, usr, status, message, "", "")
}

// renderErrorLink is renderError with an extra action, for the failure whose
// message names somewhere specific to go. A message that says "start from the
// first page" while the page only offers "Back to devices" is telling the user
// to go somewhere it does not take them.
func (h *handler) renderErrorLink(w http.ResponseWriter, r *http.Request, usr store.User, status int, message, linkText, linkURL string) {
	h.renderStatus(w, r, status, "error", errorData{
		appData:  h.newAppData(usr, store.Session{}, http.StatusText(status), ""),
		Status:   status,
		Message:  message,
		LinkText: linkText,
		LinkURL:  linkURL,
	})
}

// render executes the named page's parsed template ("layout" wrapping the
// page's own "content" block) with data into a buffer first, so a template
// execution failure never leaves a half-written response with headers already
// sent.
//
// Every rendered page is no-store: back-button-after-logout must not re-render
// a device list, an audit log, or the CSRF token in <meta> out of the
// browser's history cache. The one-time reveals depend on it most, but
// nothing is special-cased — a default nobody has to remember beats three
// call sites somebody will forget.
func (h *handler) render(w http.ResponseWriter, r *http.Request, page string, data any) {
	h.renderStatus(w, r, http.StatusOK, page, data)
}

// renderStatus is render with an explicit status code, for the error page and
// for form re-renders that must answer 422 rather than 200.
func (h *handler) renderStatus(w http.ResponseWriter, r *http.Request, status int, page string, data any) {
	tmpl, ok := h.pages[page]
	if !ok {
		// A page missing from authPages/appPages is a wiring mistake, not a
		// runtime condition. Fail with a logged error rather than a nil-map
		// dereference panic — each screen task has to remember to add its
		// entry, so make forgetting legible.
		h.deps.Log.LogAttrs(r.Context(), slog.LevelError, "webui: unknown page", slog.String("page", page))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		h.deps.Log.LogAttrs(r.Context(), slog.LevelError, "webui: render failed",
			slog.String("page", page), slog.Any("error", err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// handleRoot sends the bare base URL somewhere useful instead of 404ing:
// /devices for a signed-in user, /login otherwise.
//
// The "GET /{$}" pattern matches ONLY the root path — a bare "/" in Go's
// ServeMux is a catch-all prefix and would swallow every unmatched URL,
// turning genuine 404s into redirects.
func (h *handler) handleRoot(w http.ResponseWriter, r *http.Request) {
	if _, _, err := authenticateBrowser(h.deps.Sessions, r, h.deps.Cfg.Auth.Session.CookieName); err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

// loginData is login.html's template data.
type loginData struct {
	pageData
	ShowPasskey bool // false under auth.hide_local_login_ui (D14)
	ShowOIDC    bool // true under auth.oidc.enabled
	ShowRecover bool // true under email.enabled ("Lost your passkey?")
}

// handleLogin renders /login. It always returns 200 — hide_local_login_ui
// only omits the passkey block, it never takes the route down, since OIDC
// may still be the only way in.
func (h *handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	data := loginData{
		ShowPasskey: !h.deps.Cfg.Auth.HideLocalLoginUI,
		ShowOIDC:    h.deps.Cfg.Auth.OIDC.Enabled,
		ShowRecover: h.deps.Cfg.Email.Enabled,
	}
	// A still-valid session cookie is uncommon on /login (mainly: the user
	// navigated back after signing in) but when present it lets the
	// recovery-request form carry a real CSRF token instead of "".
	if _, sess, err := authenticateBrowser(h.deps.Sessions, r, h.deps.Cfg.Auth.Session.CookieName); err == nil {
		data.CSRFToken = sess.CSRFToken
	}
	h.render(w, r, "login", data)
}

// registerData is register.html's template data.
type registerData struct {
	pageData
	Token string // from ?token=; "" for a bootstrap claim (no invite/recovery link exists yet)
}

// handleRegister renders /register, shared by the bootstrap, recovery, and
// invite token-redeem ceremonies (they differ only in the JSON body
// static/passkey.js sends to /api/v1/register/begin, not in this page).
func (h *handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "register", registerData{Token: r.URL.Query().Get("token")})
}

// accountData is account.html's template data. NotificationsEnabled gates the
// link to /account/endpoints: those routes are only registered when
// notifications.enabled is true, so offering the link otherwise would render a
// dead end.
type accountData struct {
	appData
	NotificationsEnabled bool
}

// handleAccount renders /account. requireSession has already guaranteed a
// valid session (usr, sess) by the time this runs.
func (h *handler) handleAccount(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	h.render(w, r, "account", accountData{
		appData:              h.newAppData(usr, sess, "Account", "account"),
		NotificationsEnabled: h.deps.Cfg.Notifications.Enabled,
	})
}
