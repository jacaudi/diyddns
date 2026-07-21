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

// render executes the named page's parsed template ("layout" wrapping the
// page's own "content" block) with data into a buffer first, so a template
// execution failure never leaves a half-written response with headers
// already sent.
func (h *handler) render(w http.ResponseWriter, r *http.Request, page string, data any) {
	var buf bytes.Buffer
	if err := h.pages[page].ExecuteTemplate(&buf, "layout", data); err != nil {
		h.deps.Log.LogAttrs(r.Context(), slog.LevelError, "webui: render failed",
			slog.String("page", page), slog.Any("error", err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
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

// accountData is account.html's template data.
type accountData struct {
	pageData
	Email string
}

// handleAccount renders /account. requireSession has already guaranteed a
// valid session (usr, sess) by the time this runs.
func (h *handler) handleAccount(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	h.render(w, r, "account", accountData{
		pageData: pageData{CSRFToken: sess.CSRFToken},
		Email:    usr.Email,
	})
}
