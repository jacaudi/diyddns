package webui

import (
	"net/http"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// authenticateBrowser is this package's thin, one-line delegate to
// auth.SessionManager.AuthenticateRequest, the single, framework-agnostic
// home for "authenticate a browser request by its session cookie" (design
// §9/N2): the cookie->Authenticate knowledge itself lives only there, shared
// with internal/server/api's huma sessionMiddleware — only the huma-vs-stdlib
// glue differs between callers. Kept as a named function (rather than having
// requireSession and handlers.go call AuthenticateRequest directly) since it
// has two callers in this package.
func authenticateBrowser(sessions *auth.SessionManager, r *http.Request, cookieName string) (store.User, store.Session, error) {
	return sessions.AuthenticateRequest(r, cookieName)
}

// sessionHandler is a page handler that runs only after authentication, with
// the resolved user and session already in hand.
type sessionHandler func(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session)

// requireSession wraps next so it only runs when the request carries a valid
// session; otherwise it redirects to /login. 303 (See Other) is used rather
// than 302 so any client following the redirect always re-issues a GET,
// regardless of the original request method.
func (h *handler) requireSession(next sessionHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		usr, sess, err := authenticateBrowser(h.deps.Sessions, r, h.deps.Cfg.Auth.Session.CookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r, usr, sess)
	}
}

// adminOnly wraps next so it runs only for an admin. It returns a
// sessionHandler rather than an http.HandlerFunc so it composes with both
// requireSession (GET routes) and requirePost (mutations), which is why the
// role check exists once rather than once per guard.
func (h *handler) adminOnly(next sessionHandler) sessionHandler {
	return func(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
		if usr.Role != "admin" {
			h.renderError(w, r, usr, http.StatusForbidden, "Admin access is required for that page.")
			return
		}
		next(w, r, usr, sess)
	}
}

// requireAdmin serves next only to a signed-in admin. A signed-in non-admin
// gets 403, not a redirect: sending them to /login would loop, since they
// already have a valid session.
func (h *handler) requireAdmin(next sessionHandler) http.HandlerFunc {
	return h.requireSession(h.adminOnly(next))
}

// requirePost parses the form and validates its hidden csrf field before
// next runs. Browser form POSTs cannot set an X-CSRF-Token header, so the
// token rides in the body; auth.ValidCSRF owns what makes it valid.
func (h *handler) requirePost(next sessionHandler) http.HandlerFunc {
	return h.requireSession(func(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
		if err := r.ParseForm(); err != nil {
			h.renderError(w, r, usr, http.StatusBadRequest, "That form submission was malformed. Reload the page and try again.")
			return
		}
		if !auth.ValidCSRF(sess, r.PostFormValue("csrf")) {
			h.renderError(w, r, usr, http.StatusForbidden, "Your session expired or the form was stale. Reload the page and try again.")
			return
		}
		next(w, r, usr, sess)
	})
}

// requirePostAdmin is requirePost plus the admin role check, for admin
// mutations.
func (h *handler) requirePostAdmin(next sessionHandler) http.HandlerFunc {
	return h.requirePost(h.adminOnly(next))
}
