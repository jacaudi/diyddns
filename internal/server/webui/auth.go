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

// requireSession wraps next so it only runs when the request carries a
// valid session; otherwise it redirects to /login. 303 (See Other) is used
// rather than 302 so any client following the redirect always re-issues a
// GET, regardless of the original request method.
func (h *handler) requireSession(next func(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		usr, sess, err := authenticateBrowser(h.deps.Sessions, r, h.deps.Cfg.Auth.Session.CookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r, usr, sess)
	}
}
