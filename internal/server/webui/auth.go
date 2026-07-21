package webui

import (
	"fmt"
	"net/http"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/store"
)

// authenticateBrowser is the framework-agnostic "how to authenticate a
// browser request" check (design §9/N2): read the named session cookie off
// r, then validate it against sessions. It is this package's single source
// for that check — requireSession below is its only caller here — mirroring
// (without importing, since internal/server/api is a sibling package) the
// same cookie->SessionManager.Authenticate sequence internal/server/api's
// huma sessionMiddleware performs against the same *auth.SessionManager;
// only the huma-vs-stdlib glue differs.
func authenticateBrowser(sessions *auth.SessionManager, r *http.Request, cookieName string) (store.User, store.Session, error) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return store.User{}, store.Session{}, fmt.Errorf("webui: no session cookie: %w", err)
	}
	usr, sess, err := sessions.Authenticate(r.Context(), c.Value)
	if err != nil {
		return store.User{}, store.Session{}, fmt.Errorf("webui: %w", err)
	}
	return usr, sess, nil
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
