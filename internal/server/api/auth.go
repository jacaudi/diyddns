package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/jacaudi/diyddns/internal/config"
)

// loginMetaKey is the unexported context key type login's pre-handler
// middleware uses to forward request metadata to the business handler. It
// is deliberately not added to authmw.go's ctxKey enum: it carries no
// authentication meaning of its own (unlike deviceIDKey/userKey/
// sessionKey) and is scoped to this file's single operation.
type loginMetaKey struct{}

// loginRequestMeta is the subset of the raw HTTP request login's handler
// needs but cannot read directly, since huma business handlers receive a
// plain context.Context, never a huma.Context (see huma.Register).
type loginRequestMeta struct {
	ip  string
	ua  string
	tls bool
}

// loginMetaMiddleware captures the caller's remote address, user agent, and
// TLS-active bit and forwards them via context so login's handler can pass
// ip/ua to AuthService.Login and compute the cookie's Secure attribute. It
// never rejects a request — login carries no session/CSRF guard (it is
// pre-session, per design §5.2), this only relays request metadata.
func loginMetaMiddleware() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)
		next(huma.WithValue(ctx, loginMetaKey{}, loginRequestMeta{
			ip:  r.RemoteAddr,
			ua:  r.UserAgent(),
			tls: r.TLS != nil,
		}))
	}
}

// loginMetaFrom returns the loginRequestMeta stashed by loginMetaMiddleware,
// or the zero value if absent.
func loginMetaFrom(ctx context.Context) loginRequestMeta {
	m, _ := ctx.Value(loginMetaKey{}).(loginRequestMeta)
	return m
}

// sessionCookie builds the diyddns_session Set-Cookie header value. value is
// the session id ("" to clear it); maxAge follows net/http.Cookie semantics
// (0 = browser-session cookie, deleted on close; <0 = delete immediately).
// Secure is forced whenever the connection is over TLS or the operator has
// set cookie_secure. The X-Forwarded-Proto + trusted-proxy refinement from
// design §5.2 is deferred to a later plan — no server.trusted_proxies
// config key exists yet.
func sessionCookie(cfg config.SessionCfg, value string, maxAge int, tlsActive bool) http.Cookie {
	return http.Cookie{ //nolint:gosec // G124: Secure is computed at runtime (tlsActive || cfg.CookieSecure) per design §5.2, not a literal gosec's SSA constant-check can verify; HttpOnly and SameSite=Lax are always set below.
		Name:     cfg.CookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   tlsActive || cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

// sessionCookieOutput is the response shape shared by login (sets the
// session cookie) and logout (clears it): both operations communicate their
// effect on the browser session purely through the Set-Cookie response
// header, so they share one output type — the wire contract is identical,
// only the cookie value differs.
type sessionCookieOutput struct {
	SetCookie http.Cookie `header:"Set-Cookie"`
}

// emptyOutput is the 200-with-no-body response shape for operations that
// only need to report success (e.g. passkey rename/delete).
type emptyOutput struct{}

type meUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type meResponse struct {
	User meUser `json:"user"`
	CSRF string `json:"csrf"`
}

type meOutput struct {
	Body meResponse
}

// registerAuthOps registers the browser session operations onto apiAPI:
// logout and me both require a session. Local password login and change
// were removed with the Plan 10 flip — login is now a passkey ceremony
// (registerPasskeyOps) or OIDC (registerOIDCOps), and bootstrap is claimed
// via passkey (passkey.go's register begin/finish).
func registerAuthOps(a huma.API, deps ServerDeps) {
	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/logout",
		DefaultStatus: http.StatusOK,
		Middlewares:   huma.Middlewares{sessionMW(a, deps)},
	}, func(ctx context.Context, _ *struct{}) (*sessionCookieOutput, error) {
		sess := SessionFrom(ctx)
		if err := deps.Auth.Logout(ctx, sess.ID); err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "logout failed", slog.Any("error", err))
			return nil, huma.Error500InternalServerError("logout failed")
		}
		return &sessionCookieOutput{SetCookie: sessionCookie(deps.Cfg.Session, "", -1, false)}, nil
	})

	huma.Register(a, huma.Operation{
		Method:      http.MethodGet,
		Path:        "/api/v1/auth/me",
		Middlewares: huma.Middlewares{sessionMW(a, deps)},
	}, func(ctx context.Context, _ *struct{}) (*meOutput, error) {
		u := UserFrom(ctx)
		sess := SessionFrom(ctx)
		return &meOutput{Body: meResponse{
			User: meUser{ID: u.ID, Email: u.Email, Role: u.Role},
			CSRF: sess.CSRFToken,
		}}, nil
	})

	registerOIDCOps(a, deps)
}
