package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/service"
)

// errLoginUnauthorized is the single message returned for every login
// failure — unknown email, wrong password, disabled account, or an
// OIDC-only account with no local password — mirroring
// service.AuthService.Login's own uniform errInvalidCreds so neither the
// error nor the response shape reveals which check failed.
const errLoginUnauthorized = "invalid email or password"

// errPasswordChangeInvalid is the single message returned for every
// ChangePassword failure — wrong old password or a new password that
// fails the minimum-length policy — mapped to a uniform 422 (design §8's
// canonical code for the analogous "don't leak which" validation case,
// matching the bootstrap-default path). service.errInvalidCreds is
// unexported, so this package cannot (and, per the design's uniform-failure
// philosophy used by login/enroll, should not) distinguish the two.
const errPasswordChangeInvalid = "invalid old password or new password"

// errBootstrapInvalid is returned for bootstrap validation failures (bad
// email format, password below the minimum length) — anything that is not
// the token-closed or token-mismatch case, which get their own uniform
// messages below.
const errBootstrapInvalid = "invalid bootstrap request: check email format and password length"

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
// only need to report success: password change and bootstrap.
type emptyOutput struct{}

type loginInput struct {
	Body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
}

type passwordInput struct {
	Body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
}

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

type bootstrapInput struct {
	Body struct {
		Token    string `json:"token"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
}

// registerAuthOps registers the browser auth + bootstrap operations onto
// apiAPI: login/bootstrap carry no session/CSRF guard (pre-session);
// logout/me require a session; password requires a session and CSRF.
func registerAuthOps(a huma.API, deps ServerDeps) {
	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/login",
		DefaultStatus: http.StatusOK, // huma defaults to 204 for bodyless outputs; login returns 200 with only a Set-Cookie header
		Middlewares:   huma.Middlewares{loginMetaMiddleware()},
	}, func(ctx context.Context, in *loginInput) (*sessionCookieOutput, error) {
		meta := loginMetaFrom(ctx)
		sess, err := deps.Auth.Login(ctx, in.Body.Email, in.Body.Password, meta.ip, meta.ua)
		if err != nil {
			return nil, huma.Error401Unauthorized(errLoginUnauthorized)
		}
		return &sessionCookieOutput{SetCookie: sessionCookie(deps.Cfg.Session, sess.ID, 0, meta.tls)}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/logout",
		DefaultStatus: http.StatusOK,
		Middlewares:   huma.Middlewares{sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName)},
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
		Middlewares: huma.Middlewares{sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName)},
	}, func(ctx context.Context, _ *struct{}) (*meOutput, error) {
		u := UserFrom(ctx)
		sess := SessionFrom(ctx)
		return &meOutput{Body: meResponse{
			User: meUser{ID: u.ID, Email: u.Email, Role: u.Role},
			CSRF: sess.CSRFToken,
		}}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/password",
		DefaultStatus: http.StatusOK,
		Middlewares: huma.Middlewares{
			sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName),
			csrfMiddleware(a),
		},
	}, func(ctx context.Context, in *passwordInput) (*emptyOutput, error) {
		u := UserFrom(ctx)
		if err := deps.Auth.ChangePassword(ctx, u.ID, in.Body.OldPassword, in.Body.NewPassword); err != nil {
			return nil, huma.Error422UnprocessableEntity(errPasswordChangeInvalid)
		}
		return &emptyOutput{}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/bootstrap",
		DefaultStatus: http.StatusOK,
	}, func(ctx context.Context, in *bootstrapInput) (*emptyOutput, error) {
		if _, err := deps.Bootstrap.Consume(ctx, in.Body.Token, in.Body.Email, in.Body.Password); err != nil {
			switch {
			case errors.Is(err, service.ErrBootstrapClosed):
				return nil, huma.Error410Gone("bootstrap already completed")
			case errors.Is(err, service.ErrBootstrapToken):
				return nil, huma.Error401Unauthorized("invalid bootstrap token")
			default:
				return nil, huma.Error422UnprocessableEntity(errBootstrapInvalid)
			}
		}
		return &emptyOutput{}, nil
	})

	registerOIDCOps(a, deps)
}
