package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/jacaudi/diyddns/internal/auth"
)

// oidcFlowCookie is the sealed cookie holding the in-flight browser auth state.
const oidcFlowCookie = "diyddns_oidc_flow"

// oidcFlowAAD domain-separates the flow cookie's AEAD sealing from device-secret sealing.
var oidcFlowAAD = []byte("diyddns/oidc-flow-v1")

// redirectOIDCUnavailable and redirectNoAccount are the two uniform
// front-end-visible failure surfaces for the OIDC flow: the former for
// server-side/IdP-config problems (start couldn't even build a redirect),
// the latter for every policy/verify/link rejection in the callback — never
// a distinct error per failure reason, so the response never leaks which
// check failed (see registerOIDCOps' callback handler).
const (
	redirectOIDCUnavailable = "/login?error=oidc_unavailable"
	redirectNoAccount       = "/login?error=no_account"
)

// oidcFlowState is the JSON sealed into oidcFlowCookie.
type oidcFlowState struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
	Next     string `json:"next"`
}

// oidcRedirectOutput carries a 302 redirect plus a Set-Cookie. On success the
// cookie is the new session cookie; on every failure/terminal path it clears
// the flow cookie. Only one Set-Cookie is ever needed on the success path
// because the flow cookie is scoped to Path=/api/v1/auth/oidc with a short
// MaxAge (600s) and self-expires — see registerOIDCOps' callback handler.
type oidcRedirectOutput struct {
	Status    int
	Location  string      `header:"Location"`
	SetCookie http.Cookie `header:"Set-Cookie"`
}

// safeNext returns next if it is a local path (leading "/", not scheme- or
// protocol-relative, not a backslash-escape), else "/". This is the
// open-redirect defense for the `next` query param carried through the OIDC
// flow cookie.
func safeNext(next string) string {
	if next == "" || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || !strings.HasPrefix(u.Path, "/") {
		return "/"
	}
	return next
}

// subtleMismatch reports whether a and b differ, compared in constant time so
// the callback's state check doesn't leak timing information about how much
// of the expected state an attacker's guess matched.
func subtleMismatch(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) != 1
}

// registerOIDCOps registers the browser OIDC authorization-code + PKCE flow:
// GET /start redirects to the IdP with a sealed flow cookie; GET /callback
// validates it, completes the exchange, and mints a session. Both are plain
// pre-session redirects — no session/CSRF middleware guards them.
func registerOIDCOps(a huma.API, deps ServerDeps) {
	huma.Register(a, huma.Operation{
		Method:        http.MethodGet,
		Path:          "/api/v1/auth/oidc/start",
		DefaultStatus: http.StatusFound,
		Middlewares:   huma.Middlewares{loginMetaMiddleware()},
	}, func(ctx context.Context, in *struct {
		Next string `query:"next"`
	}) (*oidcRedirectOutput, error) {
		if !deps.OIDCMgr.Enabled() {
			return &oidcRedirectOutput{Status: http.StatusFound, Location: redirectOIDCUnavailable}, nil
		}
		req, err := deps.OIDCMgr.BeginAuth()
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "oidc begin auth failed", slog.Any("error", err))
			return &oidcRedirectOutput{Status: http.StatusFound, Location: redirectOIDCUnavailable}, nil
		}
		blob, err := json.Marshal(oidcFlowState{State: req.State, Verifier: req.Verifier, Nonce: req.Nonce, Next: safeNext(in.Next)})
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "oidc marshal flow state failed", slog.Any("error", err))
			return &oidcRedirectOutput{Status: http.StatusFound, Location: redirectOIDCUnavailable}, nil
		}
		sealed, err := auth.SealWithAAD(deps.HMACKey, blob, oidcFlowAAD)
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "oidc seal flow cookie failed", slog.Any("error", err))
			return &oidcRedirectOutput{Status: http.StatusFound, Location: redirectOIDCUnavailable}, nil
		}
		meta := loginMetaFrom(ctx)
		return &oidcRedirectOutput{
			Status:    http.StatusFound,
			Location:  req.URL,
			SetCookie: oidcFlowSetCookie(deps, sealed, 600, meta.tls),
		}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodGet,
		Path:          "/api/v1/auth/oidc/callback",
		DefaultStatus: http.StatusFound,
		Middlewares:   huma.Middlewares{loginMetaMiddleware(), oidcFlowMiddleware()},
	}, func(ctx context.Context, in *struct {
		Code  string `query:"code"`
		State string `query:"state"`
		Error string `query:"error"`
	}) (*oidcRedirectOutput, error) {
		meta := loginMetaFrom(ctx)
		clear := oidcFlowSetCookie(deps, "", -1, meta.tls) // expire the flow cookie on every terminal outcome

		if in.Error != "" {
			deps.Log.LogAttrs(ctx, slog.LevelWarn, "oidc idp returned error", slog.String("error", in.Error))
			return &oidcRedirectOutput{Status: http.StatusFound, Location: redirectNoAccount, SetCookie: clear}, nil
		}

		// The flow cookie's raw value was captured from *http.Request by
		// oidcFlowMiddleware (huma business handlers get a plain context.Context,
		// never the request — mirror loginMetaMiddleware's humago.Unwrap pattern).
		sealed, ok := oidcFlowCookieFrom(ctx)
		if !ok {
			return &oidcRedirectOutput{Status: http.StatusFound, Location: redirectNoAccount, SetCookie: clear}, nil
		}
		raw, err := auth.OpenWithAAD(deps.HMACKey, sealed, oidcFlowAAD)
		if err != nil {
			return &oidcRedirectOutput{Status: http.StatusFound, Location: redirectNoAccount, SetCookie: clear}, nil
		}
		var fs oidcFlowState
		if err := json.Unmarshal(raw, &fs); err != nil || subtleMismatch(fs.State, in.State) {
			return &oidcRedirectOutput{Status: http.StatusBadRequest, SetCookie: clear}, nil
		}

		claims, err := deps.OIDCMgr.CompleteAuth(ctx, in.Code, fs.Verifier, fs.Nonce)
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelError, "oidc complete auth failed", slog.Any("error", err))
			return &oidcRedirectOutput{Status: http.StatusFound, Location: redirectNoAccount, SetCookie: clear}, nil
		}
		sess, err := deps.OIDC.BrowserLogin(ctx, deps.Cfg.OIDC.Issuer, claims.Subject, claims.Email, claims.EmailVerified, meta.ip, meta.ua)
		if err != nil {
			deps.Log.LogAttrs(ctx, slog.LevelInfo, "oidc login rejected", slog.Any("error", err))
			return &oidcRedirectOutput{Status: http.StatusFound, Location: redirectNoAccount, SetCookie: clear}, nil
		}
		// Success: set the session cookie. The flow cookie is not re-cleared
		// here (see oidcRedirectOutput's doc comment) — its short MaxAge and
		// narrow Path already bound its lifetime.
		return &oidcRedirectOutput{
			Status:    http.StatusFound,
			Location:  safeNext(fs.Next),
			SetCookie: sessionCookie(deps.Cfg.Session, sess.ID, 0, meta.tls),
		}, nil
	})
}

// oidcFlowSetCookie builds the diyddns_oidc_flow Set-Cookie header value.
// value is the sealed flow blob ("" to clear it); maxAge follows
// net/http.Cookie semantics (<0 = delete immediately).
func oidcFlowSetCookie(deps ServerDeps, value string, maxAge int, tlsActive bool) http.Cookie {
	return http.Cookie{ //nolint:gosec // G124: Secure is computed at runtime (tlsActive || deps.Cfg.Session.CookieSecure), not a literal gosec's SSA constant-check can verify; HttpOnly and SameSite=Lax are always set below (mirrors auth.go's sessionCookie).
		Name:     oidcFlowCookie,
		Value:    value,
		Path:     "/api/v1/auth/oidc",
		HttpOnly: true,
		Secure:   tlsActive || deps.Cfg.Session.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

// oidcFlowKey is the context key for the raw (sealed) flow-cookie value.
type oidcFlowKey struct{}

// oidcFlowMiddleware reads the diyddns_oidc_flow cookie off the raw request
// (huma business handlers receive a plain context.Context, never *http.Request)
// and stashes its raw sealed value for the callback handler — the same
// humago.Unwrap → huma.WithValue pattern loginMetaMiddleware uses.
func oidcFlowMiddleware() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)
		if c, err := r.Cookie(oidcFlowCookie); err == nil {
			ctx = huma.WithValue(ctx, oidcFlowKey{}, c.Value)
		}
		next(ctx)
	}
}

// oidcFlowCookieFrom returns the raw sealed flow-cookie value stashed by
// oidcFlowMiddleware, and whether it was present.
func oidcFlowCookieFrom(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(oidcFlowKey{}).(string)
	return v, ok && v != ""
}
