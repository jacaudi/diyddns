package api

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

// maxAgentBody bounds the request body huma's HMAC middleware will buffer
// before authentication runs — a pre-auth DoS defense against unbounded
// unauthenticated reads.
const maxAgentBody = 64 * 1024

// nowUnix returns the current unix time in seconds. It is a package var so
// tests can inject a fixed clock.
var nowUnix = func() int64 { return time.Now().Unix() }

// ctxKey namespaces the request-scoped values middleware forwards to handlers.
type ctxKey int

const (
	deviceIDKey ctxKey = iota
	userKey
	sessionKey
)

// DeviceIDFrom returns the authenticated device id set by hmacMiddleware, or
// "" if none is present in ctx.
func DeviceIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(deviceIDKey).(string)
	return id
}

// UserFrom returns the authenticated user set by sessionMiddleware, or the
// zero store.User if none is present in ctx.
func UserFrom(ctx context.Context) store.User {
	u, _ := ctx.Value(userKey).(store.User)
	return u
}

// SessionFrom returns the authenticated session set by sessionMiddleware, or
// the zero store.Session if none is present in ctx.
func SessionFrom(ctx context.Context) store.Session {
	s, _ := ctx.Value(sessionKey).(store.Session)
	return s
}

// The *MW helpers are the single construction site per middleware. They exist
// because each constructor's argument list was repeated verbatim across the
// register*Ops functions — sessionMiddleware's at thirteen call sites — so
// every new parameter cost thirteen edits. Now it costs one.
func hmacMW(a huma.API, deps ServerDeps) func(huma.Context, func(huma.Context)) {
	return hmacMiddleware(a, deps.Verifier, maxAgentBody, deps.Log)
}

func sessionMW(a huma.API, deps ServerDeps) func(huma.Context, func(huma.Context)) {
	return sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName, deps.Log)
}

func csrfMW(a huma.API, deps ServerDeps) func(huma.Context, func(huma.Context)) {
	return csrfMiddleware(a, deps.Log)
}

func adminMW(a huma.API, deps ServerDeps) func(huma.Context, func(huma.Context)) {
	return adminMiddleware(a, deps.Log)
}

// hmacMiddleware verifies the HMAC request-signing envelope for agent
// operations. It bounds the body read to maxBody (pre-auth DoS defense),
// restores the body afterward so huma's own input binding can still parse it,
// and on success forwards the authenticated device id via context.
func hmacMiddleware(api huma.API, v *auth.Verifier, maxBody int64, log *slog.Logger) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)

		body, err := io.ReadAll(io.LimitReader(ctx.BodyReader(), maxBody+1))
		if err != nil || int64(len(body)) > maxBody {
			_ = huma.WriteErr(api, ctx, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body)) // restore for handler input parsing

		deviceID, err := v.Verify(ctx.Context(), auth.RequestParts{
			Device:    ctx.Header(shared.HeaderDevice),
			Timestamp: ctx.Header(shared.HeaderTimestamp),
			Nonce:     ctx.Header(shared.HeaderNonce),
			Signature: ctx.Header(shared.HeaderSignature),
			Method:    ctx.Method(),
			Path:      ctx.URL().Path,
			Body:      body,
		}, nowUnix())
		if err != nil {
			log.LogAttrs(ctx.Context(), slog.LevelWarn, "agent auth rejected",
				slog.String("reason", auth.ReasonOf(err)),
				slog.String("claimed_device_id", claimedDeviceID(ctx.Header(shared.HeaderDevice))),
				slog.String("route", r.Pattern))
			// Response unchanged: one uniform 401, never the reason. Do NOT
			// pass err — huma.NewError copies Error() into ErrorModel.Errors,
			// which would change the body's shape.
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")
			return
		}

		next(huma.WithValue(ctx, deviceIDKey, deviceID))
	}
}

// claimedDeviceID bounds an unauthenticated, attacker-controlled header value
// before it reaches a log record: over-long or non-printable-ASCII input logs
// as "" instead. Unlike a correlation id there is nothing sensible to mint in
// its place. See middleware.validRequestID for what this bound is actually
// defending against (it is not what it looks like).
//
// Same limit as middleware.validRequestID, deliberately by its own predicate
// rather than a shared one: internal/server/api does not import
// internal/server/middleware, and the two bounds have different owners — this
// one is set by what this server mints, that one by what upstream proxies
// emit. They are identical today and may diverge; keep them in step or
// diverge them deliberately. (Mirrors config.isASCII's deliberate
// duplication.)
func claimedDeviceID(s string) string {
	if len(s) > 128 {
		return ""
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7E {
			return ""
		}
	}
	return s
}

// sessionMiddleware authenticates the session cookie and forwards the
// resulting user and session via context.
func sessionMiddleware(api huma.API, sm *auth.SessionManager, cookieName string, log *slog.Logger) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)

		usr, sess, err := sm.AuthenticateRequest(r, cookieName)
		if err != nil {
			// No subject attr: the request is unauthenticated by definition, so
			// there is nothing authenticated to name, and the session cookie
			// value is a bearer credential that must never reach a log record.
			log.LogAttrs(ctx.Context(), slog.LevelWarn, "session auth rejected",
				slog.String("reason", auth.ReasonOf(err)),
				slog.String("route", r.Pattern))
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")
			return
		}

		next(huma.WithValue(huma.WithValue(ctx, userKey, usr), sessionKey, sess))
	}
}

// csrfMiddleware enforces the X-CSRF-Token header against the session's CSRF
// token using a constant-time comparison. It MUST run after sessionMiddleware
// in the middleware chain, since it reads the session from context.
func csrfMiddleware(api huma.API, log *slog.Logger) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx) // for r.Pattern on the rejection record

		sess := SessionFrom(ctx.Context())
		if !auth.ValidCSRF(sess, ctx.Header("X-CSRF-Token")) {
			// This runs after sessionMiddleware, so the user is authenticated
			// and safe to name.
			log.LogAttrs(ctx.Context(), slog.LevelWarn, "csrf rejected",
				slog.String("user_id", UserFrom(ctx.Context()).ID),
				slog.String("route", r.Pattern))
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "invalid csrf token")
			return
		}
		next(ctx)
	}
}

// adminMiddleware rejects the request with 403 unless the session-authenticated
// user has the "admin" role. It MUST run after sessionMiddleware in the chain,
// since it reads the user from context.
func adminMiddleware(api huma.API, log *slog.Logger) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx) // for r.Pattern on the rejection record

		if usr := UserFrom(ctx.Context()); usr.Role != "admin" {
			// This runs after sessionMiddleware, so the user is authenticated
			// and safe to name.
			log.LogAttrs(ctx.Context(), slog.LevelWarn, "admin role required",
				slog.String("user_id", usr.ID),
				slog.String("role", usr.Role),
				slog.String("route", r.Pattern))
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "admin role required")
			return
		}
		next(ctx)
	}
}
