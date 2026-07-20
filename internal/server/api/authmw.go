package api

import (
	"bytes"
	"context"
	"crypto/subtle"
	"io"
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

// hmacMiddleware verifies the HMAC request-signing envelope for agent
// operations. It bounds the body read to maxBody (pre-auth DoS defense),
// restores the body afterward so huma's own input binding can still parse it,
// and on success forwards the authenticated device id via context.
func hmacMiddleware(api huma.API, v *auth.Verifier, maxBody int64) func(huma.Context, func(huma.Context)) {
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
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")
			return
		}

		next(huma.WithValue(ctx, deviceIDKey, deviceID))
	}
}

// sessionMiddleware authenticates the session cookie and forwards the
// resulting user and session via context.
func sessionMiddleware(api huma.API, sm *auth.SessionManager, cookieName string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)

		c, err := r.Cookie(cookieName)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")
			return
		}

		usr, sess, err := sm.Authenticate(ctx.Context(), c.Value)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")
			return
		}

		next(huma.WithValue(huma.WithValue(ctx, userKey, usr), sessionKey, sess))
	}
}

// csrfMiddleware enforces the X-CSRF-Token header against the session's CSRF
// token using a constant-time comparison. It MUST run after sessionMiddleware
// in the middleware chain, since it reads the session from context.
func csrfMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		sess := SessionFrom(ctx.Context())
		got := ctx.Header("X-CSRF-Token")
		if sess.CSRFToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRFToken)) != 1 {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "invalid csrf token")
			return
		}
		next(ctx)
	}
}

// adminMiddleware rejects the request with 403 unless the session-authenticated
// user has the "admin" role. It MUST run after sessionMiddleware in the chain,
// since it reads the user from context.
func adminMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if UserFrom(ctx.Context()).Role != "admin" {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "admin role required")
			return
		}
		next(ctx)
	}
}
