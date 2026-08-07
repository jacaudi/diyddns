package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// webauthnChallengeCookieName is the single-source name for the sealed
// WebAuthn ceremony-challenge cookie every begin/finish op in this file
// round-trips (design D6) — distinct from the browser session cookie
// (cfg.Session.CookieName).
const webauthnChallengeCookieName = "diyddns_webauthn_challenge"

// webauthnChallengeCookieMaxAge bounds how long an unconsumed challenge
// cookie lingers client-side. It is generous relative to the ceremony's own
// server-side timeout (auth.webauthn.timeout, default 120s per
// config.keyDefaults) — claimChallenge's single-use tracking, not this
// MaxAge, is the actual security boundary; this only bounds how long a stale
// cookie survives a browser tab left open mid-ceremony. Fixed for this task
// — no config key exists for it (mirrors server.go's enrollmentCodeTTL).
const webauthnChallengeCookieMaxAge = 300

// errPasskeyVerification is the uniform message for every WebAuthn ceremony
// verification failure, mirroring service.ErrPasskeyVerification's own
// uniform-failure contract at the wire level.
const errPasskeyVerification = "passkey verification failed" // #nosec G101 -- a user-facing error message, not a credential value; gosec's keyword heuristic fires on "Pass" in "Passkey"

// passkeyChallengeCookie builds the diyddns_webauthn_challenge Set-Cookie
// header value: value is the sealed ceremony payload ("" to clear it);
// maxAge follows net/http.Cookie semantics (0 = browser-session cookie, <0 =
// delete immediately). Mirrors auth.go's sessionCookie's
// Secure/HttpOnly/SameSite policy — every cookie this server sets shares one
// security posture — rather than the narrower (value, maxAge) shape, since
// sessionCookie's Secure computation genuinely needs cfg and tlsActive too.
func passkeyChallengeCookie(cfg config.SessionCfg, value string, maxAge int, tlsActive bool) http.Cookie {
	return http.Cookie{ //nolint:gosec // G124: Secure is computed at runtime (tlsActive || cfg.CookieSecure), matching sessionCookie's (auth.go) identical policy — HttpOnly and SameSite=Lax are always set below.
		Name:     webauthnChallengeCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   tlsActive || cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

// webauthnMeta is what webauthnMetaMiddleware captures for a finish op: the
// sealed challenge cookie's raw value, and the *http.Request itself — the
// go-webauthn Finish* calls this file drives all read the request body
// directly, but huma business handlers receive only context.Context (M2).
type webauthnMeta struct {
	challenge string
	req       *http.Request
}

// webauthnMetaKey is the context key webauthnMetaMiddleware stores
// webauthnMeta under.
type webauthnMetaKey struct{}

// webauthnMetaMiddleware reads the diyddns_webauthn_challenge cookie and
// captures the raw *http.Request off the connection (huma business handlers
// receive a plain context.Context, never *http.Request — mirrors auth.go's
// loginMetaMiddleware / oidc.go's oidcFlowMiddleware humago.Unwrap pattern).
// It never rejects a request; a missing/malformed cookie is left for the
// service layer's uniform ErrPasskeyVerification to catch the same way it
// catches a tampered one.
func webauthnMetaMiddleware() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)
		var challenge string
		if c, err := r.Cookie(webauthnChallengeCookieName); err == nil {
			challenge = c.Value
		}
		next(huma.WithValue(ctx, webauthnMetaKey{}, webauthnMeta{challenge: challenge, req: r}))
	}
}

// webauthnMetaFrom returns the webauthnMeta stashed by
// webauthnMetaMiddleware, with req's Body re-armed from raw: huma already
// drained the original Body while binding it into the input struct's
// RawBody field (mirrors authmw.go's hmacMiddleware body-restore, in the
// opposite direction — that restores Body for huma's own later binding, this
// restores it for a service-layer ceremony call after huma is done with it).
func webauthnMetaFrom(ctx context.Context, raw []byte) webauthnMeta {
	m, _ := ctx.Value(webauthnMetaKey{}).(webauthnMeta)
	if m.req != nil {
		m.req.Body = io.NopCloser(bytes.NewReader(raw))
	}
	return m
}

// passkeyOptionsOutput carries a WebAuthn ceremony's ready-to-post options
// JSON verbatim — BeginLogin/BeginRegister/RedeemBegin/BeginClaim already
// marshal it, nothing here re-encodes it (huma's raw []byte Body field
// writes bytes as-is, no schema round-trip) — plus the sealed challenge
// cookie the browser must round-trip to the matching finish op.
type passkeyOptionsOutput struct {
	SetCookie   http.Cookie `header:"Set-Cookie"`
	ContentType string      `header:"Content-Type"`
	Body        []byte
}

func passkeyOptions(body []byte, cookie http.Cookie) *passkeyOptionsOutput {
	return &passkeyOptionsOutput{SetCookie: cookie, ContentType: "application/json", Body: body}
}

// loginFinishOutput carries the new session cookie AND clears the sealed
// WebAuthn challenge cookie login/begin set — two Set-Cookie headers in one
// response. huma emits one header per slice element (via AppendHeader) for a
// slice-typed header field, unlike sessionCookieOutput's single scalar
// http.Cookie field (SetHeader, which would overwrite a second value rather
// than adding it) — login/finish is the one op that needs both cookies at
// once, so it gets its own output type rather than generalizing
// sessionCookieOutput for a single caller.
type loginFinishOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
}

// webauthnFinishInput is the wire shape shared by every WebAuthn finish op:
// the raw PublicKeyCredential JSON navigator.credentials.create()/get()
// produced, forwarded byte-for-byte to go-webauthn's
// protocol.Parse*ResponseBody (via the service layer). Ops needing an extra
// field — a credential nickname, a grant token — merge it into this same
// JSON object client-side rather than using a second typed Body field:
// go-webauthn's decoder (protocol/decoder.go) does not reject unrecognized
// top-level keys, so "name"/"token" ride alongside "id"/"rawId"/"response"/
// "type" harmlessly, and the handler recovers them with a small local struct
// unmarshaled from the same RawBody bytes.
type webauthnFinishInput struct {
	RawBody []byte
}

// decodeCredID decodes a base64url (no padding) credential id path segment —
// the same encoding PasskeyService's own audit log uses
// (base64.RawURLEncoding.EncodeToString(cred.ID)) — into raw bytes. An
// unparsable id maps to store.ErrNotFound: it is indistinguishable from a
// nonexistent credential, never leaking which check failed.
func decodeCredID(id string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return nil, store.ErrNotFound
	}
	return b, nil
}

// passkeyErr maps every error this file's operations can produce — WebAuthn
// ceremony sentinels (login, account registration, grant redeem, bootstrap
// claim) and passkey-management sentinels (List/Rename/Remove) alike — to
// the right huma response, mirroring adminErr's one-mapper-per-file
// convention (admin.go). Anything unrecognized is an unexpected internal
// failure: logged and reported as a generic 500, never collapsed into the
// uniform 401 (that would hide real infrastructure problems behind a message
// meant only for ceremony verification failures).
func passkeyErr(ctx context.Context, deps ServerDeps, action string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return huma.Error404NotFound("passkey not found")
	case errors.Is(err, service.ErrLastCredential):
		return huma.Error409Conflict("cannot remove your last passkey")
	case errors.Is(err, service.ErrWebAuthnUnavailable):
		return huma.Error503ServiceUnavailable("passkey authentication is not configured")
	case errors.Is(err, service.ErrBootstrapClosed):
		return huma.Error410Gone("bootstrap already completed")
	case errors.Is(err, service.ErrBootstrapToken):
		return huma.Error401Unauthorized("invalid bootstrap token")
	case errors.Is(err, service.ErrBootstrapInvalidEmail):
		return huma.Error422UnprocessableEntity("invalid email address")
	case errors.Is(err, service.ErrGrantInvalid):
		return huma.Error401Unauthorized("registration link invalid, expired, or already used")
	case errors.Is(err, service.ErrPasskeyVerification):
		return huma.Error401Unauthorized(errPasskeyVerification)
	default:
		deps.Log.LogAttrs(ctx, slog.LevelError, action+" failed", slog.Any("error", err))
		return huma.Error500InternalServerError("failed to " + action)
	}
}

// passkeyView is the account passkey-management wire view of a stored
// credential: name / created / last-used / an authenticator hint (AAGUID) —
// never the public key or any other secret key material (design §4/§5).
type passkeyView struct {
	ID         string `json:"id"` // base64url credential id — safe to expose, not secret key material
	Name       string `json:"name"`
	AAGUID     string `json:"aaguid"` // base64url; "" if the authenticator didn't report one
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt int64  `json:"last_used_at"`
}

func newPasskeyView(c store.WebAuthnCredential) passkeyView {
	aaguid := ""
	if len(c.AAGUID) > 0 {
		aaguid = base64.RawURLEncoding.EncodeToString(c.AAGUID)
	}
	return passkeyView{
		ID:         base64.RawURLEncoding.EncodeToString(c.CredentialID),
		Name:       c.Name,
		AAGUID:     aaguid,
		CreatedAt:  c.CreatedAt,
		LastUsedAt: c.LastUsedAt,
	}
}

type listPasskeysOutput struct{ Body []passkeyView }

type renamePasskeyInput struct {
	ID   string `path:"id"`
	Body struct {
		Name string `json:"name"`
	}
}

type deletePasskeyInput struct {
	ID string `path:"id"`
}

// deletePasskeyOutput carries no body; huma emits 204 via DefaultStatus.
type deletePasskeyOutput struct{}

// registerGrantBeginInput is the body of POST /api/v1/register/begin: Token
// alone drives a registration-grant redeem (invite or recovery,
// GrantService.RedeemBegin); Token+Email together drive a bootstrap claim
// (BootstrapService.BeginClaim, design D9) — a grant redeem already knows
// its target user from the token, but a bootstrap claim does not, since no
// admin user row exists yet for BeginClaim to read an email back from.
type registerGrantBeginInput struct {
	Body struct {
		Token string `json:"token"`
		Email string `json:"email,omitempty"`
	}
}

// registerPasskeyOps registers the passkey ceremony + registration-grant
// operations onto apiAPI: pre-session login and register(grant/bootstrap),
// session-gated account passkey management, and pre-session self-service
// recovery request. Only called from Build when both deps.Passkey and
// deps.Grants are non-nil.
func registerPasskeyOps(a huma.API, deps ServerDeps) {
	session := func() huma.Middlewares {
		return huma.Middlewares{sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName)}
	}
	sessionCSRF := func() huma.Middlewares {
		return huma.Middlewares{
			sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName),
			csrfMiddleware(a),
		}
	}

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/passkey/login/begin",
		DefaultStatus: http.StatusOK,
		Middlewares:   huma.Middlewares{loginMetaMiddleware()},
	}, func(ctx context.Context, _ *struct{}) (*passkeyOptionsOutput, error) {
		meta := loginMetaFrom(ctx)
		opts, sealed, err := deps.Passkey.BeginLogin(ctx)
		if err != nil {
			return nil, passkeyErr(ctx, deps, "begin passkey login", err)
		}
		return passkeyOptions(opts, passkeyChallengeCookie(deps.Cfg.Session, sealed, webauthnChallengeCookieMaxAge, meta.tls)), nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/passkey/login/finish",
		DefaultStatus: http.StatusOK,
		Middlewares:   huma.Middlewares{loginMetaMiddleware(), webauthnMetaMiddleware()},
	}, func(ctx context.Context, in *webauthnFinishInput) (*loginFinishOutput, error) {
		lmeta := loginMetaFrom(ctx)
		wmeta := webauthnMetaFrom(ctx, in.RawBody)
		sess, err := deps.Passkey.FinishLogin(ctx, wmeta.challenge, wmeta.req, lmeta.ip, lmeta.ua)
		if err != nil {
			return nil, passkeyErr(ctx, deps, "finish passkey login", err)
		}
		return &loginFinishOutput{SetCookie: []http.Cookie{
			sessionCookie(deps.Cfg.Session, sess.ID, 0, lmeta.tls),
			passkeyChallengeCookie(deps.Cfg.Session, "", -1, false),
		}}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/account/passkeys/register/begin",
		DefaultStatus: http.StatusOK,
		Middlewares:   huma.Middlewares{sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName), loginMetaMiddleware()},
	}, func(ctx context.Context, _ *struct{}) (*passkeyOptionsOutput, error) {
		u := UserFrom(ctx)
		meta := loginMetaFrom(ctx)
		opts, sealed, err := deps.Passkey.BeginRegister(ctx, u.ID)
		if err != nil {
			return nil, passkeyErr(ctx, deps, "begin passkey registration", err)
		}
		return passkeyOptions(opts, passkeyChallengeCookie(deps.Cfg.Session, sealed, webauthnChallengeCookieMaxAge, meta.tls)), nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/account/passkeys/register/finish",
		DefaultStatus: http.StatusOK,
		Middlewares: huma.Middlewares{
			sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName),
			csrfMiddleware(a),
			webauthnMetaMiddleware(),
		},
	}, func(ctx context.Context, in *webauthnFinishInput) (*sessionCookieOutput, error) {
		u := UserFrom(ctx)
		wmeta := webauthnMetaFrom(ctx, in.RawBody)
		var extra struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(in.RawBody, &extra)
		if _, err := deps.Passkey.FinishRegister(ctx, u.ID, wmeta.challenge, extra.Name, wmeta.req); err != nil {
			return nil, passkeyErr(ctx, deps, "finish passkey registration", err)
		}
		return &sessionCookieOutput{SetCookie: passkeyChallengeCookie(deps.Cfg.Session, "", -1, false)}, nil
	})

	huma.Register(a, huma.Operation{
		Method:      http.MethodGet,
		Path:        "/api/v1/account/passkeys",
		Middlewares: session(),
	}, func(ctx context.Context, _ *struct{}) (*listPasskeysOutput, error) {
		u := UserFrom(ctx)
		creds, err := deps.Passkey.ListCredentials(ctx, u.ID)
		if err != nil {
			return nil, passkeyErr(ctx, deps, "list passkeys", err)
		}
		views := make([]passkeyView, len(creds))
		for i, c := range creds {
			views[i] = newPasskeyView(c)
		}
		return &listPasskeysOutput{Body: views}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPatch,
		Path:          "/api/v1/account/passkeys/{id}",
		DefaultStatus: http.StatusOK,
		Middlewares:   sessionCSRF(),
	}, func(ctx context.Context, in *renamePasskeyInput) (*emptyOutput, error) {
		u := UserFrom(ctx)
		credID, err := decodeCredID(in.ID)
		if err != nil {
			return nil, passkeyErr(ctx, deps, "rename passkey", err)
		}
		if err := deps.Passkey.Rename(ctx, u.ID, credID, in.Body.Name); err != nil {
			return nil, passkeyErr(ctx, deps, "rename passkey", err)
		}
		return &emptyOutput{}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodDelete,
		Path:          "/api/v1/account/passkeys/{id}",
		DefaultStatus: http.StatusNoContent,
		Middlewares:   sessionCSRF(),
	}, func(ctx context.Context, in *deletePasskeyInput) (*deletePasskeyOutput, error) {
		u := UserFrom(ctx)
		credID, err := decodeCredID(in.ID)
		if err != nil {
			return nil, passkeyErr(ctx, deps, "remove passkey", err)
		}
		if err := deps.Passkey.Remove(ctx, u.ID, credID); err != nil {
			return nil, passkeyErr(ctx, deps, "remove passkey", err)
		}
		return &deletePasskeyOutput{}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/recovery/request",
		DefaultStatus: http.StatusOK,
		Middlewares:   huma.Middlewares{loginMetaMiddleware()},
	}, func(ctx context.Context, in *struct {
		Body struct {
			Email string `json:"email"`
		}
	}) (*emptyOutput, error) {
		meta := loginMetaFrom(ctx)
		// RequestSelfServiceRecovery always returns nil — never surfacing
		// which of its internal checks (account exists, has a passkey, SMTP
		// configured) failed, so this response can never be used to
		// enumerate accounts (design §7).
		_ = deps.Grants.RequestSelfServiceRecovery(ctx, in.Body.Email, meta.ip)
		return &emptyOutput{}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/register/begin",
		DefaultStatus: http.StatusOK,
		Middlewares:   huma.Middlewares{loginMetaMiddleware()},
	}, func(ctx context.Context, in *registerGrantBeginInput) (*passkeyOptionsOutput, error) {
		meta := loginMetaFrom(ctx)
		var opts []byte
		var sealed string
		var err error
		if in.Body.Email != "" {
			sealed, opts, err = deps.Bootstrap.BeginClaim(ctx, in.Body.Token, in.Body.Email)
		} else {
			_, opts, sealed, err = deps.Grants.RedeemBegin(ctx, in.Body.Token)
		}
		if err != nil {
			return nil, passkeyErr(ctx, deps, "begin registration", err)
		}
		return passkeyOptions(opts, passkeyChallengeCookie(deps.Cfg.Session, sealed, webauthnChallengeCookieMaxAge, meta.tls)), nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/register/finish",
		DefaultStatus: http.StatusOK,
		Middlewares:   huma.Middlewares{webauthnMetaMiddleware()},
	}, func(ctx context.Context, in *webauthnFinishInput) (*sessionCookieOutput, error) {
		wmeta := webauthnMetaFrom(ctx, in.RawBody)
		var extra struct {
			Token string `json:"token"`
			Name  string `json:"name"`
		}
		_ = json.Unmarshal(in.RawBody, &extra)

		var err error
		if extra.Token != "" {
			err = deps.Grants.RedeemFinish(ctx, extra.Token, wmeta.challenge, wmeta.req, extra.Name)
		} else {
			_, err = deps.Bootstrap.FinishClaim(ctx, wmeta.challenge, wmeta.req, extra.Name)
		}
		if err != nil {
			return nil, passkeyErr(ctx, deps, "finish registration", err)
		}
		return &sessionCookieOutput{SetCookie: passkeyChallengeCookie(deps.Cfg.Session, "", -1, false)}, nil
	})
}
