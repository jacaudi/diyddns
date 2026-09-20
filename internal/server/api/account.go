package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// ---- account email-change DTOs ----

// accountEmailRequestInput is the body of POST /api/v1/account/email. The
// address is passed through unvalidated by this layer -- no trimming: a JSON
// body field carries no incidental whitespace the way an HTML form value
// does, and EmailChangeService.validateRequest already runs the real
// validation.
type accountEmailRequestInput struct {
	Body struct {
		Email string `json:"email"`
	}
}

// accountEmailRequestResponse is the wire form of exactly what
// EmailChangeService.Request returns (link, delivery, expiresAt) -- no
// reinterpretation. Request's own contract (email_change.go:151-161) already
// guarantees Link is non-empty if and only if the caller must show it.
type accountEmailRequestResponse struct {
	Link      string       `json:"link"`
	Delivery  deliveryView `json:"delivery"`
	ExpiresAt int64        `json:"expires_at"`
}
type accountEmailRequestOutput struct{ Body accountEmailRequestResponse }

// accountEmailConfirmInput is the body of POST /api/v1/account/email/confirm.
type accountEmailConfirmInput struct {
	Body struct {
		Token string `json:"token"`
	}
}

// registerAccountEmailOps registers the self-service email-change operations
// onto apiAPI (#151): request, cancel, confirm. Every op is session + CSRF
// gated -- all three mutate state, and confirm is no exception: Confirm's own
// doc comment (email_change.go:280-286) is explicit that the caller must pass
// the SESSION's user, since the link alone proves possession of the new
// mailbox, not of the account. EmailChangeService is unconditionally
// constructed (server.go), so this group registers unconditionally too, the
// same way registerDeviceOps does, unlike the Passkey/Grants/Notify
// nil-tolerant gates in Build.
func registerAccountEmailOps(a huma.API, deps ServerDeps) {
	sessionCSRF := huma.Middlewares{
		sessionMW(a, deps),
		csrfMW(a, deps),
	}

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/account/email",
		DefaultStatus: http.StatusOK,
		Middlewares:   sessionCSRF,
		Summary:       "Request a self-service email change",
		Description:   "Stages a change to the caller's own email address and mails a confirmation link to the new address. Nothing about the account changes until the link is confirmed.",
	}, func(ctx context.Context, in *accountEmailRequestInput) (*accountEmailRequestOutput, error) {
		u := UserFrom(ctx)
		link, delivery, expiresAt, err := deps.EmailChange.Request(ctx, u, in.Body.Email)
		if err != nil {
			return nil, accountEmailErr(ctx, deps, "request email change", err)
		}
		return &accountEmailRequestOutput{Body: accountEmailRequestResponse{
			Link: link, Delivery: newDeliveryView(delivery), ExpiresAt: expiresAt,
		}}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/account/email/cancel",
		DefaultStatus: http.StatusOK,
		Middlewares:   sessionCSRF,
		Summary:       "Cancel a pending self-service email change",
		Description:   "Discards the caller's pending email change, if any. A no-op (still 200) when nothing is pending.",
	}, func(ctx context.Context, _ *struct{}) (*emptyOutput, error) {
		u := UserFrom(ctx)
		if err := deps.EmailChange.Cancel(ctx, u); err != nil {
			return nil, accountEmailErr(ctx, deps, "cancel email change", err)
		}
		return &emptyOutput{}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/account/email/confirm",
		DefaultStatus: http.StatusOK,
		Middlewares:   sessionCSRF,
		Summary:       "Confirm a pending self-service email change",
		Description:   "Redeems the confirmation token mailed to the new address. The new address becomes visible via GET /api/v1/auth/me.",
	}, func(ctx context.Context, in *accountEmailConfirmInput) (*emptyOutput, error) {
		u := UserFrom(ctx)
		if err := deps.EmailChange.Confirm(ctx, u, in.Body.Token); err != nil {
			return nil, accountEmailErr(ctx, deps, "confirm email change", err)
		}
		return &emptyOutput{}, nil
	})
}

// accountEmailErr maps an EmailChangeService error to the right huma
// response, using the exact wording webui/admin.go's adminGuardMessage
// already uses for each sentinel so the two surfaces agree word-for-word.
// store.ErrNotFound is deliberately not a case here: none of
// Request/Cancel/Confirm can return it -- they operate on the session's own
// already-authenticated user, which is guaranteed to exist.
func accountEmailErr(ctx context.Context, deps ServerDeps, action string, err error) error {
	switch {
	case errors.Is(err, service.ErrEmailUnchanged):
		return huma.Error422UnprocessableEntity("That is already the account's email address.")
	case errors.Is(err, service.ErrEmailManagedByOIDC):
		return huma.Error422UnprocessableEntity("This account's email address is managed by its identity provider.")
	case errors.Is(err, service.ErrEmailChangeInvalid):
		return huma.Error422UnprocessableEntity("This confirmation link is invalid or has expired. Request the change again from your account page.")
	case errors.Is(err, service.ErrConfirmationNotSent):
		return huma.Error503ServiceUnavailable("The confirmation email could not be sent. Try again in a moment. If the account page then shows the change as already pending, cancel it and request it again.")
	case errors.Is(err, service.ErrInvalidEmail):
		return huma.Error422UnprocessableEntity("Email addresses must be plain 7-bit ASCII in user@host form, with no display name and no surrounding whitespace.")
	case errors.Is(err, store.ErrConflict):
		return huma.Error409Conflict("A user with that email address already exists.")
	default:
		deps.Log.LogAttrs(ctx, slog.LevelError, action+" failed", slog.Any("error", err))
		return huma.Error500InternalServerError("failed to " + action)
	}
}
