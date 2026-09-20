package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/server/notify"
	"github.com/jacaudi/diyddns/internal/store"
)

// ---- notification endpoint DTOs ----

// endpointView is a notification endpoint's non-secret wire view — mirrors
// store.NotificationEndpoint minus SecretSealed (sealed key material, never
// serialized to a client).
type endpointView struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	URL       string `json:"url"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

func newEndpointView(e store.NotificationEndpoint) endpointView {
	return endpointView{
		ID: e.ID, Label: e.Label, URL: e.URL, Enabled: e.Enabled,
		CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt,
	}
}

type listEndpointsOutput struct{ Body []endpointView }

type createEndpointInput struct {
	Body struct {
		Label string `json:"label"`
		URL   string `json:"url"`
	}
}

// createEndpointResponse carries the newly created endpoint plus its signing
// secret, base64-encoded and shown to the caller exactly once — the REST
// counterpart of webui's once-only reveal (webui/endpoints.go's
// handleEndpointsCreate). The secret is never returned by any other
// operation and is never persisted or logged in the clear.
type createEndpointResponse struct {
	Endpoint endpointView `json:"endpoint"`
	Secret   string       `json:"secret"`
}
type createEndpointOutput struct{ Body createEndpointResponse }

// getEndpointInput carries the {id} path parameter shared by GET and POST
// .../test — the two operations whose input is nothing but an endpoint id.
// PATCH and DELETE each have their own distinct {id}-only input type
// (patchEndpointInput, deleteEndpointInput) rather than reusing this one, so
// each op's input shape stays free to diverge; PATCH's RESPONSE shape
// (getEndpointOutput, not this type) is what it shares with GET.
type getEndpointInput struct {
	ID string `path:"id"`
}
type getEndpointOutput struct{ Body endpointView }

// patchEndpointInput is the body of PATCH /api/v1/admin/endpoints/{id}. A
// nil Enabled means "leave unchanged" — same convention as
// devices.go's patchDeviceInput. Label and URL are immutable after creation
// (NotificationService exposes no rename/re-target operation), so Enabled
// is the only mutable member here, unlike patchDeviceInput's Label+Disabled
// pair.
type patchEndpointInput struct {
	ID   string `path:"id"`
	Body struct {
		Enabled *bool `json:"enabled,omitempty"`
	}
}

type deleteEndpointInput struct {
	ID string `path:"id"`
}

// deleteEndpointOutput carries no body; huma emits 204 via DefaultStatus.
type deleteEndpointOutput struct{}

// testEndpointOutput carries no body; a successful test send is reported by
// its 200 status alone. Refusal (the endpoint is disabled) is reported as an
// error, not a body field — see registerNotificationOps.
type testEndpointOutput struct{}

// ---- notification delivery DTO ----

// redeliverInput carries the {id} path parameter of POST
// /api/v1/admin/deliveries/{id}/redeliver. Delivery ids are int64
// (store.NotificationDelivery.ID); an id that doesn't parse as one fails
// huma's own path-parameter binding with 422, rather than the 404
// webui's handleDeliveryRedeliver returns for the same case — a deliberate
// divergence, since huma validates path-parameter shape before this
// operation's function ever runs, and this surface has no reason to
// hand-parse what huma already parses.
type redeliverInput struct {
	ID int64 `path:"id"`
}

// redeliverOutput carries no body; a successful redeliver is reported by its
// 200 status alone.
type redeliverOutput struct{}

// registerNotificationOps registers the outbound-webhook admin operations
// (#152): notification-endpoint list/create/get/enable-disable/delete, a
// one-off test delivery, and delivery redeliver. Every op is session + admin
// gated via adminReadMW/adminWriteMW (authmw.go) — the same helpers
// registerAdminOps uses. Callers register this group only when deps.Notify is
// non-nil (see Build).
func registerNotificationOps(a huma.API, deps ServerDeps) {
	huma.Register(a, huma.Operation{
		Method:      http.MethodGet,
		Path:        "/api/v1/admin/endpoints",
		Middlewares: adminReadMW(a, deps),
		Summary:     "List notification endpoints",
		Description: "Lists every admin-configured outbound webhook endpoint (#106). Endpoints are server-global, not per-user.",
	}, func(ctx context.Context, _ *struct{}) (*listEndpointsOutput, error) {
		eps, err := deps.Notify.List(ctx)
		if err != nil {
			return nil, notifyErr(ctx, deps, "list notification endpoints", err)
		}
		views := make([]endpointView, len(eps))
		for i, e := range eps {
			views[i] = newEndpointView(e)
		}
		return &listEndpointsOutput{Body: views}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/admin/endpoints",
		DefaultStatus: http.StatusOK,
		Middlewares:   adminWriteMW(a, deps),
		Summary:       "Create a notification endpoint",
		Description:   "Creates a new outbound webhook endpoint and mints its signing secret. The secret is shown exactly once in this response and cannot be retrieved again.",
	}, func(ctx context.Context, in *createEndpointInput) (*createEndpointOutput, error) {
		actor := UserFrom(ctx)
		label := strings.TrimSpace(in.Body.Label)
		if label == "" {
			return nil, huma.Error422UnprocessableEntity("label must not be empty")
		}
		ep, secret, err := deps.Notify.Create(ctx, actor.ID, label, strings.TrimSpace(in.Body.URL))
		if err != nil {
			return nil, notifyErr(ctx, deps, "create notification endpoint", err)
		}
		return &createEndpointOutput{Body: createEndpointResponse{
			Endpoint: newEndpointView(ep), Secret: secret,
		}}, nil
	})

	huma.Register(a, huma.Operation{
		Method:      http.MethodGet,
		Path:        "/api/v1/admin/endpoints/{id}",
		Middlewares: adminReadMW(a, deps),
		Summary:     "Get a notification endpoint",
	}, func(ctx context.Context, in *getEndpointInput) (*getEndpointOutput, error) {
		ep, err := deps.Notify.Get(ctx, in.ID)
		if err != nil {
			return nil, notifyErr(ctx, deps, "get notification endpoint", err)
		}
		return &getEndpointOutput{Body: newEndpointView(ep)}, nil
	})

	huma.Register(a, huma.Operation{
		Method:      http.MethodPatch,
		Path:        "/api/v1/admin/endpoints/{id}",
		Middlewares: adminWriteMW(a, deps),
		Summary:     "Enable or disable a notification endpoint",
		Description: "Toggles whether the endpoint receives outbound deliveries. Label and URL are immutable after creation and are not settable here.",
	}, func(ctx context.Context, in *patchEndpointInput) (*getEndpointOutput, error) {
		actor := UserFrom(ctx)
		if in.Body.Enabled != nil {
			if err := deps.Notify.SetEnabled(ctx, actor.ID, in.ID, *in.Body.Enabled); err != nil {
				return nil, notifyErr(ctx, deps, "set notification endpoint enabled", err)
			}
		}
		ep, err := deps.Notify.Get(ctx, in.ID)
		if err != nil {
			return nil, notifyErr(ctx, deps, "get notification endpoint", err)
		}
		return &getEndpointOutput{Body: newEndpointView(ep)}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodDelete,
		Path:          "/api/v1/admin/endpoints/{id}",
		DefaultStatus: http.StatusNoContent,
		Middlewares:   adminWriteMW(a, deps),
		Summary:       "Delete a notification endpoint",
		Description:   "Deletes the endpoint and also removes its delivery history.",
	}, func(ctx context.Context, in *deleteEndpointInput) (*deleteEndpointOutput, error) {
		actor := UserFrom(ctx)
		if err := deps.Notify.Delete(ctx, actor.ID, in.ID); err != nil {
			return nil, notifyErr(ctx, deps, "delete notification endpoint", err)
		}
		return &deleteEndpointOutput{}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/admin/endpoints/{id}/test",
		DefaultStatus: http.StatusOK,
		Middlewares:   adminWriteMW(a, deps),
		Summary:       "Send a test delivery",
		Description:   "Enqueues one on-demand endpoint.test delivery attempt against the endpoint. Fails with 409 when the endpoint is disabled.",
	}, func(ctx context.Context, in *getEndpointInput) (*testEndpointOutput, error) {
		actor := UserFrom(ctx)
		sent, err := deps.Notify.Test(ctx, actor.ID, in.ID)
		if err != nil {
			return nil, notifyErr(ctx, deps, "send notification test", err)
		}
		if !sent {
			// Test's atomic INSERT refuses for one of two reasons, collapsed
			// into a single false — the same one-refusal collapse
			// webui/endpoints.go's endpointActionRefusedMessage documents:
			// the endpoint does not exist, or it exists but is disabled
			// (store.NotificationDeliveryRepo.InsertUserTest's doc). A
			// follow-up Get classifies WHICH one only now, after the
			// refusal — never before it: calling Get first (and trusting it)
			// would let the endpoint be deleted in the gap between that Get
			// and this Test, misreporting a gone endpoint as merely
			// "disabled" (409) instead of 404. Classifying after Test
			// instead reads the endpoint's state no earlier than Test's own
			// atomic check did, so the two calls can never disagree about
			// whether the endpoint still exists.
			if _, err := deps.Notify.Get(ctx, in.ID); err != nil {
				return nil, notifyErr(ctx, deps, "send notification test", err)
			}
			return nil, huma.Error409Conflict("notification endpoint is disabled")
		}
		return &testEndpointOutput{}, nil
	})

	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/api/v1/admin/deliveries/{id}/redeliver",
		DefaultStatus: http.StatusOK,
		Middlewares:   adminWriteMW(a, deps),
		Summary:       "Redeliver a notification delivery",
		Description:   "Re-arms a terminal (failed or delivered) delivery as a new attempt, preserving the original row's history.",
	}, func(ctx context.Context, in *redeliverInput) (*redeliverOutput, error) {
		actor := UserFrom(ctx)
		ok, err := deps.Notify.Redeliver(ctx, actor.ID, in.ID)
		if err != nil {
			return nil, notifyErr(ctx, deps, "redeliver notification delivery", err)
		}
		if !ok {
			// Redeliver folds "doesn't exist", "not terminal", and "its
			// endpoint is disabled" into one ok=false — the same
			// one-refusal collapse webui's deliveryRedeliverRefusedMessage
			// documents.
			return nil, huma.Error404NotFound("delivery not found, not in a retryable state, or its endpoint is disabled")
		}
		return &redeliverOutput{}, nil
	})
}

// notifyErr maps a NotificationService error to the right huma response: a
// missing endpoint → 404, a URL conflict → 409, a rejected target → 422 with
// the same actionable text webui shows (webui/endpoints.go's
// createErrorMessage documents why store.ErrConflict and notify.ErrDenied
// are the only two causes proven not to carry raw internal detail),
// everything else → logged 500.
func notifyErr(ctx context.Context, deps ServerDeps, action string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return huma.Error404NotFound("notification endpoint not found")
	case errors.Is(err, store.ErrConflict):
		return huma.Error409Conflict("an endpoint with that URL already exists")
	case errors.Is(err, notify.ErrDenied):
		return huma.Error422UnprocessableEntity("that target was rejected: " + strings.TrimPrefix(err.Error(), "service.Create: "))
	default:
		deps.Log.LogAttrs(ctx, slog.LevelError, action+" failed", slog.Any("error", err))
		return huma.Error500InternalServerError("failed to " + action)
	}
}
