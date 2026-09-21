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

// apiKeyView is the account-visible API key row: everything but the secret.
// Unlike feedTokenView (which returns the minting admin's user ID, since a
// feed token isn't owned by any one user), an API key's owner is always the
// caller, so no owner field is needed here at all.
type apiKeyView struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt int64  `json:"last_used_at"`
}

func newAPIKeyView(k store.APIKey) apiKeyView {
	return apiKeyView{ID: k.ID, Label: k.Label, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt}
}

type listAPIKeysOutput struct{ Body []apiKeyView }

// mintAPIKeyInput is the body of POST /api/v1/account/keys.
type mintAPIKeyInput struct {
	Body struct {
		Label string `json:"label"`
	}
}

// mintAPIKeyResponse carries the freshly-minted key's plaintext secret,
// shown exactly once (design D8). Key is a named field, not an embedded
// apiKeyView, for the identical reason mintFeedTokenResponse uses one
// (feed.go's doc comment has the full huma.SchemaLinkTransformer
// explanation): an anonymously-embedded field named after an unexported
// type reports as unexported, silently dropping every field but one.
type mintAPIKeyResponse struct {
	Key    apiKeyView `json:"key"`
	Secret string     `json:"secret"`
}
type mintAPIKeyOutput struct{ Body mintAPIKeyResponse }

// revokeAPIKeyInput carries the {id} path parameter of DELETE
// /api/v1/account/keys/{id}.
type revokeAPIKeyInput struct {
	ID string `path:"id"`
}

// revokeAPIKeyOutput carries no body; huma emits 204 via DefaultStatus.
type revokeAPIKeyOutput struct{}

// registerAPIKeyOps registers mint/list/revoke of the caller's own API keys
// onto apiAPI (design D8, D4). Every op is session+CSRF gated ONLY --
// sessionOrKeyMW is never wired here, structurally, so no API key of any
// scope can ever manage API keys (design D4).
func registerAPIKeyOps(a huma.API, deps ServerDeps) {
	sessionCSRF := huma.Middlewares{
		sessionMW(a, deps),
		csrfMW(a, deps),
	}

	huma.Register(a, huma.Operation{
		Method: http.MethodGet, Path: "/api/v1/account/keys", Middlewares: huma.Middlewares{sessionMW(a, deps)},
	}, func(ctx context.Context, _ *struct{}) (*listAPIKeysOutput, error) {
		u := UserFrom(ctx)
		keys, err := deps.APIKeys.ListKeys(ctx, u.ID)
		if err != nil {
			return nil, apiKeyErr(ctx, deps, "list api keys", err)
		}
		views := make([]apiKeyView, len(keys))
		for i, k := range keys {
			views[i] = newAPIKeyView(k)
		}
		return &listAPIKeysOutput{Body: views}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodPost, Path: "/api/v1/account/keys", DefaultStatus: http.StatusOK, Middlewares: sessionCSRF,
	}, func(ctx context.Context, in *mintAPIKeyInput) (*mintAPIKeyOutput, error) {
		u := UserFrom(ctx)
		key, plaintext, err := deps.APIKeys.MintKey(ctx, u.ID, in.Body.Label)
		if err != nil {
			return nil, apiKeyErr(ctx, deps, "mint api key", err)
		}
		return &mintAPIKeyOutput{Body: mintAPIKeyResponse{
			Key: newAPIKeyView(key), Secret: plaintext,
		}}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodDelete, Path: "/api/v1/account/keys/{id}", DefaultStatus: http.StatusNoContent, Middlewares: sessionCSRF,
	}, func(ctx context.Context, in *revokeAPIKeyInput) (*revokeAPIKeyOutput, error) {
		u := UserFrom(ctx)
		if err := deps.APIKeys.RevokeKey(ctx, u.ID, in.ID); err != nil {
			return nil, apiKeyErr(ctx, deps, "revoke api key", err)
		}
		return &revokeAPIKeyOutput{}, nil
	})
}

// apiKeyErr maps an APIKeyService error to the right huma response.
func apiKeyErr(ctx context.Context, deps ServerDeps, action string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return huma.Error404NotFound("api key not found")
	case errors.Is(err, store.ErrConflict):
		return huma.Error409Conflict("an api key with that label already exists")
	case errors.Is(err, service.ErrInvalidKeyLabel):
		return huma.Error422UnprocessableEntity("label must not be empty")
	default:
		deps.Log.LogAttrs(ctx, slog.LevelError, action+" failed", slog.Any("error", err))
		return huma.Error500InternalServerError("failed to " + action)
	}
}
