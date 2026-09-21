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

// feedTokenView is the admin-visible feed-token row: everything but the
// secret. CreatedBy is the minting admin's raw user ID rather than the email
// webui/feed.go's feedTokenRow resolves it to — this package's other admin
// views (e.g. adminDeviceView.UserID) return IDs, not cross-entity lookups,
// and there is no present REST consumer asking for the resolved email.
type feedTokenView struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	CreatedBy  string `json:"created_by" doc:"User ID of the minting admin; empty if that user has since been deleted."`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt int64  `json:"last_used_at"`
}

func newFeedTokenView(t store.FeedToken) feedTokenView {
	return feedTokenView{
		ID: t.ID, Label: t.Label, CreatedBy: t.CreatedBy,
		CreatedAt: t.CreatedAt, LastUsedAt: t.LastUsedAt,
	}
}

type listFeedTokensOutput struct{ Body []feedTokenView }

// mintFeedTokenInput is the body of POST /api/v1/admin/feed/tokens.
type mintFeedTokenInput struct {
	Body struct {
		Label string `json:"label"`
	}
}

// mintFeedTokenResponse carries the freshly-minted token's plaintext secret,
// shown exactly once (mirrors devices.go's rotateSecretResponse and
// mintCodeResponse — see service.FeedService.MintToken's doc comment).
// Token is a named field, not an embedded feedTokenView, matching
// admin.go's createUserResponse/issueRecoveryResponse convention for scalar
// (object) response bodies: huma's SchemaLinkTransformer only inspects a
// struct's own top-level fields' export bit, and an anonymously-embedded
// field named after an unexported type (feedTokenView) reports as
// unexported, so its promoted fields get silently dropped from the wire
// response. adminDeviceView's embedding avoids this only because it backs an
// array body, which the transformer skips entirely.
type mintFeedTokenResponse struct {
	Token  feedTokenView `json:"token"`
	Secret string        `json:"secret"`
}
type mintFeedTokenOutput struct{ Body mintFeedTokenResponse }

// revokeFeedTokenInput carries the {id} path parameter of DELETE
// /api/v1/admin/feed/tokens/{id}.
type revokeFeedTokenInput struct {
	ID string `path:"id"`
}

// revokeFeedTokenOutput carries no body; huma emits 204 via DefaultStatus.
type revokeFeedTokenOutput struct{}

// registerFeedTokenOps registers admin management of the feed's own bearer
// token onto apiAPI: mint, list, revoke — the REST equivalent of
// webui/feed.go's handleAdminFeed/handleFeedTokenMint/handleFeedTokenRevoke,
// backed by the same service.FeedService (issue #153). Every op is session +
// admin gated; mutations additionally require CSRF, matching the rest of
// /api/v1/admin/*. Build only calls this when deps.FeedEnabled is true.
func registerFeedTokenOps(a huma.API, deps ServerDeps) {
	// feedRead/feedWrite restate admin.go's registerAdminOps' adminRead()/
	// adminWrite() closures verbatim (session-or-key+admin, and
	// session-or-key+admin+CSRF).
	// Tolerated as a second copy per this codebase's Rule of Three convention
	// (authmw.go's *MW helpers exist for exactly this reason) — but a THIRD
	// copy anywhere should trigger hoisting adminRead(a, deps)/adminWrite(a,
	// deps) into authmw.go next to the existing *MW helpers, rather than a
	// fourth restatement.
	feedRead := huma.Middlewares{
		sessionOrKeyMW(a, deps),
		adminMW(a, deps),
	}
	feedWrite := huma.Middlewares{
		sessionOrKeyMW(a, deps),
		adminMW(a, deps),
		csrfMW(a, deps),
	}

	huma.Register(a, huma.Operation{
		Method: http.MethodGet, Path: "/api/v1/admin/feed/tokens", Middlewares: feedRead,
	}, func(ctx context.Context, _ *struct{}) (*listFeedTokensOutput, error) {
		toks, err := deps.Feed.ListTokens(ctx)
		if err != nil {
			return nil, feedTokenErr(ctx, deps, "list feed tokens", err)
		}
		views := make([]feedTokenView, len(toks))
		for i, t := range toks {
			views[i] = newFeedTokenView(t)
		}
		return &listFeedTokensOutput{Body: views}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodPost, Path: "/api/v1/admin/feed/tokens", DefaultStatus: http.StatusOK, Middlewares: feedWrite,
	}, func(ctx context.Context, in *mintFeedTokenInput) (*mintFeedTokenOutput, error) {
		actor := UserFrom(ctx)
		tok, plaintext, err := deps.Feed.MintToken(ctx, actor.ID, in.Body.Label)
		if err != nil {
			return nil, feedTokenErr(ctx, deps, "mint feed token", err)
		}
		return &mintFeedTokenOutput{Body: mintFeedTokenResponse{
			Token: newFeedTokenView(tok), Secret: plaintext,
		}}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodDelete, Path: "/api/v1/admin/feed/tokens/{id}", DefaultStatus: http.StatusNoContent, Middlewares: feedWrite,
	}, func(ctx context.Context, in *revokeFeedTokenInput) (*revokeFeedTokenOutput, error) {
		actor := UserFrom(ctx)
		if err := deps.Feed.RevokeToken(ctx, actor.ID, in.ID); err != nil {
			return nil, feedTokenErr(ctx, deps, "revoke feed token", err)
		}
		return &revokeFeedTokenOutput{}, nil
	})
}

// feedTokenErr maps a FeedService error to the right huma response.
func feedTokenErr(ctx context.Context, deps ServerDeps, action string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return huma.Error404NotFound("feed token not found")
	case errors.Is(err, store.ErrConflict):
		return huma.Error409Conflict("a feed token with that label already exists")
	case errors.Is(err, service.ErrInvalidLabel):
		return huma.Error422UnprocessableEntity("label must not be empty")
	default:
		deps.Log.LogAttrs(ctx, slog.LevelError, action+" failed", slog.Any("error", err))
		return huma.Error500InternalServerError("failed to " + action)
	}
}
