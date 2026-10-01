package api

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// enrollErr maps a ConsumeCode error to the right huma response, mirroring
// passkeyErr and deviceMgmtErr's one-mapper-per-file convention. Order matters:
//
//   - store.ErrNotFound (unknown, expired, used, or lost to a concurrent
//     redeem) stays the uniform 401, so a caller cannot tell which; the service
//     has already logged the reason.
//   - store.ErrConflict can only come from Devices().Create, so it means the
//     code's label is already in use on the account: a state the user created,
//     not a bad code, so 409 (and the code is left unconsumed). The service
//     answers a code lost to a concurrent redeem with ErrNotFound (401), except
//     in a narrow window between the winner's insert and its consume, where the
//     loser also gets this 409.
//   - A cancelled request is the client's doing, not an infrastructure failure:
//     499, logged at Info.
//   - Anything else is a real failure: logged at Error, 500.
func enrollErr(ctx context.Context, deps ServerDeps, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return huma.Error401Unauthorized(errEnrollUnauthorized)
	case errors.Is(err, store.ErrConflict):
		return huma.Error409Conflict(errDeviceLabelTaken)
	case store.Cancelled(ctx, err):
		deps.Log.LogAttrs(ctx, slog.LevelInfo, "enroll device cancelled", slog.Any("error", err))
		return huma.NewError(statusClientClosedRequest, msgClientClosedRequest)
	default:
		deps.Log.LogAttrs(ctx, slog.LevelError, "enroll device failed", slog.Any("error", err))
		return huma.Error500InternalServerError("failed to enroll device")
	}
}

// errEnrollUnauthorized is the single message returned for every unusable
// code — invalid, expired, or already-used — so a client can never distinguish
// one failure mode from another (design §8, "a single 401 avoids leaking which
// state"). A taken label (409) and a real failure (500) are different
// answers; see enrollErr.
const errEnrollUnauthorized = "invalid enrollment code"

// enrollResponse is the body both enrollment operations return: the
// newly-created device's id and its plaintext HMAC secret, base64-encoded
// for JSON transport. The secret is shown exactly once — see
// service.EnrollResult.
type enrollResponse struct {
	DeviceID string `json:"device_id"`
	Secret   string `json:"secret"`
}

type enrollOutput struct {
	Body enrollResponse
}

// enrollCodeInput is the body of POST /agent/v1/enroll/code.
type enrollCodeInput struct {
	Body struct {
		Code string `json:"code"`
	}
}

// registerEnrollOps registers the unauthenticated agent enrollment operations
// onto a: POST /agent/v1/enroll/code and the OIDC device-code flow. Neither
// carries auth middleware — they are how a device obtains its HMAC secret in
// the first place. Email/password enrollment was removed with the Plan 10
// flip to passkeys + OIDC only.
func registerEnrollOps(a huma.API, deps ServerDeps) {
	huma.Post(a, "/agent/v1/enroll/code", func(ctx context.Context, in *enrollCodeInput) (*enrollOutput, error) {
		res, err := deps.Enroll.ConsumeCode(ctx, in.Body.Code, service.ClientMeta{})
		if err != nil {
			return nil, enrollErr(ctx, deps, err)
		}
		return &enrollOutput{Body: enrollResponse{
			DeviceID: res.DeviceID,
			Secret:   base64.StdEncoding.EncodeToString(res.Secret),
		}}, nil
	})

	registerEnrollOIDCOps(a, deps)
}
