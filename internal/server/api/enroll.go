package api

import (
	"context"
	"encoding/base64"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/server/service"
)

// errEnrollUnauthorized is the single message returned for every enrollment
// failure — invalid, expired, or already-used code — so a client can never
// distinguish one failure mode from another (design §8, "a single 401 avoids
// leaking which state").
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
			return nil, huma.Error401Unauthorized(errEnrollUnauthorized)
		}
		return &enrollOutput{Body: enrollResponse{
			DeviceID: res.DeviceID,
			Secret:   base64.StdEncoding.EncodeToString(res.Secret),
		}}, nil
	})

	registerEnrollOIDCOps(a, deps)
}
