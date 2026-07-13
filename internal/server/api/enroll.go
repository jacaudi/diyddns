package api

import (
	"context"
	"encoding/base64"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/server/service"
)

// errEnrollUnauthorized is the single message returned for every enrollment
// failure — invalid/expired/used code, unknown email, disabled account, or
// wrong password — so a client can never distinguish one failure mode from
// another (design §8, "a single 401 avoids leaking which state").
const errEnrollUnauthorized = "invalid enrollment code or credentials"

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

// enrollCredentialsInput is the body of POST /agent/v1/enroll/credentials.
// Hostname/OS/ClientVersion are optional device metadata.
type enrollCredentialsInput struct {
	Body struct {
		Email         string `json:"email"`
		Password      string `json:"password"`
		Hostname      string `json:"hostname,omitempty"`
		OS            string `json:"os,omitempty"`
		ClientVersion string `json:"client_version,omitempty"`
	}
}

// registerEnrollOps registers the two unauthenticated agent enrollment
// operations onto a: POST /agent/v1/enroll/code and
// POST /agent/v1/enroll/credentials. Neither carries auth middleware — they
// are how a device obtains its HMAC secret in the first place.
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

	huma.Post(a, "/agent/v1/enroll/credentials", func(ctx context.Context, in *enrollCredentialsInput) (*enrollOutput, error) {
		res, err := deps.Enroll.EnrollCredentials(ctx, in.Body.Email, in.Body.Password, service.ClientMeta{
			Hostname:      in.Body.Hostname,
			OS:            in.Body.OS,
			ClientVersion: in.Body.ClientVersion,
		})
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
