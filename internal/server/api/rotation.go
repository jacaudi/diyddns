package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

// rotationSecretInput is the body of POST /agent/v1/rotation/secret. It is the
// raw bytes, with no huma Body schema: the body carries a secret, and a schema
// validation failure (422) would quote the offending value.
type rotationSecretInput struct {
	RawBody []byte
}

// registerRotationOps registers POST /agent/v1/rotation/secret onto a: step 3 of
// a secret rotation, where the client proposes its new secret inside a request
// signed with the old one. mws carry the authentication for that listener.
func registerRotationOps(a huma.API, deps ServerDeps, mws huma.Middlewares) {
	huma.Register(a, huma.Operation{
		Method:        http.MethodPost,
		Path:          "/agent/v1/rotation/secret",
		DefaultStatus: http.StatusOK,
		Middlewares:   mws,
	}, func(ctx context.Context, in *rotationSecretInput) (*struct{}, error) {
		secret, err := decodeRotationSecret(in.RawBody)
		if err != nil {
			return nil, err
		}
		deviceID := DeviceIDFrom(ctx)
		if err := deps.Rotation.StorePendingSecret(ctx, deviceID, secret); err != nil {
			return nil, rotationErr(ctx, deps, deviceID, err)
		}
		return &struct{}{}, nil
	})
}

// decodeRotationSecret parses {"secret": "<standard base64>"} into the 32 raw
// bytes. Every failure is the same 400, and none of its text carries the input.
func decodeRotationSecret(raw []byte) ([]byte, error) {
	var body struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(raw, &body); err == nil {
		if secret, err := base64.StdEncoding.DecodeString(body.Secret); err == nil && len(secret) == shared.DeviceSecretLen {
			return secret, nil
		}
	}
	return nil, huma.Error400BadRequest("secret must be 32 bytes, standard base64")
}

// rotationErr maps a StorePendingSecret error to its response. An unknown
// device (deleted after authenticating) is the uniform 401, as in certErr. The
// logged error is wrapped service errors only: none of them carries the secret.
func rotationErr(ctx context.Context, deps ServerDeps, deviceID string, err error) error {
	switch {
	case errors.Is(err, service.ErrNoSecretRotationPending):
		return newCodedError(http.StatusConflict, shared.CodeNoSecretRotationPending,
			"no secret rotation is pending for this device")
	case errors.Is(err, store.ErrNotFound):
		// The route is HMAC-signed, so the 401 names that credential (#191).
		h := http.Header{}
		h.Set(shared.HeaderWWWAuthenticate, shared.ChallengeHMAC)
		return huma.ErrorWithHeaders(huma.Error401Unauthorized("unauthorized"), h)
	default:
		deps.Log.LogAttrs(ctx, slog.LevelError, "store pending secret failed",
			slog.String("device_id", deviceID), slog.Any("error", err))
		return huma.Error500InternalServerError("failed to store the pending secret")
	}
}
