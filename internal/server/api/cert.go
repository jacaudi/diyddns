package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/jacaudi/diyddns/internal/server/agenttls"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

// certInput is the body of POST /agent/v1/cert.
type certInput struct {
	Body struct {
		CSR string `json:"csr"`
	}
}

// certOutput is the issued certificate, its CA bundle and the agent URL the
// client should use from now on.
type certOutput struct {
	Body struct {
		Certificate string `json:"certificate"`
		CABundle    string `json:"ca_bundle"`
		AgentURL    string `json:"agent_url"`
	}
}

// registerCertOps registers POST /agent/v1/cert onto a; renewal is true on the
// agent listener (see CertService.Issue). mws carry the authentication for
// that listener (HMAC on the main port).
func registerCertOps(a huma.API, deps ServerDeps, renewal bool, mws huma.Middlewares) {
	huma.Register(a, huma.Operation{
		Method:      http.MethodPost,
		Path:        "/agent/v1/cert",
		Middlewares: mws,
	}, func(ctx context.Context, in *certInput) (*certOutput, error) {
		deviceID := DeviceIDFrom(ctx)
		issued, err := deps.Cert.Issue(ctx, deviceID, []byte(in.Body.CSR), renewal)
		if err != nil {
			return nil, certErr(ctx, deps, deviceID, err)
		}
		out := &certOutput{}
		out.Body.Certificate = issued.CertificatePEM
		out.Body.CABundle = issued.CABundlePEM
		out.Body.AgentURL = issued.AgentURL
		return out, nil
	})
}

// certErr maps a CertService.Issue error to its response. An unknown device
// (deleted after authenticating) is the uniform 401; a live certificate is the
// coded 409 the client turns into an operator hint.
func certErr(ctx context.Context, deps ServerDeps, deviceID string, err error) error {
	switch {
	case errors.Is(err, service.ErrCertAlreadyIssued):
		return newCodedError(http.StatusConflict, shared.CodeCertAlreadyIssued,
			"this device already has a live certificate; ask an admin to click Reset certificate for it")
	case errors.Is(err, agenttls.ErrBadCSR):
		return huma.Error400BadRequest("invalid CSR")
	case errors.Is(err, store.ErrNotFound):
		// The route is HMAC-signed, so the 401 names that credential (#191).
		h := http.Header{}
		h.Set(shared.HeaderWWWAuthenticate, shared.ChallengeHMAC)
		return huma.ErrorWithHeaders(huma.Error401Unauthorized("unauthorized"), h)
	default:
		deps.Log.LogAttrs(ctx, slog.LevelError, "issue device certificate failed",
			slog.String("device_id", deviceID), slog.Any("error", err))
		return huma.Error500InternalServerError("failed to issue certificate")
	}
}

// mtlsRequiredMW refuses the request with the coded 403 mtls_required. It is
// attached to the main port's check-in and self when agent.require_mtls is set,
// ahead of HMAC verification, and never calls next.
func mtlsRequiredMW(ctx huma.Context, _ func(huma.Context)) {
	_, w := humago.Unwrap(ctx)
	writeCodedError(w, newCodedError(http.StatusForbidden, shared.CodeMTLSRequired,
		"this server requires mTLS on the agent port: upgrade this client"))
}
