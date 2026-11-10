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

// rotationTargetBody is the request body shared by the single-device and fleet
// rotation requests. huma rejects a target outside the enum with 422.
type rotationTargetBody struct {
	Target service.RotationTarget `json:"target" enum:"secret,cert,both"`
}

// rotationTrackView is one track of a device's pending rotation. A track with
// nothing pending is {"since":null,"status":null}.
type rotationTrackView struct {
	Since  *int64  `json:"since"`
	Status *string `json:"status"`
}

// rotationStateView is a device's pending rotation, per track.
type rotationStateView struct {
	Secret rotationTrackView `json:"secret"`
	Cert   rotationTrackView `json:"cert"`
}

// rotationCountsView is the outcome of a fleet rotation request. The noun of
// each count is a device.
type rotationCountsView struct {
	Marked          int `json:"marked"`
	AwaitingUpgrade int `json:"awaiting_upgrade"`
	AwaitingMTLS    int `json:"awaiting_mtls"`
	SkippedDisabled int `json:"skipped_disabled"`
}

type markRotationInput struct {
	ID   string `path:"id"`
	Body rotationTargetBody
}

type markRotationOutput struct{ Body rotationStateView }

type markAllRotationInput struct{ Body rotationTargetBody }

type markAllRotationOutput struct{ Body rotationCountsView }

type cancelRotationInput struct {
	ID string `path:"id"`
}

// cancelRotationOutput carries no body; huma emits 204 via DefaultStatus.
type cancelRotationOutput struct{}

// newRotationTrackView renders a track; nothing pending is the all-null view.
func newRotationTrackView(t service.TrackState) rotationTrackView {
	if t.Since == 0 {
		return rotationTrackView{}
	}
	return rotationTrackView{Since: new(t.Since), Status: new(string(t.Status))}
}

// registerAdminRotationOps registers the admin credential-rotation routes
// (#175): mark one device, mark every device, and cancel one device's rotation.
func registerAdminRotationOps(a huma.API, deps ServerDeps) {
	huma.Register(a, huma.Operation{
		Method: http.MethodPost, Path: "/api/v1/admin/devices/{id}/rotation", DefaultStatus: http.StatusOK, Middlewares: adminWriteMW(a, deps),
	}, adminMarkRotationHandler(deps))

	huma.Register(a, huma.Operation{
		Method: http.MethodPost, Path: "/api/v1/admin/devices/rotation", DefaultStatus: http.StatusOK, Middlewares: adminWriteMW(a, deps),
	}, adminMarkAllRotationHandler(deps))

	huma.Register(a, huma.Operation{
		Method: http.MethodDelete, Path: "/api/v1/admin/devices/{id}/rotation", DefaultStatus: http.StatusNoContent, Middlewares: adminWriteMW(a, deps),
	}, adminCancelRotationHandler(deps))
}

func adminMarkRotationHandler(deps ServerDeps) func(context.Context, *markRotationInput) (*markRotationOutput, error) {
	return func(ctx context.Context, in *markRotationInput) (*markRotationOutput, error) {
		dev, err := deps.Rotation.Mark(ctx, SessionFrom(ctx), in.ID, in.Body.Target)
		if err != nil {
			return nil, adminRotationErr(ctx, deps, "mark rotation", err)
		}
		s := service.RotationStateOf(dev)
		return &markRotationOutput{Body: rotationStateView{
			Secret: newRotationTrackView(s.Secret), Cert: newRotationTrackView(s.Cert),
		}}, nil
	}
}

func adminMarkAllRotationHandler(deps ServerDeps) func(context.Context, *markAllRotationInput) (*markAllRotationOutput, error) {
	return func(ctx context.Context, in *markAllRotationInput) (*markAllRotationOutput, error) {
		c, err := deps.Rotation.MarkAll(ctx, SessionFrom(ctx), in.Body.Target)
		if err != nil {
			return nil, adminRotationErr(ctx, deps, "mark rotation on all devices", err)
		}
		return &markAllRotationOutput{Body: rotationCountsView(c)}, nil
	}
}

func adminCancelRotationHandler(deps ServerDeps) func(context.Context, *cancelRotationInput) (*cancelRotationOutput, error) {
	return func(ctx context.Context, in *cancelRotationInput) (*cancelRotationOutput, error) {
		if err := deps.Rotation.Cancel(ctx, SessionFrom(ctx), in.ID); err != nil {
			return nil, adminRotationErr(ctx, deps, "cancel rotation", err)
		}
		return &cancelRotationOutput{}, nil
	}
}

// adminRotationErr maps a RotationService error to its HTTP problem. Anything not
// listed is logged here and answered with a generic 500. (Not named rotationErr:
// that is the agent step-3 mapper in rotation.go.)
func adminRotationErr(ctx context.Context, deps ServerDeps, action string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return huma.Error404NotFound("device not found")
	case errors.Is(err, service.ErrDeviceDisabled):
		return huma.Error409Conflict("device or its owner account is disabled")
	case errors.Is(err, service.ErrCertRotationUnavailable):
		return huma.Error409Conflict("certificate rotation needs the agent listener (agent.listen)")
	default:
		deps.Log.LogAttrs(ctx, slog.LevelError, action+" failed", slog.Any("error", err))
		return huma.Error500InternalServerError("failed to " + action)
	}
}
