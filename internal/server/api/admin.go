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

// ---- user DTOs ----

// adminUserView is an admin's view of a user account: includes role,
// disabled state, and whether the account is linked to an OIDC identity —
// keyed off OIDCSubject now that local passwords are gone (design I5).
type adminUserView struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	Disabled   bool   `json:"disabled"`
	OIDCLinked bool   `json:"oidc_linked"` // true = account is linked to an OIDC identity
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
}

func newAdminUserView(u store.User) adminUserView {
	return adminUserView{
		ID: u.ID, Email: u.Email, Role: u.Role, Disabled: u.Disabled,
		OIDCLinked: u.OIDCSubject != "", CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
}

type listUsersOutput struct{ Body []adminUserView }

type createUserInput struct {
	Body struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
}

// deliveryView reports whether a minted grant link was emailed, so an API client
// learns the same thing the web UI shows. The raw transport error is deliberately
// absent: it can carry the SMTP host:port and belongs in the server log, not in a
// response body.
type deliveryView struct {
	Attempted bool   `json:"attempted"`
	Sent      bool   `json:"sent"`
	To        string `json:"to,omitempty"`
}

func newDeliveryView(d service.Delivery) deliveryView {
	return deliveryView{Attempted: d.Attempted, Sent: d.Sent(), To: d.To}
}

// createUserResponse carries the newly-created (credential-less) user plus
// the one-time invite link the admin shows the user out of band — the user
// registers their first passkey by redeeming it (design D15). Local password
// creation is gone: an admin-created account has no credential until the
// invite is redeemed. Delivery reports whether that link was also emailed; the
// link is valid and MUST be shown whatever Delivery says.
type createUserResponse struct {
	User     adminUserView `json:"user"`
	Link     string        `json:"link"`
	Delivery deliveryView  `json:"delivery"`
}
type createUserOutput struct{ Body createUserResponse }

// updateUserInput is the partial-update body of PATCH
// /api/v1/admin/users/{id}. A nil field means "leave unchanged".
type updateUserInput struct {
	ID   string `path:"id"`
	Body struct {
		Role     *string `json:"role,omitempty"`
		Disabled *bool   `json:"disabled,omitempty"`
	}
}
type updateUserOutput struct{ Body adminUserView }

type deleteUserInput struct {
	ID string `path:"id"`
}

// deleteUserOutput carries no body; huma emits 204 via DefaultStatus.
type deleteUserOutput struct{}

// issueRecoveryInput carries the {id} path parameter of POST
// /api/v1/admin/users/{id}/recovery.
type issueRecoveryInput struct {
	ID string `path:"id"`
}

// issueRecoveryResponse is the one-time registration-grant link an admin
// shows the user out of band (design §7's admin-recovery path), plus whether
// that link was also emailed. It stays a distinct type from
// createUserResponse: the two ops carry different payloads (this one has no
// user) and their shapes are free to diverge, so the only knowledge they
// share is deliveryView.
type issueRecoveryResponse struct {
	Link     string       `json:"link"`
	Delivery deliveryView `json:"delivery"`
}
type issueRecoveryOutput struct{ Body issueRecoveryResponse }

// ---- admin devices DTO (adds user_id to the non-secret device view) ----

// adminDeviceView embeds the owner-scoped deviceView and adds user_id — the
// one field an admin's cross-user view needs that an owner's own view
// (already scoped to their own devices) does not.
type adminDeviceView struct {
	deviceView
	UserID string `json:"user_id"`
}
type listAllDevicesOutput struct{ Body []adminDeviceView }

// ---- audit DTOs ----

type auditInput struct {
	ActorUserID string `query:"actor_user_id"`
	EventType   string `query:"event_type"`
	Since       int64  `query:"since"`
	Until       int64  `query:"until"`
	Cursor      string `query:"cursor"`
	Limit       int    `query:"limit"`
}
type auditRow struct {
	ID          int64  `json:"id"`
	ActorUserID string `json:"actor_user_id"`
	EventType   string `json:"event_type"`
	TargetType  string `json:"target_type"`
	TargetID    string `json:"target_id"`
	IP          string `json:"ip"`
	CreatedAt   int64  `json:"created_at"`
}
type auditResponse struct {
	Rows       []auditRow `json:"rows"`
	NextCursor string     `json:"next_cursor"`
}
type auditOutput struct{ Body auditResponse }

// ---- server-info DTO ----

// serverInfoOIDC surfaces the OIDC config fields that are safe to show an
// admin. ClientSecret is deliberately never a field here — omission by
// construction, not by a redaction step that could be forgotten.
type serverInfoOIDC struct {
	Enabled         bool     `json:"enabled"`
	Required        bool     `json:"required"`
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"client_id"`
	Scopes          []string `json:"scopes"`
	AutoLinkByEmail bool     `json:"auto_link_by_email"`
	AllowOIDCSignup bool     `json:"allow_oidc_signup"`
}
type serverInfoResponse struct {
	Version         string         `json:"version"`
	Commit          string         `json:"commit"`
	Date            string         `json:"date"`
	SkewWindowSecs  int64          `json:"skew_window_secs"`
	SessionCookie   string         `json:"session_cookie"`
	SessionSecure   bool           `json:"session_secure"`
	SessionSameSite string         `json:"session_samesite"`
	OIDC            serverInfoOIDC `json:"oidc"`
}
type serverInfoOutput struct{ Body serverInfoResponse }

// registerAdminOps registers the admin-role operations onto apiAPI: user
// management (list/create/update/delete), a cross-user device list, the
// audit log, and non-secret server info. Every op is session + admin gated;
// mutations additionally require CSRF.
func registerAdminOps(a huma.API, deps ServerDeps) {
	adminRead := func() huma.Middlewares {
		return huma.Middlewares{
			sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName),
			adminMiddleware(a),
		}
	}
	adminWrite := func() huma.Middlewares {
		return huma.Middlewares{
			sessionMiddleware(a, deps.Sessions, deps.Cfg.Session.CookieName),
			adminMiddleware(a),
			csrfMiddleware(a),
		}
	}

	huma.Register(a, huma.Operation{
		Method: http.MethodGet, Path: "/api/v1/admin/users", Middlewares: adminRead(),
	}, func(ctx context.Context, _ *struct{}) (*listUsersOutput, error) {
		users, err := deps.Admin.ListUsers(ctx)
		if err != nil {
			return nil, adminErr(ctx, deps, "list users", err)
		}
		views := make([]adminUserView, len(users))
		for i, u := range users {
			views[i] = newAdminUserView(u)
		}
		return &listUsersOutput{Body: views}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodPost, Path: "/api/v1/admin/users", DefaultStatus: http.StatusOK, Middlewares: adminWrite(),
	}, func(ctx context.Context, in *createUserInput) (*createUserOutput, error) {
		actor := UserFrom(ctx)
		u, link, delivery, err := deps.Admin.CreateUserInvite(ctx, actor.ID, in.Body.Email, in.Body.Role)
		if err != nil {
			return nil, adminErr(ctx, deps, "create user", err)
		}
		return &createUserOutput{Body: createUserResponse{
			User: newAdminUserView(u), Link: link, Delivery: newDeliveryView(delivery),
		}}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodPatch, Path: "/api/v1/admin/users/{id}", Middlewares: adminWrite(),
	}, func(ctx context.Context, in *updateUserInput) (*updateUserOutput, error) {
		actor := UserFrom(ctx)
		u, err := deps.Admin.UpdateUser(ctx, actor.ID, in.ID, service.UpdateUserParams{
			Role: in.Body.Role, Disabled: in.Body.Disabled,
		})
		if err != nil {
			return nil, adminErr(ctx, deps, "update user", err)
		}
		return &updateUserOutput{Body: newAdminUserView(u)}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodDelete, Path: "/api/v1/admin/users/{id}", DefaultStatus: http.StatusNoContent, Middlewares: adminWrite(),
	}, func(ctx context.Context, in *deleteUserInput) (*deleteUserOutput, error) {
		actor := UserFrom(ctx)
		if err := deps.Admin.DeleteUser(ctx, actor.ID, in.ID); err != nil {
			return nil, adminErr(ctx, deps, "delete user", err)
		}
		return &deleteUserOutput{}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodPost, Path: "/api/v1/admin/users/{id}/recovery", DefaultStatus: http.StatusOK, Middlewares: adminWrite(),
	}, func(ctx context.Context, in *issueRecoveryInput) (*issueRecoveryOutput, error) {
		actor := UserFrom(ctx)
		// The lookup keeps the 404-on-bad-id behavior consistent with this
		// file's other {id}-scoped endpoints, and supplies the store.User
		// IssueRecovery needs to address the delivery.
		target, err := deps.Store.Users().GetByID(ctx, in.ID)
		if err != nil {
			return nil, adminErr(ctx, deps, "issue recovery", err)
		}
		link, delivery, err := deps.Grants.IssueRecovery(ctx, actor.ID, target)
		if err != nil {
			return nil, adminErr(ctx, deps, "issue recovery", err)
		}
		return &issueRecoveryOutput{Body: issueRecoveryResponse{
			Link: link, Delivery: newDeliveryView(delivery),
		}}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodGet, Path: "/api/v1/admin/devices", Middlewares: adminRead(),
	}, func(ctx context.Context, _ *struct{}) (*listAllDevicesOutput, error) {
		devices, err := deps.Admin.ListAllDevices(ctx)
		if err != nil {
			return nil, adminErr(ctx, deps, "list all devices", err)
		}
		views := make([]adminDeviceView, len(devices))
		for i, d := range devices {
			views[i] = adminDeviceView{deviceView: newDeviceView(d), UserID: d.UserID}
		}
		return &listAllDevicesOutput{Body: views}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodGet, Path: "/api/v1/admin/audit", Middlewares: adminRead(),
	}, func(ctx context.Context, in *auditInput) (*auditOutput, error) {
		page, err := deps.Admin.ListAudit(ctx, store.AuditFilter{
			ActorUserID: in.ActorUserID, EventType: in.EventType, Since: in.Since, Until: in.Until,
		}, in.Cursor, in.Limit)
		if err != nil {
			return nil, adminErr(ctx, deps, "list audit", err)
		}
		rows := make([]auditRow, len(page.Rows))
		for i, e := range page.Rows {
			rows[i] = auditRow{
				ID: e.ID, ActorUserID: e.ActorUserID, EventType: e.EventType,
				TargetType: e.TargetType, TargetID: e.TargetID, IP: e.IP, CreatedAt: e.CreatedAt,
			}
		}
		return &auditOutput{Body: auditResponse{Rows: rows, NextCursor: page.NextCursor}}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodGet, Path: "/api/v1/admin/server", Middlewares: adminRead(),
	}, func(ctx context.Context, _ *struct{}) (*serverInfoOutput, error) {
		oidc := deps.Cfg.OIDC
		sess := deps.Cfg.Session
		return &serverInfoOutput{Body: serverInfoResponse{
			Version:         deps.Info.Version,
			Commit:          deps.Info.Commit,
			Date:            deps.Info.Date,
			SkewWindowSecs:  int64(deps.Cfg.HMAC.SkewWindow.Seconds()),
			SessionCookie:   sess.CookieName,
			SessionSecure:   sess.CookieSecure,
			SessionSameSite: sess.CookieSameSite,
			OIDC: serverInfoOIDC{
				Enabled: oidc.Enabled, Required: oidc.Required, Issuer: oidc.Issuer,
				ClientID: oidc.ClientID, Scopes: oidc.Scopes,
				AutoLinkByEmail: oidc.AutoLinkByEmail, AllowOIDCSignup: oidc.AllowOIDCSignup,
			},
		}}, nil
	})
}

// adminErr maps an AdminService error to the right huma response.
func adminErr(ctx context.Context, deps ServerDeps, action string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return huma.Error404NotFound("user not found")
	case errors.Is(err, store.ErrConflict):
		return huma.Error409Conflict("a user with that email already exists")
	case errors.Is(err, service.ErrLastAdmin):
		return huma.Error409Conflict("cannot remove the last admin")
	case errors.Is(err, service.ErrSelfLockout):
		return huma.Error409Conflict("cannot disable or delete your own account")
	case errors.Is(err, service.ErrInvalidRole):
		return huma.Error422UnprocessableEntity("role must be 'admin' or 'user'")
	case errors.Is(err, service.ErrInvalidEmail):
		return huma.Error422UnprocessableEntity("invalid email address")
	case errors.Is(err, service.ErrWebAuthnUnavailable):
		return huma.Error503ServiceUnavailable("passkey authentication is not configured")
	default:
		deps.Log.LogAttrs(ctx, slog.LevelError, action+" failed", slog.Any("error", err))
		return huma.Error500InternalServerError("failed to " + action)
	}
}
