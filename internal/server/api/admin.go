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

// getUserInput carries the {id} path parameter of GET
// /api/v1/admin/users/{id} -- mirrors deleteUserInput's shape exactly.
type getUserInput struct {
	ID string `path:"id"`
}

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
	// Suppressed names a deliberate decision not to send, as opposed to "no
	// mailer configured" — both of which have attempted == false. Absent from
	// the JSON in the common case (omitempty on the zero value), so existing
	// clients see no change.
	Suppressed string `json:"suppressed,omitempty"`
}

func newDeliveryView(d service.Delivery) deliveryView {
	return deliveryView{
		Attempted:  d.Attempted,
		Sent:       d.Sent(),
		To:         d.To,
		Suppressed: string(d.Suppressed),
	}
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

// patchUserEmailInput is the body of PATCH /api/v1/admin/users/{id}/email --
// a dedicated operation, not a merge into updateUserInput: email's
// validation/conflict surface is richer than Role/Disabled's two scalars, so
// it stays separate (mirrors updateUserInput's ID+Body shape).
type patchUserEmailInput struct {
	ID   string `path:"id"`
	Body struct {
		Email string `json:"email"`
	}
}

// adminSetEmailOutput wraps AdminSet's two return values (store.User,
// Delivery) directly.
type adminSetEmailOutput struct {
	Body struct {
		User     adminUserView `json:"user"`
		Delivery deliveryView  `json:"delivery"`
	}
}

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

// listAllDeviceIPsResponse is the deduplicated, current IP address set
// across every device CURRENTLY IN THE GATEWAY FEED (#150) -- squashed to
// unique addresses, not a per-device listing, and scoped by the exact same
// membership predicate as /feed/v1/devices.json's cidrs field (store's
// ListFeed: enabled device, enabled owner, at least one address -- design
// #106 D18). A disabled device (or one whose owner is disabled) is excluded
// here exactly as it is from devices.json, not merely omitted by coincidence:
// its stored address is frozen forever once disabled (HMAC auth rejects it
// outright, and the staleness sweep skips disabled devices/owners too), so
// including it would mix an unbounded staleness guarantee into a response
// whose whole point is devices.json's data without needing a feed token.
// Field name and CIDR format (/32, /128) deliberately mirror devices.json's
// cidrs field: same conceptual data, a different transport and audience
// (session-authed admin REST here vs the feed's bearer-token REST for
// firewalls/WAFs). Both render an address through store.CIDRString, so the
// two can never diverge on format.
type listAllDeviceIPsResponse struct {
	CIDRs []string `json:"cidrs"`
}
type listAllDeviceIPsOutput struct{ Body listAllDeviceIPsResponse }

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
// management (list/create/update/delete), a cross-user device list, a
// deduplicated IP list scoped to the gateway feed's membership (#150, mirrors
// /feed/v1/devices.json's cidrs field -- see listAllDeviceIPsResponse), the
// audit log, and non-secret server info. Every op is session + admin gated;
// mutations additionally require CSRF.
func registerAdminOps(a huma.API, deps ServerDeps) {
	huma.Register(a, huma.Operation{
		Method: http.MethodGet, Path: "/api/v1/admin/users", Middlewares: adminReadMW(a, deps),
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
		Method: http.MethodGet, Path: "/api/v1/admin/users/{id}", Middlewares: adminReadMW(a, deps),
	}, func(ctx context.Context, in *getUserInput) (*updateUserOutput, error) {
		// Same store call issueRecovery's handler already makes for the
		// identical reason (single-user-by-id lookup with 404 on miss).
		u, err := deps.Store.Users().GetByID(ctx, in.ID)
		if err != nil {
			return nil, adminErr(ctx, deps, "get user", err)
		}
		return &updateUserOutput{Body: newAdminUserView(u)}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodPost, Path: "/api/v1/admin/users", DefaultStatus: http.StatusOK, Middlewares: adminWriteMW(a, deps),
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
		Method: http.MethodPatch, Path: "/api/v1/admin/users/{id}", Middlewares: adminWriteMW(a, deps),
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
		Method: http.MethodPatch, Path: "/api/v1/admin/users/{id}/email", Middlewares: adminWriteMW(a, deps),
	}, adminSetUserEmailHandler(deps))

	huma.Register(a, huma.Operation{
		Method: http.MethodDelete, Path: "/api/v1/admin/users/{id}", DefaultStatus: http.StatusNoContent, Middlewares: adminWriteMW(a, deps),
	}, func(ctx context.Context, in *deleteUserInput) (*deleteUserOutput, error) {
		actor := UserFrom(ctx)
		if err := deps.Admin.DeleteUser(ctx, actor.ID, in.ID); err != nil {
			return nil, adminErr(ctx, deps, "delete user", err)
		}
		return &deleteUserOutput{}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodPost, Path: "/api/v1/admin/users/{id}/recovery", DefaultStatus: http.StatusOK, Middlewares: adminWriteMW(a, deps),
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
		Method: http.MethodGet, Path: "/api/v1/admin/devices", Middlewares: adminReadMW(a, deps),
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
		Method: http.MethodGet, Path: "/api/v1/admin/devices/ips", Middlewares: adminReadMW(a, deps),
	}, func(ctx context.Context, _ *struct{}) (*listAllDeviceIPsOutput, error) {
		addrs, err := deps.Admin.ListAllDeviceIPs(ctx)
		if err != nil {
			return nil, adminErr(ctx, deps, "list device ips", err)
		}
		cidrs := make([]string, len(addrs))
		for i, a := range addrs {
			cidrs[i] = store.CIDRString(a)
		}
		return &listAllDeviceIPsOutput{Body: listAllDeviceIPsResponse{CIDRs: cidrs}}, nil
	})

	huma.Register(a, huma.Operation{
		Method: http.MethodGet, Path: "/api/v1/admin/audit", Middlewares: adminReadMW(a, deps),
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
		Method: http.MethodGet, Path: "/api/v1/admin/server", Middlewares: adminReadMW(a, deps),
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

// adminSetUserEmailHandler builds the handler for PATCH
// /api/v1/admin/users/{id}/email. Extracted to a named function -- unlike
// this file's other ops, which inline their handler directly in the
// huma.Register call -- solely to keep registerAdminOps under the repo's
// gocyclo ceiling (.golangci.yml min-complexity: 15): this op's two chained
// lookups (GetByID, then AdminSet) each need their own error branch, and
// inlining both pushed registerAdminOps to 17.
func adminSetUserEmailHandler(deps ServerDeps) func(context.Context, *patchUserEmailInput) (*adminSetEmailOutput, error) {
	return func(ctx context.Context, in *patchUserEmailInput) (*adminSetEmailOutput, error) {
		actor := UserFrom(ctx)
		// AdminSet needs the full store.User, not just its id; the lookup also
		// keeps the 404-on-bad-id behavior consistent with this file's other
		// {id}-scoped endpoints.
		target, err := deps.Store.Users().GetByID(ctx, in.ID)
		if err != nil {
			return nil, adminErr(ctx, deps, "set user email", err)
		}
		updated, delivery, err := deps.EmailChange.AdminSet(ctx, actor.ID, target, in.Body.Email)
		if err != nil {
			return nil, adminErr(ctx, deps, "set user email", err)
		}
		out := &adminSetEmailOutput{}
		out.Body.User = newAdminUserView(updated)
		out.Body.Delivery = newDeliveryView(delivery)
		return out, nil
	}
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
		return huma.Error422UnprocessableEntity("email address must be a plain 7-bit ASCII address in user@host form, with no display name and no surrounding whitespace")
	case errors.Is(err, service.ErrEmailUnchanged):
		return huma.Error422UnprocessableEntity("That is already the account's email address.")
	case errors.Is(err, service.ErrEmailManagedByOIDC):
		return huma.Error422UnprocessableEntity("This account's email address is managed by its identity provider.")
	case errors.Is(err, service.ErrWebAuthnUnavailable):
		return huma.Error503ServiceUnavailable("passkey authentication is not configured")
	default:
		deps.Log.LogAttrs(ctx, slog.LevelError, action+" failed", slog.Any("error", err))
		return huma.Error500InternalServerError("failed to " + action)
	}
}
