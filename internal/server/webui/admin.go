package webui

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// userRow is one row of the admin users list.
type userRow struct {
	ID       string
	Email    string
	Role     string
	Disabled bool
	Auth     string // "OIDC" | "Passkey"
	IsSelf   bool
	// LastAdmin marks the only enabled admin, so the UI can disable the
	// controls that AdminService would reject anyway. Advisory only — the
	// service guard remains authoritative.
	LastAdmin bool
}

// adminUsersData is admin-users.html's template data.
type adminUsersData struct {
	appData
	Users         []userRow
	UserCount     int
	DeviceCount   int
	DisabledCount int
	Error         string
}

// authLabel derives how an account authenticates, matching the JSON API's
// adminUserView.OIDCLinked derivation. An invited-but-unredeemed user has no
// credential at all and still reads "Passkey" here; distinguishing that needs a
// per-user credential count with no service wrapper, and is deliberately not
// done (design open question 1).
func authLabel(u store.User) string {
	if u.OIDCSubject != "" {
		return "OIDC"
	}
	return "Passkey"
}

// handleAdminUsers renders the admin users list with its three stat tiles.
func (h *handler) handleAdminUsers(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	h.renderAdminUsers(w, r, usr, sess, http.StatusOK, "")
}

// renderAdminUsers renders the list at an explicit status, so a rejected
// mutation can re-render it with a banner instead of redirecting.
func (h *handler) renderAdminUsers(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session, status int, errMsg string) {
	users, err := h.deps.Admin.ListUsers(r.Context())
	if err != nil {
		h.logAndFail(w, r, usr, "list users", err)
		return
	}
	devices, err := h.deps.Admin.ListAllDevices(r.Context())
	if err != nil {
		h.logAndFail(w, r, usr, "list all devices", err)
		return
	}

	enabledAdmins := 0
	var lastAdminID string
	for _, u := range users {
		if u.Role == "admin" && !u.Disabled {
			enabledAdmins++
			lastAdminID = u.ID
		}
	}

	rows := make([]userRow, 0, len(users))
	disabled := 0
	for _, u := range users {
		if u.Disabled {
			disabled++
		}
		rows = append(rows, userRow{
			ID: u.ID, Email: u.Email, Role: u.Role, Disabled: u.Disabled,
			Auth:      authLabel(u),
			IsSelf:    u.ID == usr.ID,
			LastAdmin: enabledAdmins == 1 && u.ID == lastAdminID,
		})
	}

	h.renderStatus(w, r, status, "admin-users", adminUsersData{
		appData:       h.newAppData(usr, sess, "Users", "admin-users"),
		Users:         rows,
		UserCount:     len(users),
		DeviceCount:   len(devices),
		DisabledCount: disabled,
		Error:         errMsg,
	})
}

// adminUser resolves an {id}-scoped admin target.
//
// AdminService has no single-user getter and this package holds no *store.Store,
// so the target is filtered out of ListUsers and the 404 is synthesized here —
// nothing on this path returns store.ErrNotFound. O(users) per request is
// correct at this scale; if the user count grows, add AdminService.GetUser
// rather than reaching past the service layer.
func (h *handler) adminUser(w http.ResponseWriter, r *http.Request, usr store.User) (store.User, []store.User, bool) {
	users, err := h.deps.Admin.ListUsers(r.Context())
	if err != nil {
		h.logAndFail(w, r, usr, "list users", err)
		return store.User{}, nil, false
	}
	target, ok := findUser(users, r.PathValue("id"))
	if !ok {
		h.renderError(w, r, usr, http.StatusNotFound, "That user does not exist.")
		return store.User{}, nil, false
	}
	return target, users, true
}

// handleAdminUserSetEnabled toggles a user's disabled flag from the list.
func (h *handler) handleAdminUserSetEnabled(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	target, _, ok := h.adminUser(w, r, usr)
	if !ok {
		return
	}
	disabled := r.PostFormValue("disabled") == "true"
	_, err := h.deps.Admin.UpdateUser(r.Context(), usr.ID, target.ID, service.UpdateUserParams{Disabled: &disabled})
	if err != nil {
		if msg, status, ok := adminGuardMessage(err); ok {
			h.renderAdminUsers(w, r, usr, sess, status, msg)
			return
		}
		h.logAndFail(w, r, usr, "update user", err)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// adminGuardMessage maps an AdminService error to user-facing copy AND the
// status that error deserves. It reports false for anything unrecognized, so
// unexpected errors still take the 500 path with their detail going to the log
// rather than the page.
//
// The guards themselves live in AdminService (last-admin, self-lockout, role and
// email validation) and are NOT re-implemented here: this only renders them.
//
// The status varies, which is why it is returned rather than assumed by the
// caller: a guard rejection is 422, a vanished target is 404, and an
// unconfigured WebAuthn RP is 503 — that last one is a server-capability
// problem, not something the admin typed wrong, and the design mandates 503 for
// it specifically.
func adminGuardMessage(err error) (msg string, status int, ok bool) {
	switch {
	case errors.Is(err, service.ErrLastAdmin):
		return "That would leave the server with no enabled admin.", http.StatusUnprocessableEntity, true
	case errors.Is(err, service.ErrSelfLockout):
		return "You cannot disable, demote, or delete your own account.", http.StatusUnprocessableEntity, true
	case errors.Is(err, service.ErrInvalidRole):
		return "Role must be either admin or user.", http.StatusUnprocessableEntity, true
	case errors.Is(err, service.ErrInvalidEmail):
		return "That is not a valid email address.", http.StatusUnprocessableEntity, true
	case errors.Is(err, store.ErrConflict):
		return "A user with that email address already exists.", http.StatusUnprocessableEntity, true
	case errors.Is(err, service.ErrWebAuthnUnavailable):
		return "Passkey authentication is not configured on this server, so no registration link can be issued.",
			http.StatusServiceUnavailable, true
	case errors.Is(err, store.ErrNotFound):
		// The target was deleted between the page render and this submit.
		return "That user no longer exists.", http.StatusNotFound, true
	default:
		return "", 0, false
	}
}

// adminUserNewData is admin-user-new.html's template data. Link is populated
// only on the reveal.
type adminUserNewData struct {
	appData
	Email       string
	Role        string
	Error       string
	Link        string
	LinkWarning string
	InvitedUser string
}

// adminUserData is admin-user.html's template data. Link is populated only on
// the recovery reveal.
type adminUserData struct {
	appData
	Target      store.User
	IsSelf      bool
	Error       string
	Link        string
	LinkWarning string
}

// grantLink makes a GrantService link presentable.
//
// GrantService builds links as baseURL + "/register?token=…" from
// cfg.Server.BaseURL, which defaults to empty — so an unset base_url yields a
// bare path rather than a URL. Prefix the derived base and tell the operator to
// set base_url, rather than handing them something unusable.
func (h *handler) grantLink(r *http.Request, link string) (string, string) {
	if !strings.HasPrefix(link, "/") {
		return link, ""
	}
	return baseURL(h.deps.Cfg, r) + link,
		"server.base_url is not configured, so this link was completed from the address you are " +
			"browsing. Set server.base_url so links are correct for everyone."
}

// handleAdminUserNewForm renders the invite form.
func (h *handler) handleAdminUserNewForm(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	h.render(w, r, "admin-user-new", adminUserNewData{
		appData: h.newAppData(usr, sess, "Invite user", "admin-users"),
		Role:    "user",
	})
}

// handleAdminUserInvite creates a credential-less user and reveals its one-time
// registration link in this response — the link is shown once, so this cannot
// redirect.
func (h *handler) handleAdminUserInvite(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	email := strings.TrimSpace(r.PostFormValue("email"))
	role := r.PostFormValue("role")
	data := adminUserNewData{
		appData: h.newAppData(usr, sess, "Invite user", "admin-users"),
		Email:   email,
		Role:    role,
	}

	invited, link, err := h.deps.Admin.CreateUserInvite(r.Context(), usr.ID, email, role)
	if err != nil {
		if msg, status, ok := adminGuardMessage(err); ok {
			data.Error = msg
			h.renderStatus(w, r, status, "admin-user-new", data)
			return
		}
		// CreateUserInvite creates the user and THEN issues the invite, with no
		// compensating delete: a failure here can leave a credential-less user
		// in the list. Surface the failure rather than pretending it worked; the
		// admin can issue a recovery link to the orphan from its edit page.
		h.logAndFail(w, r, usr, "create user invite", err)
		return
	}

	data.Link, data.LinkWarning = h.grantLink(r, link)
	data.InvitedUser = invited.Email
	h.render(w, r, "admin-user-new", data)
}

// handleAdminUserEdit renders one user's edit screen.
func (h *handler) handleAdminUserEdit(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	target, _, ok := h.adminUser(w, r, usr)
	if !ok {
		return
	}
	h.render(w, r, "admin-user", adminUserData{
		appData: h.newAppData(usr, sess, target.Email, "admin-users"),
		Target:  target,
		IsSelf:  target.ID == usr.ID,
	})
}

// renderAdminUserError re-renders the edit screen with a banner at the status
// the failure deserves — 422 for a guard rejection, 503 when WebAuthn is
// unconfigured, 404 for a vanished target (see adminGuardMessage).
func (h *handler) renderAdminUserError(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session, target store.User, status int, msg string) {
	h.renderStatus(w, r, status, "admin-user", adminUserData{
		appData: h.newAppData(usr, sess, target.Email, "admin-users"),
		Target:  target,
		IsSelf:  target.ID == usr.ID,
		Error:   msg,
	})
}

// handleAdminUserUpdate applies a role and/or disabled change.
func (h *handler) handleAdminUserUpdate(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	target, _, ok := h.adminUser(w, r, usr)
	if !ok {
		return
	}
	// Send only the fields that actually changed. AdminService.applyRole writes
	// and audits user.role_change whenever p.Role != nil (service/admin.go:172-182),
	// so passing the role unconditionally would emit a spurious role-change audit
	// entry every time an admin saves this form without touching the role.
	var params service.UpdateUserParams
	if role := r.PostFormValue("role"); role != target.Role {
		params.Role = &role
	}
	if disabled := r.PostFormValue("disabled") == "true"; disabled != target.Disabled {
		params.Disabled = &disabled
	}
	if params.Role == nil && params.Disabled == nil {
		http.Redirect(w, r, "/admin/users/"+target.ID, http.StatusSeeOther)
		return
	}

	if _, err := h.deps.Admin.UpdateUser(r.Context(), usr.ID, target.ID, params); err != nil {
		if msg, status, ok := adminGuardMessage(err); ok {
			h.renderAdminUserError(w, r, usr, sess, target, status, msg)
			return
		}
		h.logAndFail(w, r, usr, "update user", err)
		return
	}
	http.Redirect(w, r, "/admin/users/"+target.ID, http.StatusSeeOther)
}

// handleAdminUserDelete deletes a user after a server-verified typed
// confirmation.
func (h *handler) handleAdminUserDelete(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	target, _, ok := h.adminUser(w, r, usr)
	if !ok {
		return
	}
	if r.PostFormValue("confirm_email") != target.Email {
		h.renderAdminUserError(w, r, usr, sess, target, http.StatusUnprocessableEntity,
			"Type the account's email address exactly to confirm deletion. Nothing was deleted.")
		return
	}
	if err := h.deps.Admin.DeleteUser(r.Context(), usr.ID, target.ID); err != nil {
		if msg, status, ok := adminGuardMessage(err); ok {
			h.renderAdminUserError(w, r, usr, sess, target, status, msg)
			return
		}
		h.logAndFail(w, r, usr, "delete user", err)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// handleAdminUserRecovery revokes the target's passkeys and issues a one-time
// registration link, revealed in this response.
//
// The typed confirmation is not ceremony: GrantService.IssueRecovery calls
// DeleteAllByUser BEFORE minting, so a misclick logs the user out of every
// credential they own and the only way back in is the link below, which expires
// in an hour.
func (h *handler) handleAdminUserRecovery(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	target, _, ok := h.adminUser(w, r, usr)
	if !ok {
		return
	}
	if r.PostFormValue("confirm_email") != target.Email {
		h.renderAdminUserError(w, r, usr, sess, target, http.StatusUnprocessableEntity,
			"Type the account's email address exactly to confirm. No passkeys were revoked.")
		return
	}
	link, err := h.deps.Grants.IssueRecovery(r.Context(), usr.ID, target.ID)
	if err != nil {
		if msg, status, ok := adminGuardMessage(err); ok {
			h.renderAdminUserError(w, r, usr, sess, target, status, msg)
			return
		}
		h.logAndFail(w, r, usr, "issue recovery link", err)
		return
	}

	data := adminUserData{
		appData: h.newAppData(usr, sess, target.Email, "admin-users"),
		Target:  target,
		IsSelf:  target.ID == usr.ID,
	}
	data.Link, data.LinkWarning = h.grantLink(r, link)
	h.render(w, r, "admin-user", data)
}

// auditPageSize is how many audit rows one page shows. This matches
// AuditLogRepo.ListPaginated's own default; it is stated explicitly so the page
// size is a decision rather than an accident.
const auditPageSize = 100

// knownEventTypes populates the filter's datalist. It is a SUGGESTION list, not
// a constraint: the input accepts any value, so an event type added by a future
// service is filterable immediately and a stale entry here degrades to a missing
// suggestion rather than a blocked query.
//
// Never add a wildcard entry. AuditFilter.EventType is an exact match
// (event_type = ?), so "passkey.*" would return zero rows and read as "none of
// those happened".
//
// Four of these are assigned to a variable before use in the services
// (event := "device.enabled", event := "user.enabled"), so grepping for
// `EventType: "` alone does not find them.
var knownEventTypes = []string{
	"bootstrap.consumed",
	"device.deleted", "device.disabled", "device.enabled",
	"device.enroll.code", "device.enroll.oidc", "device.renamed", "device.secret.rotated",
	"email.send_failed",
	"passkey.invite_issued", "passkey.recovery_issued", "passkey.recovery_redeemed",
	"passkey.registered", "passkey.removed", "passkey.renamed", "passkey.signcount_anomaly",
	"session.revoked",
	"user.created", "user.deleted", "user.disabled", "user.enabled",
	"user.login.oidc", "user.login.passkey", "user.logout",
	"user.oidc.linked", "user.role_change",
}

// auditRow is one rendered audit entry.
type auditRow struct {
	TimeRel   string
	TimeAbs   string
	Actor     string // resolved email, or "system"
	EventType string
	Target    string
	IP        string
}

// adminAuditData is admin-audit.html's template data.
type adminAuditData struct {
	appData
	Rows       []auditRow
	Pager      pager
	EventTypes []string
	EventType  string
	Actor      string
	From       string
	To         string
	ActorNote  string
	HasCursor  bool
}

// handleAdminAudit renders the filtered, paginated audit log. Filters submit as
// a plain GET form so the resulting URL is shareable and bookmarkable.
func (h *handler) handleAdminAudit(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	q := r.URL.Query()
	users, err := h.deps.Admin.ListUsers(r.Context())
	if err != nil {
		h.logAndFail(w, r, usr, "list users", err)
		return
	}

	data := adminAuditData{
		appData:    h.newAppData(usr, sess, "Audit log", "admin-audit"),
		EventTypes: knownEventTypes,
		EventType:  q.Get("event_type"),
		Actor:      strings.TrimSpace(q.Get("actor")),
		From:       q.Get("from"),
		To:         q.Get("to"),
		HasCursor:  q.Get("cursor") != "",
	}

	filter, note := auditFilterFrom(q, users)
	if note != "" {
		data.ActorNote = note
		h.render(w, r, "admin-audit", data)
		return
	}

	page, err := h.deps.Admin.ListAudit(r.Context(), filter, q.Get("cursor"), auditPageSize)
	if err != nil {
		// Log unconditionally, for the reason given in handleDeviceHistory: the
		// store has no cursor-decode sentinel, so the 400 branch cannot prove
		// the cause and must not swallow a real database failure.
		h.deps.Log.LogAttrs(r.Context(), slog.LevelError, "webui: list audit failed",
			slog.Bool("had_cursor", data.HasCursor), slog.Any("error", err))
		if data.HasCursor {
			h.renderBadCursor(w, r, usr)
			return
		}
		h.renderError(w, r, usr, http.StatusInternalServerError, "Something went wrong. Please try again.")
		return
	}

	now := time.Now()
	for _, e := range page.Rows {
		data.Rows = append(data.Rows, auditRow{
			TimeRel:   relTime(e.CreatedAt, now),
			TimeAbs:   absTime(e.CreatedAt),
			Actor:     actorLabel(users, e.ActorUserID),
			EventType: e.EventType,
			Target:    strings.TrimSpace(e.TargetType + " " + e.TargetID),
			IP:        e.IP,
		})
	}

	data.Pager = pager{RowCount: len(page.Rows)}
	filters := url.Values{}
	for _, k := range []string{"event_type", "actor", "from", "to"} {
		if v := q.Get(k); v != "" {
			filters.Set(k, v)
		}
	}
	if page.NextCursor != "" {
		next := url.Values{}
		maps.Copy(next, filters)
		next.Set("cursor", page.NextCursor)
		data.Pager.NextURL = "/admin/audit?" + next.Encode()
	}
	if data.HasCursor {
		data.Pager.FirstURL = "/admin/audit"
		if encoded := filters.Encode(); encoded != "" {
			data.Pager.FirstURL += "?" + encoded
		}
	}

	h.render(w, r, "admin-audit", data)
}

// auditFilterFrom builds the store filter from the query string. It returns a
// note instead of a filter when an input cannot be resolved — an unmatched actor
// email or an unparseable date — so the page can say so rather than silently
// showing everything.
func auditFilterFrom(q url.Values, users []store.User) (store.AuditFilter, string) {
	filter := store.AuditFilter{EventType: q.Get("event_type")}

	if actor := strings.TrimSpace(q.Get("actor")); actor != "" {
		if strings.Contains(actor, "@") {
			id, ok := userIDByEmail(users, actor)
			if !ok {
				return store.AuditFilter{}, "No user matches " + actor + "."
			}
			filter.ActorUserID = id
		} else {
			filter.ActorUserID = actor
		}
	}

	if from := q.Get("from"); from != "" {
		since, ok := parseDayStart(from)
		if !ok {
			return store.AuditFilter{}, "From is not a valid date (expected YYYY-MM-DD)."
		}
		filter.Since = since
	}
	if to := q.Get("to"); to != "" {
		until, ok := parseDayEnd(to)
		if !ok {
			return store.AuditFilter{}, "To is not a valid date (expected YYYY-MM-DD)."
		}
		filter.Until = until
	}
	return filter, ""
}

// actorLabel resolves an audit entry's actor to an email. An empty actor is a
// system event (for example a background job), not a missing one.
func actorLabel(users []store.User, actorID string) string {
	if actorID == "" {
		return "system"
	}
	if u, ok := findUser(users, actorID); ok {
		return u.Email
	}
	return actorID // a deleted user still has entries; show the raw id rather than nothing
}

// userIDByEmail finds a user id by email address.
func userIDByEmail(users []store.User, email string) (string, bool) {
	for _, u := range users {
		if strings.EqualFold(u.Email, email) {
			return u.ID, true
		}
	}
	return "", false
}

// parseDayStart parses a <input type=date> value as UTC midnight.
func parseDayStart(v string) (int64, bool) {
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		return 0, false
	}
	return t.UTC().Unix(), true
}

// parseDayEnd parses a <input type=date> value as the last second of that UTC
// day, so a "to" filter includes the day the user named rather than stopping at
// its midnight.
func parseDayEnd(v string) (int64, bool) {
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		return 0, false
	}
	return t.UTC().Add(24*time.Hour - time.Second).Unix(), true
}

// infoRow is one line of the server info list.
type infoRow struct {
	Label string
	Value string
	Note  string // shown muted after the value, for caveats like an unhonored key
}

// adminServerData is admin-server.html's template data.
type adminServerData struct {
	appData
	Version string
	Uptime  string
	DBSize  string
	Devices int
	Rows    []infoRow
}

// handleAdminServer renders read-only runtime information.
//
// The page shows EFFECTIVE values, not raw config keys: its purpose is telling
// an operator what the server is actually doing, so a key the server ignores
// must not read as though it were in force.
//
// No secret is ever read into this view model — omission at the source rather
// than a redaction step someone can forget.
func (h *handler) handleAdminServer(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	cfg := h.deps.Cfg

	devices, err := h.deps.Admin.ListAllDevices(r.Context())
	if err != nil {
		h.logAndFail(w, r, usr, "list all devices", err)
		return
	}

	rows := []infoRow{
		{Label: "Build", Value: fmt.Sprintf("%s (%s, %s)", h.deps.Info.Version, h.deps.Info.Commit, h.deps.Info.Date)},
		{Label: "Go runtime", Value: fmt.Sprintf("%s · %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)},
		{Label: "Database", Value: cfg.Database.Path},
		{Label: "Listen", Value: cfg.Server.Listen},
		{Label: "Base URL", Value: orNotSet(cfg.Server.BaseURL),
			Note: baseURLNote(cfg.Server.BaseURL)},
		{Label: "Session cookie", Value: cfg.Auth.Session.CookieName},
		{Label: "Cookie Secure", Value: enabledLabel(r.TLS != nil || cfg.Auth.Session.CookieSecure),
			Note: "effective value: set whenever the request arrived over TLS, regardless of the config key"},
		{Label: "Cookie SameSite", Value: "Lax",
			Note: "the cookie_samesite config key is not currently honored — every cookie is set Lax"},
		{Label: "HMAC skew window", Value: cfg.Auth.HMAC.SkewWindow.String()},
		{Label: "Device staleness threshold", Value: staleAfter.String(),
			Note: "a device that has not checked in within this window shows as Stale"},
		{Label: "Local login UI", Value: enabledLabel(!cfg.Auth.HideLocalLoginUI)},
		{Label: "Email", Value: enabledLabel(cfg.Email.Enabled)},
		{Label: "OIDC", Value: enabledLabel(cfg.Auth.OIDC.Enabled), Note: oidcNote(cfg)},
	}

	rpID, rpOrigin, rpErr := cfg.Auth.ResolveWebAuthn(cfg.Server.BaseURL)
	if rpErr != nil {
		rows = append(rows, infoRow{Label: "WebAuthn", Value: "not configured",
			Note: "passkey login is unavailable until a resolvable RP ID is configured"})
	} else {
		rows = append(rows, infoRow{Label: "WebAuthn", Value: rpID, Note: "origin " + rpOrigin})
	}

	h.render(w, r, "admin-server", adminServerData{
		appData: h.newAppData(usr, sess, "Server", "admin-server"),
		Version: h.deps.Info.Version,
		Uptime:  time.Since(h.deps.StartedAt).Truncate(time.Minute).String(),
		DBSize:  dbSize(cfg.Database.Path),
		Devices: len(devices),
		Rows:    rows,
	})
}

// dbSize reports the SQLite file size, or "—" when it cannot be read (an
// in-memory database, or a path this process cannot stat).
func dbSize(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "—"
	}
	return fmt.Sprintf("%.1f MB", float64(info.Size())/(1024*1024))
}

// enabledLabel renders a boolean as operator-facing text.
func enabledLabel(on bool) string {
	if on {
		return "enabled"
	}
	return "disabled"
}

// orNotSet renders an empty config value as an explicit "not set".
func orNotSet(v string) string {
	if v == "" {
		return "not set"
	}
	return v
}

// baseURLNote warns when server.base_url is unset, which makes invite and
// recovery links incomplete and enrollment commands guess their scheme.
func baseURLNote(v string) string {
	if v != "" {
		return ""
	}
	return "set this — registration links and enrollment commands are derived from the request without it"
}

// oidcNote summarises the non-secret OIDC configuration. The client secret is
// never read here.
func oidcNote(cfg config.Server) string {
	o := cfg.Auth.OIDC
	if !o.Enabled {
		return ""
	}
	return fmt.Sprintf("issuer %s · client %s · scopes %s · required %t · auto-link %t · signup %t",
		o.Issuer, o.ClientID, strings.Join(o.Scopes, " "), o.Required, o.AutoLinkByEmail, o.AllowOIDCSignup)
}
