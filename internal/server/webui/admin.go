package webui

import (
	"errors"
	"net/http"

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
