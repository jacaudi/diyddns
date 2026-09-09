package webui

import (
	"cmp"
	"net/http"
	"slices"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

// adminDeviceRow is one row of the admin devices list: a device row plus who
// owns it. Owned decides whether the label links to the owner-scoped detail
// page — those pages stay owner-scoped, so another user's device gets no link.
type adminDeviceRow struct {
	deviceRow
	OwnerID    string
	OwnerEmail string
	Owned      bool
}

// ownerOption is one entry of the owner filter's select.
type ownerOption struct {
	ID    string
	Email string
}

// adminDevicesData is admin-devices.html's template data.
type adminDevicesData struct {
	appData
	Devices []adminDeviceRow
	Owners  []ownerOption
	Owner   string // selected owner id, "" for all
	Status  string // selected status token, "" for all
	Total   int    // devices on the server, before filtering — distinguishes the two empty states
	Summary string
}

// handleAdminDevices renders every device across users, read-only (#105).
// Filtering runs in memory for the reason given on handleDevices: the store
// returns the whole list and the scale is tens of devices.
func (h *handler) handleAdminDevices(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
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

	owner := r.URL.Query().Get("owner")
	status := r.URL.Query().Get("status")
	now := time.Now()

	rows := make([]adminDeviceRow, 0, len(devices))
	counts := map[Status]int{}
	for _, d := range devices {
		row := newDeviceRow(d, now)
		counts[row.Status]++
		if (owner != "" && d.UserID != owner) || !row.matchesStatus(status) {
			continue
		}
		rows = append(rows, adminDeviceRow{
			deviceRow:  row,
			OwnerID:    d.UserID,
			OwnerEmail: ownerLabel(users, d.UserID),
			Owned:      d.UserID == usr.ID,
		})
	}

	h.render(w, r, "admin-devices", adminDevicesData{
		appData: h.newAppData(usr, sess, "All devices", "admin-devices"),
		Devices: rows,
		Owners:  ownerOptions(users),
		Owner:   owner,
		Status:  status,
		Total:   len(devices),
		Summary: deviceSummary(len(devices), counts),
	})
}

// ownerLabel resolves a device's owner to an email. Deleting a user cascades to
// their devices, so an unresolved id is not expected; showing the raw id rather
// than nothing keeps such a row diagnosable, as actorLabel does for audit rows.
func ownerLabel(users []store.User, userID string) string {
	if u, ok := findUser(users, userID); ok {
		return u.Email
	}
	return userID
}

// ownerOptions lists every user for the owner filter, sorted by email so the
// select reads in a stable order regardless of how the store returned them.
func ownerOptions(users []store.User) []ownerOption {
	opts := make([]ownerOption, 0, len(users))
	for _, u := range users {
		opts = append(opts, ownerOption{ID: u.ID, Email: u.Email})
	}
	slices.SortFunc(opts, func(a, b ownerOption) int { return cmp.Compare(a.Email, b.Email) })
	return opts
}
