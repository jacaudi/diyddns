package webui

import (
	"errors"
	"net/http"

	"github.com/jacaudi/diyddns/internal/store"
)

// adminDevice loads ANY device for an admin, with its owner, rendering 404
// when the id names nothing. Unscoped by construction: the route middleware
// (requireAdmin / requirePostAdmin) is the authorization boundary, and
// AdminService.GetDevice is the one unscoped device read the service layer
// has (#132 D5). The 404 copy is ownedDevice's, so the two device 404s read
// the same. A device whose owner row is missing is a fault
// (service.ErrOwnerMissing), not a 404: it goes to logAndFail, which records
// both ids (#132 D18).
func (h *handler) adminDevice(w http.ResponseWriter, r *http.Request, usr store.User) (store.Device, store.User, bool) {
	dev, owner, err := h.deps.Admin.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.renderError(w, r, usr, http.StatusNotFound, "That device does not exist.")
			return store.Device{}, store.User{}, false
		}
		h.logAndFail(w, r, usr, "get device for admin", err)
		return store.Device{}, store.User{}, false
	}
	return dev, owner, true
}

// handleAdminDeviceDetail renders any device, read-only, for an admin (#132
// D2). The reads are scoped by the resolved owner's id through adminScope;
// they write nothing, so nothing is misattributed (#132 D6).
func (h *handler) handleAdminDeviceDetail(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	dev, owner, ok := h.adminDevice(w, r, usr)
	if !ok {
		return
	}
	data, err := h.newDetailData(r, usr, sess, adminScope(owner, dev), dev)
	if err != nil {
		h.logAndFail(w, r, usr, "load device history", err)
		return
	}
	h.render(w, r, "admin-device", data)
}

// handleAdminDeviceHistory renders any device's paginated IP history for an
// admin (#132 D13), under /admin/devices so every link stays in this family.
func (h *handler) handleAdminDeviceHistory(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	dev, owner, ok := h.adminDevice(w, r, usr)
	if !ok {
		return
	}
	h.renderDeviceHistory(w, r, usr, sess, adminScope(owner, dev), dev)
}

// handleAdminDeviceSetEnabled is the ONE admin mutation of a device (#132
// D4). The session goes to the service whole so the audit row carries the
// admin's id and IP (#137). Rename, secret rotation and deletion are
// deliberately not routed under /admin/devices: their absence from
// webui.New's table is the enforcement (#132 D3). No typed confirmation --
// the owner's route has none and the action is reversible.
//
// It does NOT go through adminDevice first: SetDeviceEnabled resolves the
// device itself, and resolving it twice would answer 404 and then 500 for a
// device deleted between the two reads. The service's ErrNotFound is mapped
// here to the same 404 copy adminDevice uses.
func (h *handler) handleAdminDeviceSetEnabled(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	id := r.PathValue("id")
	disabled := r.PostFormValue("disabled") == "true"
	if _, err := h.deps.Admin.SetDeviceEnabled(r.Context(), sess, id, disabled); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.renderError(w, r, usr, http.StatusNotFound, "That device does not exist.")
			return
		}
		h.logAndFail(w, r, usr, "set device enabled for admin", err)
		return
	}
	http.Redirect(w, r, "/admin/devices/"+id, http.StatusSeeOther)
}
