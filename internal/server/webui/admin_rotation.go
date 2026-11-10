package webui

import (
	"errors"
	"net/http"

	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// rotationNotes renders a device's pending rotation as one sentence per
// track, secret first, for the notes card on both device pages (#175).
func rotationNotes(s service.RotationState) []string {
	var notes []string
	if s.Secret.Since != 0 {
		notes = append(notes, rotationNote("Secret", s.Secret))
	}
	if s.Cert.Since != 0 {
		notes = append(notes, rotationNote("Certificate", s.Cert))
	}
	return notes
}

// rotationNote is one track's sentence. A plain pending track carries no
// reason: the client is simply due to pick the request up at its next check-in.
func rotationNote(name string, t service.TrackState) string {
	note := name + " rotation pending since " + absTime(t.Since)
	switch t.Status {
	case service.StatusAwaitingUpgrade:
		note += ", waiting for client upgrade"
	case service.StatusAwaitingMTLS:
		note += ", waiting for mTLS"
	}
	return note
}

// handleAdminDeviceRotate marks a rotation on any device (#175). Like the
// other admin device mutations it lets the service resolve the device, so a
// device deleted mid-request is one 404 and never a 404 then a 500.
func (h *handler) handleAdminDeviceRotate(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	id := r.PathValue("id")
	target := service.RotationTarget(r.PostFormValue("target"))
	if _, err := h.deps.Rotation.Mark(r.Context(), sess, id, target); err != nil {
		h.rotationFailed(w, r, usr, "mark device rotation for admin", err)
		return
	}
	http.Redirect(w, r, "/admin/devices/"+id, http.StatusSeeOther)
}

// handleAdminDeviceRotationCancel ends any pending rotation on a device. It is
// idempotent in the service, so a double-submit redirects without a second
// audit row.
func (h *handler) handleAdminDeviceRotationCancel(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	id := r.PathValue("id")
	if err := h.deps.Rotation.Cancel(r.Context(), sess, id); err != nil {
		h.rotationFailed(w, r, usr, "cancel device rotation for admin", err)
		return
	}
	http.Redirect(w, r, "/admin/devices/"+id, http.StatusSeeOther)
}

// rotationFailed maps the rotation service's refusals to their copy and
// status; anything else is a fault and goes to logAndFail.
func (h *handler) rotationFailed(w http.ResponseWriter, r *http.Request, usr store.User, action string, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		h.renderError(w, r, usr, http.StatusNotFound, "That device does not exist.")
	case errors.Is(err, service.ErrDeviceDisabled):
		h.renderError(w, r, usr, http.StatusConflict, "A disabled device, or a device whose account is disabled, cannot be rotated.")
	case errors.Is(err, service.ErrCertRotationUnavailable):
		h.renderError(w, r, usr, http.StatusConflict, "Certificate rotation needs the agent listener (agent.listen).")
	case errors.Is(err, service.ErrInvalidRotationTarget):
		h.renderError(w, r, usr, http.StatusBadRequest, "Choose secret, certificate or both.")
	default:
		h.logAndFail(w, r, usr, action, err)
	}
}
