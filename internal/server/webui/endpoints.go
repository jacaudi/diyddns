package webui

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jacaudi/diyddns/internal/server/notify"
	"github.com/jacaudi/diyddns/internal/store"
)

// deliveryHistoryLimit bounds how many deliveries the endpoint-detail page
// renders. NotificationService.Deliveries leaves the limit caller-supplied
// (design §10.4); this is the one call site that supplies it.
const deliveryHistoryLimit = 50

// endpointActionRefusedMessage is the ONE message shown for every reason
// POST .../test can refuse, once ownership is already confirmed (disabled,
// or the shared outbound-attempt budget is exhausted). A distinct message
// per cause would rebuild the enumeration oracle design §5.8/§10.3 closes.
const endpointActionRefusedMessage = "That action was refused. The endpoint may be disabled, or you may have reached " +
	"the outbound attempt limit for it (5 attempts per 5 minutes)."

// deliveryRedeliverRefusedMessage is the delivery-route counterpart of
// endpointActionRefusedMessage. Unlike the endpoint routes, a delivery
// cannot be ownership-checked ahead of the service call at all (design
// §10.2: it is reachable only through a join onto its endpoint's owner), so
// this single response also covers "does not exist" and "not yours" — the
// same reason NotificationService.Redeliver folds every refusal into one
// boolean.
const deliveryRedeliverRefusedMessage = "That delivery could not be redelivered. It may not exist, may not be yours, " +
	"may not be in a retryable state, or you may have reached the outbound attempt limit for its endpoint."

// endpointRow is one row of the notification endpoints list.
type endpointRow struct {
	ID         string
	Label      string
	URL        string
	Enabled    bool
	CreatedAbs string
}

// endpointsData is endpoints.html's template data. Label/URL/FieldErr carry
// a failed create form's re-render; NewLabel/Secret carry the once-only
// reveal after a successful create. Both live on the list page itself —
// there is no separate GET /account/endpoints/new route (design §10.1) — the
// same way deviceNewData carries device-new.html's form and reveal states.
type endpointsData struct {
	appData
	Endpoints []endpointRow
	Total     int

	Label    string
	URL      string
	FieldErr string

	NewLabel string
	Secret   string
}

// endpointRows converts store rows into rendered ones.
func endpointRows(eps []store.NotificationEndpoint) []endpointRow {
	rows := make([]endpointRow, 0, len(eps))
	for _, ep := range eps {
		rows = append(rows, endpointRow{
			ID:         ep.ID,
			Label:      ep.Label,
			URL:        ep.URL,
			Enabled:    ep.Enabled,
			CreatedAbs: absTime(ep.CreatedAt),
		})
	}
	return rows
}

// newEndpointsData loads the current user's endpoints and assembles the base
// list view model. Callers needing the create-form or reveal fields set them
// on the returned value before rendering.
func (h *handler) newEndpointsData(r *http.Request, usr store.User, sess store.Session) (endpointsData, error) {
	eps, err := h.deps.Notify.List(r.Context(), usr.ID)
	if err != nil {
		return endpointsData{}, err
	}
	return endpointsData{
		appData:   h.newAppData(usr, sess, "Notification endpoints", "endpoints"),
		Endpoints: endpointRows(eps),
		Total:     len(eps),
	}, nil
}

// handleEndpoints renders the notification endpoints list.
func (h *handler) handleEndpoints(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	data, err := h.newEndpointsData(r, usr, sess)
	if err != nil {
		h.logAndFail(w, r, usr, "list notification endpoints", err)
		return
	}
	h.render(w, r, "endpoints", data)
}

// handleEndpointsCreate creates a new endpoint and reveals its signing
// secret in this response — never a redirect, since the secret is shown
// exactly once (same reasoning as handleDeviceNewCreate).
func (h *handler) handleEndpointsCreate(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	label := strings.TrimSpace(r.PostFormValue("label"))
	rawURL := strings.TrimSpace(r.PostFormValue("url"))

	data, err := h.newEndpointsData(r, usr, sess)
	if err != nil {
		h.logAndFail(w, r, usr, "list notification endpoints", err)
		return
	}
	data.Label, data.URL = label, rawURL

	if label == "" || rawURL == "" {
		data.FieldErr = "Give the endpoint a label and a target URL."
		h.renderStatus(w, r, http.StatusUnprocessableEntity, "endpoints", data)
		return
	}

	ep, secret, err := h.deps.Notify.Create(r.Context(), usr.ID, label, rawURL)
	if err != nil {
		msg, ok := createErrorMessage(err)
		if !ok {
			// Create can also fail via auth.GenerateSecret, auth.SealSecret, or
			// any non-conflict store error — none of which describe only the
			// URL the user typed, and any of which may carry a raw
			// driver/internal string. Never render that; log it and show the
			// generic failure page instead (same defect class as 3eed9f8,
			// "stop blaming the database").
			h.logAndFail(w, r, usr, "create notification endpoint", err)
			return
		}
		data.FieldErr = msg
		h.renderStatus(w, r, http.StatusUnprocessableEntity, "endpoints", data)
		return
	}

	refreshed, err := h.newEndpointsData(r, usr, sess)
	if err != nil {
		// The endpoint has ALREADY been created at this point — only the
		// list re-read that follows it failed. "Please try again" would be
		// wrong here, the same way handleDeviceRotate's equivalent comment
		// explains: trying again creates a second endpoint rather than
		// retrying anything.
		h.logAndFailMessage(w, r, usr, "list notification endpoints", err,
			"The endpoint was created, but the page listing it could not be built. Reload the page to see it.")
		return
	}
	refreshed.NewLabel = ep.Label
	refreshed.Secret = secret
	h.render(w, r, "endpoints", refreshed)
}

// createErrorMessage classifies a Create failure into user-facing text, or
// reports ok=false when no such text is safe to show. It recognizes exactly
// the two causes proven not to carry raw internal detail:
//
//   - store.ErrConflict — the (user_id, url) already exists, or the
//     per-user cap was hit; both describe only counts and the URL typed.
//   - notify.ErrDenied — validateTarget (service/notification.go) rejected
//     the scheme, host, or IP literal. It performs no DNS resolution and no
//     network I/O, so its message describes only the URL the user just
//     typed.
//
// Every other Create failure (a URL that fails to even parse,
// auth.GenerateSecret, auth.SealSecret, or any non-conflict store error) may
// carry a raw driver/internal string and must never reach the page — the
// caller falls back to the generic, logged failure path instead.
func createErrorMessage(err error) (msg string, ok bool) {
	switch {
	case errors.Is(err, store.ErrConflict):
		return "You already have an endpoint with that URL, or you're at your endpoint limit.", true
	case errors.Is(err, notify.ErrDenied):
		return "That target was rejected: " + strings.TrimPrefix(err.Error(), "service.Create: "), true
	default:
		return "", false
	}
}

// ownedEndpoint loads a notification endpoint for the signed-in user,
// rendering 404 when it does not exist OR belongs to someone else.
// NotificationService reports a foreign endpoint as store.ErrNotFound, and
// that indistinguishability is the authorization boundary — do not render a
// different message or status for the two cases (mirrors ownedDevice).
func (h *handler) ownedEndpoint(w http.ResponseWriter, r *http.Request, usr store.User) (store.NotificationEndpoint, bool) {
	ep, err := h.deps.Notify.Get(r.Context(), usr.ID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.renderError(w, r, usr, http.StatusNotFound, "That notification endpoint does not exist.")
			return store.NotificationEndpoint{}, false
		}
		h.logAndFail(w, r, usr, "get notification endpoint", err)
		return store.NotificationEndpoint{}, false
	}
	return ep, true
}

// handleEndpointSetEnabled toggles an endpoint's enabled flag.
func (h *handler) handleEndpointSetEnabled(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	ep, ok := h.ownedEndpoint(w, r, usr)
	if !ok {
		return
	}
	enabled := r.PostFormValue("enabled") == "true"
	if err := h.deps.Notify.SetEnabled(r.Context(), usr.ID, ep.ID, enabled); err != nil {
		h.logAndFail(w, r, usr, "set notification endpoint enabled", err)
		return
	}
	http.Redirect(w, r, "/account/endpoints/"+ep.ID, http.StatusSeeOther)
}

// handleEndpointDelete deletes an endpoint after a server-verified typed
// confirmation, matching handleDeviceDelete's convention exactly.
func (h *handler) handleEndpointDelete(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	ep, ok := h.ownedEndpoint(w, r, usr)
	if !ok {
		return
	}
	if r.PostFormValue("confirm_label") != ep.Label {
		h.renderEndpointDetailError(w, r, usr, sess, ep,
			"Type the endpoint label exactly to confirm deletion. Nothing was deleted.")
		return
	}
	if err := h.deps.Notify.Delete(r.Context(), usr.ID, ep.ID); err != nil {
		h.logAndFail(w, r, usr, "delete notification endpoint", err)
		return
	}
	http.Redirect(w, r, "/account/endpoints", http.StatusSeeOther)
}

// handleEndpointTest sends one endpoint.test delivery attempt. Ownership is
// resolved first via ownedEndpoint — a plain read that does not reopen the
// check-then-write race NotificationService.Test's own doc comment warns
// against, because Test's INSERT still carries its own ownership, enabled,
// and budget predicates atomically regardless of what this handler already
// confirmed. A foreign or missing id 404s here exactly as every other
// endpoint route does; once ownership is confirmed, "disabled" and "over
// budget" collapse into the one generic refusal design §10.3 requires.
func (h *handler) handleEndpointTest(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	ep, ok := h.ownedEndpoint(w, r, usr)
	if !ok {
		return
	}
	sent, err := h.deps.Notify.Test(r.Context(), usr.ID, ep.ID)
	if err != nil {
		h.logAndFail(w, r, usr, "send notification test", err)
		return
	}
	if !sent {
		h.renderEndpointDetailError(w, r, usr, sess, ep, endpointActionRefusedMessage)
		return
	}
	http.Redirect(w, r, "/account/endpoints/"+ep.ID, http.StatusSeeOther)
}

// handleDeliveryRedeliver re-arms a terminal delivery as a new attempt.
// Unlike the endpoint routes, there is no ownership precheck available here
// at all — design §10.2 says a delivery is reachable only through a join
// onto its endpoint's owner, and NotificationService.Redeliver folds
// "doesn't exist", "not yours", "not terminal", "disabled", and "over
// budget" into one ok=false with no way to tell them apart. So this handler
// answers every refusal with the same 404: indistinguishable from a
// genuinely missing delivery, which is the strongest of the app's existing
// not-found conventions and leaks nothing extra.
//
// endpoint_id is a hidden form field the endpoint-detail page already knows
// (it is rendering that endpoint's own history) and is used ONLY to choose
// the redirect target on success — never for authorization, which is
// entirely the service call's job. It is still attacker-controlled POST
// data, though, so it is verified against ownedEndpoint before being
// reflected into the Location header — a value that is not the caller's own
// endpoint falls back to the generic list page instead.
func (h *handler) handleDeliveryRedeliver(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	deliveryID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		h.renderError(w, r, usr, http.StatusNotFound, deliveryRedeliverRefusedMessage)
		return
	}
	ok, err := h.deps.Notify.Redeliver(r.Context(), usr.ID, deliveryID)
	if err != nil {
		h.logAndFail(w, r, usr, "redeliver notification delivery", err)
		return
	}
	if !ok {
		h.renderError(w, r, usr, http.StatusNotFound, deliveryRedeliverRefusedMessage)
		return
	}
	dest := "/account/endpoints"
	if endpointID := r.PostFormValue("endpoint_id"); endpointID != "" {
		if _, err := h.deps.Notify.Get(r.Context(), usr.ID, endpointID); err == nil {
			dest = "/account/endpoints/" + endpointID
		}
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// failureClassLabel maps the six fixed store.NotificationDelivery.LastFailure
// classes to short human phrases. The mapping lives here, not in the
// database (design §10.4): internal/server/notify/worker.go owns the raw
// class strings as unexported consts, so the literals below are matched by
// value against that package's wire contract rather than by import. An
// empty LastFailure (pending or delivered) renders as nothing; anything
// outside the six known classes renders as "Unknown" rather than passing
// through unrecognised text.
func failureClassLabel(class string) string {
	switch class {
	case "":
		return ""
	case "blocked":
		return "Blocked by destination policy"
	case "unreachable":
		return "Unreachable"
	case "tls":
		return "TLS error"
	case "rejected":
		return "Rejected by target"
	case "gone":
		return "Target removed (410)"
	case "internal":
		return "Internal error"
	default:
		return "Unknown"
	}
}

// deliveryRow is one rendered notification_deliveries row. FailureClass is
// always the mapped phrase from failureClassLabel — never the raw class, an
// error string, a status code, or a resolved address (design §5.8/§10.4).
type deliveryRow struct {
	ID            int64
	EventType     string
	Status        string
	Attempts      int
	FailureClass  string
	CreatedAbs    string
	UpdatedAbs    string
	Redeliverable bool
}

// deliveryRows converts store rows into rendered ones. Status is one of
// store.DeliveryPending/DeliveryDelivered/DeliveryFailed; the latter two are
// the terminal states InsertRedelivery's own query accepts (built from the
// same constants — see store.deliveryTerminalStatuses), so both mark
// Redeliverable. Comparing against anything else here would let this button
// drift from what the service call underneath it actually permits.
func deliveryRows(rows []store.NotificationDelivery) []deliveryRow {
	out := make([]deliveryRow, 0, len(rows))
	for _, d := range rows {
		out = append(out, deliveryRow{
			ID:            d.ID,
			EventType:     d.EventType,
			Status:        d.Status,
			Attempts:      d.Attempts,
			FailureClass:  failureClassLabel(d.LastFailure),
			CreatedAbs:    absTime(d.CreatedAt),
			UpdatedAbs:    absTime(d.UpdatedAt),
			Redeliverable: d.Status == store.DeliveryFailed || d.Status == store.DeliveryDelivered,
		})
	}
	return out
}

// endpointDetailData is endpoint-detail.html's template data.
type endpointDetailData struct {
	appData
	Endpoint   store.NotificationEndpoint
	CreatedAbs string
	Deliveries []deliveryRow
	Error      string
}

// newEndpointDetailData assembles the detail view model, including the
// endpoint's delivery history (design §10.4).
func (h *handler) newEndpointDetailData(r *http.Request, usr store.User, sess store.Session, ep store.NotificationEndpoint) (endpointDetailData, error) {
	deliveries, err := h.deps.Notify.Deliveries(r.Context(), usr.ID, ep.ID, deliveryHistoryLimit)
	if err != nil {
		return endpointDetailData{}, err
	}
	return endpointDetailData{
		appData:    h.newAppData(usr, sess, ep.Label, "endpoints"),
		Endpoint:   ep,
		CreatedAbs: absTime(ep.CreatedAt),
		Deliveries: deliveryRows(deliveries),
	}, nil
}

// handleEndpointDetail renders one endpoint and its recent delivery history.
func (h *handler) handleEndpointDetail(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	ep, ok := h.ownedEndpoint(w, r, usr)
	if !ok {
		return
	}
	data, err := h.newEndpointDetailData(r, usr, sess, ep)
	if err != nil {
		h.logAndFail(w, r, usr, "load notification deliveries", err)
		return
	}
	h.render(w, r, "endpoint-detail", data)
}

// renderEndpointDetailError re-renders the detail page at 422 with a banner,
// for a failed confirmation or a refused action. Mirrors renderDetailError.
func (h *handler) renderEndpointDetailError(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session, ep store.NotificationEndpoint, msg string) {
	data, err := h.newEndpointDetailData(r, usr, sess, ep)
	if err != nil {
		h.logAndFail(w, r, usr, "load notification deliveries", err)
		return
	}
	data.Error = msg
	h.renderStatus(w, r, http.StatusUnprocessableEntity, "endpoint-detail", data)
}
