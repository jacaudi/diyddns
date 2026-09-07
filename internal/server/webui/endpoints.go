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

// endpointActionRefusedMessage is the ONE message shown when POST .../test is
// refused: InsertUserTest's predicate refuses when the endpoint is disabled
// OR no longer exists (deleted between this handler's Get and the INSERT).
// (The per-user attempt budget is gone with #106; the endpoint is
// admin-managed.)
const endpointActionRefusedMessage = "That action was refused. The endpoint is disabled or no longer exists."

// deliveryRedeliverRefusedMessage is the delivery-route counterpart. A
// delivery is reachable only through its endpoint, and
// NotificationService.Redeliver folds every refusal into one boolean.
const deliveryRedeliverRefusedMessage = "That delivery could not be redelivered. It may not exist, " +
	"may not be in a retryable state, or its endpoint may be disabled."

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
// there is no separate GET /admin/endpoints/new route.
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

// newEndpointsData loads every endpoint and assembles the base list view
// model. Callers needing the create-form or reveal fields set them on the
// returned value before rendering.
func (h *handler) newEndpointsData(r *http.Request, usr store.User, sess store.Session) (endpointsData, error) {
	eps, err := h.deps.Notify.List(r.Context())
	if err != nil {
		return endpointsData{}, err
	}
	return endpointsData{
		appData:   h.newAppData(usr, sess, "Notification endpoints", "admin-endpoints"),
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
			// URL the admin typed, and any of which may carry a raw
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
		// wrong here: trying again creates a second endpoint.
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
//   - store.ErrConflict — the url already exists; describes only the URL typed.
//   - notify.ErrDenied — validateTarget (service/notification.go) rejected
//     the scheme, host, or IP literal. It performs no DNS resolution and no
//     network I/O, so its message describes only the URL the admin typed.
//
// Every other Create failure may carry a raw driver/internal string and must
// never reach the page — the caller falls back to the generic, logged
// failure path instead.
func createErrorMessage(err error) (msg string, ok bool) {
	switch {
	case errors.Is(err, store.ErrConflict):
		return "An endpoint with that URL already exists.", true
	case errors.Is(err, notify.ErrDenied):
		return "That target was rejected: " + strings.TrimPrefix(err.Error(), "service.Create: "), true
	default:
		return "", false
	}
}

// loadEndpoint loads the {id}-scoped endpoint, rendering 404 when it does
// not exist.
func (h *handler) loadEndpoint(w http.ResponseWriter, r *http.Request, usr store.User) (store.NotificationEndpoint, bool) {
	ep, err := h.deps.Notify.Get(r.Context(), r.PathValue("id"))
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
	ep, ok := h.loadEndpoint(w, r, usr)
	if !ok {
		return
	}
	enabled := r.PostFormValue("enabled") == "true"
	if err := h.deps.Notify.SetEnabled(r.Context(), usr.ID, ep.ID, enabled); err != nil {
		h.logAndFail(w, r, usr, "set notification endpoint enabled", err)
		return
	}
	http.Redirect(w, r, "/admin/endpoints/"+ep.ID, http.StatusSeeOther)
}

// handleEndpointDelete deletes an endpoint after a server-verified typed
// confirmation, matching handleDeviceDelete's convention exactly.
func (h *handler) handleEndpointDelete(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	ep, ok := h.loadEndpoint(w, r, usr)
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
	http.Redirect(w, r, "/admin/endpoints", http.StatusSeeOther)
}

// handleEndpointTest sends one endpoint.test delivery attempt. A missing id
// 404s here exactly as every other endpoint route does; once found,
// "disabled" is the one refusal, and Test's INSERT still carries the enabled
// predicate atomically regardless of what this handler already saw.
func (h *handler) handleEndpointTest(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	ep, ok := h.loadEndpoint(w, r, usr)
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
	http.Redirect(w, r, "/admin/endpoints/"+ep.ID, http.StatusSeeOther)
}

// handleDeliveryRedeliver re-arms a terminal delivery as a new attempt.
// NotificationService.Redeliver folds "doesn't exist", "not terminal" and
// "disabled" into one ok=false, so every refusal is the same 404.
//
// endpoint_id is a hidden form field the endpoint-detail page already knows
// and is used ONLY to choose the redirect target on success. It is still
// attacker-controlled POST data, so it is verified to name a real endpoint
// before being reflected into the Location header; anything else falls back
// to the list page.
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
	dest := "/admin/endpoints"
	if endpointID := r.PostFormValue("endpoint_id"); endpointID != "" {
		if _, err := h.deps.Notify.Get(r.Context(), endpointID); err == nil {
			dest = "/admin/endpoints/" + endpointID
		}
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// failureLabels maps notify's six fixed failure classes to the phrase shown on
// an endpoint's page. Keyed on notify's own constants rather than re-typed
// literals: the class vocabulary is one contract and must not live in two
// packages.
var failureLabels = map[string]string{
	notify.FailureBlocked:     "Blocked by destination policy",
	notify.FailureUnreachable: "Unreachable",
	notify.FailureTLS:         "TLS error",
	notify.FailureRejected:    "Rejected by target",
	notify.FailureGone:        "Target removed (410)",
	notify.FailureInternal:    "Internal error",
}

// failureClassLabel maps a store.NotificationDelivery.LastFailure class to
// its phrase. An empty LastFailure (pending or delivered) renders as nothing;
// anything outside the six known classes renders as "Unknown" rather than
// passing through unrecognised text (design §5.8: last_failure stays a fixed
// vocabulary).
func failureClassLabel(class string) string {
	if class == "" {
		return ""
	}
	if label, ok := failureLabels[class]; ok {
		return label
	}
	return "Unknown"
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

// deliveryRows converts store rows into rendered ones. The two terminal
// statuses are the ones InsertRedelivery's own query accepts (built from the
// same constants — see store.deliveryTerminalStatuses), so both mark
// Redeliverable.
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
	deliveries, err := h.deps.Notify.Deliveries(r.Context(), ep.ID, deliveryHistoryLimit)
	if err != nil {
		return endpointDetailData{}, err
	}
	return endpointDetailData{
		appData:    h.newAppData(usr, sess, ep.Label, "admin-endpoints"),
		Endpoint:   ep,
		CreatedAbs: absTime(ep.CreatedAt),
		Deliveries: deliveryRows(deliveries),
	}, nil
}

// handleEndpointDetail renders one endpoint and its recent delivery history.
func (h *handler) handleEndpointDetail(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	ep, ok := h.loadEndpoint(w, r, usr)
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
