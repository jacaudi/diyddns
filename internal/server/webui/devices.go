package webui

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// deviceRow is one row of the devices list.
type deviceRow struct {
	ID          string
	Label       string
	Status      Status
	IPv4        string
	IPv6        string
	LastSeenAt  string // relative, e.g. "42s ago"
	LastSeenAbs string // absolute UTC, for the title attribute
}

// devicesData is devices.html's template data.
type devicesData struct {
	appData
	Devices []deviceRow
	Q       string
	Status  string
	Total   int    // devices owned, before filtering — distinguishes the two empty states
	Summary string // "3 devices · 2 online, 1 stale"
}

// handleDevices renders the devices list. Filtering runs here rather than in a
// store query: List returns all of one user's devices, and at this project's
// scale (tens of devices) a query would be machinery for nothing.
func (h *handler) handleDevices(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	devices, err := h.deps.Devices.List(r.Context(), usr.ID)
	if err != nil {
		h.logAndFail(w, r, usr, "list devices", err)
		return
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	status := r.URL.Query().Get("status")
	now := time.Now()

	rows := make([]deviceRow, 0, len(devices))
	counts := map[Status]int{}
	for _, d := range devices {
		st := deviceStatus(d, now)
		counts[st]++
		if !matchesQuery(d, q) || (status != "" && string(st) != status) {
			continue
		}
		rows = append(rows, deviceRow{
			ID:          d.ID,
			Label:       d.Label,
			Status:      st,
			IPv4:        d.CurrentIPv4,
			IPv6:        d.CurrentIPv6,
			LastSeenAt:  relTime(d.LastSeenAt, now),
			LastSeenAbs: absTime(d.LastSeenAt),
		})
	}

	h.render(w, r, "devices", devicesData{
		appData: h.newAppData(usr, sess, "My devices", "devices"),
		Devices: rows,
		Q:       q,
		Status:  status,
		Total:   len(devices),
		Summary: deviceSummary(len(devices), counts),
	})
}

// matchesQuery reports whether a device matches a free-text filter over the
// fields a user would search by.
func matchesQuery(d store.Device, q string) bool {
	if q == "" {
		return true
	}
	q = strings.ToLower(q)
	for _, field := range []string{d.Label, d.Hostname, d.CurrentIPv4, d.CurrentIPv6} {
		if strings.Contains(strings.ToLower(field), q) {
			return true
		}
	}
	return false
}

// deviceSummary renders the page subtitle, e.g. "3 devices · 2 online, 1 stale".
// It counts every status the derivation can produce, not just the two the mock
// showed, so a list of never-seen devices is not silently summarised as empty.
func deviceSummary(total int, counts map[Status]int) string {
	if total == 0 {
		return "No devices yet"
	}
	var parts []string
	for _, s := range []Status{StatusOnline, StatusStale, StatusNeverSeen, StatusDisabled} {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(s.Label())))
		}
	}
	noun := "devices"
	if total == 1 {
		noun = "device"
	}
	return fmt.Sprintf("%d %s · %s", total, noun, strings.Join(parts, ", "))
}

// logAndFail logs an unexpected service error and renders a 500. The detail goes
// to the log; the page gets a generic message, so internals never leak to a user.
func (h *handler) logAndFail(w http.ResponseWriter, r *http.Request, usr store.User, action string, err error) {
	h.deps.Log.LogAttrs(r.Context(), slog.LevelError, "webui: "+action+" failed", slog.Any("error", err))
	h.renderError(w, r, usr, http.StatusInternalServerError, "Something went wrong. Please try again.")
}

// deviceNewData is device-new.html's template data. Code is empty on the form
// step and populated on the reveal step; the template branches on it.
type deviceNewData struct {
	appData
	Label          string
	FieldErr       string
	Code           string
	Command        string
	ExpiresIn      string
	ExpiresAt      string
	BaseURLWarning string
}

// handleDeviceNewForm renders step 1: name the device.
func (h *handler) handleDeviceNewForm(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	h.render(w, r, "device-new", deviceNewData{
		appData: h.newAppData(usr, sess, "New device", "devices"),
	})
}

// handleDeviceNewCreate mints an enrollment code and renders the reveal in this
// response rather than redirecting: the code is shown exactly once, and a
// redirect would either carry it in a URL (browser history, Referer, proxy logs)
// or require stashing it server-side.
//
// Both validations below belong here because EnrollmentService.CreateCode
// performs neither: it does not reject an empty label, and it cannot report a
// duplicate one — UNIQUE (user_id, label) is on the devices table, so a
// collision only surfaces when a client redeems the code, as an opaque
// client-side failure minutes later. The duplicate pre-check is advisory only:
// two codes for the same unused label can both be minted, and whichever
// redeems second still fails.
func (h *handler) handleDeviceNewCreate(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	label := strings.TrimSpace(r.PostFormValue("label"))
	data := deviceNewData{
		appData: h.newAppData(usr, sess, "New device", "devices"),
		Label:   label,
	}

	if label == "" {
		data.FieldErr = "Give the device a label so you can recognise it in the list."
		h.renderStatus(w, r, http.StatusUnprocessableEntity, "device-new", data)
		return
	}

	existing, err := h.deps.Devices.List(r.Context(), usr.ID)
	if err != nil {
		h.logAndFail(w, r, usr, "list devices", err)
		return
	}
	for _, d := range existing {
		if strings.EqualFold(d.Label, label) {
			data.FieldErr = "You already have a device called " + label +
				". Labels must be unique, and a code for a duplicate label would fail when the client redeems it."
			h.renderStatus(w, r, http.StatusUnprocessableEntity, "device-new", data)
			return
		}
	}

	code, expiresAt, err := h.deps.Enroll.CreateCode(r.Context(), usr.ID, label)
	if err != nil {
		h.logAndFail(w, r, usr, "create enrollment code", err)
		return
	}

	base := baseURL(h.deps.Cfg, r)
	data.Code = code
	data.Command = fmt.Sprintf("diyddns-client enroll --server %s --code %s", base, code)
	data.ExpiresAt = absTime(expiresAt)
	data.ExpiresIn = relExpiry(expiresAt, time.Now())
	data.BaseURLWarning = baseURLWarning(h.deps.Cfg, base)
	h.render(w, r, "device-new", data)
}

// baseURLWarning returns copy for the case every page using the base-URL
// derivation must surface: server.base_url is unset, so the value was guessed
// from this request. It matters most here — the operator is about to paste a
// command carrying a one-time credential, and a guessed http:// scheme behind
// a TLS-terminating proxy would send it in cleartext.
func baseURLWarning(cfg config.Server, derived string) string {
	if cfg.Server.BaseURL != "" {
		return ""
	}
	return "server.base_url is not configured, so " + derived +
		" was derived from the address you are browsing. Check the scheme before running this — " +
		"if the server sits behind a TLS-terminating proxy this may say http:// when it should say https://."
}

// relExpiry renders how long a code has left, e.g. "15 minutes", relative to
// now. It reads the service's returned expiry rather than restating the TTL
// constant, so the page cannot drift from what was actually minted.
func relExpiry(expiresAt int64, now time.Time) string {
	d := time.Unix(expiresAt, 0).Sub(now)
	if d <= 0 {
		return "already expired"
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes())+1)
	}
	return fmt.Sprintf("%d hours", int(d.Hours())+1)
}

// deviceDetailData is device-detail.html's template data. Secret is populated
// only on the rotate reveal.
type deviceDetailData struct {
	appData
	Device      store.Device
	Status      Status
	LastSeenRel string
	LastSeenAbs string
	CreatedAbs  string
	Owner       string
	History     []historyRow
	Error       string

	Secret         string // base64, rotate reveal only
	Credentials    string // the credentials.json body to paste
	BaseURLWarning string // set when server.base_url is unset (see baseURLWarning)
}

// ownedDevice loads a device for the signed-in user, rendering 404 when it does
// not exist OR belongs to someone else. DeviceService reports a foreign device
// as store.ErrNotFound, and that indistinguishability is the authorization
// boundary — do not render a different message or status for the two cases.
func (h *handler) ownedDevice(w http.ResponseWriter, r *http.Request, usr store.User) (store.Device, bool) {
	dev, err := h.deps.Devices.Get(r.Context(), usr.ID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.renderError(w, r, usr, http.StatusNotFound, "That device does not exist.")
			return store.Device{}, false
		}
		h.logAndFail(w, r, usr, "get device", err)
		return store.Device{}, false
	}
	return dev, true
}

// newDetailData assembles the detail view model, including the five most recent
// history rows the page previews.
func (h *handler) newDetailData(r *http.Request, usr store.User, sess store.Session, dev store.Device) (deviceDetailData, error) {
	page, err := h.deps.Devices.History(r.Context(), usr.ID, dev.ID, "", 5)
	if err != nil {
		return deviceDetailData{}, err
	}
	now := time.Now()
	return deviceDetailData{
		appData:     h.newAppData(usr, sess, dev.Label, "devices"),
		Device:      dev,
		Status:      deviceStatus(dev, now),
		LastSeenRel: relTime(dev.LastSeenAt, now),
		LastSeenAbs: absTime(dev.LastSeenAt),
		CreatedAbs:  absTime(dev.CreatedAt),
		Owner:       usr.Email,
		History:     historyRows(page.Rows, now),
	}, nil
}

// handleDeviceDetail renders one device.
func (h *handler) handleDeviceDetail(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	dev, ok := h.ownedDevice(w, r, usr)
	if !ok {
		return
	}
	data, err := h.newDetailData(r, usr, sess, dev)
	if err != nil {
		h.logAndFail(w, r, usr, "load device history", err)
		return
	}
	h.render(w, r, "device-detail", data)
}

// handleDeviceRename renames a device and redirects back to it.
func (h *handler) handleDeviceRename(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	dev, ok := h.ownedDevice(w, r, usr)
	if !ok {
		return
	}
	label := strings.TrimSpace(r.PostFormValue("label"))
	if label == "" {
		h.renderDetailError(w, r, usr, sess, dev, "A device needs a label.")
		return
	}
	if _, err := h.deps.Devices.Rename(r.Context(), usr.ID, dev.ID, label); err != nil {
		if errors.Is(err, store.ErrConflict) {
			h.renderDetailError(w, r, usr, sess, dev, "You already have a device called "+label+".")
			return
		}
		h.logAndFail(w, r, usr, "rename device", err)
		return
	}
	http.Redirect(w, r, "/devices/"+dev.ID, http.StatusSeeOther)
}

// handleDeviceSetEnabled toggles a device's disabled flag.
func (h *handler) handleDeviceSetEnabled(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	dev, ok := h.ownedDevice(w, r, usr)
	if !ok {
		return
	}
	disabled := r.PostFormValue("disabled") == "true"
	if _, err := h.deps.Devices.SetEnabled(r.Context(), usr.ID, dev.ID, disabled); err != nil {
		h.logAndFail(w, r, usr, "set device enabled", err)
		return
	}
	http.Redirect(w, r, "/devices/"+dev.ID, http.StatusSeeOther)
}

// handleDeviceRotate mints a fresh HMAC secret and reveals it in this response.
//
// The secret is returned exactly once and never persisted in the clear, so this
// cannot redirect. It is base64.StdEncoding-encoded to match what the JSON API
// returns and what client/credentials expects ("base64 exactly as the server
// delivered it") — that encoding is a contract shared by two call sites, and
// changing one without the other breaks every agent.
func (h *handler) handleDeviceRotate(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	dev, ok := h.ownedDevice(w, r, usr)
	if !ok {
		return
	}
	if r.PostFormValue("confirm_label") != dev.Label {
		h.renderDetailError(w, r, usr, sess, dev,
			"Type the device label exactly to confirm rotating its secret.")
		return
	}
	secret, err := h.deps.Devices.RotateSecret(r.Context(), usr.ID, dev.ID)
	if err != nil {
		h.logAndFail(w, r, usr, "rotate device secret", err)
		return
	}
	data, err := h.newDetailData(r, usr, sess, dev)
	if err != nil {
		h.logAndFail(w, r, usr, "load device history", err)
		return
	}
	base := baseURL(h.deps.Cfg, r)
	encoded := base64.StdEncoding.EncodeToString(secret)
	data.Secret = encoded
	data.Credentials = fmt.Sprintf("{\n  \"server_url\": %q,\n  \"device_id\":  %q,\n  \"secret\":     %q\n}",
		base, dev.ID, encoded)
	data.BaseURLWarning = baseURLWarning(h.deps.Cfg, base)
	h.render(w, r, "device-detail", data)
}

// handleDeviceDelete deletes a device after a server-verified typed
// confirmation. The ui.js confirm() dialog is sugar; this check is the gate.
func (h *handler) handleDeviceDelete(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	dev, ok := h.ownedDevice(w, r, usr)
	if !ok {
		return
	}
	if r.PostFormValue("confirm_label") != dev.Label {
		h.renderDetailError(w, r, usr, sess, dev,
			"Type the device label exactly to confirm deletion. Nothing was deleted.")
		return
	}
	if err := h.deps.Devices.Delete(r.Context(), usr.ID, dev.ID); err != nil {
		h.logAndFail(w, r, usr, "delete device", err)
		return
	}
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

// renderDetailError re-renders the detail page at 422 with a banner, for a
// failed validation or confirmation.
func (h *handler) renderDetailError(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session, dev store.Device, msg string) {
	data, err := h.newDetailData(r, usr, sess, dev)
	if err != nil {
		h.logAndFail(w, r, usr, "load device history", err)
		return
	}
	data.Error = msg
	h.renderStatus(w, r, http.StatusUnprocessableEntity, "device-detail", data)
}

// historyRow is one rendered ip_history entry. Shared by the device-detail
// preview card (five newest) and the full history screen.
type historyRow struct {
	ObservedRel   string
	ObservedAbs   string
	IPv4          string
	IPv6          string
	ClientVersion string
}

// historyRows converts store rows into rendered ones.
func historyRows(rows []store.IPHistory, now time.Time) []historyRow {
	out := make([]historyRow, 0, len(rows))
	for _, hr := range rows {
		out = append(out, historyRow{
			ObservedRel:   relTime(hr.ObservedAt, now),
			ObservedAbs:   absTime(hr.ObservedAt),
			IPv4:          hr.IPv4,
			IPv6:          hr.IPv6,
			ClientVersion: hr.ClientVersion,
		})
	}
	return out
}

// historyPageSize is how many ip_history rows one page shows. Narrower rows
// than the audit log, so a larger page reads fine.
const historyPageSize = 50

// pager is the forward-only pagination view model. Cursors are opaque and
// forward-only and no repo counts rows, so there is no Prev and no total:
// Next advances, First restarts, and the browser's Back button walks
// backwards.
type pager struct {
	NextURL  string
	FirstURL string
	RowCount int
}

// deviceHistoryData is device-history.html's template data.
type deviceHistoryData struct {
	appData
	Device    store.Device
	Rows      []historyRow
	Pager     pager
	HasCursor bool
}

// handleDeviceHistory renders one device's paginated IP history.
func (h *handler) handleDeviceHistory(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	dev, ok := h.ownedDevice(w, r, usr)
	if !ok {
		return
	}
	cursor := r.URL.Query().Get("cursor")
	page, err := h.deps.Devices.History(r.Context(), usr.ID, dev.ID, cursor, historyPageSize)
	if err != nil {
		// Always log first. A bad cursor is user input from a pasted or
		// truncated URL, not a server fault, and this screen promises shareable
		// links — so it answers 400 rather than 500. But the store returns plain
		// fmt.Errorf values for cursor decode failures (no sentinel to match on,
		// verified in internal/store/ip_history.go), so this cannot distinguish
		// a bad cursor from a genuine database failure. Logging unconditionally
		// means the 400 path never silently swallows a real fault.
		h.deps.Log.LogAttrs(r.Context(), slog.LevelError, "webui: list device history failed",
			slog.String("device_id", dev.ID), slog.Bool("had_cursor", cursor != ""), slog.Any("error", err))
		if cursor != "" {
			h.renderError(w, r, usr, http.StatusBadRequest,
				"That page link is no longer valid. Start from the first page.")
			return
		}
		h.renderError(w, r, usr, http.StatusInternalServerError, "Something went wrong. Please try again.")
		return
	}

	base := "/devices/" + dev.ID + "/history"
	p := pager{RowCount: len(page.Rows)}
	if page.NextCursor != "" {
		p.NextURL = base + "?cursor=" + url.QueryEscape(page.NextCursor)
	}
	if cursor != "" {
		p.FirstURL = base
	}

	h.render(w, r, "device-history", deviceHistoryData{
		appData:   h.newAppData(usr, sess, dev.Label+" history", "devices"),
		Device:    dev,
		Rows:      historyRows(page.Rows, time.Now()),
		Pager:     p,
		HasCursor: cursor != "",
	})
}
