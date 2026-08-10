package webui

import (
	"fmt"
	"log/slog"
	"net/http"
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
