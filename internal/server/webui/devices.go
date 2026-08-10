package webui

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

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
