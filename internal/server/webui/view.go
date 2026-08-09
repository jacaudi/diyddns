package webui

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/store"
)

// Status is a device's derived liveness, shown as a tag on the devices list and
// the device-detail header. Its values double as the ?status= filter values on
// /devices, so the constant and the querystring token are one string rather than
// two that could drift.
type Status string

// The four device statuses. NeverSeen is not in the original mock and is
// routine: an enrolled device reads NeverSeen until its first successful
// check-in.
const (
	StatusOnline    Status = "online"
	StatusStale     Status = "stale"
	StatusDisabled  Status = "disabled"
	StatusNeverSeen Status = "never"
)

// staleAfter is how long a device may go unheard-from before it reads as Stale.
// Chosen as three times the client's DEFAULT 5m poll interval
// (internal/client/poller/poller.go) so a single missed or slow cycle does not
// flip a healthy device.
//
// It bounds nothing: the interval is a per-client flag (--interval / run.interval),
// so an operator polling less often than every 15m sees permanently-Stale
// devices. /admin/server displays this threshold so that behaviour is
// explainable rather than mysterious.
const staleAfter = 15 * time.Minute

// deviceStatus derives a device's display status. Disabled takes precedence over
// liveness: an operator who turned a device off should see that, not a stale
// warning about it. A last_seen_at in the future (clock skew between server and
// client) reads Online rather than wrapping into Stale.
func deviceStatus(d store.Device, now time.Time) Status {
	switch {
	case d.Disabled:
		return StatusDisabled
	case d.LastSeenAt == 0:
		return StatusNeverSeen
	case now.Sub(time.Unix(d.LastSeenAt, 0)) <= staleAfter:
		return StatusOnline
	default:
		return StatusStale
	}
}

// Label returns the human-readable form of a status, for tag text.
func (s Status) Label() string {
	switch s {
	case StatusOnline:
		return "Online"
	case StatusStale:
		return "Stale"
	case StatusDisabled:
		return "Disabled"
	case StatusNeverSeen:
		return "Never seen"
	default:
		return "Unknown"
	}
}

// CSSClass returns the mock.css tag modifier for a status.
func (s Status) CSSClass() string {
	switch s {
	case StatusOnline:
		return "ok"
	case StatusStale:
		return "warn"
	case StatusDisabled:
		return "danger"
	default:
		return "neutral"
	}
}

// relTime renders a unix timestamp as a short relative string ("42s ago"), for
// display next to an absolute UTC timestamp carried in a title attribute. A zero
// timestamp means "never reported", which is a distinct state from "reported a
// long time ago". A future timestamp clamps to "just now" rather than rendering
// a negative age.
func relTime(unix int64, now time.Time) string {
	if unix == 0 {
		return "never"
	}
	d := now.Sub(time.Unix(unix, 0))
	switch {
	case d < 0:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 48*time.Hour:
		return "Yesterday"
	default:
		return time.Unix(unix, 0).UTC().Format("2006-01-02")
	}
}

// absTime renders a unix timestamp as an explicit UTC string for title
// attributes and detail readouts. The server does not know the viewer's
// timezone, so every absolute time in the UI is UTC and says so.
func absTime(unix int64) string {
	if unix == 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04:05 UTC")
}

// baseURL resolves the public base URL to embed in copy-paste artifacts: the
// enroll command, the credentials.json snippet, and grant links.
//
// X-Forwarded-Proto is deliberately NOT consulted. This project has no
// trusted-proxy configuration, so honouring it would let any client dictate the
// scheme in a value the user is told to paste into a config file. When
// server.base_url is unset and the server sits behind a TLS-terminating proxy
// the result may say http://; every page that renders it also tells the operator
// to set server.base_url.
func baseURL(cfg config.Server, r *http.Request) string {
	if b := strings.TrimRight(cfg.Server.BaseURL, "/"); b != "" {
		return b
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// initials renders the avatar text in the topbar user chip: the first two
// characters of the local part, uppercased. Truncation is rune-aware, not
// byte-aware, so a multi-byte local part (e.g. CJK) yields its first two
// runes rather than a mid-character byte split that produces invalid UTF-8.
func initials(email string) string {
	local, _, _ := strings.Cut(email, "@")
	if local == "" {
		return "?"
	}
	r := []rune(local)
	if len(r) > 2 {
		r = r[:2]
	}
	local = string(r)
	return strings.ToUpper(local)
}

// findUser locates a user by id in a slice from AdminService.ListUsers.
//
// AdminService has no single-user getter and webui deliberately holds no
// *store.Store, so every {id}-scoped admin screen resolves its target this way
// and synthesizes its own 404 — nothing on this path returns store.ErrNotFound.
// O(users) per request is correct at this project's scale; if the user count
// ever grows, the fix is one AdminService.GetUser method rather than reaching
// past the service layer here.
func findUser(users []store.User, id string) (store.User, bool) {
	for _, u := range users {
		if u.ID == id {
			return u, true
		}
	}
	return store.User{}, false
}
