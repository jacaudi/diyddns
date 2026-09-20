package webui

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/stale"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
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

	// IPv4Expired and IPv6Expired are true when the family's address above is
	// a LAST-KNOWN value read back from ip_history, not the device's current
	// one -- the sweep has cleared it (design #10: clearing an address must
	// not erase where it can still be found). IPv4At/IPv6At carry that
	// value's age and are set only alongside the matching Expired flag.
	IPv4Expired bool
	IPv6Expired bool
	IPv4At      string
	IPv6At      string

	// ShowExpiry gates the countdown below. It is false whenever the
	// staleness policy is opted out (config.FeedSection.ExpiryEnabled()) --
	// at expire_after_days: 0, the default install, stale.Window is 0 and an
	// ungated countdown would read "expires in 0 days" on every row that has
	// ever been confirmed (a never-confirmed family renders "" instead --
	// see expiresInText's confirmedAt == 0 guard; the remaining <= 0 clamp
	// rules out a literal negative number for the rest). A countdown to zero
	// on a policy that is supposedly off is still wrong -- the column must
	// be absent.
	ShowExpiry  bool
	V4ExpiresIn string // e.g. "7 days"; empty when the family has never been confirmed
	V6ExpiresIn string
}

// newDeviceRow derives the rendered form of a device: its status, the two
// last-seen renderings, the last-known address for a family the sweep has
// cleared, and -- when the staleness policy is on -- each family's countdown.
// Shared by the user-scoped list and the admin list so the derivation cannot
// drift between the two screens.
func newDeviceRow(d store.Device, latest store.LatestAddress, feed config.FeedSection, now time.Time) deviceRow {
	row := deviceRow{
		ID:          d.ID,
		Label:       d.Label,
		Status:      deviceStatus(d, now),
		IPv4:        d.CurrentIPv4,
		IPv6:        d.CurrentIPv6,
		LastSeenAt:  relTime(d.LastSeenAt, now),
		LastSeenAbs: absTime(d.LastSeenAt),
	}
	if row.IPv4 == "" && latest.IPv4 != "" {
		row.IPv4, row.IPv4Expired, row.IPv4At = latest.IPv4, true, relDays(latest.IPv4At, now)
	}
	if row.IPv6 == "" && latest.IPv6 != "" {
		row.IPv6, row.IPv6Expired, row.IPv6At = latest.IPv6, true, relDays(latest.IPv6At, now)
	}
	row.ShowExpiry, row.V4ExpiresIn, row.V6ExpiresIn = expiryFields(d, feed, now)
	return row
}

// expiryFields computes ShowExpiry and each family's countdown text. Shared by
// the list (newDeviceRow, both the user-scoped and admin screens) and the
// detail page (newDetailData) so this gate cannot drift between the three --
// it used to be copied onto the detail page separately, which is exactly the
// kind of drift this project's fix rounds keep finding.
//
// A family whose address the sweep has already cleared must never show a
// countdown beside its own expiry notice: ExpireFamilies deliberately leaves
// *ConfirmedAt at its old instant (that column is the optimistic pin the
// sweep writes against, not a liveness signal), so a countdown computed from
// it would render "expires in 0 days" forever.
//
// Gated on the CURRENT column (d.CurrentIPv4/CurrentIPv6), not on a
// caller-derived "last known address" flag. On the list, that flag
// (deviceRow.IPv4Expired/IPv6Expired) is only set when history still has a
// last-known value to fall back to; a swept family whose ip_history rows have
// since been pruned (retention: ip_history_days / ip_history_per_device_max)
// would leave that flag false and let the stale *ConfirmedAt through -- the
// original defect again, keyed on history availability instead of on the
// sweep. "Does this family still hold an address" is what the current column
// means, and it is the one predicate that covers both the has-history and the
// pruned-history case, on both screens. Resist "simplifying" this back to a
// last-known-address flag.
//
// The two families are independent -- gating on each one's own current
// column, not on the other's or on the row as a whole -- so a device with a
// live IPv4 and a swept IPv6 still shows the IPv4 countdown.
//
// showExpiry is false, with both countdowns "", entirely when the staleness
// policy is opted out (config.FeedSection.ExpiryEnabled()).
func expiryFields(d store.Device, feed config.FeedSection, now time.Time) (showExpiry bool, v4ExpiresIn, v6ExpiresIn string) {
	if !feed.ExpiryEnabled() {
		return false, "", ""
	}
	window := stale.Window(feed)
	if d.CurrentIPv4 != "" {
		v4ExpiresIn = expiresInText(d.V4ConfirmedAt, window, now)
	}
	if d.CurrentIPv6 != "" {
		v6ExpiresIn = expiresInText(d.V6ConfirmedAt, window, now)
	}
	return true, v4ExpiresIn, v6ExpiresIn
}

// expiresInText renders how long until a family's address is due for
// clearing -- "7 days" -- from the same stale.Window/stale.ExpiresAt the
// sweep itself uses (design §10 item 3), so the page and the sweep cannot
// disagree. "" means the family has never been confirmed, so there is
// nothing to expire.
//
// Rounding is stale.HumanDays, the SAME function the owner email renders
// with -- not a second copy of the day math. The two used to round in
// opposite directions (this used to ceil; HumanDays floors), so a rung
// crossed partway through a day told the owner one number by email and a
// different one here (fix round, item 3).
func expiresInText(confirmedAt, window int64, now time.Time) string {
	if confirmedAt == 0 {
		return ""
	}
	remaining := stale.ExpiresAt(confirmedAt, window) - now.Unix()
	if remaining <= 0 {
		return "0 days"
	}
	return stale.HumanDays(time.Duration(remaining) * time.Second)
}

// matchesStatus reports whether the row passes a ?status= filter; an empty
// filter passes everything. The filter token is the Status constant itself.
func (r deviceRow) matchesStatus(status string) bool {
	return status == "" || string(r.Status) == status
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
	devices, latest, err := h.deps.Devices.ListWithExpiry(r.Context(), usr.ID)
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
		row := newDeviceRow(d, latest[d.ID], h.deps.Cfg.Feed, now)
		counts[row.Status]++
		if !matchesQuery(d, q) || !row.matchesStatus(status) {
			continue
		}
		rows = append(rows, row)
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
	return slices.ContainsFunc([]string{d.Label, d.Hostname, d.CurrentIPv4, d.CurrentIPv6}, func(field string) bool {
		return strings.Contains(strings.ToLower(field), q)
	})
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
	h.logAndFailMessage(w, r, usr, action, err, "Something went wrong. Please try again.")
}

// logAndFailMessage is logAndFail with caller-supplied copy, for the failures
// where "please try again" is actively misleading: a mutation that already took
// effect before the step that failed. Retrying those either repeats a
// destructive action or hits a conflict, so the page has to say what happened
// and what to do instead. The message must still be free of internal detail —
// that goes to the log, as always.
func (h *handler) logAndFailMessage(w http.ResponseWriter, r *http.Request, usr store.User, action string, err error, message string) {
	h.deps.Log.LogAttrs(r.Context(), slog.LevelError, "webui: "+action+" failed", slog.Any("error", err))
	h.renderError(w, r, usr, http.StatusInternalServerError, message)
}

// deviceNewData is device-new.html's template data. Code is empty on the form
// step and populated on the reveal step; the template branches on it.
type deviceNewData struct {
	appData
	Label             string
	FieldErr          string
	Code              string
	Command           string
	ContainerEnroll   string
	ContainerRun      string
	DevImageNote      string
	ExpiresIn         string
	ExpiresAt         string
	BaseURLWarning    string
	ContainerHostNote string
}

// clientImageRepo is the client image published by this project's CI. The
// release path is ci.yaml:115-124 (release-image-client); ci.yaml:77 builds the
// same repo for non-release pushes. Keep this and the two constants below in
// sync with README.md's container section — both describe one operator
// contract, and someone who follows one and then the other must not be given
// two different answers.
const clientImageRepo = "ghcr.io/jacaudi/diyddns/client"

// clientVolume is the credentials volume, deliberately identical to the name
// README.md already tells operators to use, so the two surfaces cannot diverge.
const clientVolume = "diyddns-client"

// clientContainer is the run container's name. Deliberately NOT clientVolume:
// `docker rm -f X` removes a container and leaves the volume untouched, so one
// string naming both object kinds makes the recovery instruction ambiguous —
// it looks like it clears the volume when it does not.
const clientContainer = "diyddns-client-run"

// releaseTagRe matches the only tag shape this project publishes: release-please
// emits vMAJOR.MINOR.PATCH and ci-build.yml pushes it via
// type=semver,pattern=v{{version}}.
//
// Everything else falls back to :latest, which always exists. That covers a dev
// build, an operator's own -ldflags string, and semver build metadata — the last
// of which matters because `+` is legal in a version but ILLEGAL in a Docker
// tag ("invalid reference format").
//
// Prereleases are excluded because release-please-config.json sets no prerelease
// key, so none can be produced. That coupling is enforced by
// TestReleasePleaseHasNoPrerelease, not by this comment.
var releaseTagRe = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// clientImage returns the client image reference to advertise and, when it had
// to fall back, the note explaining why. An empty note means "release build,
// render nothing" — the same convention baseURLWarning uses in this file.
func clientImage(v version.Info) (ref, note string) {
	if releaseTagRe.MatchString(v.Version) {
		return clientImageRepo + ":" + v.Version, ""
	}
	return clientImageRepo + ":latest",
		"This server is a development build, so the command pins :latest, which tracks main " +
			"rather than the newest release. Pin a released tag in production."
}

// containerHostNote explains the containerBaseURL rewrite to whoever is about
// to paste the enroll command. It is rendered only when the rewrite actually
// happened — an operator whose base URL already names a reachable host has no
// use for it.
const containerHostNote = "localhost was rewritten to host.docker.internal because, inside a container, " +
	"localhost is the container itself. On Docker Desktop this alias just works; on Linux add " +
	"--add-host=host.docker.internal:host-gateway to both docker run commands (enroll and run)."

// containerBaseURL rewrites base for use in the container enroll command
// only: inside a container, localhost/127.0.0.1/::1 resolve to the container
// itself, not the host running the server, so an enroll against those hosts
// fails with a connection refused even though it is the server's own
// base_url (see README.md's Containers section). host.docker.internal is the
// documented workaround, resolving out of the box on Docker Desktop and, on
// Linux, with --add-host=host.docker.internal:host-gateway.
//
// Any other host, and any base that fails to parse, is returned unchanged.
func containerBaseURL(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	host := u.Hostname()
	loopback := strings.EqualFold(host, "localhost")
	if !loopback {
		if ip := net.ParseIP(host); ip != nil {
			loopback = ip.IsLoopback()
		}
	}
	if !loopback {
		return base
	}
	port := u.Port()
	u.Host = "host.docker.internal"
	if port != "" {
		u.Host += ":" + port
	}
	return u.String()
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
	// Single-line deliberately: .copy code is white-space:nowrap, so an embedded
	// newline would render as a space while the Copy button still copied a real
	// newline — displayed and copied text would differ.
	ref, note := clientImage(h.deps.Info)
	containerBase := containerBaseURL(base)
	data.ContainerEnroll = fmt.Sprintf(
		"docker run --rm -v %s:/home/nonroot/.config %s enroll --server %s --code %s",
		clientVolume, ref, containerBase, code)
	if containerBase != base {
		data.ContainerHostNote = containerHostNote
	}
	// No subcommand and no flags: CMD ["run"] is the image default, and `run`
	// reads server_url back out of credentials.json.
	data.ContainerRun = fmt.Sprintf(
		"docker run -d --name %s --restart unless-stopped -v %s:/home/nonroot/.config %s",
		clientContainer, clientVolume, ref)
	data.DevImageNote = note
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
		" was derived from the address you are browsing. Check the scheme before running the commands below — " +
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

// deviceScope says whose device a device page is showing and where that
// device's pages live. ownerScope is the owner looking at their own device;
// adminScope is an admin looking at anyone's (#132 D6). ListURL, DetailURL,
// and HistoryURL are set by the constructor on every scope, so no page can
// render an empty href for those. OwnerURL is the one field that is
// deliberately empty on the owner's page — see its own comment below.
//
// It exists because the session user used to play two roles in newDetailData
// -- the shell (newAppData, CSRF, nav) and the SCOPE of the history reads plus
// the Owner label -- and on the admin path those are two different people. A
// second store.User parameter beside the first would be two same-typed values
// the compiler cannot tell apart; this is the second role, named.
type deviceScope struct {
	OwnerID    string // scope argument for DeviceService.History / LatestAddress
	OwnerEmail string // the facts card's Owner row
	OwnerURL   string // "" on the owner's page (plain text); /admin/users/{id} on the admin's
	Nav        string // "devices" | "admin-devices"
	ListURL    string // "/devices" | "/admin/devices"
	ListLabel  string // "Devices" | "All Devices"
	DetailURL  string // ListURL + "/" + dev.ID
	HistoryURL string // DetailURL + "/history"
}

// ownerScope is the owner-scoped view: usr owns dev, and every page lives
// under /devices.
func ownerScope(usr store.User, dev store.Device) deviceScope {
	return newDeviceScope(usr, "", "devices", "/devices", "Devices", dev)
}

// adminScope is the admin-scoped view of ANY device: owner is the device's
// owner, resolved by AdminService.GetDevice, and every page lives under
// /admin/devices. The Owner row links to the owner's admin page.
func adminScope(owner store.User, dev store.Device) deviceScope {
	return newDeviceScope(owner, "/admin/users/"+owner.ID, "admin-devices", "/admin/devices", "All Devices", dev)
}

func newDeviceScope(owner store.User, ownerURL, nav, listURL, listLabel string, dev store.Device) deviceScope {
	detail := listURL + "/" + dev.ID
	return deviceScope{
		OwnerID: owner.ID, OwnerEmail: owner.Email, OwnerURL: ownerURL,
		Nav: nav, ListURL: listURL, ListLabel: listLabel,
		DetailURL: detail, HistoryURL: detail + "/history",
	}
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
	OwnerURL    string // "" on the owner's page (plain text); /admin/users/{id} on the admin's (#132 D12)
	HistoryURL  string // this device's full-history page, owner- or admin-scoped
	History     []historyRow
	Error       string

	Secret         string // base64, rotate reveal only
	Credentials    string // the credentials.json body to paste
	BaseURLWarning string // set when server.base_url is unset (see baseURLWarning)

	// IPv4LastKnown/IPv6LastKnown carry a family's last-recorded address when
	// the sweep has cleared Device.CurrentIPv4/CurrentIPv6 -- "" means the
	// family is current (or has never reported at all), so the template
	// falls back to showing the device's own current column. *At is that
	// value's age, rendered with relDays, and is set only alongside the
	// matching LastKnown field.
	IPv4LastKnown   string
	IPv4LastKnownAt string
	IPv6LastKnown   string
	IPv6LastKnownAt string

	// ShowExpiry/V4ExpiresIn/V6ExpiresIn are the detail page's half of #127 UI
	// review finding B: the list already showed a countdown for a family that
	// still holds an address, but the detail page showed none at all. Same
	// gate as newDeviceRow (ShowExpiry off entirely when the policy is opted
	// out; per-family, keyed on the CURRENT column so a cleared family never
	// shows a countdown beside its own expiry notice) and the same
	// expiresInText/stale.HumanDays rounding, not a second copy of it.
	ShowExpiry  bool
	V4ExpiresIn string
	V6ExpiresIn string
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
// history rows the page previews. usr is the signed-in user (the shell); v
// says whose device this is and scopes the reads (#132 D6) -- the two are the
// same person on the owner's page and different people on the admin's.
func (h *handler) newDetailData(r *http.Request, usr store.User, sess store.Session, v deviceScope, dev store.Device) (deviceDetailData, error) {
	page, err := h.deps.Devices.History(r.Context(), v.OwnerID, dev.ID, "", 5)
	if err != nil {
		return deviceDetailData{}, err
	}
	now := time.Now()
	data := deviceDetailData{
		appData:     h.newAppData(usr, sess, dev.Label, v.Nav),
		Device:      dev,
		Status:      deviceStatus(dev, now),
		LastSeenRel: relTime(dev.LastSeenAt, now),
		LastSeenAbs: absTime(dev.LastSeenAt),
		CreatedAbs:  absTime(dev.CreatedAt),
		Owner:       v.OwnerEmail,
		OwnerURL:    v.OwnerURL,
		HistoryURL:  v.HistoryURL,
		History:     historyRows(page.Rows, now),
	}

	needV4 := dev.CurrentIPv4 == ""
	needV6 := dev.CurrentIPv6 == ""
	if needV4 {
		if addr, at, ok := lastKnownFamily(page.Rows, func(h store.IPHistory) string { return h.IPv4 }); ok {
			data.IPv4LastKnown, data.IPv4LastKnownAt = addr, relDays(at, now)
			needV4 = false
		}
	}
	if needV6 {
		if addr, at, ok := lastKnownFamily(page.Rows, func(h store.IPHistory) string { return h.IPv6 }); ok {
			data.IPv6LastKnown, data.IPv6LastKnownAt = addr, relDays(at, now)
			needV6 = false
		}
	}
	// The five-row preview didn't carry it -- fall back to the same
	// per-family read the list pages use, scoped to this one device.
	if needV4 || needV6 {
		latest, err := h.deps.Devices.LatestAddress(r.Context(), v.OwnerID, dev.ID)
		if err != nil {
			return deviceDetailData{}, err
		}
		if needV4 && latest.IPv4 != "" {
			data.IPv4LastKnown, data.IPv4LastKnownAt = latest.IPv4, relDays(latest.IPv4At, now)
		}
		if needV6 && latest.IPv6 != "" {
			data.IPv6LastKnown, data.IPv6LastKnownAt = latest.IPv6, relDays(latest.IPv6At, now)
		}
	}

	// Gated exactly as the list is -- see expiryFields' doc comment (shared
	// with newDeviceRow) for why the gate must be the CURRENT column, not
	// history availability.
	data.ShowExpiry, data.V4ExpiresIn, data.V6ExpiresIn = expiryFields(dev, h.deps.Cfg.Feed, now)
	return data, nil
}

// lastKnownFamily scans rows -- already newest-first from Page/History -- for
// the newest one whose family (selected by get) carries a value. ok is false
// when none of the given rows carries one, which tells the caller to fall
// back to LatestAddressPerFamily instead.
func lastKnownFamily(rows []store.IPHistory, get func(store.IPHistory) string) (addr string, at int64, ok bool) {
	for _, row := range rows {
		if v := get(row); v != "" {
			return v, row.ObservedAt, true
		}
	}
	return "", 0, false
}

// handleDeviceDetail renders one device.
func (h *handler) handleDeviceDetail(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	dev, ok := h.ownedDevice(w, r, usr)
	if !ok {
		return
	}
	data, err := h.newDetailData(r, usr, sess, ownerScope(usr, dev), dev)
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
	data, err := h.newDetailData(r, usr, sess, ownerScope(usr, dev), dev)
	if err != nil {
		// The rotation has ALREADY COMMITTED at this point and the plaintext
		// lives only in the local above — this failure is the cosmetic history
		// query newDetailData runs to fill the preview card. "Please try again"
		// would be wrong twice over: nothing was undone, and trying again
		// rotates the secret a second time.
		h.logAndFailMessage(w, r, usr, "load device history", err,
			"The secret was rotated, but the page showing it could not be built. "+
				"The new secret is not recoverable. Rotate it again to get one you can copy.")
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
	data, err := h.newDetailData(r, usr, sess, ownerScope(usr, dev), dev)
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

// renderBadCursor renders the 400 both paginated screens answer for a malformed
// or stale ?cursor= (design §4.4). The message and its companion link are
// single-sourced here: the copy names a destination, so the two must change
// together or the page tells the user to go somewhere it does not take them.
func (h *handler) renderBadCursor(w http.ResponseWriter, r *http.Request, usr store.User) {
	h.renderErrorLink(w, r, usr, http.StatusBadRequest,
		"That page link is no longer valid. Start from the first page.",
		"Start from the first page", firstPageURL(r))
}

// firstPageURL is the requested URL with only the cursor dropped, so restarting
// keeps whatever filters the user was reading — an admin sent back to an
// unfiltered audit log has lost their query. Derived from the request rather
// than rebuilt per screen, so a new filter is preserved without anyone
// remembering to add it here.
func firstPageURL(r *http.Request) string {
	q := r.URL.Query()
	q.Del("cursor")
	if encoded := q.Encode(); encoded != "" {
		return r.URL.Path + "?" + encoded
	}
	return r.URL.Path
}

// deviceHistoryData is device-history.html's template data. The four URLs
// come from the deviceScope so the owner's and the admin's history pages can
// never link into each other's route family (#132 D13).
type deviceHistoryData struct {
	appData
	Device     store.Device
	Rows       []historyRow
	Pager      pager
	HasCursor  bool
	ListURL    string
	ListLabel  string
	DetailURL  string
	HistoryURL string
}

// handleDeviceHistory renders one device's paginated IP history for its owner.
func (h *handler) handleDeviceHistory(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	dev, ok := h.ownedDevice(w, r, usr)
	if !ok {
		return
	}
	h.renderDeviceHistory(w, r, usr, sess, ownerScope(usr, dev), dev)
}

// renderDeviceHistory renders one device's paginated IP history for whichever
// relationship v names: the owner under /devices, an admin under
// /admin/devices (#132 D13). The read is scoped by v.OwnerID; the pager and
// every link are built from v.HistoryURL, exactly as they were built from the
// local "base" before the admin page existed.
func (h *handler) renderDeviceHistory(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session, v deviceScope, dev store.Device) {
	cursor := r.URL.Query().Get("cursor")
	page, err := h.deps.Devices.History(r.Context(), v.OwnerID, dev.ID, cursor, historyPageSize)
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
			h.renderBadCursor(w, r, usr)
			return
		}
		h.renderError(w, r, usr, http.StatusInternalServerError, "Something went wrong. Please try again.")
		return
	}

	p := pager{RowCount: len(page.Rows)}
	if page.NextCursor != "" {
		p.NextURL = v.HistoryURL + "?cursor=" + url.QueryEscape(page.NextCursor)
	}
	if cursor != "" {
		p.FirstURL = v.HistoryURL
	}

	h.render(w, r, "device-history", deviceHistoryData{
		appData:    h.newAppData(usr, sess, dev.Label+" history", v.Nav),
		Device:     dev,
		Rows:       historyRows(page.Rows, time.Now()),
		Pager:      p,
		HasCursor:  cursor != "",
		ListURL:    v.ListURL,
		ListLabel:  v.ListLabel,
		DetailURL:  v.DetailURL,
		HistoryURL: v.HistoryURL,
	})
}
