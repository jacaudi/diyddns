package webui

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/stale"
	"github.com/jacaudi/diyddns/internal/store"
	"github.com/jacaudi/diyddns/internal/version"
)

func TestClientImage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		version  string
		wantRef  string
		wantNote bool
	}{
		{"release", "v0.1.0", "ghcr.io/jacaudi/diyddns/client:v0.1.0", false},
		{"double digits", "v10.20.30", "ghcr.io/jacaudi/diyddns/client:v10.20.30", false},
		{"dev build", "v0.0.0-dev", "ghcr.io/jacaudi/diyddns/client:latest", true},
		{"empty", "", "ghcr.io/jacaudi/diyddns/client:latest", true},
		{"test fixture", "test", "ghcr.io/jacaudi/diyddns/client:latest", true},
		{"operator ldflags", "mybuild", "ghcr.io/jacaudi/diyddns/client:latest", true},
		// Build metadata is legal semver but an ILLEGAL Docker tag: docker
		// rejects it outright with "invalid reference format".
		{"build metadata", "v1.2.3+build7", "ghcr.io/jacaudi/diyddns/client:latest", true},
		// Prereleases are excluded deliberately — see TestReleasePleaseHasNoPrerelease.
		{"prerelease", "v1.2.3-rc.1", "ghcr.io/jacaudi/diyddns/client:latest", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref, note := clientImage(version.Info{Version: tc.version})
			if ref != tc.wantRef {
				t.Errorf("ref = %q, want %q", ref, tc.wantRef)
			}
			if got := note != ""; got != tc.wantNote {
				t.Errorf("note present = %v, want %v (note=%q)", got, tc.wantNote, note)
			}
		})
	}
}

// TestReleasePleaseHasNoPrerelease makes clientImage's prerelease exclusion
// mechanical rather than aspirational. releaseTagRe deliberately rejects
// vX.Y.Z-rc.N and falls back to :latest, which is correct ONLY while
// release-please cannot emit a prerelease tag. docker/metadata-action DOES
// publish an image for a prerelease, so if this config ever grows a prerelease
// key, clientImage would point RC operators away from an image that exists —
// and at a :latest that tracks main, i.e. ahead of their own server.
//
// The walk only descends into objects, not arrays; a prerelease key nested
// inside a plugins array would be missed. Adequate as a canary.
func TestReleasePleaseHasNoPrerelease(t *testing.T) {
	raw, err := os.ReadFile("../../../release-please-config.json")
	if err != nil {
		t.Fatalf("read release-please-config.json: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse release-please-config.json: %v", err)
	}
	var found []string
	var walk func(string, map[string]any)
	walk = func(path string, m map[string]any) {
		for k, v := range m {
			if strings.Contains(strings.ToLower(k), "prerelease") {
				found = append(found, path+"/"+k)
			}
			if nested, ok := v.(map[string]any); ok {
				walk(path+"/"+k, nested)
			}
		}
	}
	walk("", cfg)
	if len(found) > 0 {
		t.Fatalf("release-please-config.json now has prerelease key(s) %v — "+
			"revisit releaseTagRe in devices.go: prerelease images DO get published, "+
			"so falling back to :latest now points operators at the wrong image", found)
	}
}

// webUIFixture bundles a fully-wired handler with one signed-in user, for
// tests that exercise a full HTTP request against the #127 staleness
// surfaces. now is a fixed snapshot of store.NowUnix so every seed helper's
// offset stays exact regardless of how long the test takes to run.
//
// Deliberately not t.Parallel() -- see TestAccount_RendersInAppShell:
// testDeps's store.Open races under -race with a concurrent one via goose's
// package-level globals.
type webUIFixture struct {
	deps   Deps
	st     *store.Store
	h      http.Handler
	usr    store.User
	cookie *http.Cookie
	now    int64
}

// newWebUIFixture builds a fixture with the staleness policy ON at the
// design's default window (21 days) -- production's default -- so a test that
// only sets a confirmation instant, without calling setFeed, exercises the
// policy as an operator actually runs it.
func newWebUIFixture(t *testing.T) *webUIFixture {
	t.Helper()
	deps, st := testDeps(t)
	deps.Cfg.Feed.Enabled = true
	deps.Cfg.Feed.ExpireAfterDays = 21
	h, _ := New(deps)
	usr := seedUser(t, st, "fixture@example.com", "user")
	return &webUIFixture{
		deps:   deps,
		st:     st,
		h:      h,
		usr:    usr,
		cookie: signIn(t, deps, usr),
		now:    store.NowUnix(),
	}
}

// setFeed replaces the staleness policy and rebuilds the handler so the new
// config takes effect -- New copies Deps by value, so the handler built in
// newWebUIFixture keeps seeing the old policy otherwise.
func (f *webUIFixture) setFeed(t *testing.T, feed config.FeedSection) {
	t.Helper()
	f.deps.Cfg.Feed = feed
	f.h, _ = New(f.deps)
}

// get performs a signed-in GET and requires 200, returning the body.
func (f *webUIFixture) get(t *testing.T, path string) string {
	t.Helper()
	rec := getPage(t, f.h, f.cookie, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200:\n%s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// seedConfirmedAt seeds one device whose IPv4 was confirmed at the absolute
// unix instant confirmedAt (not an offset -- callers pass h.now-N*86400) and
// is still current -- the ordinary case a countdown renders for.
func (f *webUIFixture) seedConfirmedAt(t *testing.T, confirmedAt int64) string {
	t.Helper()
	d := seedDevice(t, f.st, f.usr.ID, "device-"+store.NewID())
	if err := f.st.Devices().UpdateIP(t.Context(), d.ID, "10.0.0.1", "", "", "", "", confirmedAt); err != nil {
		t.Fatalf("seed confirmed device: %v", err)
	}
	return d.ID
}

// seedExpired seeds a device that reported addr ageSeconds ago, then had it
// cleared exactly as DeviceRepo.ExpireFamilies writes it: current_ipv4 NULL,
// plus the sweep's own ip_history row recording the clearing. The detail
// page's fallback is exercised against the real shape of that write, not an
// approximation of it.
func (f *webUIFixture) seedExpired(t *testing.T, addr string, ageSeconds int64) string {
	t.Helper()
	d := seedDevice(t, f.st, f.usr.ID, "expired-"+store.NewID())
	confirmedAt := f.now - ageSeconds
	if _, err := f.st.IPHistory().Append(t.Context(), store.IPHistory{
		DeviceID: d.ID, IPv4: addr, ObservedAt: confirmedAt,
	}); err != nil {
		t.Fatalf("seed real report: %v", err)
	}
	if err := f.st.Devices().UpdateIP(t.Context(), d.ID, addr, "", "", "", "", confirmedAt); err != nil {
		t.Fatalf("seed confirmed device: %v", err)
	}
	if _, changed, err := f.st.Devices().ExpireFamilies(t.Context(), d.ID, true, false, confirmedAt, 0, f.now); err != nil {
		t.Fatalf("seed expiry sweep: %v", err)
	} else if !changed {
		t.Fatal("seed expiry sweep: ExpireFamilies reported no change")
	}
	return d.ID
}

// D17 end to end: the detail page shows what the address WAS and when.
func TestDeviceDetail_ShowsLastKnownAddressAfterExpiry(t *testing.T) {
	h := newWebUIFixture(t)
	id := h.seedExpired(t, "203.0.113.9", 23*86400)

	body := h.get(t, "/devices/"+id)
	for _, want := range []string{"203.0.113.9", "23 days ago"} {
		if !strings.Contains(body, want) {
			t.Errorf("device page missing %q", want)
		}
	}
}

// The countdown must NOT render when the policy is opted out: Window is 0, so
// an ungated template prints "expires in 0 days" on a DEFAULT install -- not
// a negative number (expiresInText's confirmedAt==0 guard and remaining<=0
// clamp rule that out), but still wrong when the policy claims to be off.
func TestDeviceList_NoCountdownWhenExpiryDisabled(t *testing.T) {
	h := newWebUIFixture(t)
	h.setFeed(t, config.FeedSection{Enabled: true, ExpireAfterDays: 0})
	h.seedConfirmedAt(t, h.now-14*86400)

	if body := h.get(t, "/devices"); strings.Contains(body, "expires in") {
		t.Errorf("countdown rendered with the policy opted out:\n%s", body)
	}
}

// §10 item 3: the countdown comes from the same function the sweep uses, so
// the page and the sweep cannot disagree.
// Fix round 1, item 3: the fixture's default window (21 days) is also
// config's default, so a hardcoded 21*86400 literal in place of
// stale.Window(feed) would keep this test green -- and be wrong for every
// operator running a non-default window. A non-default window here, plus a
// substring specific enough that "16 days" cannot satisfy it, makes the two
// distinguishable.
func TestDeviceList_CountdownUsesTheSameWindowAsTheSweep(t *testing.T) {
	h := newWebUIFixture(t)
	h.setFeed(t, config.FeedSection{Enabled: true, ExpireAfterDays: 10})
	h.seedConfirmedAt(t, h.now-4*86400) // 6 days left at W=10

	if body := h.get(t, "/devices"); !strings.Contains(body, "expires in 6 days") {
		t.Errorf("countdown missing or the wrong window was used:\n%s", body)
	}
}

// TestExpiresInText_AgreesWithTheOwnerEmail: fix round, item 3. The sweep's
// owner email (stale.HumanDays) and this page's countdown used to round in
// OPPOSITE directions -- the email floors, the page ceiled -- so a rung
// crossed partway through a day (the typical case for an hourly sweep) told
// the owner one number by email and a different one on the device list. Pinned
// at the canonical mismatch from the review: 13d23h30m remaining reads "13
// days" (floor, matching the email) not "14 days" (the old ceiling).
func TestExpiresInText_AgreesWithTheOwnerEmail(t *testing.T) {
	now := time.Unix(100*86400, 0)
	window := stale.Window(config.FeedSection{Enabled: true, ExpireAfterDays: 21})
	// confirmedAt chosen so ExpiresAt(confirmedAt, window) - now.Unix() is
	// exactly 13d23h30m: elapsed = 21d - 13d23h30m = 7d30m.
	elapsed := int64((7*24*time.Hour + 30*time.Minute).Seconds())
	confirmedAt := now.Unix() - elapsed

	got := expiresInText(confirmedAt, window, now)
	if got != "13 days" {
		t.Errorf("expiresInText = %q, want %q (floor, matching stale.HumanDays)", got, "13 days")
	}
}

// TestNewDeviceRow_ShowsLastKnownAddressWhenCurrentIsEmpty: the list pages'
// row derivation must fall back to the last-recorded address the same way
// the detail page does (design #10) -- otherwise a sweep-cleared device
// renders a bare dash on /devices with no way to see what it used to be.
func TestNewDeviceRow_ShowsLastKnownAddressWhenCurrentIsEmpty(t *testing.T) {
	now := time.Unix(100*86400, 0)
	d := store.Device{ID: "d1", Label: "laptop"}
	latest := store.LatestAddress{IPv4: "203.0.113.9", IPv4At: 77 * 86400}

	row := newDeviceRow(d, latest, config.FeedSection{}, now)

	if !row.IPv4Expired {
		t.Fatal("IPv4Expired = false, want true for a cleared family with a recorded last-known value")
	}
	if row.IPv4 != "203.0.113.9" {
		t.Errorf("IPv4 = %q, want the last-known value 203.0.113.9", row.IPv4)
	}
	if row.IPv4At != "23 days ago" {
		t.Errorf("IPv4At = %q, want 23 days ago", row.IPv4At)
	}
}

// TestNewDeviceRow_SuppressesCountdownForAnExpiredFamily: fix round 1, item
// 1. ExpireFamilies clears current_ipv4 but deliberately leaves
// v4_confirmed_at at its old (now permanently stale) instant -- that column
// is the optimistic pin the sweep writes against, not a liveness signal. An
// ungated countdown computed from that stale instant renders "expires in 0
// days" forever beside "expired 23 days ago", on exactly the devices this
// feature exists to explain. The two families are independent: IPv6 is still
// live here and must still show its own countdown.
func TestNewDeviceRow_SuppressesCountdownForAnExpiredFamily(t *testing.T) {
	now := time.Unix(100*86400, 0)
	feed := config.FeedSection{Enabled: true, ExpireAfterDays: 21}
	d := store.Device{
		ID:            "d1",
		CurrentIPv6:   "2001:db8::1",
		V4ConfirmedAt: 50 * 86400, // long past expiry; ExpireFamilies never touches this
		V6ConfirmedAt: 86 * 86400, // confirmed 14 days ago -> 7 days left at W=21
	}
	latest := store.LatestAddress{IPv4: "203.0.113.9", IPv4At: 77 * 86400}

	row := newDeviceRow(d, latest, feed, now)

	if !row.IPv4Expired {
		t.Fatal("IPv4Expired = false, want true")
	}
	if row.V4ExpiresIn != "" {
		t.Errorf("V4ExpiresIn = %q, want empty -- a cleared family must never show a countdown beside its own expiry notice", row.V4ExpiresIn)
	}
	if row.V6ExpiresIn != "7 days" {
		t.Errorf("V6ExpiresIn = %q, want 7 days -- a live family's countdown must still render", row.V6ExpiresIn)
	}
}

// TestNewDeviceRow_SuppressesCountdownForAnExpiredIPv6Family mirrors
// TestNewDeviceRow_SuppressesCountdownForAnExpiredFamily with the families
// swapped: fix round 2, item 2 -- the IPv4 case alone left the IPv6 half of
// the per-family gate unpinned (mutating it to "if true" changed nothing any
// test observed).
func TestNewDeviceRow_SuppressesCountdownForAnExpiredIPv6Family(t *testing.T) {
	now := time.Unix(100*86400, 0)
	feed := config.FeedSection{Enabled: true, ExpireAfterDays: 21}
	d := store.Device{
		ID:            "d1",
		CurrentIPv4:   "10.0.0.1",
		V4ConfirmedAt: 86 * 86400, // confirmed 14 days ago -> 7 days left at W=21
		V6ConfirmedAt: 50 * 86400, // long past expiry; ExpireFamilies never touches this
	}
	latest := store.LatestAddress{IPv6: "2001:db8::1", IPv6At: 77 * 86400}

	row := newDeviceRow(d, latest, feed, now)

	if !row.IPv6Expired {
		t.Fatal("IPv6Expired = false, want true")
	}
	if row.V6ExpiresIn != "" {
		t.Errorf("V6ExpiresIn = %q, want empty -- a cleared family must never show a countdown beside its own expiry notice", row.V6ExpiresIn)
	}
	if row.V4ExpiresIn != "7 days" {
		t.Errorf("V4ExpiresIn = %q, want 7 days -- a live family's countdown must still render", row.V4ExpiresIn)
	}
}

// TestNewDeviceRow_NoCountdownWhenAddressPrunedFromHistory: fix round 2,
// item 1. IPv4Expired is set only when history still has a last-known value
// to show (row.IPv4 == "" && latest.IPv4 != ""), so a swept family whose
// ip_history rows have since been pruned (retention: ip_history_days /
// ip_history_per_device_max) leaves IPv4Expired false -- gating the
// countdown on that flag would then compute it from the stale
// V4ConfirmedAt ExpireFamilies never touches, reproducing the original
// defect keyed on history availability instead of on the sweep. The real
// precondition is the current column itself.
func TestNewDeviceRow_NoCountdownWhenAddressPrunedFromHistory(t *testing.T) {
	now := time.Unix(100*86400, 0)
	feed := config.FeedSection{Enabled: true, ExpireAfterDays: 21}
	d := store.Device{
		ID:            "d1",
		V4ConfirmedAt: 50 * 86400, // long past expiry; ExpireFamilies never touches this
	}
	// latest is the zero value: the pruner has removed every ip_history row
	// that carried an IPv4 address for this device, so
	// LatestAddressPerFamily has nothing to fall back to.
	row := newDeviceRow(d, store.LatestAddress{}, feed, now)

	if row.IPv4Expired {
		t.Fatal("IPv4Expired = true, want false: there is no last-known value left to show")
	}
	if row.V4ExpiresIn != "" {
		t.Errorf("V4ExpiresIn = %q, want empty -- the sweep cleared this family; there is nothing to count down", row.V4ExpiresIn)
	}
}

// TestNewDeviceRow_NoCountdownWhenExpiryDisabled pins the Go-side half of
// the ShowExpiry gate directly. TestDeviceList_NoCountdownWhenExpiryDisabled
// (an end-to-end absence check) only fails if BOTH the Go gate here AND
// partials.html's {{if and .ShowExpiry .V4ExpiresIn}} are removed at once --
// removing either alone leaves the other one suppressing the output, so
// that test alone cannot catch a single-token regression in either gate.
// This test pins the Go half independently.
func TestNewDeviceRow_NoCountdownWhenExpiryDisabled(t *testing.T) {
	now := time.Unix(100*86400, 0)
	d := store.Device{ID: "d1", CurrentIPv4: "10.0.0.1", V4ConfirmedAt: 86 * 86400}

	row := newDeviceRow(d, store.LatestAddress{}, config.FeedSection{Enabled: true, ExpireAfterDays: 0}, now)

	if row.ShowExpiry {
		t.Error("ShowExpiry = true, want false when the policy is opted out")
	}
	if row.V4ExpiresIn != "" {
		t.Errorf("V4ExpiresIn = %q, want empty when the policy is opted out", row.V4ExpiresIn)
	}
}

// TestDeviceDetail_FallsBackBeyondFivePreviewRows: when none of the five
// newest history rows carries a family's address, the detail page still
// finds it via the single-device fallback (service.DeviceService.LatestAddress),
// not just the preview window newDetailData fetches for its History card.
func TestDeviceDetail_FallsBackBeyondFivePreviewRows(t *testing.T) {
	h := newWebUIFixture(t)
	id := h.seedExpired(t, "203.0.113.9", 40*86400)
	// Six more IPv6-only check-ins push the real IPv4 report out of the
	// five-row preview window.
	for range 6 {
		seedHistory(t, h.st, id, "", "2001:db8::1", "")
	}

	body := h.get(t, "/devices/"+id)
	if !strings.Contains(body, "203.0.113.9") {
		t.Errorf("device page missing last-known IPv4 beyond the 5-row preview:\n%s", body)
	}
}
