package service

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

// seedDevice creates and returns a device for usr with an empty initial
// IP/metadata state (mirrors a freshly-enrolled device before its first
// checkin). Reused by later service test files in this package.
func seedDevice(t *testing.T, st *store.Store, userID, label string) store.Device {
	t.Helper()
	d, err := st.Devices().Create(t.Context(), store.Device{
		UserID:     userID,
		Label:      label,
		SecretHash: "sealed-secret",
	})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return d
}

func TestCheckin_FirstReport_StoresAndAppendsHistory(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewCheckinService(st, nopNotifier{}, slog.New(slog.DiscardHandler), time.Now)

	res, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{
		IPv4: "1.2.3.4", Hostname: "lp", OS: "linux", ClientVersion: "1.0.0",
	})
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if !res.Stored {
		t.Fatal("Checkin: Stored = false, want true on first report")
	}
	if res.DeviceID != dev.ID || res.CurrentIPv4 != "1.2.3.4" {
		t.Fatalf("Checkin result = %+v, want DeviceID=%q CurrentIPv4=1.2.3.4", res, dev.ID)
	}

	page, err := st.IPHistory().Page(t.Context(), dev.ID, "", 50)
	if err != nil {
		t.Fatalf("IPHistory.Page: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("ip_history rows = %d, want 1", len(page.Rows))
	}
	if page.Rows[0].IPv4 != "1.2.3.4" {
		t.Fatalf("ip_history row IPv4 = %q, want 1.2.3.4", page.Rows[0].IPv4)
	}

	updated, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("Devices.GetByID: %v", err)
	}
	if updated.CurrentIPv4 != "1.2.3.4" {
		t.Fatalf("device CurrentIPv4 = %q, want 1.2.3.4", updated.CurrentIPv4)
	}
	if updated.LastSeenAt == 0 {
		t.Fatal("device LastSeenAt = 0, want set after IP change")
	}
}

func TestCheckin_IdenticalReport_TouchesLastSeenButNoHistory(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewCheckinService(st, nopNotifier{}, slog.New(slog.DiscardHandler), time.Now)

	report := CheckinReport{IPv4: "1.2.3.4", Hostname: "lp", OS: "linux", ClientVersion: "1.0.0"}
	if _, err := svc.Checkin(t.Context(), dev.ID, report); err != nil {
		t.Fatalf("first Checkin: %v", err)
	}
	// Rewind last_seen_at to a known-old value so the liveness advance is
	// observable despite NowUnix() second-granularity.
	if err := st.Devices().Touch(t.Context(), dev.ID, true, true, 1000); err != nil {
		t.Fatalf("rewind Touch: %v", err)
	}

	res, err := svc.Checkin(t.Context(), dev.ID, report) // unchanged IP
	if err != nil {
		t.Fatalf("second Checkin: %v", err)
	}
	if res.Stored {
		t.Fatal("Checkin: Stored = true, want false for an unchanged report")
	}
	if res.CurrentIPv4 != "1.2.3.4" {
		t.Fatalf("Checkin result CurrentIPv4 = %q, want 1.2.3.4", res.CurrentIPv4)
	}

	// ip_history still does NOT grow on an unchanged check-in.
	page, err := st.IPHistory().Page(t.Context(), dev.ID, "", 50)
	if err != nil {
		t.Fatalf("IPHistory.Page: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("ip_history rows = %d, want 1 (no new row on unchanged checkin)", len(page.Rows))
	}

	// last_seen_at DID advance past the rewound value (liveness; #12).
	after, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("Devices.GetByID: %v", err)
	}
	if after.LastSeenAt <= 1000 {
		t.Fatalf("device LastSeenAt did not advance on unchanged check-in: got %d, want > 1000", after.LastSeenAt)
	}
}

func TestCheckin_ChangedIP_AppendsNewHistoryRow(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewCheckinService(st, nopNotifier{}, slog.New(slog.DiscardHandler), time.Now)

	if _, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "1.2.3.4"}); err != nil {
		t.Fatalf("first Checkin: %v", err)
	}

	res, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "5.6.7.8"})
	if err != nil {
		t.Fatalf("second Checkin: %v", err)
	}
	if !res.Stored {
		t.Fatal("Checkin: Stored = false, want true for a changed IP")
	}
	if res.CurrentIPv4 != "5.6.7.8" {
		t.Fatalf("Checkin result CurrentIPv4 = %q, want 5.6.7.8", res.CurrentIPv4)
	}

	page, err := st.IPHistory().Page(t.Context(), dev.ID, "", 50)
	if err != nil {
		t.Fatalf("IPHistory.Page: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("ip_history rows = %d, want 2 (append on IP change)", len(page.Rows))
	}
}

func TestCheckin_OmittedFamily_PreservesStoredValue(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewCheckinService(st, nopNotifier{}, slog.New(slog.DiscardHandler), time.Now)

	// Establish a dual-stack device: both families stored.
	if _, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "1.2.3.4", IPv6: "2606:4700::1"}); err != nil {
		t.Fatalf("seed dual-stack Checkin: %v", err)
	}

	// A client that confirms only IPv4 omits IPv6 (sends ""). The stored
	// IPv6 must be preserved, not clobbered to NULL.
	res, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "5.6.7.8"})
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if !res.Stored {
		t.Fatal("Checkin: Stored = false, want true (ipv4 changed)")
	}
	if res.CurrentIPv4 != "5.6.7.8" {
		t.Fatalf("Checkin result CurrentIPv4 = %q, want 5.6.7.8", res.CurrentIPv4)
	}
	if res.CurrentIPv6 != "2606:4700::1" {
		t.Fatalf("Checkin result CurrentIPv6 = %q, want preserved 2606:4700::1", res.CurrentIPv6)
	}

	updated, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("Devices.GetByID: %v", err)
	}
	if updated.CurrentIPv4 != "5.6.7.8" {
		t.Fatalf("device CurrentIPv4 = %q, want 5.6.7.8", updated.CurrentIPv4)
	}
	if updated.CurrentIPv6 != "2606:4700::1" {
		t.Fatalf("device CurrentIPv6 = %q, want preserved 2606:4700::1 (omitted family must not clobber)", updated.CurrentIPv6)
	}

	page, err := st.IPHistory().Page(t.Context(), dev.ID, "", 50)
	if err != nil {
		t.Fatalf("IPHistory.Page: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("ip_history rows = %d, want 2", len(page.Rows))
	}
	// Newest row (Page is newest-first) must carry the preserved ipv6.
	if page.Rows[0].IPv6 != "2606:4700::1" {
		t.Fatalf("newest ip_history row IPv6 = %q, want preserved 2606:4700::1", page.Rows[0].IPv6)
	}
	if page.Rows[0].IPv4 != "5.6.7.8" {
		t.Fatalf("newest ip_history row IPv4 = %q, want 5.6.7.8", page.Rows[0].IPv4)
	}
}

func TestCheckin_OmittedFamilyMatchingStored_IsNoOp(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewCheckinService(st, nopNotifier{}, slog.New(slog.DiscardHandler), time.Now)

	if _, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "1.2.3.4", IPv6: "2606:4700::1"}); err != nil {
		t.Fatalf("seed dual-stack Checkin: %v", err)
	}

	// Client re-asserts only IPv4 (unchanged) and omits IPv6. Effective
	// values equal the stored values → no-op, no new row.
	res, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "1.2.3.4"})
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if res.Stored {
		t.Fatal("Checkin: Stored = true, want false (effective values unchanged)")
	}
	if res.CurrentIPv6 != "2606:4700::1" {
		t.Fatalf("Checkin result CurrentIPv6 = %q, want 2606:4700::1", res.CurrentIPv6)
	}

	page, err := st.IPHistory().Page(t.Context(), dev.ID, "", 50)
	if err != nil {
		t.Fatalf("IPHistory.Page: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("ip_history rows = %d, want 1 (no new row on effective no-op)", len(page.Rows))
	}
}

func TestCheckinService_Self_ReturnsDevice(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewCheckinService(st, nopNotifier{}, slog.New(slog.DiscardHandler), time.Now)

	got, err := svc.Self(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("Self: %v", err)
	}
	if got.ID != dev.ID {
		t.Fatalf("Self: ID = %q, want %q", got.ID, dev.ID)
	}
}

// recordingNotifier captures IPChanged calls without doing any I/O.
type recordingNotifier struct{ events []store.IPChangeEvent }

func (r *recordingNotifier) IPChanged(_ context.Context, ev store.IPChangeEvent) {
	r.events = append(r.events, ev)
}

func TestCheckin_UnchangedIPDoesNotNotify(t *testing.T) {
	// The helpers that actually exist: openTestStore (enrollment_test.go:28),
	// seedUser, and seedDevice (checkin_test.go:12). There is no combined
	// fixture and no returned ctx — the existing tests use t.Context().
	st := openTestStore(t)
	ctx := t.Context()
	usr := seedUser(t, st, "owner@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")

	// seedDevice starts a device with EMPTY IP state, so give it a prior
	// address before asserting anything about previous values — otherwise
	// "PrevIPv4 == dev.CurrentIPv4" is "" == "" and passes against an
	// implementation that never sets PrevIPv4 at all.
	if _, err := NewCheckinService(st, nopNotifier{}, slog.New(slog.DiscardHandler), time.Now).Checkin(ctx, dev.ID,
		CheckinReport{IPv4: "1.0.0.7", IPv6: "2606:4700::7"}); err != nil {
		t.Fatalf("seed prior address: %v", err)
	}
	dev, err := st.Devices().GetByID(ctx, dev.ID)
	if err != nil {
		t.Fatalf("reload device: %v", err)
	}
	n := &recordingNotifier{}
	svc := NewCheckinService(st, n, slog.New(slog.DiscardHandler), time.Now)

	rep := CheckinReport{IPv4: dev.CurrentIPv4, IPv6: dev.CurrentIPv6}
	res, err := svc.Checkin(ctx, dev.ID, rep)
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if res.Stored {
		t.Fatal("Stored = true for an unchanged check-in")
	}
	if len(n.events) != 0 {
		t.Errorf("notified %d times on an unchanged check-in, want 0", len(n.events))
	}
}

func TestCheckin_ChangedIPNotifiesOnceWithPreviousValues(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	usr := seedUser(t, st, "owner@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	if _, err := NewCheckinService(st, nopNotifier{}, slog.New(slog.DiscardHandler), time.Now).Checkin(ctx, dev.ID,
		CheckinReport{IPv4: "1.0.0.7", IPv6: "2606:4700::7"}); err != nil {
		t.Fatalf("seed prior address: %v", err)
	}
	dev, err := st.Devices().GetByID(ctx, dev.ID)
	if err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if dev.CurrentIPv4 == "" {
		t.Fatal("fixture did not establish a prior IPv4; the previous-value assertions below would be vacuous")
	}

	n := &recordingNotifier{}
	svc := NewCheckinService(st, n, slog.New(slog.DiscardHandler), time.Now)

	rep := CheckinReport{IPv4: "8.8.4.4"} // v6 omitted: merge-on-empty preserves it
	res, err := svc.Checkin(ctx, dev.ID, rep)
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if !res.Stored {
		t.Fatal("Stored = false for a changed check-in")
	}
	if len(n.events) != 1 {
		t.Fatalf("notified %d times, want 1", len(n.events))
	}
	ev := n.events[0]
	if ev.PrevIPv4 != dev.CurrentIPv4 {
		t.Errorf("PrevIPv4 = %q, want %q", ev.PrevIPv4, dev.CurrentIPv4)
	}
	if ev.CurrIPv4 != "8.8.4.4" {
		t.Errorf("CurrIPv4 = %q, want 8.8.4.4", ev.CurrIPv4)
	}
	if ev.PrevIPv6 != dev.CurrentIPv6 || ev.CurrIPv6 != dev.CurrentIPv6 {
		t.Errorf("v6 moved: prev=%q curr=%q, want both %q", ev.PrevIPv6, ev.CurrIPv6, dev.CurrentIPv6)
	}
	if ev.EventID == 0 {
		t.Error("EventID = 0, want the ip_history row id")
	}
	if got := ev.Changed(); len(got) != 1 || got[0] != "ipv4" {
		t.Errorf("Changed() = %v, want [ipv4]", got)
	}
}

// The hard constraint: the device liveness path must survive a broken hook.
// This test drives a `defer recover()` around the notify call in Checkin. If
// the implementation omits it, this panics and the test fails — which is the
// point.
func TestCheckin_NotifierPanicDoesNotFailCheckin(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	usr := seedUser(t, st, "owner@example.com", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewCheckinService(st, panickingNotifier{}, slog.New(slog.DiscardHandler), time.Now)

	res, err := svc.Checkin(ctx, dev.ID, CheckinReport{IPv4: "1.0.0.1"})
	if err != nil {
		t.Fatalf("Checkin failed because of the notifier: %v", err)
	}
	if !res.Stored {
		t.Error("Stored = false; the check-in itself must have succeeded")
	}
}

// panickingNotifier is the worst case a broken hook can present: not an error
// (IPChanged returns none by design) but a panic — a nil logger or nil repo in
// the Enqueuer would do exactly this. Without a recover in Checkin's call site
// it propagates and the device gets a 500, violating the hard constraint that
// /agent/v1/checkin survives a broken hook.
type panickingNotifier struct{}

func (panickingNotifier) IPChanged(context.Context, store.IPChangeEvent) {
	panic("notifier exploded")
}

// blockIPHistoryInserts installs a SQLite trigger that aborts every INSERT
// into ip_history, so a check-in fails between its two writes without any
// fake store or injected repository. The trigger is removed on cleanup.
func blockIPHistoryInserts(t *testing.T, st *store.Store) {
	t.Helper()
	const create = `CREATE TRIGGER block_ip_history_insert
		BEFORE INSERT ON ip_history
		BEGIN SELECT RAISE(ABORT, 'injected ip_history failure'); END`
	if _, err := st.DB().ExecContext(t.Context(), create); err != nil {
		t.Fatalf("install trigger: %v", err)
	}
	t.Cleanup(func() {
		if _, err := st.DB().ExecContext(context.Background(), `DROP TRIGGER block_ip_history_insert`); err != nil {
			t.Errorf("drop trigger: %v", err)
		}
	})
}

func TestCheckin_HistoryAppendFails_LeavesDeviceUnchanged(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewCheckinService(st, nopNotifier{}, slog.New(slog.DiscardHandler), time.Now)

	// Establish a known stored address, then make the history write fail.
	if _, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "1.2.3.4"}); err != nil {
		t.Fatalf("seed Checkin: %v", err)
	}
	blockIPHistoryInserts(t, st)

	if _, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "5.6.7.8"}); err == nil {
		t.Fatal("Checkin: error = nil, want the injected ip_history failure")
	}

	// #97: the device row and ip_history must agree — both writes land or
	// neither does. A half-applied check-in shows the new IP with no history
	// row for it, so "last change" silently skips the change.
	got, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("Devices.GetByID: %v", err)
	}
	if got.CurrentIPv4 != "1.2.3.4" {
		t.Errorf("device CurrentIPv4 = %q, want 1.2.3.4 (the failed check-in must roll back)", got.CurrentIPv4)
	}

	page, err := st.IPHistory().Page(t.Context(), dev.ID, "", 50)
	if err != nil {
		t.Fatalf("IPHistory.Page: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Errorf("ip_history rows = %d, want 1 (only the seed check-in)", len(page.Rows))
	}
}

// nopNotifier and nopDeviceNotifier stand in for the fan-out in tests that do
// not observe notifications.
type nopNotifier struct{}

func (nopNotifier) IPChanged(context.Context, store.IPChangeEvent) {}

type nopDeviceNotifier struct{}

func (nopDeviceNotifier) DeviceAdded(context.Context, store.Device)   {}
func (nopDeviceNotifier) DeviceRemoved(context.Context, store.Device) {}

// fakeClock is a settable clock for the WARN rate limiter.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

// noOriginHint is the exact hint the no-public-origin WARN carries.
const noOriginHint = "server.trusted_proxies may not cover your proxy, or the device reaches the server over a private path (LAN/VPN); its client falls back to lookup in auto mode"

// newSourceFixture returns a service over a fresh store with a capture logger
// and a fake clock, plus a seeded device that has never checked in.
func newSourceFixture(t *testing.T) (*CheckinService, *store.Store, store.Device, *lockedBuffer, *fakeClock) {
	t.Helper()
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	log, buf := captureLog()
	clk := &fakeClock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	return NewCheckinService(st, nopNotifier{}, log, clk.now), st, dev, buf, clk
}

// warnsNamed returns the WARN records in buf whose message is msg.
func warnsNamed(t *testing.T, buf *lockedBuffer, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, rec := range logRecords(t, buf) {
		if rec["level"] == "WARN" && rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

func reloadDevice(t *testing.T, st *store.Store, id string) store.Device {
	t.Helper()
	d, err := st.Devices().GetByID(t.Context(), id)
	if err != nil {
		t.Fatalf("Devices.GetByID: %v", err)
	}
	return d
}

func TestCheckinReportedWinsIgnoresObserved(t *testing.T) {
	svc, st, dev, _, _ := newSourceFixture(t)

	res, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "8.8.8.8", Observed: netip.MustParseAddr("1.1.1.1")})
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if got := reloadDevice(t, st, dev.ID).CurrentIPv4; got != "8.8.8.8" {
		t.Errorf("stored v4 = %q, want 8.8.8.8 (reported wins)", got)
	}
	if res.SourceV4 != SourceReported || res.SourceV6 != "" {
		t.Errorf("sources = (%q, %q), want (reported, \"\")", res.SourceV4, res.SourceV6)
	}
}

func TestCheckinReportedCanonicalised(t *testing.T) {
	svc, st, dev, _, _ := newSourceFixture(t)

	if _, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv6: "2606:4700:0::1"}); err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if got := reloadDevice(t, st, dev.ID).CurrentIPv6; got != "2606:4700::1" {
		t.Errorf("stored v6 = %q, want 2606:4700::1", got)
	}
}

func TestCheckinReportedInvalidDropped(t *testing.T) {
	tests := []struct {
		name   string
		report CheckinReport
		v6     bool // which family the dropped value was reported in
	}{
		{"unparseable v4", CheckinReport{IPv4: "nope"}, false},
		{"v6 in ipv4", CheckinReport{IPv4: "2606:4700::1"}, false},
		{"4-in-6 in ipv4", CheckinReport{IPv4: "::ffff:8.8.8.8"}, false},
		{"v4 in ipv6", CheckinReport{IPv6: "8.8.8.8"}, true},
		{"4-in-6 in ipv6", CheckinReport{IPv6: "::ffff:8.8.8.8"}, true},
		{"private v4", CheckinReport{IPv4: "10.0.0.1"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, st, dev, _, _ := newSourceFixture(t)
			if _, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "1.2.3.4", IPv6: "2606:4700::1"}); err != nil {
				t.Fatalf("seed Checkin: %v", err)
			}

			res, err := svc.Checkin(t.Context(), dev.ID, tc.report)
			if err != nil {
				t.Fatalf("Checkin: %v", err)
			}
			if res.Stored {
				t.Error("Stored = true, want false for a dropped report")
			}
			got := reloadDevice(t, st, dev.ID)
			if got.CurrentIPv4 != "1.2.3.4" || got.CurrentIPv6 != "2606:4700::1" {
				t.Errorf("device = (%q, %q), want unchanged (1.2.3.4, 2606:4700::1)", got.CurrentIPv4, got.CurrentIPv6)
			}
			src, other := res.SourceV4, res.SourceV6
			if tc.v6 {
				src, other = other, src
			}
			if src != SourceNone || other != "" {
				t.Errorf("sources = (reported family %q, other %q), want (none, \"\")", src, other)
			}
		})
	}
}

func TestCheckinReportedPrivateFamilyDropped(t *testing.T) {
	svc, st, dev, buf, clk := newSourceFixture(t)
	report := CheckinReport{IPv4: "10.0.0.1", IPv6: "2606:4700::1"}

	res, err := svc.Checkin(t.Context(), dev.ID, report)
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	got := reloadDevice(t, st, dev.ID)
	if got.CurrentIPv4 != "" || got.CurrentIPv6 != "2606:4700::1" {
		t.Errorf("device = (%q, %q), want (\"\", 2606:4700::1)", got.CurrentIPv4, got.CurrentIPv6)
	}
	if res.SourceV4 != SourceNone || res.SourceV6 != SourceReported {
		t.Errorf("sources = (%q, %q), want (none, reported)", res.SourceV4, res.SourceV6)
	}

	const msg = "check-in reported a non-public address; dropped"
	warns := warnsNamed(t, buf, msg)
	if len(warns) != 1 {
		t.Fatalf("dropped WARNs = %d, want 1:\n%s", len(warns), buf.String())
	}
	if warns[0]["device_id"] != dev.ID || warns[0]["family"] != "ipv4" {
		t.Errorf("WARN fields = %v, want device_id=%s family=ipv4", warns[0], dev.ID)
	}

	// Rate limited: same device inside the hour stays at one, past it logs again.
	clk.t = clk.t.Add(59 * time.Minute)
	if _, err := svc.Checkin(t.Context(), dev.ID, report); err != nil {
		t.Fatalf("Checkin +59m: %v", err)
	}
	if n := len(warnsNamed(t, buf, msg)); n != 1 {
		t.Errorf("dropped WARNs at +59m = %d, want 1", n)
	}
	clk.t = clk.t.Add(2 * time.Minute)
	if _, err := svc.Checkin(t.Context(), dev.ID, report); err != nil {
		t.Fatalf("Checkin +61m: %v", err)
	}
	if n := len(warnsNamed(t, buf, msg)); n != 2 {
		t.Errorf("dropped WARNs at +61m = %d, want 2", n)
	}
}

func TestCheckinReportedPrivateDoesNotFallBackToObserved(t *testing.T) {
	svc, st, dev, _, _ := newSourceFixture(t)
	if _, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "1.2.3.4"}); err != nil {
		t.Fatalf("seed Checkin: %v", err)
	}

	res, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "10.0.0.1", Observed: netip.MustParseAddr("1.1.1.1")})
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if got := reloadDevice(t, st, dev.ID).CurrentIPv4; got != "1.2.3.4" {
		t.Errorf("stored v4 = %q, want unchanged 1.2.3.4 (no fallback to observed)", got)
	}
	if res.SourceV4 != SourceNone {
		t.Errorf("SourceV4 = %q, want none", res.SourceV4)
	}
}

func TestCheckinObservedFillsFamily(t *testing.T) {
	svc, st, dev, _, _ := newSourceFixture(t)
	if _, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv6: "2606:4700::1"}); err != nil {
		t.Fatalf("seed Checkin: %v", err)
	}
	// Pin both confirmation instants to a known-old value so the advance of
	// one and not the other is observable at NowUnix() granularity.
	if err := st.Devices().Touch(t.Context(), dev.ID, true, true, 1000); err != nil {
		t.Fatalf("rewind Touch: %v", err)
	}

	res, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{Observed: netip.MustParseAddr("1.1.1.1")})
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	got := reloadDevice(t, st, dev.ID)
	if got.CurrentIPv4 != "1.1.1.1" || got.CurrentIPv6 != "2606:4700::1" {
		t.Errorf("device = (%q, %q), want (1.1.1.1, 2606:4700::1 kept)", got.CurrentIPv4, got.CurrentIPv6)
	}
	if res.SourceV4 != SourceObserved || res.SourceV6 != "" {
		t.Errorf("sources = (%q, %q), want (observed, \"\")", res.SourceV4, res.SourceV6)
	}
	if got.V4ConfirmedAt <= 1000 {
		t.Errorf("V4ConfirmedAt = %d, want advanced past 1000", got.V4ConfirmedAt)
	}
	if got.V6ConfirmedAt != 1000 {
		t.Errorf("V6ConfirmedAt = %d, want untouched 1000", got.V6ConfirmedAt)
	}
}

func TestCheckinObservedV6(t *testing.T) {
	svc, st, dev, _, _ := newSourceFixture(t)

	res, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{Observed: netip.MustParseAddr("2606:4700::2")})
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if res.SourceV6 != SourceObserved || res.SourceV4 != "" {
		t.Errorf("sources = (%q, %q), want (\"\", observed)", res.SourceV4, res.SourceV6)
	}
	if got := reloadDevice(t, st, dev.ID).CurrentIPv6; got != "2606:4700::2" {
		t.Errorf("stored v6 = %q, want 2606:4700::2", got)
	}
}

func TestCheckinObservedPrivateIsNone(t *testing.T) {
	svc, st, dev, buf, clk := newSourceFixture(t)
	priv := netip.MustParseAddr("10.0.0.5")
	report := CheckinReport{Observed: priv, Peer: priv}

	res, err := svc.Checkin(t.Context(), dev.ID, report)
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if res.SourceV4 != SourceNone || res.SourceV6 != "" {
		t.Errorf("sources = (%q, %q), want (none, \"\")", res.SourceV4, res.SourceV6)
	}
	got := reloadDevice(t, st, dev.ID)
	if got.CurrentIPv4 != "" || got.LastSeenAt == 0 {
		t.Errorf("device = %+v, want no v4 recorded but LastSeenAt set (Touch)", got)
	}

	const msg = "check-in had no public origin address"
	warns := warnsNamed(t, buf, msg)
	if len(warns) != 1 {
		t.Fatalf("WARNs = %d, want 1:\n%s", len(warns), buf.String())
	}
	w := warns[0]
	if w["device_id"] != dev.ID || w["peer"] != "10.0.0.5" || w["observed"] != "10.0.0.5" || w["hint"] != noOriginHint {
		t.Errorf("WARN = %v, want device_id=%s peer/observed=10.0.0.5 hint=%q", w, dev.ID, noOriginHint)
	}

	clk.t = clk.t.Add(59 * time.Minute)
	if _, err := svc.Checkin(t.Context(), dev.ID, report); err != nil {
		t.Fatalf("Checkin +59m: %v", err)
	}
	if n := len(warnsNamed(t, buf, msg)); n != 1 {
		t.Errorf("WARNs at +59m = %d, want 1", n)
	}
	clk.t = clk.t.Add(2 * time.Minute)
	if _, err := svc.Checkin(t.Context(), dev.ID, report); err != nil {
		t.Fatalf("Checkin +61m: %v", err)
	}
	if n := len(warnsNamed(t, buf, msg)); n != 2 {
		t.Errorf("WARNs at +61m = %d, want 2", n)
	}
}

// A request with no observation at all (no peer address resolved: a trusted
// peer with no usable X-Forwarded-For, a PROXY LOCAL / still-trusted
// post-wrap source) reaches the service as a zero Observed and must record
// nothing.
func TestCheckinNoObservationIsTouchOnly(t *testing.T) {
	svc, st, dev, buf, _ := newSourceFixture(t)

	res, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{})
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if res.SourceV4 != "" || res.SourceV6 != "" {
		t.Errorf("sources = (%q, %q), want both omitted", res.SourceV4, res.SourceV6)
	}
	got := reloadDevice(t, st, dev.ID)
	if got.CurrentIPv4 != "" || got.CurrentIPv6 != "" || got.LastSeenAt == 0 {
		t.Errorf("device = %+v, want no IP recorded but LastSeenAt set (Touch)", got)
	}
	if n := len(warnsNamed(t, buf, "check-in had no public origin address")); n != 1 {
		t.Errorf("no-origin WARNs = %d, want 1:\n%s", n, buf.String())
	}
}

func TestWarnLimiterParallel(t *testing.T) {
	var l warnLimiter
	t0 := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if l.allow("dev", t0) {
				allowed.Add(1)
			}
		})
	}
	wg.Wait()
	if got := allowed.Load(); got != 1 {
		t.Errorf("allow returned true %d times, want exactly 1", got)
	}
}
