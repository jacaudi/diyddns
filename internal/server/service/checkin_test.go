package service

import (
	"context"
	"testing"

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
	svc := NewCheckinService(st, NopNotifier{})

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
	svc := NewCheckinService(st, NopNotifier{})

	report := CheckinReport{IPv4: "1.2.3.4", Hostname: "lp", OS: "linux", ClientVersion: "1.0.0"}
	if _, err := svc.Checkin(t.Context(), dev.ID, report); err != nil {
		t.Fatalf("first Checkin: %v", err)
	}
	// Rewind last_seen_at to a known-old value so the liveness advance is
	// observable despite NowUnix() second-granularity.
	if err := st.Devices().Touch(t.Context(), dev.ID, 1000); err != nil {
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
	svc := NewCheckinService(st, NopNotifier{})

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
	svc := NewCheckinService(st, NopNotifier{})

	// Establish a dual-stack device: both families stored.
	if _, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "1.2.3.4", IPv6: "2001:db8::1"}); err != nil {
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
	if res.CurrentIPv6 != "2001:db8::1" {
		t.Fatalf("Checkin result CurrentIPv6 = %q, want preserved 2001:db8::1", res.CurrentIPv6)
	}

	updated, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("Devices.GetByID: %v", err)
	}
	if updated.CurrentIPv4 != "5.6.7.8" {
		t.Fatalf("device CurrentIPv4 = %q, want 5.6.7.8", updated.CurrentIPv4)
	}
	if updated.CurrentIPv6 != "2001:db8::1" {
		t.Fatalf("device CurrentIPv6 = %q, want preserved 2001:db8::1 (omitted family must not clobber)", updated.CurrentIPv6)
	}

	page, err := st.IPHistory().Page(t.Context(), dev.ID, "", 50)
	if err != nil {
		t.Fatalf("IPHistory.Page: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("ip_history rows = %d, want 2", len(page.Rows))
	}
	// Newest row (Page is newest-first) must carry the preserved ipv6.
	if page.Rows[0].IPv6 != "2001:db8::1" {
		t.Fatalf("newest ip_history row IPv6 = %q, want preserved 2001:db8::1", page.Rows[0].IPv6)
	}
	if page.Rows[0].IPv4 != "5.6.7.8" {
		t.Fatalf("newest ip_history row IPv4 = %q, want 5.6.7.8", page.Rows[0].IPv4)
	}
}

func TestCheckin_OmittedFamilyMatchingStored_IsNoOp(t *testing.T) {
	st := openTestStore(t)
	usr := seedUser(t, st, "a@b.co", "user")
	dev := seedDevice(t, st, usr.ID, "laptop")
	svc := NewCheckinService(st, NopNotifier{})

	if _, err := svc.Checkin(t.Context(), dev.ID, CheckinReport{IPv4: "1.2.3.4", IPv6: "2001:db8::1"}); err != nil {
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
	if res.CurrentIPv6 != "2001:db8::1" {
		t.Fatalf("Checkin result CurrentIPv6 = %q, want 2001:db8::1", res.CurrentIPv6)
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
	svc := NewCheckinService(st, NopNotifier{})

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
	if _, err := NewCheckinService(st, NopNotifier{}).Checkin(ctx, dev.ID,
		CheckinReport{IPv4: "198.51.100.7", IPv6: "2001:db8::7"}); err != nil {
		t.Fatalf("seed prior address: %v", err)
	}
	dev, err := st.Devices().GetByID(ctx, dev.ID)
	if err != nil {
		t.Fatalf("reload device: %v", err)
	}
	n := &recordingNotifier{}
	svc := NewCheckinService(st, n)

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
	if _, err := NewCheckinService(st, NopNotifier{}).Checkin(ctx, dev.ID,
		CheckinReport{IPv4: "198.51.100.7", IPv6: "2001:db8::7"}); err != nil {
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
	svc := NewCheckinService(st, n)

	rep := CheckinReport{IPv4: "203.0.113.9"} // v6 omitted: merge-on-empty preserves it
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
	if ev.CurrIPv4 != "203.0.113.9" {
		t.Errorf("CurrIPv4 = %q, want 203.0.113.9", ev.CurrIPv4)
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
	svc := NewCheckinService(st, panickingNotifier{})

	res, err := svc.Checkin(ctx, dev.ID, CheckinReport{IPv4: "203.0.113.10"})
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
