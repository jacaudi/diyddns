package server

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server/feed"
	"github.com/jacaudi/diyddns/internal/server/notify"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/server/stale"
	"github.com/jacaudi/diyddns/internal/store"
)

// recordingChannel implements stale.Channel and records every Delivery sent,
// standing in for SMTP so sweep_test.go can inspect exactly which staleness
// notices went out.
type recordingChannel struct {
	sent []stale.Delivery
}

func (c *recordingChannel) Send(_ context.Context, d stale.Delivery) error {
	c.sent = append(c.sent, d)
	return nil
}

// sweepFixture wires a sweeper against a real store exactly as production
// does: a real *fanout for the write path ExpireAddresses uses, and a
// recordingChannel + one fixed admin in place of SMTP.
type sweepFixture struct {
	t       *testing.T
	st      *store.Store
	checkin *service.CheckinService
	sweeper *sweeper
	ch      *recordingChannel
	now     int64

	// seenOutboxID is lastEvent's high-water mark: the highest
	// notification_deliveries.id it has already reported, so a round that
	// enqueues nothing does not fall back to reporting a PRIOR round's event
	// as if it were this round's (coordinator fix round 1, item 2).
	seenOutboxID int64
}

func newSweepFixture(t *testing.T) *sweepFixture {
	t.Helper()
	st := openTestStore(t)
	seedEnabledEndpoint(t, st, "ep")
	fo := newFanout(st, notify.NewEnqueuer(st, discardLog()), feed.New(), discardLog())
	ch := &recordingChannel{}
	admins := func(context.Context) ([]store.User, error) {
		return []store.User{{Email: "admin@example.test", Role: "admin"}}, nil
	}
	disp := stale.NewDispatcher(ch, admins, discardLog())
	cfg := config.FeedSection{Enabled: true, ExpireAfterDays: 21}
	return &sweepFixture{
		t:       t,
		st:      st,
		checkin: service.NewCheckinService(st, fo),
		sweeper: newSweeper(st, fo, cfg, disp, discardLog()),
		ch:      ch,
		now:     100_000_000, // an arbitrary large instant; Run takes "now" as a parameter, so it need not track wall-clock time
	}
}

// seed creates a device owned by a fresh user with the given addresses and
// confirmation instants, returning its id.
func (h *sweepFixture) seed(t *testing.T, v4, v6 string, v4Confirmed, v6Confirmed int64) string {
	t.Helper()
	u, err := h.st.Users().Create(t.Context(), store.User{Email: store.NewID() + "@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	d, err := h.st.Devices().Create(t.Context(), store.Device{
		UserID: u.ID, Label: store.NewID(), SecretHash: "h",
		CurrentIPv4: v4, CurrentIPv6: v6,
		V4ConfirmedAt: v4Confirmed, V6ConfirmedAt: v6Confirmed,
	})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return d.ID
}

// seedDisabledDevice seeds a due device whose OWN row is disabled, for
// candidateQuery's "d.disabled = 0" guard (coordinator fix round 1, item 6).
func (h *sweepFixture) seedDisabledDevice(t *testing.T, v4, v6 string, v4Confirmed, v6Confirmed int64) string {
	t.Helper()
	id := h.seed(t, v4, v6, v4Confirmed, v6Confirmed)
	if err := h.st.Devices().SetDisabled(t.Context(), id, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}
	return id
}

// seedDisabledOwner seeds a due device whose OWNER is disabled, for
// candidateQuery's "u.disabled = 0" guard (coordinator fix round 1, item 6).
func (h *sweepFixture) seedDisabledOwner(t *testing.T, v4, v6 string, v4Confirmed, v6Confirmed int64) string {
	t.Helper()
	u, err := h.st.Users().Create(t.Context(), store.User{Email: store.NewID() + "@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := h.st.Users().SetDisabled(t.Context(), u.ID, true); err != nil {
		t.Fatalf("SetDisabled owner: %v", err)
	}
	d, err := h.st.Devices().Create(t.Context(), store.Device{
		UserID: u.ID, Label: store.NewID(), SecretHash: "h",
		CurrentIPv4: v4, CurrentIPv6: v6,
		V4ConfirmedAt: v4Confirmed, V6ConfirmedAt: v6Confirmed,
	})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return d.ID
}

// seedDue seeds one device with a never-confirmed IPv4 address: a guaranteed
// candidate under any positive window, used only to build volume for the
// deadlock guard.
func (h *sweepFixture) seedDue(t *testing.T) {
	t.Helper()
	h.seed(t, "1.2.3.4", "", 0, 0)
}

func (h *sweepFixture) device(t *testing.T, id string) store.Device {
	t.Helper()
	d, err := h.st.Devices().GetByID(t.Context(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	return d
}

// resetDevice restores id's IPv4 address, confirmation instant and warning
// level directly (bypassing Checkin/Touch semantics, which would stamp
// v4_confirmed_at with the real wall clock instead of the stale value a test
// round needs), for a test that repeats a sweep/checkin race across several
// rounds.
func (h *sweepFixture) resetDevice(t *testing.T, id, v4 string, v4Confirmed int64) {
	t.Helper()
	if _, err := h.st.DB().ExecContext(t.Context(),
		`UPDATE devices SET current_ipv4 = ?, v4_confirmed_at = ?, v4_warn_level = 0, updated_at = ? WHERE id = ?`,
		v4, v4Confirmed, store.NowUnix(), id,
	); err != nil {
		t.Fatalf("resetDevice: %v", err)
	}
}

// lastEvent decodes the outbox delivery enqueued most recently SINCE THE LAST
// CALL -- ranked by notification_deliveries.id, which is enqueue order, i.e.
// "the stream's last word" D9 is about. It is deliberately NOT the payload's
// own embedded id (the ip_history row id):
// that id is fixed by each event's own write before the fanout mutex is ever
// involved, so picking the highest PAYLOAD id would reflect write order and
// stay correct even with the mutex removed -- the outbox row's OWN id is what
// actually moves if enqueue order is allowed to race ahead of write order.
//
// Restricting to ids above h.seenOutboxID (coordinator fix round 1, item 2)
// matters because a round can legitimately enqueue nothing at all: if the
// concurrent check-in's Touch lands before the sweep's ExpireAddresses, the
// sweep's pin fails and neither goroutine emits an event that round. Without
// the high-water mark, this method would return the PRIOR round's event, and
// a caller comparing it against the CURRENT round's row state would compare
// two different rounds against each other and fail on a false positive.
//
// Every row from DueForAttempt is decoded as expireEvent without checking its
// event_type: every producer this fixture exercises (Checkin's IPChanged,
// ExpireAddresses) emits device.ip_changed, and none of DeviceAdded/
// DeviceRemoved is ever called in these tests, so filtering here would be
// dead code guarding against a payload shape this fixture never produces.
func (h *sweepFixture) lastEvent() (expireEvent, bool) {
	h.t.Helper()
	due, err := h.st.NotificationDeliveries().DueForAttempt(h.t.Context(), store.NowUnix()+1, 1000)
	if err != nil {
		h.t.Fatalf("DueForAttempt: %v", err)
	}
	var last expireEvent
	var found bool
	lastOutboxID := h.seenOutboxID
	for _, d := range due {
		if d.ID <= h.seenOutboxID {
			continue // already reported by an earlier call
		}
		if found && d.ID < lastOutboxID {
			continue
		}
		var ev expireEvent
		if err := json.Unmarshal(d.Payload, &ev); err != nil {
			h.t.Fatalf("unmarshal payload: %v", err)
		}
		last, found, lastOutboxID = ev, true, d.ID
	}
	h.seenOutboxID = lastOutboxID
	return last, found
}

// notices returns every Notice this fixture's channel has recorded, one entry
// per LOGICAL notice. The same Notice value reaches the channel twice when
// its audience includes both the owner (sent inline via SendOwner) and the
// admin digest (RecipientsFor, D13), so entries are de-duplicated on
// (Kind, Family, Device.ID, Rung) -- which recur only for that reason: a
// removal is excluded from candidacy once it lands, and a rung cannot recur
// for the same device+family because DueRung only increases.
func (h *sweepFixture) notices() []stale.Notice {
	type key struct {
		kind     stale.Kind
		family   int
		deviceID string
		rung     int
	}
	seen := map[key]bool{}
	var out []stale.Notice
	for _, d := range h.ch.sent {
		for _, n := range d.Notices {
			k := key{n.Kind, n.Family, n.Device.ID, n.Rung}
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, n)
		}
	}
	return out
}

// The deadlock guard, in executable form. If the sweep writes while its cursor
// is open this never returns, and the context deadline is the only observable.
func TestSweep_IssuesNoWriteWhileACursorIsOpen(t *testing.T) {
	h := newSweepFixture(t)
	for range 50 {
		h.seedDue(t)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := h.sweeper.Run(ctx, h.now); err != nil {
		t.Fatalf("Run: %v (a deadline here means a write ran inside rows.Next())", err)
	}
}

// The candidacy term must select single-stack and partially-cleared devices. A
// scalar MIN over CASE arms survived two review passes while silently
// excluding exactly these populations, so this asserts the MATERIALISE step,
// not merely that a device eventually expires.
//
// It runs through modernc.org/sqlite, which is what newSweepFixture opens --
// the CLI agreeing is not evidence about the driver the product uses.
func TestSweep_CandidacyIncludesSingleStackAndPartiallyCleared(t *testing.T) {
	h := newSweepFixture(t)
	ids := map[string]string{
		"v4-only-due":      h.seed(t, "1.2.3.4", "", 100, 0),
		"v6-only-due":      h.seed(t, "", "2001:db8::1", 0, 100),
		"dual-due":         h.seed(t, "1.2.3.4", "2001:db8::1", 100, 100),
		"v6-cleared-v4due": h.seed(t, "1.2.3.4", "", 100, 50),
		"never-confirmed":  h.seed(t, "1.2.3.4", "", 0, 0),
		"fresh":            h.seed(t, "1.2.3.4", "2001:db8::1", h.now, h.now),
		"no-address":       h.seed(t, "", "", 100, 100),
		// coordinator fix round 1, item 6: otherwise a due device excluded
		// only by candidateQuery's disabled guards has no fixture row at all,
		// and dropping "d.disabled = 0 AND u.disabled = 0" passes every test.
		"disabled-device": h.seedDisabledDevice(t, "1.2.3.4", "", 100, 0),
		"disabled-owner":  h.seedDisabledOwner(t, "1.2.3.4", "", 100, 0),
	}
	got, err := h.sweeper.candidates(t.Context(), h.now)
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]bool{}
	for _, c := range got {
		in[c.ID] = true
	}
	for name, want := range map[string]bool{
		"v4-only-due": true, "v6-only-due": true, "dual-due": true,
		"v6-cleared-v4due": true, "never-confirmed": true,
		"fresh": false, "no-address": false,
		"disabled-device": false, "disabled-owner": false,
	} {
		if in[ids[name]] != want {
			t.Errorf("%s: candidate = %v, want %v", name, in[ids[name]], want)
		}
	}
}

// §6.2: expiry is evaluated BEFORE rungs. Otherwise a device already past its
// instant receives an "expires in -12 hours" warning immediately before its
// removal notice.
func TestSweep_ExpiryBeforeRungs(t *testing.T) {
	h := newSweepFixture(t)
	id := h.seed(t, "1.2.3.4", "", 100, 0) // long past expiry

	if err := h.sweeper.Run(t.Context(), h.now); err != nil {
		t.Fatal(err)
	}
	for _, n := range h.notices() {
		if n.Kind == stale.KindWarning {
			t.Errorf("device past expiry got warning rung %d before removal", n.Rung)
		}
	}
	if h.device(t, id).CurrentIPv4 != "" {
		t.Error("device past expiry was not expired")
	}
}

// D5: each address on its own clock. A device that keeps reporting IPv4 but
// stopped asserting IPv6 loses IPv6 on schedule and keeps IPv4 indefinitely.
func TestSweep_PerFamilyClocks(t *testing.T) {
	h := newSweepFixture(t)
	id := h.seed(t, "1.2.3.4", "2001:db8::1", h.now, h.now-22*86400)

	if err := h.sweeper.Run(t.Context(), h.now); err != nil {
		t.Fatal(err)
	}
	got := h.device(t, id)
	if got.CurrentIPv6 != "" {
		t.Error("stale IPv6 survived")
	}
	if got.CurrentIPv4 == "" {
		t.Error("live IPv4 was cleared")
	}
}

// §6.4: a cleared device that checks in again re-enters with NO readmit code
// path. This is the payoff of D7 and deserves an explicit test.
func TestSweep_ReEntryNeedsNoReadmitPath(t *testing.T) {
	h := newSweepFixture(t)
	id := h.seed(t, "1.2.3.4", "", 100, 0)
	if err := h.sweeper.Run(t.Context(), h.now); err != nil {
		t.Fatal(err)
	}
	if h.device(t, id).CurrentIPv4 != "" {
		t.Fatal("precondition: the address should have been cleared")
	}
	// An ordinary check-in. Nothing about it is staleness-aware.
	if _, err := h.checkin.Checkin(t.Context(), id, service.CheckinReport{IPv4: "5.6.7.8"}); err != nil {
		t.Fatal(err)
	}
	if got := h.device(t, id).CurrentIPv4; got != "5.6.7.8" {
		t.Errorf("CurrentIPv4 = %q, want 5.6.7.8", got)
	}
}

// §6.4: the flap that revision 8 needed a dedicated decision to prevent cannot
// occur here, and this test is what says so.
func TestSweep_V6DeadDeviceDoesNotFlap(t *testing.T) {
	h := newSweepFixture(t)
	id := h.seed(t, "1.2.3.4", "2001:db8::1", h.now, h.now-22*86400)

	for tick := range 5 {
		if err := h.sweeper.Run(t.Context(), h.now+int64(tick)*3600); err != nil {
			t.Fatal(err)
		}
		// The client keeps asserting ONLY IPv4.
		if _, err := h.checkin.Checkin(t.Context(), id, service.CheckinReport{IPv4: "1.2.3.4"}); err != nil {
			t.Fatal(err)
		}
	}
	removals := 0
	for _, n := range h.notices() {
		if n.Kind == stale.KindRemoved {
			removals++
		}
	}
	if removals != 1 {
		t.Errorf("%d removal notices across five ticks, want exactly 1", removals)
	}
}

// TestSweep_CheckinPreservesConfirmedForUnassertedFamily is not one of the
// plan's eight named tests. It closes a gap TestSweep_V6DeadDeviceDoesNotFlap
// cannot: that test's loop always runs Run() before Checkin(), so by the time
// Checkin ever sees the device its IPv6 has already been cleared by removal,
// and the raw-vs-merged assertion distinction is unobservable once a family
// is empty -- both readings agree it is "not asserted". Verified directly:
// mutating service.Checkin to derive v4Asserted/v6Asserted from the merged
// effective values instead of the raw report left the whole suite green,
// including TestSweep_V6DeadDeviceDoesNotFlap.
//
// This test instead seeds IPv6 well inside its window (present, not yet due),
// so a check-in that omits it exercises the one condition where raw and
// merged actually diverge: the merge is a no-op (the stored value survives
// unchanged) precisely because the family was never re-asserted this cycle.
func TestSweep_CheckinPreservesConfirmedForUnassertedFamily(t *testing.T) {
	h := newSweepFixture(t)
	staleSince := h.now - 10*86400 // well inside the 21-day window: present, not due
	id := h.seed(t, "1.2.3.4", "2001:db8::1", h.now, staleSince)

	if _, err := h.checkin.Checkin(t.Context(), id, service.CheckinReport{IPv4: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if got := h.device(t, id).V6ConfirmedAt; got != staleSince {
		t.Errorf("V6ConfirmedAt = %d, want %d unchanged -- an omitted family must not be "+
			"treated as asserted merely because its merged value is unchanged", got, staleSince)
	}
}

// TestSweep_WarnFiresAtRungBoundary is not one of the plan's eight named
// tests. Coordinator fix round 1, item 1: the entire warning ladder was
// unreached by any existing test. Every OTHER fixture in this file seeds a
// confirmedAt that is fresh (h.now), never confirmed (0), or already past the
// removal instant (h.now-22*86400); the one exception --
// TestSweep_CheckinPreservesConfirmedForUnassertedFamily's staleSince
// (h.now-10*86400, deliberately inside the window, per its own comment) --
// never passes through Run() at all, so it exercises Checkin, not the sweep's
// ladder. warn() (Step 6.3), AdvanceWarnLevel, survivingAfter, confirmedAt and
// warnLevel therefore had zero KindWarning coverage. Verified: swapping
// stale.FirstRung(s.cfg) for stale.Window(s.cfg) in candidates()'s bound left
// every one of the other nine tests in this file green (see the mutation
// probe table in the task report).
func TestSweep_WarnFiresAtRungBoundary(t *testing.T) {
	h := newSweepFixture(t)
	w := stale.Window(h.sweeper.cfg)
	rung1 := stale.Rungs(w)[0]
	// IPv4 sits exactly at rung 1; IPv6 is fresh, so the notice's Surviving
	// must name it.
	id := h.seed(t, "1.2.3.4", "2001:db8::1", h.now-rung1, h.now)

	if err := h.sweeper.Run(t.Context(), h.now); err != nil {
		t.Fatal(err)
	}

	var got *stale.Notice
	for _, n := range h.notices() {
		if n.Kind == stale.KindWarning && n.Family == 4 {
			got = &n
		}
	}
	if got == nil {
		t.Fatal("no IPv4 warning notice fired at the rung-1 boundary")
	}
	if got.Rung != 1 {
		t.Errorf("Rung = %d, want 1", got.Rung)
	}
	if !slices.Contains(got.Surviving, 6) {
		t.Errorf("Surviving = %v, want it to include IPv6", got.Surviving)
	}
	if lvl := h.device(t, id).V4WarnLevel; lvl != 1 {
		t.Errorf("V4WarnLevel = %d, want 1", lvl)
	}

	// A second tick at the identical elapsed time must not re-fire: "overdue
	// rungs do not stack" (warn's own doc comment). Counted on the raw
	// channel, flattened and filtered to this exact (Kind, Family, Rung) --
	// not h.notices()'s deduped view, which would hide a re-send of the
	// identical tuple, and not a bare len(h.ch.sent), which would also fail
	// if rung 1 were ever promoted to the admin audience, for a reason that
	// has nothing to do with re-sending.
	if err := h.sweeper.Run(t.Context(), h.now); err != nil {
		t.Fatal(err)
	}
	fires := 0
	for _, d := range h.ch.sent {
		for _, n := range d.Notices {
			if n.Kind == stale.KindWarning && n.Family == 4 && n.Rung == 1 {
				fires++
			}
		}
	}
	if fires != 1 {
		t.Errorf("rung-1 IPv4 warning delivered %d times across two identical ticks, want 1 (no re-send)", fires)
	}
}

// S-1: when BOTH families come due in one tick, neither removal notice may
// claim the other survives. Computing Surviving from the pre-write candidate
// produces exactly that contradiction, and a test that inspects only one of
// the two notices passes against it.
func TestSweep_FullExpiryNoticesAgree(t *testing.T) {
	h := newSweepFixture(t)
	h.seed(t, "1.2.3.4", "2001:db8::1", 100, 100) // both long overdue

	if err := h.sweeper.Run(t.Context(), h.now); err != nil {
		t.Fatal(err)
	}
	var removals []stale.Notice
	for _, n := range h.notices() {
		if n.Kind == stale.KindRemoved {
			removals = append(removals, n)
		}
	}
	if len(removals) != 2 {
		t.Fatalf("got %d removal notices, want 2 (one per family)", len(removals))
	}
	for _, n := range removals {
		if len(n.Surviving) != 0 {
			t.Errorf("family %d notice claims %v survives, but both families were cleared",
				n.Family, n.Surviving)
		}
	}
}

// D9, from design §13: the write and its event must not be separable. A
// re-entry interleaved between them must not leave the stream's last word
// disagreeing with the row.
//
// This is a smoke test, not a guard: removing fanout's mutex did not
// reproduce a failure here across 100+ rounds over 8 local runs -- the race
// window between ExpireAddresses's commit and its own dispatch call is a few
// microseconds, and Go's scheduler essentially never lands there without an
// artificial delay, which must never be added to production code just to make
// a test deterministic. This test exercises the interleaving path; it does
// not prove the mutex is load-bearing. That argument is made in
// ExpireAddresses's own doc comment (fanout.go), not here -- a reader relying
// on this test as the proof would be trusting something it cannot show.
func TestSweep_ReEntryCannotReorderAgainstTheExpiry(t *testing.T) {
	h := newSweepFixture(t)
	id := h.seed(t, "1.2.3.4", "", 100, 0)

	// Drive a check-in from another goroutine while the sweep runs, repeatedly,
	// and assert the invariant after each round: whatever the last event says
	// about membership matches what the row says.
	for range 20 {
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = h.checkin.Checkin(t.Context(), id, service.CheckinReport{IPv4: "1.2.3.4"})
		}()
		_ = h.sweeper.Run(t.Context(), h.now)
		<-done

		rowHasAddress := h.device(t, id).CurrentIPv4 != ""
		if last, ok := h.lastEvent(); ok {
			eventSaysPresent := last.Current.IPv4 != nil
			if eventSaysPresent != rowHasAddress {
				t.Fatalf("stream says present=%v, row says present=%v",
					eventSaysPresent, rowHasAddress)
			}
		}
		h.resetDevice(t, id, "1.2.3.4", 100)
	}
}
