package store

import "testing"

// seedDeviceFull creates a user and a device carrying both address families
// and confirmation instants, for the ExpireFamilies tests below that need a
// fully-populated, expiry-eligible device without caring who owns it.
func seedDeviceFull(t *testing.T, s *Store, v4, v6 string, v4Confirmed, v6Confirmed int64) Device {
	t.Helper()
	u := seedUser(t, s)
	d, err := s.Devices().Create(t.Context(), Device{
		UserID: u.ID, Label: NewID(), SecretHash: "h",
		CurrentIPv4: v4, CurrentIPv6: v6,
		V4ConfirmedAt: v4Confirmed, V6ConfirmedAt: v6Confirmed,
	})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return d
}

// historyCount returns the number of ip_history rows for deviceID, for tests
// asserting ExpireFamilies appends exactly one.
func historyCount(t *testing.T, s *Store, deviceID string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM ip_history WHERE device_id = ?`, deviceID,
	).Scan(&n); err != nil {
		t.Fatalf("historyCount: %v", err)
	}
	return n
}

// D7: expiry CLEARS the address. Everything downstream -- listFeedQuery,
// inFeed, feed.Render, every payload renderer -- is untouched by this design
// precisely because they all already treat NULL as absent.
func TestExpireFamilies_ClearsTheAddress(t *testing.T) {
	st, ctx := newTestStore(t)
	d := seedDeviceFull(t, st, "1.2.3.4", "2001:db8::1", 1000, 1000)

	_, ok, err := st.Devices().ExpireFamilies(ctx, d.ID, false, true, 1000, 1000, 5000)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	got, _ := st.Devices().GetByID(ctx, d.ID)
	if got.CurrentIPv6 != "" {
		t.Errorf("CurrentIPv6 = %q, want cleared", got.CurrentIPv6)
	}
	if got.CurrentIPv4 != "1.2.3.4" {
		t.Errorf("CurrentIPv4 = %q, want untouched", got.CurrentIPv4)
	}
}

// D7, the trap: reusing updateDeviceIP would advance last_seen_at and show a
// long-dead device as having just been seen.
func TestExpireFamilies_DoesNotTouchLastSeenAt(t *testing.T) {
	st, ctx := newTestStore(t)
	d := seedDeviceFull(t, st, "1.2.3.4", "", 1000, 0)
	before, _ := st.Devices().GetByID(ctx, d.ID)

	if _, _, err := st.Devices().ExpireFamilies(ctx, d.ID, true, false, 1000, 0, 5000); err != nil {
		t.Fatal(err)
	}
	after, _ := st.Devices().GetByID(ctx, d.ID)
	if after.LastSeenAt != before.LastSeenAt {
		t.Errorf("LastSeenAt moved %d -> %d; a dead device must not look just-seen",
			before.LastSeenAt, after.LastSeenAt)
	}
}

// D8: the write is pinned on the confirmation instants the sweep read, so a
// device that checked in during the tick is never expired.
func TestExpireFamilies_PinFailsWhenDeviceConfirmedMeanwhile(t *testing.T) {
	st, ctx := newTestStore(t)
	d := seedDeviceFull(t, st, "1.2.3.4", "", 1000, 0)

	// The sweep read 1000; the device checks in first.
	if err := st.Devices().Touch(ctx, d.ID, true, false, 9000); err != nil {
		t.Fatal(err)
	}
	_, ok, err := st.Devices().ExpireFamilies(ctx, d.ID, true, false, 1000, 0, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("the pinned write succeeded after the device confirmed")
	}
	got, _ := st.Devices().GetByID(ctx, d.ID)
	if got.CurrentIPv4 == "" {
		t.Error("a live device's address was cleared")
	}
}

// §6.2: exactly one ip_history row, in the same transaction. It supplies the
// event's id.
//
// It is NOT the row D17 reads back: this row records the state AFTER clearing,
// so the cleared family is NULL in it. The UI reads the newest row in which
// that family is non-NULL -- see Task 8.
func TestExpireFamilies_AppendsOneHistoryRow(t *testing.T) {
	st, ctx := newTestStore(t)
	d := seedDeviceFull(t, st, "1.2.3.4", "2001:db8::1", 1000, 1000)
	before := historyCount(t, st, d.ID)

	if _, _, err := st.Devices().ExpireFamilies(ctx, d.ID, true, true, 1000, 1000, 5000); err != nil {
		t.Fatal(err)
	}
	if got := historyCount(t, st, d.ID) - before; got != 1 {
		t.Errorf("appended %d history rows, want 1", got)
	}
}

// S6: a second call with the same pin, after the family is already NULL, must
// report no change and append no second history row. SQLite counts a no-op
// UPDATE as one affected row, so RowsAffected alone does not say this.
func TestExpireFamilies_SecondCallIsANoOp(t *testing.T) {
	st, ctx := newTestStore(t)
	d := seedDeviceFull(t, st, "1.2.3.4", "", 1000, 0)

	if _, ok, err := st.Devices().ExpireFamilies(ctx, d.ID, true, false, 1000, 0, 5000); err != nil || !ok {
		t.Fatalf("first call: ok=%v err=%v", ok, err)
	}
	n := historyCount(t, st, d.ID)

	_, ok, err := st.Devices().ExpireFamilies(ctx, d.ID, true, false, 1000, 0, 6000)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("second call reported a change against an already-cleared family")
	}
	if got := historyCount(t, st, d.ID); got != n {
		t.Errorf("history rows %d -> %d; the no-op appended a row", n, got)
	}
}

// The brief's opening sentence requires the reset alongside the clear, but
// only for the family actually due -- a careless "reset both unconditionally"
// edit would still pass every other ExpireFamilies test, since none of them
// reads a warn level. Checking the UN-due family stayed put is the half that
// catches that mistake.
func TestExpireFamilies_ResetsWarnLevelForDueFamilyOnly(t *testing.T) {
	st, ctx := newTestStore(t)
	d := seedDeviceFull(t, st, "1.2.3.4", "2001:db8::1", 1000, 1000)
	setWarnLevels(t, st, d.ID, 3, 3)

	if _, _, err := st.Devices().ExpireFamilies(ctx, d.ID, true, false, 1000, 1000, 5000); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Devices().GetByID(ctx, d.ID)
	if got.V4WarnLevel != 0 {
		t.Errorf("V4WarnLevel = %d, want 0: the due family's level must reset", got.V4WarnLevel)
	}
	if got.V6WarnLevel != 3 {
		t.Errorf("V6WarnLevel = %d, want 3: an un-due family's level must not be touched", got.V6WarnLevel)
	}
}
