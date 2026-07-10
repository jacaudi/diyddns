package store

import (
	"context"
	"errors"
	"testing"
)

// newTestDevice creates a user and a device owned by that user, returning the
// created Device. Helper shared by every ip_history test that needs a parent
// device to attach history rows to.
func newTestDevice(t *testing.T, ctx context.Context, s *Store, email, label string) Device {
	t.Helper()

	user, err := s.Users().Create(ctx, User{Email: email, Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	device, err := s.Devices().Create(ctx, Device{UserID: user.ID, Label: label, SecretHash: "hash"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	return device
}

func TestIPHistoryAppendAssignsIDAndDefaultsObservedAt(t *testing.T) {
	s, ctx := newTestStore(t)
	device := newTestDevice(t, ctx, s, "append-default@example.com", "laptop")
	repo := s.IPHistory()

	before := NowUnix()
	created, err := repo.Append(ctx, IPHistory{DeviceID: device.ID, IPv4: "203.0.113.5"})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("Append did not assign an ID")
	}
	if created.ObservedAt < before {
		t.Fatalf("Append did not default ObservedAt to now: got %d, want >= %d", created.ObservedAt, before)
	}
	if created.IPv4 != "203.0.113.5" {
		t.Fatalf("Append did not preserve IPv4: got %q", created.IPv4)
	}
}

func TestIPHistoryAppendPreservesExplicitObservedAt(t *testing.T) {
	s, ctx := newTestStore(t)
	device := newTestDevice(t, ctx, s, "append-explicit@example.com", "laptop")
	repo := s.IPHistory()

	created, err := repo.Append(ctx, IPHistory{DeviceID: device.ID, ObservedAt: 12345})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if created.ObservedAt != 12345 {
		t.Fatalf("Append overwrote explicit ObservedAt: got %d, want 12345", created.ObservedAt)
	}
}

func TestIPHistoryLatestReturnsNewestByObservedAtThenID(t *testing.T) {
	s, ctx := newTestStore(t)
	device := newTestDevice(t, ctx, s, "latest@example.com", "laptop")
	repo := s.IPHistory()

	if _, err := repo.Append(ctx, IPHistory{DeviceID: device.ID, ObservedAt: 100, IPv4: "10.0.0.1"}); err != nil {
		t.Fatalf("Append first: %v", err)
	}
	// Two rows share the same observed_at; the higher id (inserted later)
	// must win the tiebreak.
	if _, err := repo.Append(ctx, IPHistory{DeviceID: device.ID, ObservedAt: 200, IPv4: "10.0.0.2"}); err != nil {
		t.Fatalf("Append second: %v", err)
	}
	third, err := repo.Append(ctx, IPHistory{DeviceID: device.ID, ObservedAt: 200, IPv4: "10.0.0.3"})
	if err != nil {
		t.Fatalf("Append third: %v", err)
	}

	got, err := repo.Latest(ctx, device.ID)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != third {
		t.Fatalf("Latest() = %+v, want %+v", got, third)
	}
}

func TestIPHistoryLatestMissingReturnsNotFound(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.IPHistory()

	_, err := repo.Latest(ctx, "missing-device")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Latest missing: err = %v, want ErrNotFound", err)
	}
}

// TestIPHistoryPageRoundTripsAllRowsAndReachesEnd appends 7 rows (with a
// deliberate observed_at tie to prove the id DESC tiebreak), pages through
// them 3 at a time, and asserts every row is seen exactly once, in
// (observed_at DESC, id DESC) order, ending with an empty NextCursor.
func TestIPHistoryPageRoundTripsAllRowsAndReachesEnd(t *testing.T) {
	s, ctx := newTestStore(t)
	device := newTestDevice(t, ctx, s, "page-roundtrip@example.com", "laptop")
	repo := s.IPHistory()

	observedAts := []int64{100, 200, 200, 300, 400, 500, 500}
	var wantIDs []int64
	for _, observedAt := range observedAts {
		row, err := repo.Append(ctx, IPHistory{DeviceID: device.ID, ObservedAt: observedAt})
		if err != nil {
			t.Fatalf("Append(observed_at=%d): %v", observedAt, err)
		}
		wantIDs = append(wantIDs, row.ID)
	}
	// Expected descending order by (observed_at, id): reverse insertion order,
	// since observedAts is non-decreasing and ids are assigned sequentially.
	want := make([]int64, len(wantIDs))
	for i, id := range wantIDs {
		want[len(wantIDs)-1-i] = id
	}

	const pageSize = 3
	var gotIDs []int64
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > len(want) {
			t.Fatal("Page did not terminate: exceeded expected page count")
		}
		page, err := repo.Page(ctx, device.ID, cursor, pageSize)
		if err != nil {
			t.Fatalf("Page(cursor=%q): %v", cursor, err)
		}
		for _, row := range page.Rows {
			gotIDs = append(gotIDs, row.ID)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	if len(gotIDs) != len(want) {
		t.Fatalf("Page round-trip returned %d rows, want %d", len(gotIDs), len(want))
	}
	for i, id := range gotIDs {
		if id != want[i] {
			t.Fatalf("Page round-trip [%d] = id %d, want %d (full sequence: got=%v want=%v)", i, id, want[i], gotIDs, want)
		}
	}
}

func TestIPHistoryPageEmptyDeviceReturnsEmptyPageAndNoCursor(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.IPHistory()

	page, err := repo.Page(ctx, "missing-device", "", 50)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if len(page.Rows) != 0 {
		t.Fatalf("Page for missing device returned %d rows, want 0", len(page.Rows))
	}
	if page.NextCursor != "" {
		t.Fatalf("Page for missing device NextCursor = %q, want empty", page.NextCursor)
	}
}

func TestClampPageLimitDefaultsAndClamps(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "zero defaults to 50", limit: 0, want: 50},
		{name: "negative defaults to 50", limit: -5, want: 50},
		{name: "one stays one", limit: 1, want: 1},
		{name: "500 stays 500", limit: 500, want: 500},
		{name: "over 500 clamps to 500", limit: 501, want: 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clampPageLimit(tt.limit)
			if got != tt.want {
				t.Errorf("clampPageLimit(%d) = %d, want %d", tt.limit, got, tt.want)
			}
		})
	}
}

// TestIPHistoryPruneAlwaysKeepsLatestSingleRow proves the v1 acceptance
// criterion: a device with exactly one history row must never have that row
// pruned, no matter how aggressive the age cutoff or per-device cap.
func TestIPHistoryPruneAlwaysKeepsLatestSingleRow(t *testing.T) {
	s, ctx := newTestStore(t)
	device := newTestDevice(t, ctx, s, "prune-keep-latest@example.com", "laptop")
	repo := s.IPHistory()

	only, err := repo.Append(ctx, IPHistory{DeviceID: device.ID, ObservedAt: 1})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	aggressiveCutoff := NowUnix() + 100000
	for _, perDeviceMax := range []int{1, 0} {
		n, err := repo.Prune(ctx, device.ID, aggressiveCutoff, perDeviceMax)
		if err != nil {
			t.Fatalf("Prune(perDeviceMax=%d): %v", perDeviceMax, err)
		}
		if n != 0 {
			t.Fatalf("Prune(perDeviceMax=%d) deleted %d rows, want 0 (always-keep-latest violated)", perDeviceMax, n)
		}
	}

	got, err := repo.Latest(ctx, device.ID)
	if err != nil {
		t.Fatalf("Latest after Prune: %v", err)
	}
	if got != only {
		t.Fatalf("Latest after Prune = %+v, want %+v (row must survive)", got, only)
	}
}

// TestIPHistoryPruneByAgeDeletesOlderKeepsNewer proves rows older than the
// cutoff are removed and newer rows (plus the always-kept latest) survive.
func TestIPHistoryPruneByAgeDeletesOlderKeepsNewer(t *testing.T) {
	s, ctx := newTestStore(t)
	device := newTestDevice(t, ctx, s, "prune-by-age@example.com", "laptop")
	repo := s.IPHistory()

	var ids []int64
	for _, observedAt := range []int64{100, 200, 300, 400, 500} {
		row, err := repo.Append(ctx, IPHistory{DeviceID: device.ID, ObservedAt: observedAt})
		if err != nil {
			t.Fatalf("Append(observed_at=%d): %v", observedAt, err)
		}
		ids = append(ids, row.ID)
	}

	// perDeviceMax large enough that the cap never fires; only age matters.
	n, err := repo.Prune(ctx, device.ID, 350, 1000)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 3 {
		t.Fatalf("Prune by age deleted %d rows, want 3 (observed_at 100,200,300)", n)
	}

	page, err := repo.Page(ctx, device.ID, "", 50)
	if err != nil {
		t.Fatalf("Page after Prune: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("Page after Prune by age returned %d rows, want 2", len(page.Rows))
	}
	remaining := map[int64]bool{ids[3]: false, ids[4]: false}
	for _, row := range page.Rows {
		if _, ok := remaining[row.ID]; !ok {
			t.Fatalf("Page after Prune by age returned unexpected surviving id %d", row.ID)
		}
		remaining[row.ID] = true
	}
	for id, seen := range remaining {
		if !seen {
			t.Fatalf("Prune by age unexpectedly deleted id %d that should have survived", id)
		}
	}
}

// TestIPHistoryPruneByPerDeviceMaxKeepsOnlyNewest proves only the newest
// perDeviceMax rows survive (plus the always-kept latest, which is already
// among the newest here).
func TestIPHistoryPruneByPerDeviceMaxKeepsOnlyNewest(t *testing.T) {
	s, ctx := newTestStore(t)
	device := newTestDevice(t, ctx, s, "prune-by-cap@example.com", "laptop")
	repo := s.IPHistory()

	var ids []int64
	for _, observedAt := range []int64{100, 200, 300, 400, 500} {
		row, err := repo.Append(ctx, IPHistory{DeviceID: device.ID, ObservedAt: observedAt})
		if err != nil {
			t.Fatalf("Append(observed_at=%d): %v", observedAt, err)
		}
		ids = append(ids, row.ID)
	}

	// olderThan=0 so age never fires; only the per-device cap of 2 matters.
	n, err := repo.Prune(ctx, device.ID, 0, 2)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 3 {
		t.Fatalf("Prune by cap deleted %d rows, want 3", n)
	}

	page, err := repo.Page(ctx, device.ID, "", 50)
	if err != nil {
		t.Fatalf("Page after Prune: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("Page after Prune by cap returned %d rows, want 2 (perDeviceMax)", len(page.Rows))
	}
	remaining := map[int64]bool{ids[3]: false, ids[4]: false}
	for _, row := range page.Rows {
		if _, ok := remaining[row.ID]; !ok {
			t.Fatalf("Page after Prune by cap returned unexpected surviving id %d", row.ID)
		}
		remaining[row.ID] = true
	}
	for id, seen := range remaining {
		if !seen {
			t.Fatalf("Prune by cap unexpectedly deleted id %d that should have survived", id)
		}
	}
}

// TestIPHistoryPrunePerDeviceMaxZeroDisablesCountCap proves the real
// contract on a MULTI-row device: perDeviceMax=0 DISABLES the per-device
// count cap ("0 = unlimited" per the design's retention convention). With
// the age branch also disabled (olderThan=0), Prune must delete nothing —
// perDeviceMax=0 is NOT "keep only the latest".
func TestIPHistoryPrunePerDeviceMaxZeroDisablesCountCap(t *testing.T) {
	s, ctx := newTestStore(t)
	device := newTestDevice(t, ctx, s, "prune-cap-zero@example.com", "laptop")
	repo := s.IPHistory()

	for _, observedAt := range []int64{100, 200, 300, 400, 500} {
		if _, err := repo.Append(ctx, IPHistory{DeviceID: device.ID, ObservedAt: observedAt}); err != nil {
			t.Fatalf("Append(observed_at=%d): %v", observedAt, err)
		}
	}

	// olderThan=0 disables age pruning; perDeviceMax=0 disables the count cap.
	// Both limits off → nothing to delete on a 5-row device.
	n, err := repo.Prune(ctx, device.ID, 0, 0)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 0 {
		t.Fatalf("Prune(olderThan=0, perDeviceMax=0) deleted %d rows, want 0 (count cap must be disabled, not keep-only-latest)", n)
	}

	page, err := repo.Page(ctx, device.ID, "", 50)
	if err != nil {
		t.Fatalf("Page after Prune: %v", err)
	}
	if len(page.Rows) != 5 {
		t.Fatalf("Page after Prune(perDeviceMax=0) returned %d rows, want 5 (all retained)", len(page.Rows))
	}
}

// TestIPHistoryPruneAgeIndependentOfDisabledCountCap proves age pruning works
// even when the count cap is disabled (perDeviceMax=0): with an aggressive
// future cutoff every row is "older", so all-but-latest are deleted via the
// age branch while MAX(id) stays protected. This isolates the age branch from
// the count cap.
func TestIPHistoryPruneAgeIndependentOfDisabledCountCap(t *testing.T) {
	s, ctx := newTestStore(t)
	device := newTestDevice(t, ctx, s, "prune-age-cap-zero@example.com", "laptop")
	repo := s.IPHistory()

	var ids []int64
	for _, observedAt := range []int64{100, 200, 300, 400, 500} {
		row, err := repo.Append(ctx, IPHistory{DeviceID: device.ID, ObservedAt: observedAt})
		if err != nil {
			t.Fatalf("Append(observed_at=%d): %v", observedAt, err)
		}
		ids = append(ids, row.ID)
	}
	newestID := ids[len(ids)-1]

	// perDeviceMax=0 disables the count cap; the aggressive future cutoff makes
	// every row "older", so the age branch deletes all but the protected latest.
	n, err := repo.Prune(ctx, device.ID, NowUnix()+100000, 0)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 4 {
		t.Fatalf("Prune(aggressive age, perDeviceMax=0) deleted %d rows, want 4 (all but latest via age branch)", n)
	}

	got, err := repo.Latest(ctx, device.ID)
	if err != nil {
		t.Fatalf("Latest after Prune: %v", err)
	}
	if got.ID != newestID {
		t.Fatalf("Latest after Prune = id %d, want %d (newest must survive)", got.ID, newestID)
	}
}

// TestIPHistoryPruneScopesToDevice proves Prune only touches the target
// device's rows; another device's history is untouched.
func TestIPHistoryPruneScopesToDevice(t *testing.T) {
	s, ctx := newTestStore(t)
	target := newTestDevice(t, ctx, s, "prune-scope-target@example.com", "laptop")
	other := newTestDevice(t, ctx, s, "prune-scope-other@example.com", "phone")
	repo := s.IPHistory()

	for _, observedAt := range []int64{100, 200, 300} {
		if _, err := repo.Append(ctx, IPHistory{DeviceID: target.ID, ObservedAt: observedAt}); err != nil {
			t.Fatalf("Append target(observed_at=%d): %v", observedAt, err)
		}
	}
	otherRow, err := repo.Append(ctx, IPHistory{DeviceID: other.ID, ObservedAt: 100})
	if err != nil {
		t.Fatalf("Append other: %v", err)
	}

	// Aggressive cutoff + cap=1 against the target device only.
	n, err := repo.Prune(ctx, target.ID, NowUnix()+100000, 1)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 2 {
		t.Fatalf("Prune scoped to target deleted %d rows, want 2", n)
	}

	got, err := repo.Latest(ctx, other.ID)
	if err != nil {
		t.Fatalf("Latest for other device: %v", err)
	}
	if got != otherRow {
		t.Fatalf("Prune touched other device's row: Latest() = %+v, want %+v", got, otherRow)
	}
}

// TestIPHistoryDeviceDeleteCascadesToIPHistory proves the ON DELETE CASCADE
// the schema declares on ip_history.device_id actually fires: deleting the
// parent device via the public Devices().Delete API must remove that
// device's ip_history rows too. Task 13 deferred this test to this task.
func TestIPHistoryDeviceDeleteCascadesToIPHistory(t *testing.T) {
	s, ctx := newTestStore(t)
	device := newTestDevice(t, ctx, s, "cascade-ip-history@example.com", "laptop")
	repo := s.IPHistory()

	if _, err := repo.Append(ctx, IPHistory{DeviceID: device.ID, ObservedAt: 100}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if _, err := repo.Latest(ctx, device.ID); err != nil {
		t.Fatalf("Latest before device delete: %v", err)
	}

	if err := s.Devices().Delete(ctx, device.ID); err != nil {
		t.Fatalf("delete device: %v", err)
	}

	_, err := repo.Latest(ctx, device.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Latest after cascading device delete: err = %v, want ErrNotFound", err)
	}
}
