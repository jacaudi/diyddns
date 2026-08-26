package store

import (
	"errors"
	"testing"
)

// ---------- 1. Append returns row with ID > 0 ----------

func TestIPHistoryAppendAssignsID(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "hist1@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "dev1", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	h := IPHistory{
		DeviceID:   d.ID,
		IPv4:       "1.2.3.4",
		ObservedAt: 1000,
	}
	got, err := s.IPHistory().Append(ctx, h)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if got.ID <= 0 {
		t.Errorf("Append: ID = %d, want > 0", got.ID)
	}
}

// ---------- 2. Append sets ObservedAt if zero ----------

func TestIPHistoryAppendSetsObservedAtIfZero(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "hist2@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "dev2", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	before := NowUnix()
	h := IPHistory{
		DeviceID:   d.ID,
		IPv4:       "5.6.7.8",
		ObservedAt: 0, // should be filled in
	}
	got, err := s.IPHistory().Append(ctx, h)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	after := NowUnix()

	if got.ObservedAt < before || got.ObservedAt > after+1 {
		t.Errorf("Append: ObservedAt = %d, want in [%d, %d]", got.ObservedAt, before, after+1)
	}
}

// ---------- 3. Latest returns the newest row ----------

func TestIPHistoryLatestReturnsNewest(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "hist3@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "dev3", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	for _, ts := range []int64{100, 300, 200} {
		_, err := s.IPHistory().Append(ctx, IPHistory{
			DeviceID:   d.ID,
			IPv4:       "1.2.3.4",
			ObservedAt: ts,
		})
		if err != nil {
			t.Fatalf("Append ts=%d: %v", ts, err)
		}
	}

	got, err := s.IPHistory().Latest(ctx, d.ID)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got.ObservedAt != 300 {
		t.Errorf("Latest: ObservedAt = %d, want 300", got.ObservedAt)
	}
}

// ---------- 4. Latest with no rows → ErrNotFound ----------

func TestIPHistoryLatestNotFound(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "hist4@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "dev4", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	_, err = s.IPHistory().Latest(ctx, d.ID)
	if err == nil {
		t.Fatal("Latest: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Latest: got %v, want ErrNotFound", err)
	}
}

// ---------- 5. Page: first page returns limit rows in DESC order ----------

func TestIPHistoryPageFirstPage(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "hist5@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "dev5", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	// Insert 5 rows with observed_at = 100, 200, 300, 400, 500.
	for i := int64(1); i <= 5; i++ {
		_, err := s.IPHistory().Append(ctx, IPHistory{
			DeviceID:   d.ID,
			IPv4:       "1.2.3.4",
			ObservedAt: i * 100,
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	page, err := s.IPHistory().Page(ctx, d.ID, "", 3)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if len(page.Rows) != 3 {
		t.Fatalf("Page: got %d rows, want 3", len(page.Rows))
	}
	// Should be newest-first: 500, 400, 300.
	wantTs := []int64{500, 400, 300}
	for i, row := range page.Rows {
		if row.ObservedAt != wantTs[i] {
			t.Errorf("Page.Rows[%d].ObservedAt = %d, want %d", i, row.ObservedAt, wantTs[i])
		}
	}
	if page.NextCursor == "" {
		t.Error("Page: NextCursor should be non-empty (more rows remain)")
	}
}

// ---------- 6. Page: walk to end via cursor ----------

func TestIPHistoryPageWalksToEnd(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "hist6@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "dev6", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	for i := int64(1); i <= 5; i++ {
		_, err := s.IPHistory().Append(ctx, IPHistory{
			DeviceID:   d.ID,
			IPv4:       "1.2.3.4",
			ObservedAt: i * 100,
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// First page (3 rows, should leave 2 remaining).
	page1, err := s.IPHistory().Page(ctx, d.ID, "", 3)
	if err != nil {
		t.Fatalf("Page1: %v", err)
	}
	if page1.NextCursor == "" {
		t.Fatal("Page1: expected non-empty NextCursor")
	}

	// Second page: should get 2 rows and no further cursor.
	page2, err := s.IPHistory().Page(ctx, d.ID, page1.NextCursor, 3)
	if err != nil {
		t.Fatalf("Page2: %v", err)
	}
	if len(page2.Rows) != 2 {
		t.Fatalf("Page2: got %d rows, want 2", len(page2.Rows))
	}
	if page2.NextCursor != "" {
		t.Errorf("Page2: NextCursor should be empty, got %q", page2.NextCursor)
	}
	// Should be 200, 100 in descending order.
	wantTs := []int64{200, 100}
	for i, row := range page2.Rows {
		if row.ObservedAt != wantTs[i] {
			t.Errorf("Page2.Rows[%d].ObservedAt = %d, want %d", i, row.ObservedAt, wantTs[i])
		}
	}
}

// ---------- 7. Page: limit clamping ----------

func TestIPHistoryPageLimitClamping(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "hist7@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "dev7", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	// Insert 3 rows so we can test without timeout.
	for i := int64(1); i <= 3; i++ {
		_, err := s.IPHistory().Append(ctx, IPHistory{
			DeviceID:   d.ID,
			IPv4:       "1.2.3.4",
			ObservedAt: i * 100,
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// limit <= 0 should default to 50.
	page0, err := s.IPHistory().Page(ctx, d.ID, "", 0)
	if err != nil {
		t.Fatalf("Page(limit=0): %v", err)
	}
	// With only 3 rows and default limit 50, no NextCursor.
	if len(page0.Rows) != 3 {
		t.Errorf("Page(limit=0): got %d rows, want 3", len(page0.Rows))
	}
	if page0.NextCursor != "" {
		t.Errorf("Page(limit=0): NextCursor = %q, want empty (default 50 > 3 rows)", page0.NextCursor)
	}

	// limit > 500 should clamp to 500. With only 3 rows, all returned.
	page501, err := s.IPHistory().Page(ctx, d.ID, "", 501)
	if err != nil {
		t.Fatalf("Page(limit=501): %v", err)
	}
	if len(page501.Rows) != 3 {
		t.Errorf("Page(limit=501): got %d rows, want 3", len(page501.Rows))
	}
	if page501.NextCursor != "" {
		t.Errorf("Page(limit=501): NextCursor = %q, want empty (clamped 500 > 3 rows)", page501.NextCursor)
	}
}

// ---------- 8. Prune by age keeps the latest ----------

func TestIPHistoryPruneByAgeKeepsLatest(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "hist8@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "dev8", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	// Insert in observed_at order so id ordering matches observed_at ordering.
	for _, ts := range []int64{100, 200, 300} {
		_, err := s.IPHistory().Append(ctx, IPHistory{
			DeviceID:   d.ID,
			IPv4:       "1.2.3.4",
			ObservedAt: ts,
		})
		if err != nil {
			t.Fatalf("Append ts=%d: %v", ts, err)
		}
	}

	// olderThan=250 → rows at 100 and 200 are candidates. perDeviceMax=0 → no cap.
	// MAX(id) is the row with ts=300, excluded from deletion by NOT IN clause.
	// So rows 100 and 200 are deleted. Returns 2.
	deleted, err := s.IPHistory().Prune(ctx, d.ID, 250, 0, 1000)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 2 {
		t.Errorf("Prune: deleted = %d, want 2", deleted)
	}

	// Only the row with ts=300 should remain.
	latest, err := s.IPHistory().Latest(ctx, d.ID)
	if err != nil {
		t.Fatalf("Latest after Prune: %v", err)
	}
	if latest.ObservedAt != 300 {
		t.Errorf("Latest.ObservedAt = %d, want 300", latest.ObservedAt)
	}

	page, err := s.IPHistory().Page(ctx, d.ID, "", 10)
	if err != nil {
		t.Fatalf("Page after Prune: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Errorf("Page: got %d rows, want 1", len(page.Rows))
	}
}

// ---------- 9. Prune by cap keeps the newest N ----------

func TestIPHistoryPruneByCapKeepsLatest(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "hist9@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "dev9", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	// Insert 5 rows with observed_at = 100..500.
	for i := int64(1); i <= 5; i++ {
		_, err := s.IPHistory().Append(ctx, IPHistory{
			DeviceID:   d.ID,
			IPv4:       "1.2.3.4",
			ObservedAt: i * 100,
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// olderThan=0 → observed_at < 0 never fires. perDeviceMax=2 → keep 2 newest.
	// Expected: delete rows with ids 1, 2, 3 (3 deleted), keep ids 4, 5.
	deleted, err := s.IPHistory().Prune(ctx, d.ID, 0, 2, 1000)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 3 {
		t.Errorf("Prune: deleted = %d, want 3", deleted)
	}

	page, err := s.IPHistory().Page(ctx, d.ID, "", 10)
	if err != nil {
		t.Fatalf("Page after Prune: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("Page: got %d rows, want 2", len(page.Rows))
	}
	// Remaining rows should be the two newest: ts=500, ts=400.
	if page.Rows[0].ObservedAt != 500 {
		t.Errorf("Rows[0].ObservedAt = %d, want 500", page.Rows[0].ObservedAt)
	}
	if page.Rows[1].ObservedAt != 400 {
		t.Errorf("Rows[1].ObservedAt = %d, want 400", page.Rows[1].ObservedAt)
	}
}

// ---------- 10. Prune never deletes the sole latest row ----------

func TestIPHistoryPruneNeverDeletesSoleLatest(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "hist10@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "dev10", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	_, err = s.IPHistory().Append(ctx, IPHistory{
		DeviceID:   d.ID,
		IPv4:       "1.2.3.4",
		ObservedAt: 10,
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Even with an aggressive cutoff, the single row must survive.
	deleted, err := s.IPHistory().Prune(ctx, d.ID, 999999999, 0, 1000)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 0 {
		t.Errorf("Prune: deleted = %d, want 0 (should never delete sole latest)", deleted)
	}

	// Row still there.
	_, err = s.IPHistory().Latest(ctx, d.ID)
	if err != nil {
		t.Fatalf("Latest after safe Prune: %v", err)
	}
}

// ---------- 11. Prune combined age + cap ----------

func TestIPHistoryPruneCombinedAgeAndCap(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "hist11@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "dev11", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	for _, ts := range []int64{100, 200, 300, 400, 500} {
		_, err := s.IPHistory().Append(ctx, IPHistory{
			DeviceID:   d.ID,
			IPv4:       "1.2.3.4",
			ObservedAt: ts,
		})
		if err != nil {
			t.Fatalf("Append ts=%d: %v", ts, err)
		}
	}

	// Age cutoff: <350 → rows 100, 200, 300 are candidates.
	// Cap: keep 2 newest → delete rows with ids 1,2,3 (same 3).
	// Either way, 3 rows deleted. Latest (id=5, ts=500) preserved.
	deleted, err := s.IPHistory().Prune(ctx, d.ID, 350, 2, 1000)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 3 {
		t.Errorf("Prune: deleted = %d, want 3", deleted)
	}

	page, err := s.IPHistory().Page(ctx, d.ID, "", 10)
	if err != nil {
		t.Fatalf("Page after Prune: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("Page: got %d rows, want 2", len(page.Rows))
	}
	if page.Rows[0].ObservedAt != 500 {
		t.Errorf("Rows[0].ObservedAt = %d, want 500", page.Rows[0].ObservedAt)
	}
	if page.Rows[1].ObservedAt != 400 {
		t.Errorf("Rows[1].ObservedAt = %d, want 400", page.Rows[1].ObservedAt)
	}
}

// ---------- 12. FK cascade on device delete ----------

func TestIPHistoryPruneFKCascadeOnDeviceDelete(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "hist12@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "dev12", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	for i := int64(1); i <= 3; i++ {
		_, err := s.IPHistory().Append(ctx, IPHistory{
			DeviceID:   d.ID,
			IPv4:       "1.2.3.4",
			ObservedAt: i * 100,
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// Delete the device; FK cascade should remove ip_history rows.
	if err := s.Devices().Delete(ctx, d.ID); err != nil {
		t.Fatalf("Delete device: %v", err)
	}

	var count int
	if err := s.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM ip_history WHERE device_id = ?`, d.ID,
	).Scan(&count); err != nil {
		t.Fatalf("count ip_history: %v", err)
	}
	if count != 0 {
		t.Errorf("cascade: ip_history count = %d, want 0", count)
	}
}

// ---------- 8b. Prune honours the batch bound ----------

func TestIPHistoryPruneRespectsBatch(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "hist8b@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "dev8b", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	for i := int64(1); i <= 10; i++ {
		if _, err := s.IPHistory().Append(ctx, IPHistory{
			DeviceID: d.ID, IPv4: "1.2.3.4", ObservedAt: i * 100,
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// 9 rows are eligible (MAX(id) is always kept), but batch=2 caps this call.
	deleted, err := s.IPHistory().Prune(ctx, d.ID, 99999, 0, 2)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 2 {
		t.Errorf("Prune: deleted = %d, want 2 (the batch bound)", deleted)
	}
}

// ---------- 8c. The cap-DISABLED form still keeps the latest row ----------
//
// D3a gives the cap-disabled configuration its own statement, so
// always-keep-latest has to be re-proven for it rather than inherited.

func TestIPHistoryPruneCapDisabledKeepsLatest(t *testing.T) {
	s, ctx := newTestStore(t)

	u, err := s.Users().Create(ctx, User{Email: "hist8c@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := s.Devices().Create(ctx, Device{UserID: u.ID, Label: "dev8c", SecretHash: "h"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	for i := int64(1); i <= 3; i++ {
		if _, err := s.IPHistory().Append(ctx, IPHistory{
			DeviceID: d.ID, IPv4: "1.2.3.4", ObservedAt: i * 100,
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// Every row is older than the cutoff, and the cap is OFF.
	deleted, err := s.IPHistory().Prune(ctx, d.ID, 99999, 0, 1000)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 2 {
		t.Errorf("Prune: deleted = %d, want 2 (the newest row must survive)", deleted)
	}
	latest, err := s.IPHistory().Latest(ctx, d.ID)
	if err != nil {
		t.Fatalf("Latest after Prune: %v", err)
	}
	if latest.ObservedAt != 300 {
		t.Errorf("Latest.ObservedAt = %d, want 300", latest.ObservedAt)
	}
}
