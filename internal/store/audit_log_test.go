package store

import (
	"testing"
)

// ---------- 1. Append assigns ID and sets CreatedAt when zero ----------

func TestAuditLogAppendAssignsIDAndCreatedAt(t *testing.T) {
	s, ctx := newTestStore(t)

	before := NowUnix()
	e := AuditEntry{
		EventType: "user.login",
		CreatedAt: 0, // should be set to NowUnix()
	}
	got, err := s.AuditLog().Append(ctx, e)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	after := NowUnix()

	if got.ID <= 0 {
		t.Errorf("Append: ID = %d, want > 0", got.ID)
	}
	if got.CreatedAt < before || got.CreatedAt > after+2 {
		t.Errorf("Append: CreatedAt = %d, want in [%d, %d]", got.CreatedAt, before, after+2)
	}
}

// ---------- 2. Append preserves provided CreatedAt ----------

func TestAuditLogAppendPreservesProvidedCreatedAt(t *testing.T) {
	s, ctx := newTestStore(t)

	e := AuditEntry{
		EventType: "user.logout",
		CreatedAt: 12345,
	}
	got, err := s.AuditLog().Append(ctx, e)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if got.CreatedAt != 12345 {
		t.Errorf("Append: CreatedAt = %d, want 12345", got.CreatedAt)
	}
}

// ---------- 3. Append round-trips all fields ----------

func TestAuditLogAppendRoundTripAllFields(t *testing.T) {
	s, ctx := newTestStore(t)

	in := AuditEntry{
		ActorUserID: "user-abc",
		EventType:   "device.created",
		TargetType:  "device",
		TargetID:    "dev-xyz",
		DetailsJSON: `{"label":"home"}`,
		IP:          "10.0.0.1",
		UserAgent:   "DIYDDNS/1.0",
		CreatedAt:   999,
	}
	inserted, err := s.AuditLog().Append(ctx, in)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	page, err := s.AuditLog().ListPaginated(ctx, AuditFilter{}, "", 100)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("ListPaginated: got %d rows, want 1", len(page.Rows))
	}
	got := page.Rows[0]

	if got.ID != inserted.ID {
		t.Errorf("ID: got %d, want %d", got.ID, inserted.ID)
	}
	if got.ActorUserID != in.ActorUserID {
		t.Errorf("ActorUserID: got %q, want %q", got.ActorUserID, in.ActorUserID)
	}
	if got.EventType != in.EventType {
		t.Errorf("EventType: got %q, want %q", got.EventType, in.EventType)
	}
	if got.TargetType != in.TargetType {
		t.Errorf("TargetType: got %q, want %q", got.TargetType, in.TargetType)
	}
	if got.TargetID != in.TargetID {
		t.Errorf("TargetID: got %q, want %q", got.TargetID, in.TargetID)
	}
	if got.DetailsJSON != in.DetailsJSON {
		t.Errorf("DetailsJSON: got %q, want %q", got.DetailsJSON, in.DetailsJSON)
	}
	if got.IP != in.IP {
		t.Errorf("IP: got %q, want %q", got.IP, in.IP)
	}
	if got.UserAgent != in.UserAgent {
		t.Errorf("UserAgent: got %q, want %q", got.UserAgent, in.UserAgent)
	}
	if got.CreatedAt != in.CreatedAt {
		t.Errorf("CreatedAt: got %d, want %d", got.CreatedAt, in.CreatedAt)
	}
}

// ---------- 4. ListPaginated returns newest-first ----------

func TestAuditLogListPaginatedNewestFirst(t *testing.T) {
	s, ctx := newTestStore(t)

	for _, ts := range []int64{100, 200, 300, 400, 500} {
		_, err := s.AuditLog().Append(ctx, AuditEntry{
			EventType: "test.event",
			CreatedAt: ts,
		})
		if err != nil {
			t.Fatalf("Append ts=%d: %v", ts, err)
		}
	}

	page, err := s.AuditLog().ListPaginated(ctx, AuditFilter{}, "", 100)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 5 {
		t.Fatalf("ListPaginated: got %d rows, want 5", len(page.Rows))
	}
	wantTs := []int64{500, 400, 300, 200, 100}
	for i, row := range page.Rows {
		if row.CreatedAt != wantTs[i] {
			t.Errorf("Rows[%d].CreatedAt = %d, want %d", i, row.CreatedAt, wantTs[i])
		}
	}
}

// ---------- 5. ListPaginated cursor walks all rows ----------

func TestAuditLogListPaginatedCursorWalks(t *testing.T) {
	s, ctx := newTestStore(t)

	for _, ts := range []int64{100, 200, 300, 400, 500} {
		_, err := s.AuditLog().Append(ctx, AuditEntry{
			EventType: "test.event",
			CreatedAt: ts,
		})
		if err != nil {
			t.Fatalf("Append ts=%d: %v", ts, err)
		}
	}

	// First page: limit 2 → [500, 400]
	page1, err := s.AuditLog().ListPaginated(ctx, AuditFilter{}, "", 2)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Rows) != 2 {
		t.Fatalf("page1: got %d rows, want 2", len(page1.Rows))
	}
	if page1.NextCursor == "" {
		t.Fatal("page1: NextCursor should be non-empty")
	}
	if page1.Rows[0].CreatedAt != 500 || page1.Rows[1].CreatedAt != 400 {
		t.Errorf("page1: got CreatedAt [%d, %d], want [500, 400]",
			page1.Rows[0].CreatedAt, page1.Rows[1].CreatedAt)
	}

	// Second page: limit 2 → [300, 200]
	page2, err := s.AuditLog().ListPaginated(ctx, AuditFilter{}, page1.NextCursor, 2)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Rows) != 2 {
		t.Fatalf("page2: got %d rows, want 2", len(page2.Rows))
	}
	if page2.NextCursor == "" {
		t.Fatal("page2: NextCursor should be non-empty")
	}
	if page2.Rows[0].CreatedAt != 300 || page2.Rows[1].CreatedAt != 200 {
		t.Errorf("page2: got CreatedAt [%d, %d], want [300, 200]",
			page2.Rows[0].CreatedAt, page2.Rows[1].CreatedAt)
	}

	// Third page: limit 2 → [100], NextCursor empty
	page3, err := s.AuditLog().ListPaginated(ctx, AuditFilter{}, page2.NextCursor, 2)
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	if len(page3.Rows) != 1 {
		t.Fatalf("page3: got %d rows, want 1", len(page3.Rows))
	}
	if page3.NextCursor != "" {
		t.Errorf("page3: NextCursor = %q, want empty", page3.NextCursor)
	}
	if page3.Rows[0].CreatedAt != 100 {
		t.Errorf("page3: CreatedAt = %d, want 100", page3.Rows[0].CreatedAt)
	}
}

// ---------- 6. ListPaginated limit clamping ----------

func TestAuditLogListPaginatedLimitClamping(t *testing.T) {
	s, ctx := newTestStore(t)

	// Insert 3 rows to test without timeout.
	for _, ts := range []int64{100, 200, 300} {
		_, err := s.AuditLog().Append(ctx, AuditEntry{
			EventType: "test.event",
			CreatedAt: ts,
		})
		if err != nil {
			t.Fatalf("Append ts=%d: %v", ts, err)
		}
	}

	// limit <= 0 should default to 100; with only 3 rows, all returned.
	page0, err := s.AuditLog().ListPaginated(ctx, AuditFilter{}, "", 0)
	if err != nil {
		t.Fatalf("ListPaginated(limit=0): %v", err)
	}
	if len(page0.Rows) != 3 {
		t.Errorf("limit=0: got %d rows, want 3", len(page0.Rows))
	}
	if page0.NextCursor != "" {
		t.Errorf("limit=0: NextCursor = %q, want empty (default 100 > 3 rows)", page0.NextCursor)
	}

	// limit > 500 should clamp to 500; with only 3 rows, all returned.
	page501, err := s.AuditLog().ListPaginated(ctx, AuditFilter{}, "", 501)
	if err != nil {
		t.Fatalf("ListPaginated(limit=501): %v", err)
	}
	if len(page501.Rows) != 3 {
		t.Errorf("limit=501: got %d rows, want 3", len(page501.Rows))
	}
	if page501.NextCursor != "" {
		t.Errorf("limit=501: NextCursor = %q, want empty (clamped 500 > 3 rows)", page501.NextCursor)
	}
}

// ---------- 7. Filter by ActorUserID ----------

func TestAuditLogFilterByActorUserID(t *testing.T) {
	s, ctx := newTestStore(t)

	for _, actor := range []string{"alice", "bob", "alice"} {
		_, err := s.AuditLog().Append(ctx, AuditEntry{
			ActorUserID: actor,
			EventType:   "test.event",
			CreatedAt:   100,
		})
		if err != nil {
			t.Fatalf("Append actor=%s: %v", actor, err)
		}
	}

	page, err := s.AuditLog().ListPaginated(ctx, AuditFilter{ActorUserID: "alice"}, "", 100)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("ListPaginated: got %d rows, want 2", len(page.Rows))
	}
	for _, row := range page.Rows {
		if row.ActorUserID != "alice" {
			t.Errorf("ActorUserID = %q, want %q", row.ActorUserID, "alice")
		}
	}
}

// ---------- 8. Filter by EventType ----------

func TestAuditLogFilterByEventType(t *testing.T) {
	s, ctx := newTestStore(t)

	for _, et := range []string{"user.login", "device.created", "user.login"} {
		_, err := s.AuditLog().Append(ctx, AuditEntry{
			EventType: et,
			CreatedAt: 100,
		})
		if err != nil {
			t.Fatalf("Append et=%s: %v", et, err)
		}
	}

	page, err := s.AuditLog().ListPaginated(ctx, AuditFilter{EventType: "user.login"}, "", 100)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("ListPaginated: got %d rows, want 2", len(page.Rows))
	}
	for _, row := range page.Rows {
		if row.EventType != "user.login" {
			t.Errorf("EventType = %q, want %q", row.EventType, "user.login")
		}
	}
}

// ---------- 9. Filter by Since and Until ----------

func TestAuditLogFilterBySinceAndUntil(t *testing.T) {
	s, ctx := newTestStore(t)

	for _, ts := range []int64{100, 200, 300} {
		_, err := s.AuditLog().Append(ctx, AuditEntry{
			EventType: "test.event",
			CreatedAt: ts,
		})
		if err != nil {
			t.Fatalf("Append ts=%d: %v", ts, err)
		}
	}

	page, err := s.AuditLog().ListPaginated(ctx, AuditFilter{Since: 150, Until: 250}, "", 100)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("ListPaginated: got %d rows, want 1", len(page.Rows))
	}
	if page.Rows[0].CreatedAt != 200 {
		t.Errorf("CreatedAt = %d, want 200", page.Rows[0].CreatedAt)
	}
}

// ---------- 10. Filter combines all fields ----------

func TestAuditLogFilterCombinesAllFields(t *testing.T) {
	s, ctx := newTestStore(t)

	entries := []AuditEntry{
		{ActorUserID: "alice", EventType: "user.login", CreatedAt: 100},
		{ActorUserID: "alice", EventType: "user.login", CreatedAt: 200},
		{ActorUserID: "alice", EventType: "user.login", CreatedAt: 300},
		{ActorUserID: "bob", EventType: "user.login", CreatedAt: 200},
		{ActorUserID: "alice", EventType: "device.created", CreatedAt: 200},
	}
	for _, e := range entries {
		_, err := s.AuditLog().Append(ctx, e)
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	// Filter: alice + user.login + since=150 + until=250 → only the row at ts=200
	f := AuditFilter{
		ActorUserID: "alice",
		EventType:   "user.login",
		Since:       150,
		Until:       250,
	}
	page, err := s.AuditLog().ListPaginated(ctx, f, "", 100)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("ListPaginated: got %d rows, want 1", len(page.Rows))
	}
	got := page.Rows[0]
	if got.ActorUserID != "alice" || got.EventType != "user.login" || got.CreatedAt != 200 {
		t.Errorf("unexpected row: actor=%q event=%q ts=%d", got.ActorUserID, got.EventType, got.CreatedAt)
	}
}

// ---------- 11. Prune by age ----------

func TestAuditLogPruneByAge(t *testing.T) {
	s, ctx := newTestStore(t)

	for _, ts := range []int64{100, 200, 300} {
		_, err := s.AuditLog().Append(ctx, AuditEntry{
			EventType: "test.event",
			CreatedAt: ts,
		})
		if err != nil {
			t.Fatalf("Append ts=%d: %v", ts, err)
		}
	}

	deleted, err := s.AuditLog().Prune(ctx, 250, 1000)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 2 {
		t.Errorf("Prune: deleted = %d, want 2", deleted)
	}

	page, err := s.AuditLog().ListPaginated(ctx, AuditFilter{}, "", 100)
	if err != nil {
		t.Fatalf("ListPaginated after Prune: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("ListPaginated: got %d rows, want 1", len(page.Rows))
	}
	if page.Rows[0].CreatedAt != 300 {
		t.Errorf("remaining row CreatedAt = %d, want 300", page.Rows[0].CreatedAt)
	}
}

// ---------- 11b. Prune honours the batch bound ----------

func TestAuditLogPruneRespectsBatch(t *testing.T) {
	s, ctx := newTestStore(t)

	for i := range 10 {
		if _, err := s.AuditLog().Append(ctx, AuditEntry{
			EventType: "test.event", CreatedAt: int64(100 + i*10),
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// All 10 rows are older than the cutoff; batch=3 caps this call.
	deleted, err := s.AuditLog().Prune(ctx, 99999, 3)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 3 {
		t.Errorf("Prune: deleted = %d, want 3 (the batch bound)", deleted)
	}
}
