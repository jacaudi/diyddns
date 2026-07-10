package store

import (
	"testing"
)

func TestAuditLogAppendAssignsIDAndDefaultsCreatedAt(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.AuditLog()

	before := NowUnix()
	created, err := repo.Append(ctx, AuditEntry{EventType: "system.startup"})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("Append did not assign an ID")
	}
	if created.CreatedAt < before {
		t.Fatalf("Append did not default CreatedAt to now: got %d, want >= %d", created.CreatedAt, before)
	}
	if created.ActorUserID != "" {
		t.Fatalf("Append system event: ActorUserID = %q, want empty (no actor)", created.ActorUserID)
	}
}

func TestAuditLogAppendPreservesExplicitCreatedAtAndActor(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.AuditLog()

	created, err := repo.Append(ctx, AuditEntry{
		ActorUserID: "user-123", // bare string: actor_user_id has no FK constraint
		EventType:   "auth.login",
		TargetType:  "session",
		TargetID:    "sess-456",
		DetailsJSON: `{"ip":"203.0.113.5"}`,
		IP:          "203.0.113.5",
		UserAgent:   "test-agent/1.0",
		CreatedAt:   12345,
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if created.CreatedAt != 12345 {
		t.Fatalf("Append overwrote explicit CreatedAt: got %d, want 12345", created.CreatedAt)
	}
	if created.ActorUserID != "user-123" {
		t.Fatalf("Append did not preserve ActorUserID: got %q", created.ActorUserID)
	}
	if created.TargetType != "session" || created.TargetID != "sess-456" {
		t.Fatalf("Append did not preserve target fields: got type=%q id=%q", created.TargetType, created.TargetID)
	}
	if created.DetailsJSON != `{"ip":"203.0.113.5"}` {
		t.Fatalf("Append did not preserve DetailsJSON: got %q", created.DetailsJSON)
	}
	if created.IP != "203.0.113.5" || created.UserAgent != "test-agent/1.0" {
		t.Fatalf("Append did not preserve IP/UserAgent: got ip=%q ua=%q", created.IP, created.UserAgent)
	}
}

// TestAuditLogListPaginatedRoundTripsAllRowsAndReachesEnd appends 7 rows
// (with a deliberate created_at tie to prove the id DESC tiebreak), pages
// through them 3 at a time with no filter, and asserts every row is seen
// exactly once, in (created_at DESC, id DESC) order, ending with an empty
// NextCursor.
func TestAuditLogListPaginatedRoundTripsAllRowsAndReachesEnd(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.AuditLog()

	createdAts := []int64{100, 200, 200, 300, 400, 500, 500}
	var wantIDs []int64
	for _, createdAt := range createdAts {
		row, err := repo.Append(ctx, AuditEntry{EventType: "event", CreatedAt: createdAt})
		if err != nil {
			t.Fatalf("Append(created_at=%d): %v", createdAt, err)
		}
		wantIDs = append(wantIDs, row.ID)
	}
	// Expected descending order by (created_at, id): reverse insertion order,
	// since createdAts is non-decreasing and ids are assigned sequentially.
	want := make([]int64, len(wantIDs))
	for i, id := range wantIDs {
		want[len(wantIDs)-1-i] = id
	}

	const pageSize = 3
	var gotIDs []int64
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > len(want) {
			t.Fatal("ListPaginated did not terminate: exceeded expected page count")
		}
		page, err := repo.ListPaginated(ctx, AuditFilter{}, cursor, pageSize)
		if err != nil {
			t.Fatalf("ListPaginated(cursor=%q): %v", cursor, err)
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
		t.Fatalf("ListPaginated round-trip returned %d rows, want %d", len(gotIDs), len(want))
	}
	for i, id := range gotIDs {
		if id != want[i] {
			t.Fatalf("ListPaginated round-trip [%d] = id %d, want %d (full sequence: got=%v want=%v)", i, id, want[i], gotIDs, want)
		}
	}
}

func TestAuditLogListPaginatedEmptyReturnsEmptyPageAndNoCursor(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.AuditLog()

	page, err := repo.ListPaginated(ctx, AuditFilter{}, "", 50)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 0 {
		t.Fatalf("ListPaginated on empty table returned %d rows, want 0", len(page.Rows))
	}
	if page.NextCursor != "" {
		t.Fatalf("ListPaginated on empty table NextCursor = %q, want empty", page.NextCursor)
	}
}

func TestAuditLogListPaginatedDefaultLimitIsOneHundred(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.AuditLog()

	for i := range 150 {
		if _, err := repo.Append(ctx, AuditEntry{EventType: "event", CreatedAt: int64(i + 1)}); err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
	}

	page, err := repo.ListPaginated(ctx, AuditFilter{}, "", 0)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 100 {
		t.Fatalf("ListPaginated(limit=0) returned %d rows, want 100 (default)", len(page.Rows))
	}
	if page.NextCursor == "" {
		t.Fatal("ListPaginated(limit=0) NextCursor empty, want non-empty (150 rows > default 100)")
	}
}

// TestAuditLogListPaginatedFilterByActorUserID proves ActorUserID narrows
// the result set to only that actor's events, and that pagination still
// terminates correctly within the filtered subset (no leakage of other
// actors' rows across pages).
func TestAuditLogListPaginatedFilterByActorUserID(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.AuditLog()

	var wantIDs []int64
	for i, createdAt := range []int64{100, 200, 300, 400, 500} {
		row, err := repo.Append(ctx, AuditEntry{ActorUserID: "actor-a", EventType: "event", CreatedAt: createdAt})
		if err != nil {
			t.Fatalf("Append actor-a(%d): %v", i, err)
		}
		wantIDs = append(wantIDs, row.ID)
	}
	for _, createdAt := range []int64{150, 250, 350} {
		if _, err := repo.Append(ctx, AuditEntry{ActorUserID: "actor-b", EventType: "event", CreatedAt: createdAt}); err != nil {
			t.Fatalf("Append actor-b: %v", err)
		}
	}
	want := make([]int64, len(wantIDs))
	for i, id := range wantIDs {
		want[len(wantIDs)-1-i] = id
	}

	const pageSize = 2
	var gotIDs []int64
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > len(want) {
			t.Fatal("ListPaginated did not terminate")
		}
		page, err := repo.ListPaginated(ctx, AuditFilter{ActorUserID: "actor-a"}, cursor, pageSize)
		if err != nil {
			t.Fatalf("ListPaginated(cursor=%q): %v", cursor, err)
		}
		for _, row := range page.Rows {
			if row.ActorUserID != "actor-a" {
				t.Fatalf("ListPaginated filter by ActorUserID leaked row with ActorUserID = %q", row.ActorUserID)
			}
			gotIDs = append(gotIDs, row.ID)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	if len(gotIDs) != len(want) {
		t.Fatalf("ListPaginated filter by ActorUserID returned %d rows, want %d", len(gotIDs), len(want))
	}
	for i, id := range gotIDs {
		if id != want[i] {
			t.Fatalf("ListPaginated filter by ActorUserID [%d] = id %d, want %d", i, id, want[i])
		}
	}
}

// TestAuditLogListPaginatedFilterByEventType proves EventType narrows the
// result set to an exact match only.
func TestAuditLogListPaginatedFilterByEventType(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.AuditLog()

	loginID, err := repo.Append(ctx, AuditEntry{EventType: "auth.login", CreatedAt: 100})
	if err != nil {
		t.Fatalf("Append login: %v", err)
	}
	if _, err := repo.Append(ctx, AuditEntry{EventType: "auth.logout", CreatedAt: 200}); err != nil {
		t.Fatalf("Append logout: %v", err)
	}
	if _, err := repo.Append(ctx, AuditEntry{EventType: "device.enroll", CreatedAt: 300}); err != nil {
		t.Fatalf("Append enroll: %v", err)
	}

	page, err := repo.ListPaginated(ctx, AuditFilter{EventType: "auth.login"}, "", 50)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("ListPaginated filter by EventType returned %d rows, want 1", len(page.Rows))
	}
	if page.Rows[0].ID != loginID.ID {
		t.Fatalf("ListPaginated filter by EventType returned id %d, want %d", page.Rows[0].ID, loginID.ID)
	}
}

// TestAuditLogListPaginatedFilterBySinceUntilWindow proves Since/Until bound
// the created_at range (inclusive on both ends), and pagination still works
// within the filtered window.
func TestAuditLogListPaginatedFilterBySinceUntilWindow(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.AuditLog()

	var allIDs []int64
	for _, createdAt := range []int64{100, 200, 300, 400, 500} {
		row, err := repo.Append(ctx, AuditEntry{EventType: "event", CreatedAt: createdAt})
		if err != nil {
			t.Fatalf("Append(created_at=%d): %v", createdAt, err)
		}
		allIDs = append(allIDs, row.ID)
	}
	// Window [200, 400] inclusive should return ids for createdAts 200,300,400.
	wantIDs := []int64{allIDs[3], allIDs[2], allIDs[1]} // 400 desc to 200

	const pageSize = 2
	var gotIDs []int64
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > len(wantIDs) {
			t.Fatal("ListPaginated did not terminate")
		}
		page, err := repo.ListPaginated(ctx, AuditFilter{Since: 200, Until: 400}, cursor, pageSize)
		if err != nil {
			t.Fatalf("ListPaginated(cursor=%q): %v", cursor, err)
		}
		for _, row := range page.Rows {
			if row.CreatedAt < 200 || row.CreatedAt > 400 {
				t.Fatalf("ListPaginated filter by Since/Until leaked row with CreatedAt = %d", row.CreatedAt)
			}
			gotIDs = append(gotIDs, row.ID)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	if len(gotIDs) != len(wantIDs) {
		t.Fatalf("ListPaginated filter by Since/Until returned %d rows, want %d", len(gotIDs), len(wantIDs))
	}
	for i, id := range gotIDs {
		if id != wantIDs[i] {
			t.Fatalf("ListPaginated filter by Since/Until [%d] = id %d, want %d", i, id, wantIDs[i])
		}
	}
}

// TestAuditLogPruneDeletesOlderKeepsNewer proves Prune removes rows with
// created_at strictly before olderThan and leaves the rest untouched — no
// always-keep-latest guard (unlike ip_history), since audit_log is a plain
// append-only log with no natural "latest per key" to protect.
func TestAuditLogPruneDeletesOlderKeepsNewer(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.AuditLog()

	var ids []int64
	for _, createdAt := range []int64{100, 200, 300, 400, 500} {
		row, err := repo.Append(ctx, AuditEntry{EventType: "event", CreatedAt: createdAt})
		if err != nil {
			t.Fatalf("Append(created_at=%d): %v", createdAt, err)
		}
		ids = append(ids, row.ID)
	}

	n, err := repo.Prune(ctx, 350)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 3 {
		t.Fatalf("Prune deleted %d rows, want 3 (created_at 100,200,300)", n)
	}

	page, err := repo.ListPaginated(ctx, AuditFilter{}, "", 50)
	if err != nil {
		t.Fatalf("ListPaginated after Prune: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("ListPaginated after Prune returned %d rows, want 2", len(page.Rows))
	}
	remaining := map[int64]bool{ids[3]: false, ids[4]: false}
	for _, row := range page.Rows {
		if _, ok := remaining[row.ID]; !ok {
			t.Fatalf("ListPaginated after Prune returned unexpected surviving id %d", row.ID)
		}
		remaining[row.ID] = true
	}
	for id, seen := range remaining {
		if !seen {
			t.Fatalf("Prune unexpectedly deleted id %d that should have survived", id)
		}
	}
}

func TestAuditLogPruneOnEmptyTableDeletesNothing(t *testing.T) {
	s, ctx := newTestStore(t)
	repo := s.AuditLog()

	n, err := repo.Prune(ctx, NowUnix()+100000)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 0 {
		t.Fatalf("Prune on empty table deleted %d rows, want 0", n)
	}
}

func TestClampAuditLimitDefaultsAndClamps(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "zero defaults to 100", limit: 0, want: 100},
		{name: "negative defaults to 100", limit: -5, want: 100},
		{name: "one stays one", limit: 1, want: 1},
		{name: "500 stays 500", limit: 500, want: 500},
		{name: "over 500 clamps to 500", limit: 501, want: 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clampAuditLimit(tt.limit)
			if got != tt.want {
				t.Errorf("clampAuditLimit(%d) = %d, want %d", tt.limit, got, tt.want)
			}
		})
	}
}
