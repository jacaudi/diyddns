package store

import (
	"errors"
	"sync"
	"testing"
)

// TestMigration007_Shape asserts the schema after Open (which runs every
// embedded migration): endpoints have no user_id, the attempts ledger and the
// user_initiated_at column are gone, feed_tokens and feed_state exist with
// feed_state seeded at seq 0, and foreign keys are still enforced.
func TestMigration007_Shape(t *testing.T) {
	s, ctx := newTestStore(t)

	if dbColumnExists(t, ctx, s.DB(), "notification_endpoints", "user_id") {
		t.Error("notification_endpoints.user_id still exists after 00007")
	}
	if dbColumnExists(t, ctx, s.DB(), "notification_deliveries", "user_initiated_at") {
		t.Error("notification_deliveries.user_initiated_at still exists after 00007")
	}
	if dbTableExists(t, ctx, s.DB(), "notification_attempts") {
		t.Error("notification_attempts still exists after 00007")
	}
	for _, tbl := range []string{"feed_tokens", "feed_state"} {
		if !dbTableExists(t, ctx, s.DB(), tbl) {
			t.Errorf("table %q missing after 00007", tbl)
		}
	}

	var seq, changedAt int64
	if err := s.DB().QueryRowContext(ctx, `SELECT seq, changed_at FROM feed_state WHERE id = 1`).Scan(&seq, &changedAt); err != nil {
		t.Fatalf("feed_state row: %v", err)
	}
	if seq != 0 || changedAt == 0 {
		t.Errorf("feed_state = (seq %d, changed_at %d), want (0, non-zero)", seq, changedAt)
	}

	var fk int
	if err := s.DB().QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("PRAGMA foreign_keys = %d, want 1 after the migration", fk)
	}
	var violations int
	if err := s.DB().QueryRowContext(ctx, `SELECT count(*) FROM pragma_foreign_key_check`).Scan(&violations); err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	if violations != 0 {
		t.Errorf("foreign_key_check reports %d violations, want 0", violations)
	}

	// The child FK survived the parent rebuild verbatim: a delivery with a
	// dangling endpoint_id must be rejected.
	_, err := s.DB().ExecContext(ctx,
		`INSERT INTO notification_deliveries
		   (endpoint_id, event_type, event_id, payload, attempts, next_attempt_at, status, created_at, updated_at)
		 VALUES ('no-such-endpoint', 'device.ip_changed', 1, X'7B7D', 0, 1, 'pending', 1, 1)`)
	if err == nil {
		t.Error("insert with a dangling endpoint_id succeeded; the FK to notification_endpoints was lost in the rebuild")
	}
}

// TestFeedState_BumpIsMonotonicUnderConcurrency: seq strictly increases across
// concurrent callers and changed_at follows the caller's now.
func TestFeedState_BumpIsMonotonicUnderConcurrency(t *testing.T) {
	s, ctx := newTestStore(t)
	const racers = 20

	var wg sync.WaitGroup
	seqs := make([]int64, racers)
	errs := make([]error, racers)
	for i := range racers {
		wg.Go(func() {
			seqs[i], errs[i] = s.FeedState().Bump(ctx, int64(1000+i))
		})
	}
	wg.Wait()

	seen := make(map[int64]bool, racers)
	for i := range racers {
		if errs[i] != nil {
			t.Fatalf("Bump[%d]: %v", i, errs[i])
		}
		if seqs[i] < 1 || seqs[i] > racers {
			t.Errorf("Bump[%d] = %d, want 1..%d", i, seqs[i], racers)
		}
		if seen[seqs[i]] {
			t.Errorf("seq %d returned twice", seqs[i])
		}
		seen[seqs[i]] = true
	}

	st, err := s.FeedState().Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if st.Seq != racers {
		t.Errorf("final seq = %d, want %d", st.Seq, racers)
	}
	if st.ChangedAt < 1000 || st.ChangedAt >= 1000+racers {
		t.Errorf("changed_at = %d, want one of the callers' timestamps", st.ChangedAt)
	}
}

func TestFeedTokens_CRUD(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()

	tok := FeedToken{ID: NewID(), Label: "envoy", TokenHash: "hash-1", CreatedBy: "", CreatedAt: now}
	if err := s.FeedTokens().Create(ctx, tok); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.FeedTokens().GetByHash(ctx, "hash-1")
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.ID != tok.ID || got.Label != "envoy" || got.LastUsedAt != 0 || got.CreatedBy != "" {
		t.Errorf("GetByHash = %+v, want id %s label envoy last_used 0 created_by \"\"", got, tok.ID)
	}

	if _, err := s.FeedTokens().GetByHash(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByHash(unknown) err = %v, want ErrNotFound", err)
	}

	dup := FeedToken{ID: NewID(), Label: "envoy", TokenHash: "hash-2", CreatedAt: now}
	if err := s.FeedTokens().Create(ctx, dup); !errors.Is(err, ErrConflict) {
		t.Errorf("Create(duplicate label) err = %v, want ErrConflict", err)
	}

	if err := s.FeedTokens().TouchLastUsed(ctx, tok.ID, now+5); err != nil {
		t.Fatalf("TouchLastUsed: %v", err)
	}
	list, err := s.FeedTokens().List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].LastUsedAt != now+5 {
		t.Errorf("List = %+v, want one token with last_used_at %d", list, now+5)
	}

	if err := s.FeedTokens().Delete(ctx, tok.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.FeedTokens().Delete(ctx, tok.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete(again) err = %v, want ErrNotFound", err)
	}
	if _, err := s.FeedTokens().GetByHash(ctx, "hash-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByHash after delete err = %v, want ErrNotFound", err)
	}
}

// TestFeedTokens_GetByID: the primary-key lookup the stream handler's
// revoke re-check uses (finding S1) returns the live row, and ErrNotFound
// once the row is deleted — the same "revoked is simply absent" contract
// GetByHash already has.
func TestFeedTokens_GetByID(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()

	tok := FeedToken{ID: NewID(), Label: "envoy", TokenHash: "hash-1", CreatedAt: now}
	if err := s.FeedTokens().Create(ctx, tok); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.FeedTokens().GetByID(ctx, tok.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != tok.ID || got.Label != "envoy" {
		t.Errorf("GetByID = %+v, want id %s label envoy", got, tok.ID)
	}

	if err := s.FeedTokens().Delete(ctx, tok.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.FeedTokens().GetByID(ctx, tok.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID after delete err = %v, want ErrNotFound", err)
	}
}

// TestFeedTokens_CreatedBySurvivesUserDeletion: created_by is ON DELETE SET
// NULL, so deleting the minting admin keeps the token and blanks the field.
func TestFeedTokens_CreatedBySurvivesUserDeletion(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()
	admin, err := s.Users().Create(ctx, User{Email: "admin@example.com", Role: "admin"})
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	tok := FeedToken{ID: NewID(), Label: "t", TokenHash: "h", CreatedBy: admin.ID, CreatedAt: now}
	if err := s.FeedTokens().Create(ctx, tok); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Users().Delete(ctx, admin.ID); err != nil {
		t.Fatalf("delete admin: %v", err)
	}
	got, err := s.FeedTokens().GetByHash(ctx, "h")
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.CreatedBy != "" {
		t.Errorf("created_by = %q after the creator was deleted, want \"\"", got.CreatedBy)
	}
}

// TestDevices_ListFeed applies the membership predicate (design D18): enabled
// device, enabled owner, at least one address; ordered by id; nullable columns
// scanned safely (an IPv6-only device must not fail the scan).
func TestDevices_ListFeed(t *testing.T) {
	s, ctx := newTestStore(t)
	now := NowUnix()

	alice, err := s.Users().Create(ctx, User{Email: "alice@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	bob, err := s.Users().Create(ctx, User{Email: "bob@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed bob: %v", err)
	}
	if err := s.Users().SetDisabled(ctx, bob.ID, true); err != nil {
		t.Fatalf("disable bob: %v", err)
	}

	mk := func(id, userID, label, v4, v6 string, disabled bool) {
		t.Helper()
		if _, err := s.DB().ExecContext(ctx,
			`INSERT INTO devices (id, user_id, label, secret_hash, current_ipv4, current_ipv6, last_seen_at, disabled, created_at, updated_at)
			 VALUES (?, ?, ?, 'h', NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, ?)`,
			id, userID, label, v4, v6, now, boolToInt(disabled), now, now); err != nil {
			t.Fatalf("seed device %s: %v", id, err)
		}
	}
	mk("d1", alice.ID, "both", "203.0.113.9", "2001:db8::1", false)
	mk("d2", alice.ID, "v6only", "", "2001:db8::2", false)
	mk("d3", alice.ID, "noaddr", "", "", false)
	mk("d4", alice.ID, "disabled", "203.0.113.4", "", true)
	mk("d5", bob.ID, "owner-disabled", "203.0.113.5", "", false)

	got, err := s.Devices().ListFeed(ctx)
	if err != nil {
		t.Fatalf("ListFeed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListFeed returned %d rows, want 2: %+v", len(got), got)
	}
	if got[0].ID != "d1" || got[1].ID != "d2" {
		t.Errorf("order = [%s %s], want [d1 d2]", got[0].ID, got[1].ID)
	}
	if got[0].IPv4 != "203.0.113.9" || got[0].IPv6 != "2001:db8::1" || got[0].Label != "both" || got[0].LastSeenAt != now {
		t.Errorf("d1 = %+v", got[0])
	}
	if got[1].IPv4 != "" || got[1].IPv6 != "2001:db8::2" {
		t.Errorf("d2 = %+v, want IPv4 \"\" (NULL) and IPv6 set", got[1])
	}
}
