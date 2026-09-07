package feed

import (
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

// Test seams. Each setter returns a restore func for t.Cleanup. These are
// the only writers of the timing vars outside this file's package tests, and
// package feed uses no t.Parallel(), so an unrestored write would leak into
// every later test.

// SetPingInterval shortens the ping ticker for tests.
func SetPingInterval(d time.Duration) func() {
	old := pingInterval
	pingInterval = d
	return func() { pingInterval = old }
}

// SetPingTimeout shortens the per-ping timeout for tests.
func SetPingTimeout(d time.Duration) func() {
	old := pingTimeout
	pingTimeout = d
	return func() { pingTimeout = old }
}

// SetWriteTimeout shortens the per-write timeout for tests.
func SetWriteTimeout(d time.Duration) func() {
	old := writeTimeout
	writeTimeout = d
	return func() { writeTimeout = old }
}

// SetBeforeSnapshot installs the hook the stream handler calls immediately
// before rendering the snapshot.
func SetBeforeSnapshot(fn func()) func() {
	old := beforeSnapshot
	beforeSnapshot = fn
	return func() { beforeSnapshot = old }
}

// WaitPumps blocks until every subscribed pump has unsubscribed, so a test
// can wait for the abandoned pump of a timed-out Shutdown before goleak runs.
func (h *Hub) WaitPumps() { h.wg.Wait() }

// Live reports the number of subscribers currently in the map.
func (h *Hub) Live() int { return h.live() }

// SeedMember inserts an enabled user and an enabled device with an IPv4 —
// one row of the membership predicate (D18). Exported and defined here, not
// in a _test.go of either package, because both the internal tests (package
// feed) and the stream integration tests (package feed_test) in this
// directory need exactly this helper and a second copy would be the same
// knowledge written twice. Moved here verbatim from Task 7's handlers_test.go,
// which deletes its copy in Step 6.
func SeedMember(t *testing.T, st *store.Store, id, v4 string) {
	t.Helper()
	ctx := t.Context()
	now := store.NowUnix()
	if _, err := st.DB().ExecContext(ctx,
		`INSERT OR IGNORE INTO users (id, email, role, disabled, created_at, updated_at)
		 VALUES ('u1', 'u1@example.com', 'user', 0, ?, ?)`, now, now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO devices (id, user_id, label, secret_hash, current_ipv4, last_seen_at, disabled, created_at, updated_at)
		 VALUES (?, 'u1', ?, 'h', ?, ?, 0, ?, ?)`, id, id, v4, now, now, now); err != nil {
		t.Fatalf("seed device: %v", err)
	}
}
