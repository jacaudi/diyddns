package notify

import (
	"path/filepath"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

// newTestStore returns a Store backed by a fresh on-disk SQLite database in
// t.TempDir(), migrations applied. Mirrors the fixture every other package that
// needs a real database carries; there is deliberately no shared helper.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return st
}
