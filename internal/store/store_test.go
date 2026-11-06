package store

import (
	"log/slog"
	"path/filepath"
	"testing"
)

// TestOpen_TwiceInOneProcess guards #103's registration trap: a timing
// wrapper registered with sql.Register would panic on the second Open.
func TestOpen_TwiceInOneProcess(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.DiscardHandler)
	a, err := Open(t.Context(), filepath.Join(dir, "a.db"), log)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	b, err := Open(t.Context(), filepath.Join(dir, "b.db"), log)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("close a: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("close b: %v", err)
	}
}
