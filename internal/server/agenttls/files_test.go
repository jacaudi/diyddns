package agenttls

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRollForward_PropagatesSyncDirError(t *testing.T) {
	// Stage the pending file in a readable dir, then make it unreadable so
	// readKey cannot be what fails: stage via a second dir and move it in.
	src := t.TempDir()
	_, key, err := newCACert(time.Now())
	if err != nil {
		t.Fatalf("newCACert: %v", err)
	}
	if err := writePending(src, "k", key); err != nil {
		t.Fatalf("writePending: %v", err)
	}
	dir := t.TempDir()
	if err := os.Rename(filepath.Join(src, pendingName("k")), filepath.Join(dir, pendingName("k"))); err != nil {
		t.Fatalf("stage pending: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	// 0300 blocks reading the dir entry list but not open-by-name, so readKey
	// and the rename succeed and only the directory sync fails.
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if moved, err := rollForward(dir, "k", &key.PublicKey); err == nil {
		t.Errorf("rollForward = %v, nil; want the directory sync error", moved)
	}
}
