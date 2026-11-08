package atomicfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// unreadableDir returns a directory that can be written to (create, rename,
// link) but not opened for reading, so only the directory fsync can fail.
func unreadableDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	return dir
}

// assertOnly fails unless dir holds exactly name with content want at 0600:
// no temporary file may survive a write.
func assertOnly(t *testing.T, dir, name, want string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != name {
		t.Fatalf("dir holds %v, want only %s", entries, name)
	}
	got, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != want {
		t.Errorf("content = %q, want %q", got, want)
	}
	fi, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

func TestWriteFile_ReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFile(dir, "f", []byte("old")); err != nil {
		t.Fatalf("first WriteFile: %v", err)
	}
	if err := WriteFile(dir, "f", []byte("new")); err != nil {
		t.Fatalf("second WriteFile: %v", err)
	}
	assertOnly(t, dir, "f", "new")
}

func TestWriteFile_PropagatesSyncDirError(t *testing.T) {
	if err := WriteFile(unreadableDir(t), "f", []byte("x")); err == nil {
		t.Error("WriteFile succeeded although the directory could not be synced")
	}
}

func TestCreate_PublishesNewFile(t *testing.T) {
	dir := t.TempDir()
	if err := Create(dir, "f", []byte("x")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	assertOnly(t, dir, "f", "x")
}

// Create must never replace: the loser gets fs.ErrExist, the existing content
// survives, and the loser's temporary file is removed.
func TestCreate_RefusesExisting(t *testing.T) {
	dir := t.TempDir()
	if err := Create(dir, "f", []byte("first")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	err := Create(dir, "f", []byte("second"))
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second Create = %v, want fs.ErrExist", err)
	}
	assertOnly(t, dir, "f", "first")
}

func TestSyncDir(t *testing.T) {
	if err := SyncDir(t.TempDir()); err != nil {
		t.Errorf("SyncDir(existing dir) = %v, want nil", err)
	}
	if err := SyncDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("SyncDir(missing dir) = nil, want an error")
	}
}
