//go:build linux || darwin

package agenttls

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireLock_SecondIsErrLocked(t *testing.T) {
	dir := t.TempDir()

	first, err := AcquireLock(dir)
	if err != nil {
		t.Fatalf("first AcquireLock: %v", err)
	}
	if _, err := AcquireLock(dir); !errors.Is(err, ErrLocked) {
		t.Errorf("second AcquireLock err = %v, want ErrLocked", err)
	}

	fi, err := os.Stat(filepath.Join(dir, LockFile))
	if err != nil {
		t.Fatalf("stat lock file: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("lock file mode = %o, want 600", got)
	}

	if err := first.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	third, err := AcquireLock(dir)
	if err != nil {
		t.Fatalf("third AcquireLock after Release: %v", err)
	}
	if err := third.Release(); err != nil {
		t.Errorf("third Release: %v", err)
	}
}
