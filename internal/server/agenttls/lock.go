//go:build linux || darwin

package agenttls

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ErrLocked means another process holds the agent.tls.dir lock.
var ErrLocked = errors.New("agenttls: agent.tls.dir is locked by another process")

// Lock is an exclusive flock on dir/.lock. The kernel drops it if the holder
// dies, so a crash never leaves a stale lock behind.
type Lock struct{ f *os.File }

// AcquireLock takes the exclusive, non-blocking lock on dir/.lock, creating
// the file 0600. It returns ErrLocked when another holder has it.
func AcquireLock(dir string) (*Lock, error) {
	path := filepath.Join(dir, LockFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: path is under operator-configured agent.tls.dir, not request input
	if err != nil {
		return nil, fmt.Errorf("agenttls: open lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrLocked, path)
		}
		return nil, fmt.Errorf("agenttls: lock %s: %w", path, err)
	}
	return &Lock{f: f}, nil
}

// Release drops the lock by closing the file.
func (l *Lock) Release() error {
	if err := l.f.Close(); err != nil {
		return fmt.Errorf("agenttls: release lock: %w", err)
	}
	return nil
}
