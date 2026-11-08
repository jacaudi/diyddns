// Package atomicfile writes owner-only (0600) files so a crash leaves either
// the old file or the whole new one, never a torn write, and the new
// directory entry survives power loss.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile replaces dir/name with data. It writes a temp file in dir, fsyncs
// it, renames it into place and fsyncs dir.
func WriteFile(dir, name string, data []byte) error {
	tmp, err := writeTemp(dir, name, data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("atomicfile: rename %s into place: %w", name, err)
	}
	return SyncDir(dir)
}

// Create is WriteFile that never replaces: it publishes with os.Link, which
// fails atomically when dir/name already exists (the error matches
// fs.ErrExist), so of two concurrent Creates exactly one wins. The temp file
// is removed either way.
func Create(dir, name string, data []byte) error {
	tmp, err := writeTemp(dir, name, data)
	if err != nil {
		return err
	}
	err = os.Link(tmp, filepath.Join(dir, name))
	_ = os.Remove(tmp) // after a Link, tmp is a second entry holding the same data
	if err != nil {
		return fmt.Errorf("atomicfile: link %s: %w", name, err)
	}
	return SyncDir(dir)
}

// writeTemp writes data to a fresh 0600 temp file in dir and fsyncs it,
// returning its path. On error nothing is left behind.
func writeTemp(dir, name string, data []byte) (_ string, err error) {
	f, err := os.CreateTemp(dir, "."+name+".tmp.*") // O_EXCL, 0600
	if err != nil {
		return "", fmt.Errorf("atomicfile: create temp for %s in %s: %w", name, dir, err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return "", fmt.Errorf("atomicfile: write %s: %w", tmp, err)
	}
	if err = f.Sync(); err != nil {
		return "", fmt.Errorf("atomicfile: sync %s: %w", tmp, err)
	}
	// Exactly 0600 even under a umask that strips owner bits from CreateTemp's.
	if err = f.Chmod(0o600); err != nil {
		return "", fmt.Errorf("atomicfile: chmod %s: %w", tmp, err)
	}
	if err = f.Close(); err != nil {
		return "", fmt.Errorf("atomicfile: close %s: %w", tmp, err)
	}
	return tmp, nil
}

// SyncDir fsyncs dir itself so a create or rename in it survives power loss;
// fsyncing the file alone does not persist its directory entry.
func SyncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: callers pass their own state directory, not request input
	if err != nil {
		return fmt.Errorf("atomicfile: open dir %s for sync: %w", dir, err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("atomicfile: sync dir %s: %w", dir, err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("atomicfile: close dir %s: %w", dir, err)
	}
	return nil
}
