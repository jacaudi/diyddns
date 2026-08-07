// Package credentials reads and writes the diyddns-client credentials file
// (credentials.json): the device_id + HMAC secret minted at enrollment, plus
// the server URL. It is deliberately independent of the enrollment logic so
// future commands (run, status, rotate) can read credentials without importing
// the enroll package.
package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotFound is returned by Load when the credentials file does not exist.
var ErrNotFound = errors.New("credentials: file not found")

// ErrExists is returned by Save when the file already exists and force is false.
var ErrExists = errors.New("credentials: file already exists")

// Credentials is the on-disk credentials.json shape. Secret is the device HMAC
// key as base64 (exactly as the server delivered it).
type Credentials struct {
	ServerURL string `json:"server_url"`
	DeviceID  string `json:"device_id"`
	Secret    string `json:"secret"`
}

// DefaultPath returns the default credentials path under the user's
// OS-specific config directory, as resolved by os.UserConfigDir
// (<user-config-dir>/diyddns/credentials.json).
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("credentials: resolve config dir: %w", err)
	}
	return filepath.Join(dir, "diyddns", "credentials.json"), nil
}

// Load reads and parses the credentials file. It returns ErrNotFound if the
// file is absent.
func Load(path string) (Credentials, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the operator-provided credentials-file location (--credentials-file flag or DefaultPath), not untrusted input; reading it is this function's purpose.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Credentials{}, ErrNotFound
		}
		return Credentials{}, fmt.Errorf("credentials: read %s: %w", path, err)
	}
	var c Credentials
	if err := json.Unmarshal(data, &c); err != nil {
		return Credentials{}, fmt.Errorf("credentials: parse %s: %w", path, err)
	}
	return c, nil
}

// Save writes c to path atomically with mode 0600, creating parent dirs (0700).
// If the file already exists and force is false it returns ErrExists.
//
// The non-force path is race-free against concurrent Save calls. os.CreateTemp
// gives each call its own temporary file (an O_EXCL retry loop, so no two
// callers share a tmp path), and the final publish uses os.Link rather than
// os.Rename. Link fails atomically with EEXIST if the destination already
// exists — unlike Rename, which replaces the destination unconditionally on
// both POSIX and modern Windows — so two concurrent Save(path, _, false) calls
// can no longer both "win" and silently clobber each other; exactly one
// succeeds and the other gets ErrExists.
//
// Note that a losing racer has written its temporary file before discovering it
// lost, so "refuses to overwrite" is a guarantee about path, not a promise that
// nothing was written anywhere; the temporary file is always removed.
func Save(path string, c Credentials, force bool) error {
	if !force {
		switch _, err := os.Stat(path); {
		case err == nil:
			return ErrExists
		case !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("credentials: stat %s: %w", path, err)
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("credentials: mkdir %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(c, "", "  ") // #nosec G117 -- persisting the device secret to credentials.json is the intended design (written atomically at mode 0600); the secret must be on disk for the agent to HMAC-sign later check-ins.
	if err != nil {
		return fmt.Errorf("credentials: marshal: %w", err)
	}

	// CreateTemp opens with O_EXCL at mode 0600 and retries until it wins a
	// unique name, so concurrent Saves never collide on the temporary file.
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("credentials: create temp in %s: %w", dir, err)
	}
	tmp := f.Name()
	// One cleanup covering every return path below. Rename consumes tmp (the
	// Remove then no-ops) and Link deliberately leaves it behind as a second
	// directory entry, so without this a stranded tmp file would hold a
	// complete, live device secret at mode 0600.
	defer func() { _ = os.Remove(tmp) }()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("credentials: write %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("credentials: close %s: %w", tmp, err)
	}

	if force {
		if err := os.Rename(tmp, path); err != nil {
			return fmt.Errorf("credentials: rename %s: %w", path, err)
		}
		return nil
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return fmt.Errorf("credentials: link %s: %w", path, err)
	}
	return nil
}
