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

	"github.com/jacaudi/diyddns/internal/shared/atomicfile"
)

// ErrNotFound is returned by Load when the credentials file does not exist.
var ErrNotFound = errors.New("credentials: file not found")

// ErrExists is returned by Save when the file already exists and force is false.
var ErrExists = errors.New("credentials: file already exists")

// Credentials is the on-disk credentials.json shape. Secret is the device HMAC
// key as base64 (exactly as the server delivered it). PendingSecret is the
// replacement a secret rotation generated and has not yet seen promoted; it is
// absent outside a rotation.
type Credentials struct {
	ServerURL     string `json:"server_url"`
	DeviceID      string `json:"device_id"`
	Secret        string `json:"secret"`
	PendingSecret string `json:"pending_secret,omitempty"`
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
// The non-force path is race-free against concurrent Save calls: it publishes
// with atomicfile.Create, whose temp file is per-call (O_EXCL) and whose final
// step is os.Link rather than os.Rename. Link fails atomically with EEXIST if
// the destination already exists — unlike Rename, which replaces the
// destination unconditionally on both POSIX and modern Windows — so two
// concurrent Save(path, _, false) calls can no longer both "win" and silently
// clobber each other; exactly one succeeds and the other gets ErrExists.
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
	name := filepath.Base(path)
	if force {
		if err := atomicfile.WriteFile(dir, name, data); err != nil {
			return fmt.Errorf("credentials: save %s: %w", path, err)
		}
		return nil
	}
	if err := atomicfile.Create(dir, name, data); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return fmt.Errorf("credentials: save %s: %w", path, err)
	}
	return nil
}
