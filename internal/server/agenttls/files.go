package agenttls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jacaudi/diyddns/internal/shared/atomicfile"
)

// File names inside agent.tls.dir.
const (
	CAKeyFile       = "ca.key"
	CABackupKeyFile = "ca-backup.key"
	AgentCertFile   = "agent.crt"
	AgentKeyFile    = "agent.key"
	LockFile        = ".lock"
)

const ecKeyPEMType = "EC PRIVATE KEY"

// pendingName is the staging name writePending uses for a key file.
func pendingName(name string) string { return "." + name + ".pending" }

// writePending stores key as dir/.<name>.pending (0600), the staging file
// rollForward later renames to name. Staging lets the database insert happen
// between "key exists" and "key is in place" without losing the key to a crash.
func writePending(dir, name string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("agenttls: marshal %s: %w", name, err)
	}
	return atomicfile.WriteFile(dir, pendingName(name), pem.EncodeToMemory(&pem.Block{Type: ecKeyPEMType, Bytes: der}))
}

// readKey loads a P-256 private key written by writePending. Errors name the
// path but never carry key material.
func readKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is under operator-configured agent.tls.dir, not request input
	if err != nil {
		return nil, fmt.Errorf("agenttls: read key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != ecKeyPEMType {
		return nil, fmt.Errorf("agenttls: %s is not a PEM %s", path, ecKeyPEMType)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("agenttls: parse key %s: %w", path, err)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("agenttls: key %s is %s, want P-256", path, key.Curve.Params().Name)
	}
	return key, nil
}

// rollForward completes an interrupted key install: when dir/.<name>.pending
// exists and holds the private half of pub, it is renamed to name. It reports
// whether it renamed. An absent or non-matching pending file is left alone.
func rollForward(dir, name string, pub *ecdsa.PublicKey) (bool, error) {
	pending := filepath.Join(dir, pendingName(name))
	key, err := readKey(pending)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !key.PublicKey.Equal(pub) {
		return false, nil
	}
	if err := os.Rename(pending, filepath.Join(dir, name)); err != nil {
		return false, fmt.Errorf("agenttls: roll %s forward: %w", name, err)
	}
	if err := atomicfile.SyncDir(dir); err != nil {
		return false, err
	}
	return true, nil
}
